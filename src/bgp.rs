//! BGP message parser and the few encoders the passive listener needs.
//!
//! UPDATE (RFC 4271), MP-BGP (RFC 4760), 4-byte ASNs and AS4_PATH merging
//! (RFC 6793), ADD-PATH (RFC 7911), communities (RFC 1997), large communities
//! (RFC 8092), OPEN capabilities (RFC 5492) with extended optional parameters
//! (RFC 9072).
//!
//! Every length field is checked against the remaining buffer; malformed input
//! returns an error and never panics.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use thiserror::Error;

use crate::wire::{Cursor, Truncated};

pub const HEADER_LEN: usize = 19;
/// RFC 8654 extended messages raise the 4096-byte limit to 65535.
pub const MAX_MESSAGE_LEN: usize = 65_535;
pub const MSG_OPEN: u8 = 1;
pub const MSG_UPDATE: u8 = 2;
pub const MSG_NOTIFICATION: u8 = 3;
pub const MSG_KEEPALIVE: u8 = 4;
pub const MSG_ROUTE_REFRESH: u8 = 5;
/// RFC 6793 placeholder for a 4-byte ASN in 2-byte fields.
pub const AS_TRANS: u32 = 23_456;

const ATTR_ORIGIN: u8 = 1;
const ATTR_AS_PATH: u8 = 2;
const ATTR_COMMUNITIES: u8 = 8;
const ATTR_MP_REACH: u8 = 14;
const ATTR_MP_UNREACH: u8 = 15;
const ATTR_AS4_PATH: u8 = 17;
const ATTR_LARGE_COMMUNITIES: u8 = 32;
const FLAG_EXTENDED_LEN: u8 = 0x10;

pub const AFI_IPV4: u16 = 1;
pub const AFI_IPV6: u16 = 2;
pub const SAFI_UNICAST: u8 = 1;

const CAP_MP: u8 = 1;
const CAP_AS4: u8 = 65;
const CAP_ADD_PATH: u8 = 69;
const OPT_PARAM_CAPABILITIES: u8 = 2;
/// Upper bound on capabilities kept from one OPEN.
const MAX_CAPS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BgpError {
    #[error("truncated BGP {0}")]
    Truncated(&'static str),
    #[error("invalid BGP marker")]
    BadMarker,
    #[error("BGP length field {declared} does not match message size {actual}")]
    BadLength { declared: usize, actual: usize },
    #[error("expected BGP UPDATE (type 2), got type {0}")]
    NotUpdate(u8),
    #[error("expected BGP OPEN (type 1), got type {0}")]
    NotOpen(u8),
    #[error("invalid prefix length {0}")]
    BadPrefixLen(u8),
    #[error("malformed path attribute {code}: {reason}")]
    BadAttribute { code: u8, reason: &'static str },
    #[error("malformed OPEN: {0}")]
    BadOpen(&'static str),
}

impl From<Truncated> for BgpError {
    fn from(t: Truncated) -> Self {
        BgpError::Truncated(t.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Igp,
    Egp,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Set(Vec<u32>),
    Sequence(Vec<u32>),
    ConfedSequence(Vec<u32>),
    ConfedSet(Vec<u32>),
}

impl Segment {
    fn is_confed(&self) -> bool {
        matches!(self, Segment::ConfedSequence(_) | Segment::ConfedSet(_))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AsPath(pub Vec<Segment>);

/// Single ASN from a segment that is not a confederation segment.
/// An AS_SET with more than one member has no unambiguous ASN.
fn segment_asn(seg: &Segment, last: bool) -> Option<Option<u32>> {
    match seg {
        Segment::Sequence(a) => Some(if last { a.last() } else { a.first() }.copied()),
        Segment::Set(a) => Some(if a.len() == 1 {
            a.first().copied()
        } else {
            None
        }),
        Segment::ConfedSequence(_) | Segment::ConfedSet(_) => None,
    }
}

impl AsPath {
    /// Origin ASN: the right-most ASN outside confederation segments.
    pub fn origin(&self) -> Option<u32> {
        self.0.iter().rev().find_map(|s| segment_asn(s, true))?
    }

    /// First-hop upstream: the left-most ASN outside confederation segments.
    pub fn first_hop(&self) -> Option<u32> {
        self.0.iter().find_map(|s| segment_asn(s, false))?
    }

    /// Path length for best-path selection (RFC 4271 9.1.2.2): an AS_SET
    /// counts as one, confederation segments do not count.
    pub fn path_len(&self) -> usize {
        self.0
            .iter()
            .map(|s| match s {
                Segment::Sequence(a) => a.len(),
                Segment::Set(_) => 1,
                _ => 0,
            })
            .sum()
    }

    /// Every ASN in order (sets and confederation segments flattened).
    pub fn flatten(&self) -> Vec<u32> {
        self.0
            .iter()
            .flat_map(|s| match s {
                Segment::Set(a)
                | Segment::Sequence(a)
                | Segment::ConfedSequence(a)
                | Segment::ConfedSet(a) => a.iter().copied(),
            })
            .collect()
    }

    /// AS_SEQUENCE hops with prepending collapsed, for relationship checks.
    /// `None` when the path holds an ambiguous multi-member AS_SET.
    pub fn hops(&self) -> Option<Vec<u32>> {
        let mut out: Vec<u32> = Vec::new();
        for s in &self.0 {
            let asns: &[u32] = match s {
                Segment::Sequence(a) => a,
                Segment::Set(a) if a.len() == 1 => a,
                Segment::Set(_) => return None,
                _ => continue,
            };
            for a in asns {
                if out.last() != Some(a) {
                    out.push(*a);
                }
            }
        }
        Some(out)
    }
}

/// Collapses consecutive duplicate tokens of a rendered AS path ("prepends").
pub fn collapse_prepends(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for t in path.split_whitespace() {
        if out.last() != Some(&t) {
            out.push(t);
        }
    }
    out.join(" ")
}

impl fmt::Display for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let join =
            |a: &[u32], sep: &str| a.iter().map(u32::to_string).collect::<Vec<_>>().join(sep);
        let parts: Vec<String> = self
            .0
            .iter()
            .map(|s| match s {
                Segment::Sequence(a) => join(a, " "),
                Segment::Set(a) => format!("{{{}}}", join(a, ",")),
                Segment::ConfedSequence(a) => format!("({})", join(a, " ")),
                Segment::ConfedSet(a) => format!("[{}]", join(a, ",")),
            })
            .collect();
        f.write_str(&parts.join(" "))
    }
}

/// RFC 6793 4.2.3: rebuild the real path from a 2-byte AS_PATH (with AS_TRANS)
/// and the AS4_PATH attribute.
pub fn merge_as4_path(as_path: &AsPath, as4_path: &AsPath) -> AsPath {
    let as4: Vec<Segment> = as4_path
        .0
        .iter()
        .filter(|s| !s.is_confed())
        .cloned()
        .collect();
    let n4 = AsPath(as4.clone()).path_len();
    let n2 = as_path.path_len();
    if n2 < n4 {
        return as_path.clone();
    }
    let mut keep = n2 - n4;
    let mut out = Vec::new();
    for seg in &as_path.0 {
        match seg {
            Segment::ConfedSequence(_) | Segment::ConfedSet(_) => out.push(seg.clone()),
            Segment::Set(_) if keep > 0 => {
                out.push(seg.clone());
                keep -= 1;
            }
            Segment::Sequence(a) if keep > 0 => {
                let take = a.len().min(keep);
                out.push(Segment::Sequence(a[..take].to_vec()));
                keep -= take;
            }
            _ => break,
        }
    }
    out.extend(as4);
    AsPath(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attributes {
    pub origin: Option<Origin>,
    pub as_path: AsPath,
    pub communities: Vec<u32>,
    pub large_communities: Vec<[u32; 3]>,
}

/// One NLRI entry; `path_id` is set when ADD-PATH is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nlri {
    pub prefix: IpNet,
    pub path_id: Option<u32>,
}

impl From<IpNet> for Nlri {
    fn from(prefix: IpNet) -> Self {
        Nlri {
            prefix,
            path_id: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Update {
    pub withdrawn: Vec<Nlri>,
    pub announced: Vec<Nlri>,
    pub attrs: Attributes,
}

/// How to decode an UPDATE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseOptions {
    /// 4-byte AS_PATH encoding (otherwise 2-byte, merged with AS4_PATH).
    pub as4: bool,
    /// ADD-PATH path identifiers precede IPv4 / IPv6 unicast NLRI.
    pub add_path_v4: bool,
    pub add_path_v6: bool,
    /// TABLE_DUMP_V2 RIB entry attributes: MP_REACH_NLRI carries only the next hop.
    pub mrt_rib: bool,
}

impl ParseOptions {
    pub fn new(as4: bool) -> Self {
        ParseOptions {
            as4,
            ..Self::default()
        }
    }

    pub fn with_add_path(mut self, v4: bool, v6: bool) -> Self {
        self.add_path_v4 = v4;
        self.add_path_v6 = v6;
        self
    }

    fn add_path(&self, v6: bool) -> bool {
        if v6 {
            self.add_path_v6
        } else {
            self.add_path_v4
        }
    }
}

/// Validates marker and length; returns the message type and body.
pub fn split_message(msg: &[u8]) -> Result<(u8, &[u8]), BgpError> {
    let mut c = Cursor::new(msg);
    if c.take(16, "marker")?.iter().any(|b| *b != 0xff) {
        return Err(BgpError::BadMarker);
    }
    let declared = usize::from(c.u16("length")?);
    if declared != msg.len() || declared < HEADER_LEN {
        return Err(BgpError::BadLength {
            declared,
            actual: msg.len(),
        });
    }
    let msg_type = c.u8("type")?;
    Ok((msg_type, c.rest()))
}

/// Parses a complete BGP message (header included) that must be an UPDATE.
pub fn parse_update_message(msg: &[u8], opts: ParseOptions) -> Result<Update, BgpError> {
    let (msg_type, body) = split_message(msg)?;
    if msg_type != MSG_UPDATE {
        return Err(BgpError::NotUpdate(msg_type));
    }
    parse_update_body(body, opts)
}

pub fn parse_update_body(body: &[u8], opts: ParseOptions) -> Result<Update, BgpError> {
    let mut c = Cursor::new(body);
    let mut update = Update::default();
    let wlen = usize::from(c.u16("withdrawn routes length")?);
    parse_nlri(
        c.take(wlen, "withdrawn routes")?,
        false,
        opts.add_path_v4,
        &mut update.withdrawn,
    )?;
    let alen = usize::from(c.u16("path attributes length")?);
    update.attrs = parse_attributes(c.take(alen, "path attributes")?, opts, &mut update)?;
    parse_nlri(c.rest(), false, opts.add_path_v4, &mut update.announced)?;
    Ok(update)
}

/// Decodes one prefix (`bits` already read) from `c`.
pub(crate) fn read_prefix(c: &mut Cursor<'_>, bits: u8, v6: bool) -> Result<IpNet, BgpError> {
    if bits > if v6 { 128 } else { 32 } {
        return Err(BgpError::BadPrefixLen(bits));
    }
    let raw = c.take(usize::from(bits).div_ceil(8), "prefix")?;
    Ok(if v6 {
        let mut a = [0u8; 16];
        a[..raw.len()].copy_from_slice(raw);
        IpNet::V6(
            Ipv6Net::new(Ipv6Addr::from(a), bits)
                .map_err(|_| BgpError::BadPrefixLen(bits))?
                .trunc(),
        )
    } else {
        let mut a = [0u8; 4];
        a[..raw.len()].copy_from_slice(raw);
        IpNet::V4(
            Ipv4Net::new(Ipv4Addr::from(a), bits)
                .map_err(|_| BgpError::BadPrefixLen(bits))?
                .trunc(),
        )
    })
}

fn parse_nlri(buf: &[u8], v6: bool, add_path: bool, out: &mut Vec<Nlri>) -> Result<(), BgpError> {
    let mut c = Cursor::new(buf);
    while !c.is_empty() {
        let path_id = if add_path {
            Some(c.u32("ADD-PATH path identifier")?)
        } else {
            None
        };
        let bits = c.u8("prefix length")?;
        let prefix = read_prefix(&mut c, bits, v6)?;
        out.push(Nlri { prefix, path_id });
    }
    Ok(())
}

fn bad(code: u8, reason: &'static str) -> BgpError {
    BgpError::BadAttribute { code, reason }
}

/// Parses the path attribute block. MP_REACH / MP_UNREACH NLRI are appended
/// to `update`; the returned attributes have AS4_PATH already merged.
pub fn parse_attributes(
    buf: &[u8],
    opts: ParseOptions,
    update: &mut Update,
) -> Result<Attributes, BgpError> {
    let mut attrs = Attributes::default();
    let mut as4_path = None;
    let mut c = Cursor::new(buf);
    while !c.is_empty() {
        let flags = c.u8("attribute flags")?;
        let code = c.u8("attribute type")?;
        let len = if flags & FLAG_EXTENDED_LEN != 0 {
            usize::from(c.u16("attribute length")?)
        } else {
            usize::from(c.u8("attribute length")?)
        };
        let value = c.take(len, "attribute value")?;
        match code {
            ATTR_ORIGIN => {
                attrs.origin = Some(match value {
                    [0] => Origin::Igp,
                    [1] => Origin::Egp,
                    [2] => Origin::Incomplete,
                    _ => return Err(bad(code, "ORIGIN must be one byte with value 0-2")),
                });
            }
            ATTR_AS_PATH => attrs.as_path = parse_as_path(value, opts.as4, code)?,
            ATTR_AS4_PATH => as4_path = Some(parse_as_path(value, true, code)?),
            ATTR_COMMUNITIES => {
                if value.len() % 4 != 0 {
                    return Err(bad(code, "COMMUNITIES length is not a multiple of 4"));
                }
                attrs.communities = value
                    .chunks_exact(4)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                    .collect();
            }
            ATTR_LARGE_COMMUNITIES => {
                if value.len() % 12 != 0 {
                    return Err(bad(code, "LARGE_COMMUNITY length is not a multiple of 12"));
                }
                attrs.large_communities = value
                    .chunks_exact(12)
                    .map(|b| {
                        let w = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
                        [w(0), w(4), w(8)]
                    })
                    .collect();
            }
            ATTR_MP_REACH if !opts.mrt_rib => parse_mp_reach(value, opts, &mut update.announced)?,
            ATTR_MP_UNREACH if !opts.mrt_rib => {
                parse_mp_unreach(value, opts, &mut update.withdrawn)?
            }
            _ => {}
        }
    }
    // A 4-byte speaker must ignore AS4_PATH (RFC 6793 4.1).
    if let (false, Some(p4)) = (opts.as4, as4_path) {
        attrs.as_path = merge_as4_path(&attrs.as_path, &p4);
    }
    Ok(attrs)
}

fn parse_as_path(value: &[u8], as4: bool, code: u8) -> Result<AsPath, BgpError> {
    let width = if as4 { 4 } else { 2 };
    let mut c = Cursor::new(value);
    let mut segments = Vec::new();
    while !c.is_empty() {
        let seg_type = c.u8("AS_PATH segment type")?;
        let count = usize::from(c.u8("AS_PATH segment length")?);
        if count == 0 {
            return Err(bad(code, "empty AS_PATH segment"));
        }
        let raw = c.take(count * width, "AS_PATH segment")?;
        let asns: Vec<u32> = if as4 {
            raw.chunks_exact(4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                .collect()
        } else {
            raw.chunks_exact(2)
                .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
                .collect()
        };
        segments.push(match seg_type {
            1 => Segment::Set(asns),
            2 => Segment::Sequence(asns),
            3 => Segment::ConfedSequence(asns),
            4 => Segment::ConfedSet(asns),
            _ => return Err(bad(code, "unknown AS_PATH segment type")),
        });
    }
    Ok(AsPath(segments))
}

/// Returns `Some(v6)` for unicast address families we decode, `None` otherwise.
pub fn unicast_family(afi: u16, safi: u8) -> Option<bool> {
    match (afi, safi) {
        (AFI_IPV4, SAFI_UNICAST) => Some(false),
        (AFI_IPV6, SAFI_UNICAST) => Some(true),
        _ => None,
    }
}

fn parse_mp_reach(value: &[u8], opts: ParseOptions, out: &mut Vec<Nlri>) -> Result<(), BgpError> {
    let mut c = Cursor::new(value);
    let afi = c.u16("MP_REACH AFI")?;
    let safi = c.u8("MP_REACH SAFI")?;
    let nh_len = usize::from(c.u8("MP_REACH next hop length")?);
    c.take(nh_len, "MP_REACH next hop")?;
    c.u8("MP_REACH reserved")?;
    match unicast_family(afi, safi) {
        Some(v6) => parse_nlri(c.rest(), v6, opts.add_path(v6), out),
        None => Ok(()),
    }
}

fn parse_mp_unreach(value: &[u8], opts: ParseOptions, out: &mut Vec<Nlri>) -> Result<(), BgpError> {
    let mut c = Cursor::new(value);
    let afi = c.u16("MP_UNREACH AFI")?;
    let safi = c.u8("MP_UNREACH SAFI")?;
    match unicast_family(afi, safi) {
        Some(v6) => parse_nlri(c.rest(), v6, opts.add_path(v6), out),
        None => Ok(()),
    }
}

/// Formats a community as `asn:value`.
pub fn community_to_string(c: u32) -> String {
    format!("{}:{}", c >> 16, c & 0xffff)
}

/// Formats a large community as `global:local1:local2`.
pub fn large_community_to_string(c: &[u32; 3]) -> String {
    format!("{}:{}:{}", c[0], c[1], c[2])
}

/// ADD-PATH send/receive flags (RFC 7911 section 4).
pub const ADD_PATH_RECEIVE: u8 = 1;
pub const ADD_PATH_SEND: u8 = 2;

/// Capabilities advertised in an OPEN that matter to this collector.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub as4: Option<u32>,
    pub multiprotocol: Vec<(u16, u8)>,
    /// (AFI, SAFI, send/receive bits).
    pub add_path: Vec<(u16, u8, u8)>,
}

impl Capabilities {
    fn add_path_bits(&self, afi: u16, safi: u8) -> u8 {
        self.add_path
            .iter()
            .filter(|(a, s, _)| *a == afi && *s == safi)
            .fold(0, |acc, (_, _, b)| acc | b)
    }
}

/// True when `sender` sends ADD-PATH NLRI for AFI/SAFI to `receiver`.
pub fn add_path_negotiated(
    receiver: &Capabilities,
    sender: &Capabilities,
    afi: u16,
    safi: u8,
) -> bool {
    receiver.add_path_bits(afi, safi) & ADD_PATH_RECEIVE != 0
        && sender.add_path_bits(afi, safi) & ADD_PATH_SEND != 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub version: u8,
    pub my_as: u16,
    pub hold_time: u16,
    pub bgp_id: Ipv4Addr,
    pub caps: Capabilities,
}

impl Open {
    /// The speaker's real ASN (4-byte capability wins over My AS).
    pub fn asn(&self) -> u32 {
        self.caps.as4.unwrap_or(u32::from(self.my_as))
    }

    /// Parse options for UPDATEs `sender` sends to `self` (the receiver).
    pub fn update_options(&self, sender: &Open) -> ParseOptions {
        ParseOptions::new(self.caps.as4.is_some() && sender.caps.as4.is_some()).with_add_path(
            add_path_negotiated(&self.caps, &sender.caps, AFI_IPV4, SAFI_UNICAST),
            add_path_negotiated(&self.caps, &sender.caps, AFI_IPV6, SAFI_UNICAST),
        )
    }
}

/// Parses a complete OPEN message (header included).
pub fn parse_open_message(msg: &[u8]) -> Result<Open, BgpError> {
    let (msg_type, body) = split_message(msg)?;
    if msg_type != MSG_OPEN {
        return Err(BgpError::NotOpen(msg_type));
    }
    let mut c = Cursor::new(body);
    let version = c.u8("OPEN version")?;
    let my_as = c.u16("OPEN my AS")?;
    let hold_time = c.u16("OPEN hold time")?;
    let id = c.take(4, "OPEN BGP identifier")?;
    let bgp_id = Ipv4Addr::new(id[0], id[1], id[2], id[3]);
    let mut opt_len = usize::from(c.u8("OPEN optional parameters length")?);
    // RFC 9072 extended optional parameters: length 255 followed by type 255.
    let extended = opt_len == 255 && c.peek_u8() == Some(255);
    if extended {
        c.u8("extended parameters marker")?;
        opt_len = usize::from(c.u16("extended optional parameters length")?);
    }
    let mut params = Cursor::new(c.take(opt_len, "OPEN optional parameters")?);
    let mut caps = Capabilities::default();
    while !params.is_empty() {
        let ptype = params.u8("optional parameter type")?;
        let plen = if extended {
            usize::from(params.u16("optional parameter length")?)
        } else {
            usize::from(params.u8("optional parameter length")?)
        };
        let value = params.take(plen, "optional parameter value")?;
        if ptype == OPT_PARAM_CAPABILITIES {
            parse_capabilities(value, &mut caps)?;
        }
    }
    Ok(Open {
        version,
        my_as,
        hold_time,
        bgp_id,
        caps,
    })
}

fn parse_capabilities(buf: &[u8], caps: &mut Capabilities) -> Result<(), BgpError> {
    let mut c = Cursor::new(buf);
    while !c.is_empty() {
        let code = c.u8("capability code")?;
        let len = usize::from(c.u8("capability length")?);
        let mut v = Cursor::new(c.take(len, "capability value")?);
        if caps.multiprotocol.len() + caps.add_path.len() >= MAX_CAPS {
            continue;
        }
        match code {
            CAP_MP => {
                let afi = v.u16("MP capability AFI")?;
                v.u8("MP capability reserved")?;
                caps.multiprotocol.push((afi, v.u8("MP capability SAFI")?));
            }
            CAP_AS4 => caps.as4 = Some(v.u32("4-octet AS capability")?),
            CAP_ADD_PATH => {
                while !v.is_empty() {
                    let afi = v.u16("ADD-PATH AFI")?;
                    let safi = v.u8("ADD-PATH SAFI")?;
                    let bits = v.u8("ADD-PATH send/receive")?;
                    if !(1..=3).contains(&bits) {
                        return Err(BgpError::BadOpen("ADD-PATH send/receive must be 1-3"));
                    }
                    caps.add_path.push((afi, safi, bits));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Wraps `body` in a BGP header.
pub fn encode_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xff; 16];
    // Callers build bodies far below the 65535-byte limit.
    out.extend_from_slice(
        &u16::try_from(HEADER_LEN + body.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    out.push(msg_type);
    out.extend_from_slice(body);
    out
}

/// OPEN for a receive-only speaker: MP IPv4/IPv6 unicast, 4-byte AS and
/// ADD-PATH receive for both families.
pub fn encode_open(local_asn: u32, hold_time: u16, router_id: Ipv4Addr) -> Vec<u8> {
    let my_as = u16::try_from(local_asn).unwrap_or(AS_TRANS as u16);
    let mut caps = Vec::new();
    for afi in [AFI_IPV4, AFI_IPV6] {
        caps.extend_from_slice(&[CAP_MP, 4]);
        caps.extend_from_slice(&afi.to_be_bytes());
        caps.extend_from_slice(&[0, SAFI_UNICAST]);
    }
    caps.extend_from_slice(&[CAP_AS4, 4]);
    caps.extend_from_slice(&local_asn.to_be_bytes());
    caps.extend_from_slice(&[CAP_ADD_PATH, 8]);
    for afi in [AFI_IPV4, AFI_IPV6] {
        caps.extend_from_slice(&afi.to_be_bytes());
        caps.extend_from_slice(&[SAFI_UNICAST, ADD_PATH_RECEIVE]);
    }
    let mut body = vec![4];
    body.extend_from_slice(&my_as.to_be_bytes());
    body.extend_from_slice(&hold_time.to_be_bytes());
    body.extend_from_slice(&router_id.octets());
    body.push(u8::try_from(caps.len() + 2).unwrap_or(0));
    body.push(OPT_PARAM_CAPABILITIES);
    body.push(u8::try_from(caps.len()).unwrap_or(0));
    body.extend(caps);
    encode_message(MSG_OPEN, &body)
}

pub fn encode_keepalive() -> Vec<u8> {
    encode_message(MSG_KEEPALIVE, &[])
}

pub fn encode_notification(code: u8, subcode: u8) -> Vec<u8> {
    encode_message(MSG_NOTIFICATION, &[code, subcode])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    const AS4: ParseOptions = ParseOptions {
        as4: true,
        add_path_v4: false,
        add_path_v6: false,
        mrt_rib: false,
    };

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn nets(n: &[Nlri]) -> Vec<IpNet> {
        n.iter().map(|n| n.prefix).collect()
    }

    #[test]
    fn parses_ipv4_announcement() {
        let msg = update_v4(
            &[],
            &[
                origin_attr(0),
                as_path_attr(&[(2, &[64501, 64500])]),
                communities_attr(&[(64500 << 16) | 100]),
            ],
            &["198.51.100.0/24", "203.0.113.128/25"],
        );
        let u = parse_update_message(&msg, AS4).unwrap();
        assert_eq!(
            nets(&u.announced),
            vec![net("198.51.100.0/24"), net("203.0.113.128/25")]
        );
        assert!(u.withdrawn.is_empty());
        assert_eq!(u.attrs.origin, Some(Origin::Igp));
        assert_eq!(u.attrs.as_path.origin(), Some(64500));
        assert_eq!(u.attrs.as_path.first_hop(), Some(64501));
        assert_eq!(u.attrs.as_path.to_string(), "64501 64500");
        assert_eq!(community_to_string(u.attrs.communities[0]), "64500:100");
    }

    #[test]
    fn parses_withdrawals_and_default_route() {
        let msg = update_v4(&["198.51.100.0/24", "0.0.0.0/0"], &[], &[]);
        let u = parse_update_message(&msg, AS4).unwrap();
        assert_eq!(
            nets(&u.withdrawn),
            vec![net("198.51.100.0/24"), net("0.0.0.0/0")]
        );
        assert!(u.announced.is_empty());
    }

    #[test]
    fn parses_ipv6_mp_reach_and_unreach() {
        let msg = update_v4(
            &[],
            &[
                origin_attr(0),
                as_path_attr(&[(2, &[64502, 64500])]),
                mp_reach_v6(&["2001:db8:100::/48"]),
                mp_unreach_v6(&["2001:db8:200::/40"]),
            ],
            &[],
        );
        let u = parse_update_message(&msg, AS4).unwrap();
        assert_eq!(nets(&u.announced), vec![net("2001:db8:100::/48")]);
        assert_eq!(nets(&u.withdrawn), vec![net("2001:db8:200::/40")]);
    }

    #[test]
    fn as_set_and_confederation_handling() {
        let msg = update_v4(
            &[],
            &[as_path_attr(&[
                (3, &[64510]),
                (2, &[64501]),
                (1, &[64500, 64499]),
            ])],
            &["192.0.2.0/24"],
        );
        let u = parse_update_message(&msg, AS4).unwrap();
        assert_eq!(u.attrs.as_path.to_string(), "(64510) 64501 {64500,64499}");
        assert_eq!(u.attrs.as_path.first_hop(), Some(64501));
        assert_eq!(
            u.attrs.as_path.origin(),
            None,
            "multi-member AS_SET is ambiguous"
        );

        let single = AsPath(vec![
            Segment::Sequence(vec![64501]),
            Segment::Set(vec![64500]),
        ]);
        assert_eq!(single.origin(), Some(64500));
        assert_eq!(AsPath::default().origin(), None);
    }

    #[test]
    fn parses_legacy_two_byte_as_path() {
        let path = attr(0x40, 2, &[2, 2, 0xfb, 0xf5, 0xfb, 0xf4]);
        let msg = update_v4(&[], &[path], &["192.0.2.0/24"]);
        let u = parse_update_message(&msg, ParseOptions::default()).unwrap();
        assert_eq!(
            u.attrs.as_path.0,
            vec![Segment::Sequence(vec![64501, 64500])]
        );
    }

    #[test]
    fn extended_length_attribute() {
        let communities: Vec<u32> = (0..100).map(|i| (64500 << 16) | i).collect();
        let msg = update_v4(&[], &[communities_attr(&communities)], &["192.0.2.0/24"]);
        let u = parse_update_message(&msg, AS4).unwrap();
        assert_eq!(u.attrs.communities.len(), 100);
    }

    #[test]
    fn rejects_bad_header() {
        let mut msg = update_v4(&[], &[], &["192.0.2.0/24"]);
        msg[0] = 0;
        assert_eq!(parse_update_message(&msg, AS4), Err(BgpError::BadMarker));

        let mut msg = update_v4(&[], &[], &["192.0.2.0/24"]);
        msg[17] = 0xff;
        assert!(matches!(
            parse_update_message(&msg, AS4),
            Err(BgpError::BadLength { .. })
        ));

        let mut msg = update_v4(&[], &[], &[]);
        msg[18] = 4;
        assert_eq!(parse_update_message(&msg, AS4), Err(BgpError::NotUpdate(4)));
    }

    #[test]
    fn rejects_malformed_bodies() {
        // Prefix length 33 for IPv4.
        let msg = bgp_message(2, &[0, 0, 0, 0, 33, 192, 0, 2, 0, 0]);
        assert_eq!(
            parse_update_message(&msg, AS4),
            Err(BgpError::BadPrefixLen(33))
        );
        // Withdrawn length longer than the body.
        let msg = bgp_message(2, &[0, 50, 0, 0]);
        assert!(matches!(
            parse_update_message(&msg, AS4),
            Err(BgpError::Truncated(_))
        ));
        // Bad ORIGIN value.
        let msg = update_v4(&[], &[attr(0x40, 1, &[7])], &[]);
        assert!(matches!(
            parse_update_message(&msg, AS4),
            Err(BgpError::BadAttribute { code: 1, .. })
        ));
        // COMMUNITIES not a multiple of 4.
        let msg = update_v4(&[], &[attr(0xc0, 8, &[1, 2, 3])], &[]);
        assert!(matches!(
            parse_update_message(&msg, AS4),
            Err(BgpError::BadAttribute { code: 8, .. })
        ));
        // AS_PATH segment claims more ASNs than present, empty segment, unknown type.
        for value in [
            &[2u8, 3, 0, 0, 0xfb, 0xf4][..],
            &[2, 0],
            &[9, 1, 0, 0, 0xfb, 0xf4],
        ] {
            let msg = update_v4(&[], &[attr(0x40, 2, value)], &[]);
            assert!(parse_update_message(&msg, AS4).is_err());
        }
        // Attribute length runs past the attribute block.
        let msg = update_v4(&[], &[vec![0x40, 1, 9, 0]], &[]);
        assert!(matches!(
            parse_update_message(&msg, AS4),
            Err(BgpError::Truncated(_))
        ));
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let msg = update_v4(
            &["203.0.113.0/24"],
            &[
                origin_attr(0),
                as_path_attr(&[(2, &[64501, 64500])]),
                communities_attr(&[1, 2]),
                mp_reach_v6(&["2001:db8:100::/48"]),
            ],
            &["198.51.100.0/24"],
        );
        assert!(parse_update_message(&msg, AS4).is_ok());
        for cut in 0..msg.len() {
            let mut m = msg[..cut].to_vec();
            if m.len() >= 18 {
                // Keep the header length consistent so the body parser is exercised.
                m[16..18].copy_from_slice(&(cut as u16).to_be_bytes());
            }
            let _ = parse_update_message(&m, AS4);
        }
    }

    #[test]
    fn ignores_non_unicast_mp_families() {
        // AFI 2 / SAFI 128 (VPN) is skipped without error.
        let value = [0, 2, 128, 0, 0, 1, 2, 3];
        let msg = update_v4(&[], &[attr(0x80, 14, &value)], &[]);
        assert!(parse_update_message(&msg, AS4)
            .unwrap()
            .announced
            .is_empty());
    }

    #[test]
    fn large_communities() {
        let msg = update_v4(
            &[],
            &[large_communities_attr(&[
                [64500, 1, 2],
                [4_200_000_000, 0, 7],
            ])],
            &["192.0.2.0/24"],
        );
        let u = parse_update_message(&msg, AS4).unwrap();
        let s: Vec<String> = u
            .attrs
            .large_communities
            .iter()
            .map(large_community_to_string)
            .collect();
        assert_eq!(s, ["64500:1:2", "4200000000:0:7"]);
        let msg = update_v4(&[], &[attr(0xc0, 32, &[0; 11])], &[]);
        assert!(matches!(
            parse_update_message(&msg, AS4),
            Err(BgpError::BadAttribute { code: 32, .. })
        ));
    }

    #[test]
    fn as4_path_is_merged_for_two_byte_speakers() {
        // AS_PATH 64501 23456 23456 (2-byte), AS4_PATH 4200000001 4200000002.
        let two = attr(0x40, 2, &[2, 3, 0xfb, 0xf5, 0x5b, 0xa0, 0x5b, 0xa0]);
        let mut v = vec![2, 2];
        v.extend_from_slice(&4_200_000_001u32.to_be_bytes());
        v.extend_from_slice(&4_200_000_002u32.to_be_bytes());
        let four = attr(0xc0, 17, &v);
        let msg = update_v4(&[], &[two, four.clone()], &["192.0.2.0/24"]);
        let u = parse_update_message(&msg, ParseOptions::default()).unwrap();
        assert_eq!(u.attrs.as_path.to_string(), "64501 4200000001 4200000002");
        assert_eq!(u.attrs.as_path.origin(), Some(4_200_000_002));
        // A 4-byte session ignores AS4_PATH.
        let p4 = as_path_attr(&[(2, &[64501, 64500])]);
        let msg = update_v4(&[], &[p4, four], &["192.0.2.0/24"]);
        let u = parse_update_message(&msg, AS4).unwrap();
        assert_eq!(u.attrs.as_path.to_string(), "64501 64500");
    }

    #[test]
    fn as4_merge_rules() {
        let seq = |a: &[u32]| Segment::Sequence(a.to_vec());
        // AS4_PATH longer than AS_PATH is ignored.
        let p2 = AsPath(vec![seq(&[64501])]);
        let p4 = AsPath(vec![seq(&[1, 2])]);
        assert_eq!(merge_as4_path(&p2, &p4), p2);
        // Confederation segments in AS4_PATH are discarded; leading confed kept.
        let p2 = AsPath(vec![
            Segment::ConfedSequence(vec![65001]),
            seq(&[64501, AS_TRANS]),
        ]);
        let p4 = AsPath(vec![Segment::ConfedSet(vec![9]), seq(&[4_200_000_000])]);
        assert_eq!(
            merge_as4_path(&p2, &p4).to_string(),
            "(65001) 64501 4200000000"
        );
    }

    #[test]
    fn add_path_nlri() {
        let msg = update_v4_add_path(
            &[(7, "203.0.113.0/24")],
            &[origin_attr(0), as_path_attr(&[(2, &[64501, 64500])])],
            &[(1, "198.51.100.0/24"), (2, "198.51.100.0/24")],
        );
        let u = parse_update_message(&msg, AS4.with_add_path(true, false)).unwrap();
        let ids: Vec<_> = u.announced.iter().map(|n| (n.prefix, n.path_id)).collect();
        assert_eq!(
            ids,
            vec![
                (net("198.51.100.0/24"), Some(1)),
                (net("198.51.100.0/24"), Some(2))
            ]
        );
        assert_eq!(u.withdrawn[0].path_id, Some(7));
        // IPv6 MP_REACH with path ids.
        let msg = update_v4(
            &[],
            &[mp_reach_v6_add_path(&[(9, "2001:db8:100::/48")])],
            &[],
        );
        let u = parse_update_message(&msg, AS4.with_add_path(false, true)).unwrap();
        assert_eq!(u.announced[0].path_id, Some(9));
        assert_eq!(u.announced[0].prefix, net("2001:db8:100::/48"));
    }

    #[test]
    fn path_length_hops_and_prepends() {
        let p = AsPath(vec![
            Segment::ConfedSequence(vec![65001, 65002]),
            Segment::Sequence(vec![64501, 64501, 64502]),
            Segment::Set(vec![64500, 64499]),
        ]);
        assert_eq!(p.path_len(), 4);
        assert_eq!(p.hops(), None);
        let p = AsPath(vec![Segment::Sequence(vec![64501, 64501, 64500, 64500])]);
        assert_eq!(p.hops(), Some(vec![64501, 64500]));
        assert_eq!(p.flatten().len(), 4);
        assert_eq!(collapse_prepends("64501 64501 64500"), "64501 64500");
    }

    #[test]
    fn open_roundtrip_and_capabilities() {
        let raw = encode_open(4_200_000_000, 90, Ipv4Addr::new(192, 0, 2, 254));
        let o = parse_open_message(&raw).unwrap();
        assert_eq!(u32::from(o.my_as), AS_TRANS);
        assert_eq!(o.asn(), 4_200_000_000);
        assert_eq!(o.hold_time, 90);
        assert!(o.caps.multiprotocol.contains(&(AFI_IPV6, SAFI_UNICAST)));
        // Peer that sends ADD-PATH for IPv4 only.
        let mut peer = o.clone();
        peer.caps.add_path = vec![(AFI_IPV4, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE)];
        let opts = o.update_options(&peer);
        assert!(opts.as4 && opts.add_path_v4 && !opts.add_path_v6);
        // Truncations never panic.
        for cut in 0..raw.len() {
            let mut m = raw[..cut].to_vec();
            if m.len() >= 18 {
                m[16..18].copy_from_slice(&(cut as u16).to_be_bytes());
            }
            let _ = parse_open_message(&m);
        }
        assert_eq!(
            parse_open_message(&encode_keepalive()),
            Err(BgpError::NotOpen(4))
        );
    }

    #[test]
    fn extended_optional_parameters() {
        // RFC 9072: 255, 255, u16 length, then params with u16 lengths.
        let cap = [65u8, 4, 0, 0, 0xfb, 0xf4];
        let mut params = vec![2u8];
        params.extend_from_slice(&(cap.len() as u16).to_be_bytes());
        params.extend_from_slice(&cap);
        let mut body = vec![4, 0xfb, 0xf4, 0, 90, 192, 0, 2, 1, 255, 255];
        body.extend_from_slice(&(params.len() as u16).to_be_bytes());
        body.extend(params);
        let o = parse_open_message(&encode_message(MSG_OPEN, &body)).unwrap();
        assert_eq!(o.asn(), 64500);
    }
}
