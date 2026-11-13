//! BGP Monitoring Protocol (RFC 7854) message parser and framing, including
//! Loc-RIB monitoring (RFC 9069) and ADD-PATH negotiated from Peer Up OPENs.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::bgp::{self, BgpError, Open, ParseOptions, Update};
use crate::wire::{Cursor, Truncated};

pub const VERSION: u8 = 3;
pub const COMMON_HEADER_LEN: usize = 6;
pub const PER_PEER_HEADER_LEN: usize = 42;
/// Hard upper bound for one BMP message: a per-peer header plus the largest
/// (RFC 8654 extended) BGP message, with room for Peer Up's two OPENs.
pub const MAX_MESSAGE_LEN: usize = 1 << 17;

const TYPE_ROUTE_MONITORING: u8 = 0;
const TYPE_STATISTICS: u8 = 1;
const TYPE_PEER_DOWN: u8 = 2;
const TYPE_PEER_UP: u8 = 3;
const TYPE_INITIATION: u8 = 4;
const TYPE_TERMINATION: u8 = 5;

/// RFC 9069 Loc-RIB instance peer type.
pub const PEER_TYPE_LOC_RIB: u8 = 3;
const FLAG_V6: u8 = 0x80;
const FLAG_LEGACY_AS_PATH: u8 = 0x20;
/// RFC 8671: the message reports Adj-RIB-Out (routes the router sends).
pub const FLAG_ADJ_RIB_OUT: u8 = 0x10;
/// Per-session bound on remembered peer capabilities.
const MAX_PEERS: usize = 8192;

#[derive(Debug, Error)]
pub enum BmpError {
    #[error("truncated BMP {0}")]
    Truncated(&'static str),
    #[error("unsupported BMP version {0}")]
    Version(u8),
    #[error("BMP message length {0} is outside 6..={max}", max = MAX_MESSAGE_LEN)]
    Length(usize),
    #[error("BMP length field {declared} does not match message size {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("route monitoring: {0}")]
    Bgp(#[from] BgpError),
    #[error("read error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<Truncated> for BmpError {
    fn from(t: Truncated) -> Self {
        BmpError::Truncated(t.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    pub msg_type: u8,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHeader {
    pub peer_type: u8,
    pub flags: u8,
    pub distinguisher: u64,
    pub address: IpAddr,
    pub asn: u32,
    /// Seconds since the Unix epoch, as reported by the router (0 if unset).
    pub timestamp: u32,
}

impl PeerHeader {
    /// Loc-RIB (RFC 9069): the router's own best paths, no real peer address.
    pub fn is_loc_rib(&self) -> bool {
        self.peer_type == PEER_TYPE_LOC_RIB
    }

    fn key(&self) -> (u8, u64, IpAddr) {
        (self.peer_type, self.distinguisher, self.address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    RouteMonitoring {
        peer: PeerHeader,
        update: Update,
    },
    Statistics {
        peer: PeerHeader,
        count: u32,
    },
    PeerDown {
        peer: PeerHeader,
        reason: u8,
    },
    /// `sent` is the monitored router's OPEN, `received` the peer's.
    PeerUp {
        peer: PeerHeader,
        sent: Option<Open>,
        received: Option<Open>,
    },
    /// Information TLVs as (type, lossy UTF-8 value).
    Initiation {
        info: Vec<(u16, String)>,
    },
    Termination {
        info: Vec<(u16, String)>,
    },
    /// Route Mirroring and message types this collector does not decode.
    Other {
        msg_type: u8,
    },
}

impl Message {
    pub fn peer(&self) -> Option<&PeerHeader> {
        match self {
            Message::RouteMonitoring { peer, .. }
            | Message::Statistics { peer, .. }
            | Message::PeerDown { peer, .. }
            | Message::PeerUp { peer, .. } => Some(peer),
            _ => None,
        }
    }
}

pub fn parse_common_header(buf: &[u8]) -> Result<CommonHeader, BmpError> {
    let mut c = Cursor::new(buf);
    let version = c.u8("version")?;
    if version != VERSION {
        return Err(BmpError::Version(version));
    }
    let length = usize::try_from(c.u32("length")?).unwrap_or(usize::MAX);
    if !(COMMON_HEADER_LEN..=MAX_MESSAGE_LEN).contains(&length) {
        return Err(BmpError::Length(length));
    }
    let msg_type = c.u8("message type")?;
    Ok(CommonHeader { msg_type, length })
}

fn parse_peer_header(c: &mut Cursor<'_>) -> Result<PeerHeader, BmpError> {
    let peer_type = c.u8("peer type")?;
    let flags = c.u8("peer flags")?;
    let d = c.take(8, "peer distinguisher")?;
    let mut dist = [0u8; 8];
    dist.copy_from_slice(d);
    let raw = c.take(16, "peer address")?;
    let mut a = [0u8; 16];
    a.copy_from_slice(raw);
    // For Loc-RIB the 0x80 bit is the F (filtered) flag and the address is zero.
    let address = if peer_type != PEER_TYPE_LOC_RIB && flags & FLAG_V6 != 0 {
        IpAddr::V6(Ipv6Addr::from(a))
    } else {
        IpAddr::V4(Ipv4Addr::new(a[12], a[13], a[14], a[15]))
    };
    let asn = c.u32("peer AS")?;
    c.take(4, "peer BGP ID")?;
    let timestamp = c.u32("timestamp")?;
    c.take(4, "timestamp microseconds")?;
    Ok(PeerHeader {
        peer_type,
        flags,
        distinguisher: u64::from_be_bytes(dist),
        address,
        asn,
        timestamp,
    })
}

fn parse_tlvs(c: &mut Cursor<'_>) -> Result<Vec<(u16, String)>, BmpError> {
    let mut out = Vec::new();
    while !c.is_empty() {
        let t = c.u16("TLV type")?;
        let len = usize::from(c.u16("TLV length")?);
        let v = c.take(len, "TLV value")?;
        out.push((t, String::from_utf8_lossy(v).into_owned()));
    }
    Ok(out)
}

/// Takes one embedded BGP message (length from its own header).
fn take_bgp<'a>(c: &mut Cursor<'a>, what: &'static str) -> Result<&'a [u8], BmpError> {
    let mut peek = Cursor::new(c.peek_rest());
    peek.take(16, what)?;
    let len = usize::from(peek.u16(what)?);
    Ok(c.take(len, what)?)
}

/// Per-router BMP session state: ADD-PATH and 4-byte AS negotiated in each
/// peer's Peer Up, used to decode its Route Monitoring messages.
#[derive(Debug, Default)]
pub struct SessionState {
    peers: HashMap<(u8, u64, IpAddr), ParseOptions>,
}

impl SessionState {
    /// Parses one complete BMP message and updates the negotiated state.
    pub fn parse(&mut self, buf: &[u8]) -> Result<Message, BmpError> {
        let msg = parse_message_with(buf, |p| self.peers.get(&p.key()).copied())?;
        match &msg {
            Message::PeerUp {
                peer,
                sent: Some(sent),
                received: Some(received),
            } => {
                if self.peers.len() < MAX_PEERS || self.peers.contains_key(&peer.key()) {
                    // Adj-RIB-In: the peer (received OPEN) sends to the router (sent OPEN).
                    self.peers.insert(peer.key(), sent.update_options(received));
                }
            }
            Message::PeerDown { peer, .. } => {
                self.peers.remove(&peer.key());
            }
            _ => {}
        }
        Ok(msg)
    }
}

/// Parses one complete BMP message without session context.
pub fn parse_message(buf: &[u8]) -> Result<Message, BmpError> {
    SessionState::default().parse(buf)
}

fn parse_message_with(
    buf: &[u8],
    negotiated: impl Fn(&PeerHeader) -> Option<ParseOptions>,
) -> Result<Message, BmpError> {
    let header = parse_common_header(buf)?;
    if header.length != buf.len() {
        return Err(BmpError::LengthMismatch {
            declared: header.length,
            actual: buf.len(),
        });
    }
    let mut c = Cursor::new(buf);
    c.take(COMMON_HEADER_LEN, "common header")?;
    Ok(match header.msg_type {
        TYPE_ROUTE_MONITORING => {
            let peer = parse_peer_header(&mut c)?;
            // Loc-RIB has no legacy-AS flag: it always carries 4-byte paths.
            let as4 = peer.is_loc_rib() || peer.flags & FLAG_LEGACY_AS_PATH == 0;
            let body = c.rest();
            let update = match negotiated(&peer) {
                Some(n) => bgp::parse_update_message(body, ParseOptions { as4, ..n })?,
                // No Peer Up seen (collector restarted mid-session): try plain
                // NLRI first, then ADD-PATH encoding.
                None => {
                    let plain = ParseOptions::new(as4);
                    bgp::parse_update_message(body, plain).or_else(|e| {
                        bgp::parse_update_message(body, plain.with_add_path(true, true))
                            .map_err(|_| e)
                    })?
                }
            };
            Message::RouteMonitoring { peer, update }
        }
        TYPE_STATISTICS => {
            let peer = parse_peer_header(&mut c)?;
            let count = c.u32("statistics count")?;
            Message::Statistics { peer, count }
        }
        TYPE_PEER_DOWN => {
            let peer = parse_peer_header(&mut c)?;
            let reason = c.u8("peer down reason")?;
            Message::PeerDown { peer, reason }
        }
        TYPE_PEER_UP => {
            let peer = parse_peer_header(&mut c)?;
            // Local address (16) + local port (2) + remote port (2), then two OPENs.
            c.take(20, "peer up local address and ports")?;
            // A malformed OPEN only loses capability information, not the event.
            let sent = take_bgp(&mut c, "peer up sent OPEN")
                .ok()
                .and_then(|m| bgp::parse_open_message(m).ok());
            let received = take_bgp(&mut c, "peer up received OPEN")
                .ok()
                .and_then(|m| bgp::parse_open_message(m).ok());
            Message::PeerUp {
                peer,
                sent,
                received,
            }
        }
        TYPE_INITIATION => Message::Initiation {
            info: parse_tlvs(&mut c)?,
        },
        TYPE_TERMINATION => Message::Termination {
            info: parse_tlvs(&mut c)?,
        },
        msg_type => Message::Other { msg_type },
    })
}

/// Reads one length-delimited BMP message from a stream.
/// Returns `Ok(None)` on a clean end of stream at a message boundary.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, BmpError> {
    let mut header = [0u8; COMMON_HEADER_LEN];
    let mut filled = 0;
    while filled < header.len() {
        let n = r.read(&mut header[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(BmpError::Truncated("common header"))
            };
        }
        filled += n;
    }
    // The length is validated (and bounded) before anything is allocated.
    let h = parse_common_header(&header)?;
    let mut buf = vec![0u8; h.length];
    buf[..COMMON_HEADER_LEN].copy_from_slice(&header);
    r.read_exact(&mut buf[COMMON_HEADER_LEN..])
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => BmpError::Truncated("message body"),
            _ => BmpError::Io(e),
        })?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn route_monitoring_roundtrip() {
        let msg = announce("192.0.2.1", 64501, 1000, "198.51.100.0/24", &[64501, 64500]);
        match parse_message(&msg).unwrap() {
            Message::RouteMonitoring { peer, update } => {
                assert_eq!(peer.address, ip("192.0.2.1"));
                assert_eq!(peer.asn, 64501);
                assert_eq!(peer.timestamp, 1000);
                assert_eq!(
                    update.announced[0].prefix,
                    "198.51.100.0/24".parse().unwrap()
                );
                assert_eq!(update.attrs.as_path.origin(), Some(64500));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn ipv6_peer_address() {
        let msg = announce(
            "2001:db8::2",
            64502,
            1,
            "2001:db8:100::/48",
            &[64502, 64500],
        );
        let m = parse_message(&msg).unwrap();
        assert_eq!(m.peer().unwrap().address, ip("2001:db8::2"));
    }

    #[test]
    fn legacy_as_path_flag_selects_two_byte_asns() {
        let upd = update_v4(
            &[],
            &[attr(0x40, 2, &[2, 2, 0xfb, 0xf5, 0xfb, 0xf4])],
            &["192.0.2.0/24"],
        );
        let mut body = per_peer(ip("192.0.2.1"), 64501, 0);
        body[1] |= FLAG_LEGACY_AS_PATH;
        body.extend(upd);
        match parse_message(&bmp(0, &body)).unwrap() {
            Message::RouteMonitoring { update, .. } => {
                assert_eq!(update.attrs.as_path.to_string(), "64501 64500")
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn session_messages() {
        assert!(matches!(
            parse_message(&peer_up(ip("192.0.2.1"), 64501, 5)).unwrap(),
            Message::PeerUp { .. }
        ));
        assert!(matches!(
            parse_message(&peer_down(ip("192.0.2.1"), 64501, 5, 4)).unwrap(),
            Message::PeerDown { reason: 4, .. }
        ));
        match parse_message(&initiation("edge-router-1", "test")).unwrap() {
            Message::Initiation { info } => {
                assert_eq!(info[0], (2, "edge-router-1".to_string()));
                assert_eq!(info[1], (1, "test".to_string()));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            parse_message(&termination(0)).unwrap(),
            Message::Termination { .. }
        ));
        let mut stats = per_peer(ip("192.0.2.1"), 64501, 5);
        stats.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            parse_message(&bmp(1, &stats)).unwrap(),
            Message::Statistics { count: 0, .. }
        ));
        assert!(matches!(
            parse_message(&bmp(6, &[1, 2, 3])).unwrap(),
            Message::Other { msg_type: 6 }
        ));
    }

    #[test]
    fn rejects_bad_common_header() {
        assert!(matches!(
            parse_common_header(&[1, 0, 0, 0, 6, 4]),
            Err(BmpError::Version(1))
        ));
        assert!(matches!(
            parse_common_header(&[3, 0, 0, 0, 5, 4]),
            Err(BmpError::Length(5))
        ));
        assert!(matches!(
            parse_common_header(&[3, 0xff, 0xff, 0xff, 0xff, 0]),
            Err(BmpError::Length(_))
        ));
        assert!(matches!(
            parse_common_header(&[3, 0, 0]),
            Err(BmpError::Truncated(_))
        ));
        let mut msg = initiation("x", "y");
        msg.push(0);
        assert!(matches!(
            parse_message(&msg),
            Err(BmpError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn rejects_non_update_in_route_monitoring() {
        let mut body = per_peer(ip("192.0.2.1"), 64501, 0);
        body.extend(bgp_message(4, &[]));
        assert!(matches!(
            parse_message(&bmp(0, &body)),
            Err(BmpError::Bgp(BgpError::NotUpdate(4)))
        ));
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let samples = [
            announce("192.0.2.1", 64501, 7, "198.51.100.0/24", &[64501, 64500]),
            announce("192.0.2.1", 64501, 7, "2001:db8:100::/48", &[64501, 64500]),
            peer_up(ip("192.0.2.1"), 64501, 7),
            peer_down(ip("192.0.2.1"), 64501, 7, 1),
            initiation("a", "b"),
        ];
        for (i, full) in samples.iter().enumerate() {
            assert!(parse_message(full).is_ok());
            for cut in 0..full.len() {
                let mut m = full[..cut].to_vec();
                if m.len() >= COMMON_HEADER_LEN {
                    // Make the header agree so the inner parsers see the short body.
                    m[1..5].copy_from_slice(&(cut as u32).to_be_bytes());
                }
                let res = parse_message(&m);
                // A cut Route Monitoring message always breaks the embedded BGP length.
                if i < 2 {
                    assert!(res.is_err(), "cut at {cut} parsed");
                }
            }
        }
    }

    #[tokio::test]
    async fn framing_reads_messages_and_detects_eof() {
        let mut stream = initiation("a", "b");
        stream.extend(announce(
            "192.0.2.1",
            64501,
            7,
            "198.51.100.0/24",
            &[64501, 64500],
        ));
        let mut r = &stream[..];
        assert!(read_frame(&mut r).await.unwrap().is_some());
        assert!(read_frame(&mut r).await.unwrap().is_some());
        assert!(read_frame(&mut r).await.unwrap().is_none());

        let mut short = &stream[..3];
        assert!(matches!(
            read_frame(&mut short).await,
            Err(BmpError::Truncated(_))
        ));
        let mut short = &stream[..10];
        assert!(matches!(
            read_frame(&mut short).await,
            Err(BmpError::Truncated(_))
        ));
    }

    #[tokio::test]
    async fn framing_refuses_oversized_length_before_allocating() {
        let mut huge: &[u8] = &[3, 0x10, 0, 0, 0, 0];
        assert!(matches!(
            read_frame(&mut huge).await,
            Err(BmpError::Length(_))
        ));
    }

    #[test]
    fn loc_rib_peer_type() {
        let upd = update_v4(
            &[],
            &[origin_attr(0), as_path_attr(&[(2, &[64501, 64500])])],
            &["198.51.100.0/24"],
        );
        let mut body = per_peer(ip("0.0.0.0"), 64496, 9);
        body[0] = PEER_TYPE_LOC_RIB;
        body[1] = 0x80 | FLAG_LEGACY_AS_PATH; // F flag; A bit is not defined for Loc-RIB
        body.extend(upd);
        match parse_message(&bmp(0, &body)).unwrap() {
            Message::RouteMonitoring { peer, update } => {
                assert!(peer.is_loc_rib());
                assert_eq!(peer.address, ip("0.0.0.0"));
                assert_eq!(update.attrs.as_path.to_string(), "64501 64500");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn add_path_negotiated_in_peer_up() {
        let peer = ip("192.0.2.1");
        let mut s = SessionState::default();
        match s.parse(&peer_up_add_path(peer, 64501, 1)).unwrap() {
            Message::PeerUp { sent, received, .. } => {
                assert!(sent.is_some() && received.is_some())
            }
            other => panic!("unexpected {other:?}"),
        }
        let upd = update_v4_add_path(
            &[],
            &[origin_attr(0), as_path_attr(&[(2, &[64501, 64500])])],
            &[(5, "198.51.100.0/24")],
        );
        let msg = route_monitoring(peer, 64501, 2, &upd);
        match s.parse(&msg).unwrap() {
            Message::RouteMonitoring { update, .. } => {
                assert_eq!(update.announced[0].path_id, Some(5))
            }
            other => panic!("unexpected {other:?}"),
        }
        // Without the Peer Up the ADD-PATH encoding is detected by fallback.
        match parse_message(&msg).unwrap() {
            Message::RouteMonitoring { update, .. } => {
                assert_eq!(update.announced[0].path_id, Some(5))
            }
            other => panic!("unexpected {other:?}"),
        }
        // Peer Down forgets the negotiated state.
        s.parse(&peer_down(peer, 64501, 3, 4)).unwrap();
        assert!(s.peers.is_empty());
    }
}
