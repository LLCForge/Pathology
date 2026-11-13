//! MRT (RFC 6396) reader for seeding the baseline from RIB dumps and update
//! archives: TABLE_DUMP_V2 (incl. RFC 8050 ADD-PATH RIB subtypes) and
//! BGP4MP / BGP4MP_ET UPDATE messages. Gzip-compressed files are read
//! transparently; bzip2 files must be decompressed first.

use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{bail, Context, Result};
use ipnet::IpNet;

use crate::bgp::{self, Attributes, ParseOptions, Update};
use crate::wire::Cursor;

/// Largest accepted record body (a RIB entry with every peer of a collector).
pub const MAX_RECORD: usize = 16 * 1024 * 1024;

const TYPE_TABLE_DUMP_V2: u16 = 13;
const TYPE_BGP4MP: u16 = 16;
const TYPE_BGP4MP_ET: u16 = 17;

const TDV2_PEER_INDEX: u16 = 1;
const TDV2_RIB_IPV4_UNICAST: u16 = 2;
const TDV2_RIB_IPV6_UNICAST: u16 = 4;
const TDV2_RIB_IPV4_UNICAST_ADDPATH: u16 = 8;
const TDV2_RIB_IPV6_UNICAST_ADDPATH: u16 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrtPeer {
    pub address: IpAddr,
    pub asn: u32,
}

/// One route taken from a dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrtRoute {
    pub timestamp: u64,
    pub peer: MrtPeer,
    pub prefix: IpNet,
    pub withdraw: bool,
    pub attrs: Attributes,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MrtStats {
    pub records: u64,
    pub routes: u64,
    /// Records whose body could not be decoded (skipped).
    pub skipped: u64,
    /// Records of types this reader does not use.
    pub ignored: u64,
}

/// Streams records from `r`, calling `f` for every route.
pub struct MrtReader<R: Read> {
    r: R,
    peers: Vec<MrtPeer>,
    pub stats: MrtStats,
}

/// Reads exactly `buf.len()` bytes; `Ok(false)` on a clean EOF before the first byte.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

impl<R: Read> MrtReader<R> {
    pub fn new(r: R) -> Self {
        MrtReader {
            r,
            peers: Vec::new(),
            stats: MrtStats::default(),
        }
    }

    pub fn for_each(&mut self, mut f: impl FnMut(MrtRoute)) -> Result<MrtStats> {
        let mut header = [0u8; 12];
        let mut offset = 0u64;
        while read_full(&mut self.r, &mut header)
            .with_context(|| format!("reading MRT header at byte {offset}"))?
        {
            let ts = u64::from(u32::from_be_bytes([
                header[0], header[1], header[2], header[3],
            ]));
            let typ = u16::from_be_bytes([header[4], header[5]]);
            let sub = u16::from_be_bytes([header[6], header[7]]);
            let len = usize::try_from(u32::from_be_bytes([
                header[8], header[9], header[10], header[11],
            ]))
            .unwrap_or(usize::MAX);
            if len > MAX_RECORD {
                bail!("MRT record at byte {offset} claims {len} bytes (limit {MAX_RECORD}); not an MRT file?");
            }
            let mut body = vec![0u8; len];
            if !read_full(&mut self.r, &mut body)
                .with_context(|| format!("MRT record at byte {offset} is truncated"))?
                && len > 0
            {
                bail!("MRT record at byte {offset} is truncated");
            }
            offset += 12 + len as u64;
            self.stats.records += 1;
            let res = match typ {
                TYPE_TABLE_DUMP_V2 => self.table_dump_v2(sub, ts, &body, &mut f),
                TYPE_BGP4MP => self.bgp4mp(sub, ts, &body, &mut f),
                TYPE_BGP4MP_ET => match body.get(4..) {
                    // The extended timestamp's microseconds lead the body.
                    Some(rest) => self.bgp4mp(sub, ts, rest, &mut f),
                    None => Err(bgp::BgpError::Truncated("BGP4MP_ET microseconds")),
                },
                _ => {
                    self.stats.ignored += 1;
                    Ok(())
                }
            };
            if res.is_err() {
                self.stats.skipped += 1;
            }
        }
        Ok(self.stats)
    }

    fn table_dump_v2(
        &mut self,
        sub: u16,
        ts: u64,
        body: &[u8],
        f: &mut impl FnMut(MrtRoute),
    ) -> Result<(), bgp::BgpError> {
        let mut c = Cursor::new(body);
        match sub {
            TDV2_PEER_INDEX => {
                c.take(4, "collector BGP ID")?;
                let name_len = usize::from(c.u16("view name length")?);
                c.take(name_len, "view name")?;
                let count = c.u16("peer count")?;
                let mut peers = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let ptype = c.u8("peer type")?;
                    c.take(4, "peer BGP ID")?;
                    let address = read_ip(&mut c, ptype & 1 != 0)?;
                    let asn = if ptype & 2 != 0 {
                        c.u32("peer AS")?
                    } else {
                        u32::from(c.u16("peer AS")?)
                    };
                    peers.push(MrtPeer { address, asn });
                }
                self.peers = peers;
                Ok(())
            }
            TDV2_RIB_IPV4_UNICAST
            | TDV2_RIB_IPV6_UNICAST
            | TDV2_RIB_IPV4_UNICAST_ADDPATH
            | TDV2_RIB_IPV6_UNICAST_ADDPATH => {
                let v6 = matches!(sub, TDV2_RIB_IPV6_UNICAST | TDV2_RIB_IPV6_UNICAST_ADDPATH);
                let add_path = sub >= TDV2_RIB_IPV4_UNICAST_ADDPATH;
                c.u32("sequence number")?;
                let bits = c.u8("prefix length")?;
                let prefix = bgp::read_prefix(&mut c, bits, v6)?;
                let count = c.u16("entry count")?;
                for _ in 0..count {
                    let idx = usize::from(c.u16("peer index")?);
                    let originated = u64::from(c.u32("originated time")?);
                    if add_path {
                        c.u32("path identifier")?;
                    }
                    let alen = usize::from(c.u16("attribute length")?);
                    let raw = c.take(alen, "attributes")?;
                    // RFC 6396 4.3.4: AS_PATH is always 4-byte in TABLE_DUMP_V2.
                    let opts = ParseOptions {
                        mrt_rib: true,
                        ..ParseOptions::new(true)
                    };
                    let attrs = bgp::parse_attributes(raw, opts, &mut Update::default())?;
                    let peer = *self.peers.get(idx).ok_or(bgp::BgpError::Truncated(
                        "peer index outside PEER_INDEX_TABLE",
                    ))?;
                    self.stats.routes += 1;
                    f(MrtRoute {
                        timestamp: if originated > 0 { originated } else { ts },
                        peer,
                        prefix,
                        withdraw: false,
                        attrs,
                    });
                }
                Ok(())
            }
            _ => {
                self.stats.ignored += 1;
                Ok(())
            }
        }
    }

    fn bgp4mp(
        &mut self,
        sub: u16,
        ts: u64,
        body: &[u8],
        f: &mut impl FnMut(MrtRoute),
    ) -> Result<(), bgp::BgpError> {
        // MESSAGE(1), MESSAGE_AS4(4), *_LOCAL(6, 7), *_ADDPATH(8-11).
        let (as4, add_path) = match sub {
            1 | 6 => (false, false),
            4 | 7 => (true, false),
            8 | 10 => (false, true),
            9 | 11 => (true, true),
            _ => {
                self.stats.ignored += 1;
                return Ok(());
            }
        };
        let mut c = Cursor::new(body);
        let peer_asn = if as4 {
            c.u32("peer AS")?
        } else {
            u32::from(c.u16("peer AS")?)
        };
        c.take(if as4 { 4 } else { 2 }, "local AS")?;
        c.u16("interface index")?;
        let v6 = match c.u16("address family")? {
            1 => false,
            2 => true,
            _ => return Err(bgp::BgpError::Truncated("unknown BGP4MP address family")),
        };
        let address = read_ip(&mut c, v6)?;
        read_ip(&mut c, v6)?;
        let msg = c.rest();
        let Ok((bgp::MSG_UPDATE, _)) = bgp::split_message(msg) else {
            self.stats.ignored += 1;
            return Ok(());
        };
        let update = bgp::parse_update_message(
            msg,
            ParseOptions::new(as4).with_add_path(add_path, add_path),
        )?;
        let peer = MrtPeer {
            address,
            asn: peer_asn,
        };
        for (n, withdraw) in update
            .withdrawn
            .iter()
            .map(|n| (n, true))
            .chain(update.announced.iter().map(|n| (n, false)))
        {
            self.stats.routes += 1;
            f(MrtRoute {
                timestamp: ts,
                peer,
                prefix: n.prefix,
                withdraw,
                attrs: if withdraw {
                    Attributes::default()
                } else {
                    update.attrs.clone()
                },
            });
        }
        Ok(())
    }
}

fn read_ip(c: &mut Cursor<'_>, v6: bool) -> Result<IpAddr, bgp::BgpError> {
    Ok(if v6 {
        let b = c.take(16, "IPv6 address")?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        IpAddr::V6(Ipv6Addr::from(a))
    } else {
        let b = c.take(4, "IPv4 address")?;
        IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    })
}

/// Opens a dump, transparently decompressing gzip.
pub fn open(path: &Path) -> Result<MrtReader<Box<dyn Read>>> {
    let mut f =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    let mut magic = [0u8; 3];
    let n = {
        use std::io::BufRead;
        let buf = f
            .fill_buf()
            .with_context(|| format!("reading {}", path.display()))?;
        let n = buf.len().min(3);
        magic[..n].copy_from_slice(&buf[..n]);
        n
    };
    let r: Box<dyn Read> = if n >= 2 && magic[..2] == [0x1f, 0x8b] {
        Box::new(flate2::read::MultiGzDecoder::new(f))
    } else if n == 3 && &magic == b"BZh" {
        bail!(
            "{} is bzip2-compressed; decompress it first (bunzip2 -k {})",
            path.display(),
            path.display()
        );
    } else {
        Box::new(f)
    };
    Ok(MrtReader::new(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn table_dump_v2_rib() {
        let data = mrt_rib_dump();
        let mut routes = Vec::new();
        let stats = MrtReader::new(&data[..])
            .for_each(|r| routes.push(r))
            .unwrap();
        assert_eq!(stats.records, 4);
        assert_eq!(stats.skipped, 0);
        assert_eq!(routes.len(), 3);
        assert_eq!(
            routes[0].prefix,
            "198.51.100.0/24".parse::<IpNet>().unwrap()
        );
        assert_eq!(routes[0].peer.asn, 64501);
        assert_eq!(routes[0].attrs.as_path.to_string(), "64501 64500");
        assert_eq!(
            routes[1].peer.address,
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            routes[2].prefix,
            "2001:db8:100::/48".parse::<IpNet>().unwrap()
        );
        assert_eq!(routes[2].timestamp, u64::from(DEMO_BASE) + 5);
    }

    #[test]
    fn bgp4mp_updates_and_gzip() {
        let data = mrt_bgp4mp_updates();
        let dir = std::env::temp_dir().join(format!("pathology-mrt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("updates.gz");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &data).unwrap();
        std::fs::write(&path, gz.finish().unwrap()).unwrap();
        let mut routes = Vec::new();
        let stats = open(&path).unwrap().for_each(|r| routes.push(r)).unwrap();
        assert_eq!(stats.records, 3);
        assert_eq!(stats.ignored, 1, "a KEEPALIVE record");
        assert_eq!(routes.len(), 2);
        assert!(!routes[0].withdraw && routes[1].withdraw);
        assert_eq!(routes[0].attrs.as_path.to_string(), "64502 64500");
        std::fs::write(&path, b"BZh91AY&SY").unwrap();
        assert!(format!("{:#}", open(&path).err().unwrap()).contains("bzip2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn damaged_input() {
        let mut data = mrt_rib_dump();
        // Huge length: refused before allocating.
        let mut huge = data.clone();
        huge[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(MrtReader::new(&huge[..]).for_each(|_| {}).is_err());
        // Truncated tail: an error, not a panic.
        data.truncate(data.len() - 3);
        assert!(MrtReader::new(&data[..]).for_each(|_| {}).is_err());
        // Every truncated body is skipped or rejected without panicking.
        let full = mrt_rib_dump();
        for cut in 12..full.len() {
            let _ = MrtReader::new(&full[..cut]).for_each(|_| {});
        }
    }
}
