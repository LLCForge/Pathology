//! Hand-written BMP/BGP encoders used to build test messages and the demo capture.

use std::net::IpAddr;

use ipnet::IpNet;

pub fn encode_prefix(p: &IpNet) -> Vec<u8> {
    let bits = p.prefix_len();
    let n = usize::from(bits).div_ceil(8);
    let mut out = vec![bits];
    match p.network() {
        IpAddr::V4(a) => out.extend_from_slice(&a.octets()[..n]),
        IpAddr::V6(a) => out.extend_from_slice(&a.octets()[..n]),
    }
    out
}

fn prefixes(list: &[&str]) -> Vec<u8> {
    list.iter()
        .flat_map(|s| encode_prefix(&s.parse().unwrap()))
        .collect()
}

pub fn attr(flags: u8, code: u8, value: &[u8]) -> Vec<u8> {
    if value.len() > 255 {
        let mut out = vec![flags | 0x10, code];
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    } else {
        let mut out = vec![flags, code, value.len() as u8];
        out.extend_from_slice(value);
        out
    }
}

pub fn origin_attr(v: u8) -> Vec<u8> {
    attr(0x40, 1, &[v])
}

/// 4-byte AS_PATH; each segment is (type, asns).
pub fn as_path_attr(segments: &[(u8, &[u32])]) -> Vec<u8> {
    let mut v = Vec::new();
    for (t, asns) in segments {
        v.push(*t);
        v.push(asns.len() as u8);
        for a in *asns {
            v.extend_from_slice(&a.to_be_bytes());
        }
    }
    attr(0x40, 2, &v)
}

pub fn next_hop_attr(a: [u8; 4]) -> Vec<u8> {
    attr(0x40, 3, &a)
}

pub fn communities_attr(list: &[u32]) -> Vec<u8> {
    let v: Vec<u8> = list.iter().flat_map(|c| c.to_be_bytes()).collect();
    attr(0xc0, 8, &v)
}

pub fn large_communities_attr(list: &[[u32; 3]]) -> Vec<u8> {
    let v: Vec<u8> = list
        .iter()
        .flatten()
        .flat_map(|c| c.to_be_bytes())
        .collect();
    attr(0xc0, 32, &v)
}

fn prefixes_add_path(list: &[(u32, &str)]) -> Vec<u8> {
    list.iter()
        .flat_map(|(id, s)| {
            let mut v = id.to_be_bytes().to_vec();
            v.extend(encode_prefix(&s.parse().unwrap()));
            v
        })
        .collect()
}

pub fn mp_reach_v6_add_path(list: &[(u32, &str)]) -> Vec<u8> {
    let mut v = vec![0, 2, 1, 16];
    v.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    v.push(0);
    v.extend(prefixes_add_path(list));
    attr(0x80, 14, &v)
}

pub fn update_v4_add_path(
    withdrawn: &[(u32, &str)],
    attrs: &[Vec<u8>],
    nlri: &[(u32, &str)],
) -> Vec<u8> {
    let w = prefixes_add_path(withdrawn);
    let a: Vec<u8> = attrs.concat();
    let mut body = Vec::new();
    body.extend_from_slice(&(w.len() as u16).to_be_bytes());
    body.extend(w);
    body.extend_from_slice(&(a.len() as u16).to_be_bytes());
    body.extend(a);
    body.extend(prefixes_add_path(nlri));
    bgp_message(2, &body)
}

pub fn mp_reach_v6(list: &[&str]) -> Vec<u8> {
    let mut v = vec![0, 2, 1, 16];
    v.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    v.push(0);
    v.extend(prefixes(list));
    attr(0x80, 14, &v)
}

pub fn mp_unreach_v6(list: &[&str]) -> Vec<u8> {
    let mut v = vec![0, 2, 1];
    v.extend(prefixes(list));
    attr(0x80, 15, &v)
}

pub fn bgp_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xff; 16];
    out.extend_from_slice(&((19 + body.len()) as u16).to_be_bytes());
    out.push(msg_type);
    out.extend_from_slice(body);
    out
}

pub fn update_v4(withdrawn: &[&str], attrs: &[Vec<u8>], nlri: &[&str]) -> Vec<u8> {
    let w = prefixes(withdrawn);
    let a: Vec<u8> = attrs.concat();
    let mut body = Vec::new();
    body.extend_from_slice(&(w.len() as u16).to_be_bytes());
    body.extend(w);
    body.extend_from_slice(&(a.len() as u16).to_be_bytes());
    body.extend(a);
    body.extend(prefixes(nlri));
    bgp_message(2, &body)
}

fn open_message(asn: u16) -> Vec<u8> {
    let mut body = vec![4];
    body.extend_from_slice(&asn.to_be_bytes());
    body.extend_from_slice(&90u16.to_be_bytes());
    body.extend_from_slice(&[192, 0, 2, 254]);
    body.push(0);
    bgp_message(1, &body)
}

pub fn bmp(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![3];
    out.extend_from_slice(&((6 + body.len()) as u32).to_be_bytes());
    out.push(msg_type);
    out.extend_from_slice(body);
    out
}

pub fn per_peer(peer: IpAddr, asn: u32, ts: u32) -> Vec<u8> {
    let mut out = vec![0];
    let mut addr = [0u8; 16];
    match peer {
        IpAddr::V4(a) => {
            out.push(0);
            addr[12..].copy_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(0x80);
            addr = a.octets();
        }
    }
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&addr);
    out.extend_from_slice(&asn.to_be_bytes());
    out.extend_from_slice(&[192, 0, 2, 1]);
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

pub fn route_monitoring(peer: IpAddr, asn: u32, ts: u32, update: &[u8]) -> Vec<u8> {
    let mut body = per_peer(peer, asn, ts);
    body.extend_from_slice(update);
    bmp(0, &body)
}

pub fn peer_up(peer: IpAddr, asn: u32, ts: u32) -> Vec<u8> {
    let mut body = per_peer(peer, asn, ts);
    let mut local = [0u8; 16];
    local[12..].copy_from_slice(&[192, 0, 2, 254]);
    body.extend_from_slice(&local);
    body.extend_from_slice(&179u16.to_be_bytes());
    body.extend_from_slice(&50000u16.to_be_bytes());
    body.extend(open_message(64496));
    body.extend(open_message(asn as u16));
    bmp(3, &body)
}

/// Peer Up whose OPENs negotiate 4-byte AS and ADD-PATH for both families.
pub fn peer_up_add_path(peer: IpAddr, asn: u32, ts: u32) -> Vec<u8> {
    let id = std::net::Ipv4Addr::new(192, 0, 2, 254);
    let mut body = per_peer(peer, asn, ts);
    body.extend_from_slice(&[0u8; 20]);
    // Router side: receive. Peer side: patch receive (1) into send+receive (3).
    body.extend(crate::bgp::encode_open(64496, 90, id));
    let mut theirs = crate::bgp::encode_open(asn, 90, id);
    let n = theirs.len();
    theirs[n - 1] = 3;
    theirs[n - 5] = 3;
    body.extend(theirs);
    bmp(3, &body)
}

pub fn peer_down(peer: IpAddr, asn: u32, ts: u32, reason: u8) -> Vec<u8> {
    let mut body = per_peer(peer, asn, ts);
    body.push(reason);
    bmp(2, &body)
}

fn tlv(t: u16, v: &[u8]) -> Vec<u8> {
    let mut out = t.to_be_bytes().to_vec();
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
    out
}

pub fn initiation(sys_name: &str, sys_descr: &str) -> Vec<u8> {
    let mut body = tlv(2, sys_name.as_bytes());
    body.extend(tlv(1, sys_descr.as_bytes()));
    bmp(4, &body)
}

pub fn termination(reason: u16) -> Vec<u8> {
    bmp(5, &tlv(1, &reason.to_be_bytes()))
}

/// One announcement with ORIGIN IGP, the given 4-byte AS_SEQUENCE and an IPv4 or IPv6 prefix.
pub fn announce(peer: &str, asn: u32, ts: u32, prefix: &str, path: &[u32]) -> Vec<u8> {
    let p: IpNet = prefix.parse().unwrap();
    let mut attrs = vec![origin_attr(0), as_path_attr(&[(2, path)])];
    let upd = if p.network().is_ipv4() {
        attrs.push(next_hop_attr([192, 0, 2, 1]));
        update_v4(&[], &attrs, &[prefix])
    } else {
        attrs.push(mp_reach_v6(&[prefix]));
        update_v4(&[], &attrs, &[])
    };
    route_monitoring(peer.parse().unwrap(), asn, ts, &upd)
}

pub fn withdraw(peer: &str, asn: u32, ts: u32, prefix: &str) -> Vec<u8> {
    let p: IpNet = prefix.parse().unwrap();
    let upd = if p.network().is_ipv4() {
        update_v4(&[prefix], &[], &[])
    } else {
        update_v4(&[], &[mp_unreach_v6(&[prefix])], &[])
    };
    route_monitoring(peer.parse().unwrap(), asn, ts, &upd)
}

/// 2026-03-01T00:00:00Z
pub const DEMO_BASE: u32 = 1_772_323_200;
const DAY: u32 = 86_400;

/// The checked-in demo capture: two weeks of stable routes, then a burst of anomalies.
pub fn demo_capture() -> Vec<u8> {
    let (p1, p2, p3) = ("192.0.2.1", "192.0.2.2", "192.0.2.3");
    let v4 = "198.51.100.0/24";
    let v6 = "2001:db8:100::/48";
    let mut out = initiation("edge-router-1", "demo capture");
    out.extend(peer_up(p1.parse().unwrap(), 64501, DEMO_BASE));
    out.extend(peer_up(p2.parse().unwrap(), 64502, DEMO_BASE));
    for day in [0, 4, 9, 14] {
        let ts = DEMO_BASE + day * DAY;
        out.extend(announce(p1, 64501, ts, v4, &[64501, 64500]));
        out.extend(announce(p2, 64502, ts, v4, &[64502, 64500]));
        out.extend(announce(p1, 64501, ts, v6, &[64501, 64500]));
    }
    let t = DEMO_BASE + 15 * DAY + 9 * 3600;
    out.extend(announce(p1, 64501, t, v4, &[64501, 64511, 64500]));
    out.extend(peer_up(p3.parse().unwrap(), 64503, t + 120));
    out.extend(announce(p3, 64503, t + 300, v4, &[64503, 64500]));
    out.extend(announce(
        p1,
        64501,
        t + 720,
        "198.51.100.128/25",
        &[64501, 64510],
    ));
    out.extend(announce(p2, 64502, t + 725, v4, &[64502, 64510]));
    out.extend(withdraw(p1, 64501, t + 1200, v6));
    out.extend(announce(p1, 64501, t + 1500, v6, &[64501, 64509]));
    out.extend(peer_down(p3.parse().unwrap(), 64503, t + 1800, 4));
    out.extend(termination(0));
    out
}

pub fn mrt_record(ts: u32, typ: u16, sub: u16, body: &[u8]) -> Vec<u8> {
    let mut out = ts.to_be_bytes().to_vec();
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&sub.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn rib_entry(peer_index: u16, originated: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
    let a = attrs.concat();
    let mut out = peer_index.to_be_bytes().to_vec();
    out.extend_from_slice(&originated.to_be_bytes());
    out.extend_from_slice(&(a.len() as u16).to_be_bytes());
    out.extend(a);
    out
}

/// TABLE_DUMP_V2: PEER_INDEX_TABLE, one IPv4 and one IPv6 RIB record, and an
/// ignored legacy TABLE_DUMP record.
pub fn mrt_rib_dump() -> Vec<u8> {
    let mut pit = vec![192, 0, 2, 100, 0, 0, 0, 2];
    pit.extend_from_slice(&[2, 192, 0, 2, 1, 192, 0, 2, 1]);
    pit.extend_from_slice(&64501u32.to_be_bytes());
    pit.extend_from_slice(&[3, 192, 0, 2, 2]);
    pit.extend_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    pit.extend_from_slice(&64502u32.to_be_bytes());
    let mut v4 = vec![0, 0, 0, 0];
    v4.extend(encode_prefix(&"198.51.100.0/24".parse().unwrap()));
    v4.extend_from_slice(&2u16.to_be_bytes());
    v4.extend(rib_entry(
        0,
        DEMO_BASE,
        &[origin_attr(0), as_path_attr(&[(2, &[64501, 64500])])],
    ));
    v4.extend(rib_entry(
        1,
        DEMO_BASE,
        &[origin_attr(0), as_path_attr(&[(2, &[64502, 64500])])],
    ));
    let mut v6 = vec![0, 0, 0, 1];
    v6.extend(encode_prefix(&"2001:db8:100::/48".parse().unwrap()));
    v6.extend_from_slice(&1u16.to_be_bytes());
    let mut nh = vec![16];
    nh.extend_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    v6.extend(rib_entry(
        1,
        DEMO_BASE + 5,
        &[
            origin_attr(0),
            as_path_attr(&[(2, &[64502, 64500])]),
            attr(0x80, 14, &nh),
        ],
    ));
    let mut out = mrt_record(DEMO_BASE, 13, 1, &pit);
    out.extend(mrt_record(DEMO_BASE, 13, 2, &v4));
    out.extend(mrt_record(DEMO_BASE, 13, 4, &v6));
    out.extend(mrt_record(DEMO_BASE, 12, 1, &[0; 8]));
    out
}

fn bgp4mp_as4(msg: &[u8]) -> Vec<u8> {
    let mut b = 64502u32.to_be_bytes().to_vec();
    b.extend_from_slice(&64496u32.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 1, 192, 0, 2, 2, 192, 0, 2, 254]);
    b.extend_from_slice(msg);
    b
}

/// BGP4MP: an announcement, a KEEPALIVE and (as BGP4MP_ET) a withdrawal.
pub fn mrt_bgp4mp_updates() -> Vec<u8> {
    let ann = update_v4(
        &[],
        &[
            origin_attr(0),
            as_path_attr(&[(2, &[64502, 64500])]),
            next_hop_attr([192, 0, 2, 2]),
        ],
        &["198.51.100.0/24"],
    );
    let wd = update_v4(&["198.51.100.0/24"], &[], &[]);
    let mut out = mrt_record(DEMO_BASE, 16, 4, &bgp4mp_as4(&ann));
    out.extend(mrt_record(
        DEMO_BASE,
        16,
        4,
        &bgp4mp_as4(&bgp_message(4, &[])),
    ));
    let mut et = 0u32.to_be_bytes().to_vec();
    et.extend(bgp4mp_as4(&wd));
    out.extend(mrt_record(DEMO_BASE + 60, 17, 4, &et));
    out
}
