//! Passive, receive-only BGP listener for routers without BMP.
//!
//! Configured routers connect to `collector.bgp.listen`; Pathology answers the
//! OPEN (4-byte AS, MP IPv4/IPv6 unicast, ADD-PATH receive), keeps the session
//! alive with KEEPALIVEs and turns every UPDATE into the same event a BMP
//! Route Monitoring message produces. It never sends an UPDATE.
//!
//! Binding port 179 needs CAP_NET_BIND_SERVICE (or root) on Linux; macOS
//! 10.14+ and Windows allow it to unprivileged processes. TCP-MD5 (RFC 2385)
//! is not supported: configure the router session without a password.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tracing::{info, warn};

use crate::bgp::{self, BgpError, Open, ParseOptions};
use crate::bmp::{Message, PeerHeader};
use crate::collector::Event;
use crate::metrics::{inc, METRICS};

const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
/// RFC 4271 notification codes used here.
const ERR_HEADER: u8 = 1;
const ERR_OPEN: u8 = 2;
const ERR_UPDATE: u8 = 3;
const ERR_HOLD_TIMER: u8 = 4;
const ERR_FSM: u8 = 5;
const OPEN_BAD_PEER_AS: u8 = 2;
const OPEN_BAD_BGP_ID: u8 = 3;
const OPEN_UNACCEPTABLE_HOLD: u8 = 6;
const OPEN_UNSUPPORTED_VERSION: u8 = 1;
const UPDATE_MALFORMED: u8 = 1;
const HEADER_BAD_TYPE: u8 = 3;
/// BMP Peer Down reasons reused for synthesised events.
const DOWN_LOCAL_NOTIFICATION: u8 = 1;
const DOWN_REMOTE_NOTIFICATION: u8 = 3;
const DOWN_REMOTE_CLOSED: u8 = 4;

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub local_asn: u32,
    pub router_id: Ipv4Addr,
    pub hold_time: u16,
    /// Allowed peer address → expected ASN.
    pub peers: HashMap<IpAddr, u32>,
}

struct Established;

impl Established {
    fn new() -> Self {
        METRICS
            .bgp_sessions_established
            .fetch_add(1, Ordering::Relaxed);
        Established
    }
}

impl Drop for Established {
    fn drop(&mut self) {
        METRICS
            .bgp_sessions_established
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Accepts sessions until aborted.
pub async fn run(listener: TcpListener, cfg: ListenerConfig, tx: mpsc::Sender<Event>) {
    let mut sessions = JoinSet::new();
    let mut by_peer: HashMap<IpAddr, AbortHandle> = HashMap::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, addr) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(error = %e, "BGP accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let peer = addr.ip().to_canonical();
                let Some(asn) = cfg.peers.get(&peer).copied() else {
                    inc(&METRICS.bgp_sessions_rejected);
                    warn!(%peer, "rejected BGP connection: address is not a configured peer");
                    continue;
                };
                // A reconnecting peer replaces its old (possibly half-open) session.
                if let Some(old) = by_peer.remove(&peer) {
                    old.abort();
                }
                let h = sessions.spawn(session(stream, peer, asn, cfg.clone(), tx.clone()));
                by_peer.insert(peer, h);
            }
            Some(_) = sessions.join_next() => {}
        }
    }
}

#[derive(Debug)]
enum SessionEnd {
    /// We sent a NOTIFICATION.
    Local(String),
    /// The peer sent a NOTIFICATION.
    Remote(String),
    /// TCP closed / IO error.
    Closed(String),
    Shutdown,
}

/// Reads one BGP message (header included), bounded to 65535 bytes.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut header = [0u8; bgp::HEADER_LEN];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    if header[..16].iter().any(|b| *b != 0xff) {
        return Err("invalid BGP marker".into());
    }
    let len = usize::from(u16::from_be_bytes([header[16], header[17]]));
    if len < bgp::HEADER_LEN {
        return Err(format!("invalid BGP length {len}"));
    }
    let mut msg = vec![0u8; len];
    msg[..bgp::HEADER_LEN].copy_from_slice(&header);
    r.read_exact(&mut msg[bgp::HEADER_LEN..])
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(msg))
}

fn peer_header(peer: IpAddr, asn: u32) -> PeerHeader {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    PeerHeader {
        peer_type: 0,
        flags: if peer.is_ipv6() { 0x80 } else { 0 },
        distinguisher: 0,
        address: peer,
        asn,
        timestamp: u32::try_from(now).unwrap_or(u32::MAX),
    }
}

type Incoming = Result<Option<Vec<u8>>, String>;

async fn session(
    stream: TcpStream,
    peer: IpAddr,
    asn: u32,
    cfg: ListenerConfig,
    tx: mpsc::Sender<Event>,
) {
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.into_split();
    // A dedicated reader keeps message reads whole while the session loop
    // also waits on the keepalive timer (a cancelled read would desync).
    let (msg_tx, mut msgs) = mpsc::channel::<Incoming>(64);
    let reader = tokio::spawn(async move {
        loop {
            let r = read_message(&mut rd).await;
            let stop = !matches!(r, Ok(Some(_)));
            if msg_tx.send(r).await.is_err() || stop {
                return;
            }
        }
    });
    let mut established = None;
    let end = run_session(&mut wr, &mut msgs, peer, asn, &cfg, &tx, &mut established).await;
    reader.abort();
    if let SessionEnd::Local(_) = &end {
        inc(&METRICS.bgp_session_errors);
    }
    let (reason, why) = match end {
        SessionEnd::Local(w) => (DOWN_LOCAL_NOTIFICATION, w),
        SessionEnd::Remote(w) => (DOWN_REMOTE_NOTIFICATION, w),
        SessionEnd::Closed(w) => (DOWN_REMOTE_CLOSED, w),
        SessionEnd::Shutdown => return,
    };
    info!(%peer, reason = %why, "BGP session closed");
    if established.take().is_some() {
        let msg = Message::PeerDown {
            peer: peer_header(peer, asn),
            reason,
        };
        let _ = tx.send(Event::Message { router: peer, msg }).await;
    }
}

async fn notify(stream: &mut OwnedWriteHalf, code: u8, subcode: u8, why: String) -> SessionEnd {
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        stream.write_all(&bgp::encode_notification(code, subcode)),
    )
    .await;
    SessionEnd::Local(why)
}

/// Validates the peer's OPEN; returns the parse options for its UPDATEs.
fn check_open(theirs: &Open, ours: &Open, expected_asn: u32) -> Result<ParseOptions, (u8, String)> {
    if theirs.version != 4 {
        return Err((
            OPEN_UNSUPPORTED_VERSION,
            format!("unsupported BGP version {}", theirs.version),
        ));
    }
    if theirs.asn() != expected_asn {
        return Err((
            OPEN_BAD_PEER_AS,
            format!(
                "peer AS{} does not match configured AS{expected_asn}",
                theirs.asn()
            ),
        ));
    }
    if (1..3).contains(&theirs.hold_time) {
        return Err((
            OPEN_UNACCEPTABLE_HOLD,
            format!("hold time {} is not allowed", theirs.hold_time),
        ));
    }
    if theirs.bgp_id.is_unspecified() {
        return Err((OPEN_BAD_BGP_ID, "BGP identifier 0.0.0.0".into()));
    }
    Ok(ours.update_options(theirs))
}

async fn next_msg(msgs: &mut mpsc::Receiver<Incoming>, wait: Duration) -> Option<Incoming> {
    tokio::time::timeout(wait, msgs.recv())
        .await
        .ok()
        .map(|m| m.unwrap_or(Ok(None)))
}

async fn run_session(
    stream: &mut OwnedWriteHalf,
    msgs: &mut mpsc::Receiver<Incoming>,
    peer: IpAddr,
    asn: u32,
    cfg: &ListenerConfig,
    tx: &mpsc::Sender<Event>,
    established: &mut Option<Established>,
) -> SessionEnd {
    let our_open = bgp::encode_open(cfg.local_asn, cfg.hold_time, cfg.router_id);
    let ours = match bgp::parse_open_message(&our_open) {
        Ok(o) => o,
        Err(e) => return SessionEnd::Local(format!("internal OPEN encoding error: {e}")),
    };
    if let Err(e) = stream.write_all(&our_open).await {
        return SessionEnd::Closed(e.to_string());
    }

    // OpenSent: wait for the peer's OPEN.
    let raw = match next_msg(msgs, OPEN_TIMEOUT).await {
        None => return notify(stream, ERR_HOLD_TIMER, 0, "no OPEN received".into()).await,
        Some(Err(e)) => return notify(stream, ERR_HEADER, 0, e).await,
        Some(Ok(None)) => return SessionEnd::Closed("closed before OPEN".into()),
        Some(Ok(Some(m))) => m,
    };
    let theirs = match bgp::parse_open_message(&raw) {
        Ok(o) => o,
        Err(BgpError::NotOpen(bgp::MSG_NOTIFICATION)) => {
            return SessionEnd::Remote("NOTIFICATION instead of OPEN".into())
        }
        Err(e) => return notify(stream, ERR_OPEN, 0, format!("bad OPEN: {e}")).await,
    };
    let opts = match check_open(&theirs, &ours, asn) {
        Ok(o) => o,
        Err((sub, why)) => return notify(stream, ERR_OPEN, sub, why).await,
    };
    let hold = match (cfg.hold_time, theirs.hold_time) {
        (0, _) | (_, 0) => 0,
        (a, b) => a.min(b),
    };
    let hold_dur = (hold > 0).then(|| Duration::from_secs(u64::from(hold)));
    if let Err(e) = stream.write_all(&bgp::encode_keepalive()).await {
        return SessionEnd::Closed(e.to_string());
    }

    let mut keepalive = tokio::time::interval(Duration::from_secs(u64::from((hold / 3).max(1))));
    keepalive.tick().await;
    // Hold time 0: no hold timer (a year stands in for "never").
    let read_timeout = hold_dur.unwrap_or(Duration::from_secs(365 * 86_400));
    loop {
        let raw = tokio::select! {
            r = next_msg(msgs, read_timeout) => r,
            _ = keepalive.tick(), if hold > 0 => {
                if let Err(e) = stream.write_all(&bgp::encode_keepalive()).await {
                    return SessionEnd::Closed(e.to_string());
                }
                continue;
            }
        };
        let raw = match raw {
            None => return notify(stream, ERR_HOLD_TIMER, 0, "hold timer expired".into()).await,
            Some(Err(e)) => return notify(stream, ERR_HEADER, 0, e).await,
            Some(Ok(None)) => return SessionEnd::Closed("peer closed the connection".into()),
            Some(Ok(Some(m))) => m,
        };
        inc(&METRICS.bgp_messages);
        let (msg_type, body) = match bgp::split_message(&raw) {
            Ok(x) => x,
            Err(e) => return notify(stream, ERR_HEADER, 0, e.to_string()).await,
        };
        match msg_type {
            bgp::MSG_KEEPALIVE => {
                if established.is_none() {
                    *established = Some(Established::new());
                    info!(%peer, peer_asn = asn, hold, "BGP session established (receive-only)");
                    let msg = Message::PeerUp {
                        peer: peer_header(peer, asn),
                        sent: Some(ours.clone()),
                        received: Some(theirs.clone()),
                    };
                    if tx.send(Event::Message { router: peer, msg }).await.is_err() {
                        return SessionEnd::Shutdown;
                    }
                }
            }
            bgp::MSG_UPDATE if established.is_some() => {
                let update = match bgp::parse_update_body(body, opts) {
                    Ok(u) => u,
                    Err(e) => {
                        return notify(
                            stream,
                            ERR_UPDATE,
                            UPDATE_MALFORMED,
                            format!("malformed UPDATE: {e}"),
                        )
                        .await
                    }
                };
                let msg = Message::RouteMonitoring {
                    peer: peer_header(peer, asn),
                    update,
                };
                if tx.send(Event::Message { router: peer, msg }).await.is_err() {
                    return SessionEnd::Shutdown;
                }
            }
            bgp::MSG_NOTIFICATION => {
                let (code, sub) = (
                    body.first().copied().unwrap_or(0),
                    body.get(1).copied().unwrap_or(0),
                );
                return SessionEnd::Remote(format!("peer sent NOTIFICATION {code}/{sub}"));
            }
            bgp::MSG_ROUTE_REFRESH if established.is_some() => {}
            bgp::MSG_UPDATE | bgp::MSG_ROUTE_REFRESH | bgp::MSG_OPEN => {
                return notify(
                    stream,
                    ERR_FSM,
                    0,
                    format!("unexpected message type {msg_type}"),
                )
                .await
            }
            other => {
                return notify(
                    stream,
                    ERR_HEADER,
                    HEADER_BAD_TYPE,
                    format!("unknown message type {other}"),
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    fn cfg(peer_asn: u32) -> ListenerConfig {
        ListenerConfig {
            local_asn: 64496,
            router_id: Ipv4Addr::new(192, 0, 2, 254),
            hold_time: 3,
            peers: HashMap::from([("127.0.0.1".parse().unwrap(), peer_asn)]),
        }
    }

    async fn start(
        c: ListenerConfig,
    ) -> (
        std::net::SocketAddr,
        mpsc::Receiver<Event>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(16);
        (addr, rx, tokio::spawn(run(listener, c, tx)))
    }

    #[tokio::test]
    async fn receive_only_session() {
        let (addr, mut rx, task) = start(cfg(64501)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        // Our side first sends its OPEN.
        let open = read_message(&mut s).await.unwrap().unwrap();
        let ours = bgp::parse_open_message(&open).unwrap();
        assert_eq!(ours.asn(), 64496);
        s.write_all(&bgp::encode_open(64501, 3, Ipv4Addr::new(192, 0, 2, 1)))
            .await
            .unwrap();
        // KEEPALIVE confirms the OPEN.
        let ka = read_message(&mut s).await.unwrap().unwrap();
        assert_eq!(ka[18], bgp::MSG_KEEPALIVE);
        s.write_all(&bgp::encode_keepalive()).await.unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            Event::Message {
                msg: Message::PeerUp { .. },
                ..
            }
        ));
        let upd = update_v4(
            &[],
            &[
                origin_attr(0),
                as_path_attr(&[(2, &[64501, 64500])]),
                next_hop_attr([192, 0, 2, 1]),
            ],
            &["198.51.100.0/24"],
        );
        s.write_all(&upd).await.unwrap();
        match rx.recv().await.unwrap() {
            Event::Message {
                router,
                msg: Message::RouteMonitoring { peer, update },
            } => {
                assert_eq!(router, "127.0.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(peer.asn, 64501);
                assert_eq!(update.attrs.as_path.to_string(), "64501 64500");
            }
            other => panic!("unexpected {other:?}"),
        }
        // Keepalives keep coming (hold 3s → every second); we never get an UPDATE.
        let m = tokio::time::timeout(Duration::from_secs(3), read_message(&mut s))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(m[18], bgp::MSG_KEEPALIVE);
        // A malformed UPDATE gets a NOTIFICATION and a Peer Down event.
        s.write_all(&bgp::encode_message(bgp::MSG_UPDATE, &[0, 9]))
            .await
            .unwrap();
        loop {
            let m = read_message(&mut s).await.unwrap().unwrap();
            if m[18] == bgp::MSG_NOTIFICATION {
                assert_eq!(m[19], ERR_UPDATE);
                break;
            }
        }
        assert!(matches!(
            rx.recv().await.unwrap(),
            Event::Message {
                msg: Message::PeerDown {
                    reason: DOWN_LOCAL_NOTIFICATION,
                    ..
                },
                ..
            }
        ));
        task.abort();
    }

    #[tokio::test]
    async fn wrong_peer_as_is_refused() {
        let (addr, mut rx, task) = start(cfg(64502)).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        read_message(&mut s).await.unwrap().unwrap();
        s.write_all(&bgp::encode_open(64501, 90, Ipv4Addr::new(192, 0, 2, 1)))
            .await
            .unwrap();
        let n = read_message(&mut s).await.unwrap().unwrap();
        assert_eq!(
            (n[18], n[19], n[20]),
            (bgp::MSG_NOTIFICATION, ERR_OPEN, OPEN_BAD_PEER_AS)
        );
        assert!(rx.try_recv().is_err(), "never established, no events");
        task.abort();
    }

    #[tokio::test]
    async fn unknown_address_is_dropped() {
        let mut c = cfg(64501);
        c.peers = HashMap::from([("192.0.2.1".parse().unwrap(), 64501)]);
        let (addr, _rx, task) = start(c).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        assert!(read_message(&mut s).await.unwrap_or(None).is_none());
        task.abort();
    }

    #[test]
    fn open_checks() {
        let ours =
            bgp::parse_open_message(&bgp::encode_open(64496, 90, Ipv4Addr::new(192, 0, 2, 254)))
                .unwrap();
        let mut theirs =
            bgp::parse_open_message(&bgp::encode_open(64501, 2, Ipv4Addr::new(192, 0, 2, 1)))
                .unwrap();
        assert_eq!(
            check_open(&theirs, &ours, 64501).unwrap_err().0,
            OPEN_UNACCEPTABLE_HOLD
        );
        theirs.hold_time = 0;
        assert!(check_open(&theirs, &ours, 64501).is_ok());
        theirs.bgp_id = Ipv4Addr::UNSPECIFIED;
        assert_eq!(
            check_open(&theirs, &ours, 64501).unwrap_err().0,
            OPEN_BAD_BGP_ID
        );
    }
}
