//! BMP TCP listener: allowlist check, one task per router session.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tracing::{info, warn};

use crate::bmp::{self, Message, SessionState};
use crate::metrics::{inc, METRICS};

/// What the collectors hand to the detector loop.
#[derive(Debug)]
pub enum Event {
    /// A BMP message from `router`, or a synthesised one from a passive BGP
    /// session (where the router is the peer itself).
    Message { router: IpAddr, msg: Message },
    /// A router's BMP TCP session was established.
    RouterUp(IpAddr),
    /// A router's BMP TCP session ended.
    RouterDown { router: IpAddr, reason: String },
}

struct ActiveSession;

impl ActiveSession {
    fn new() -> Self {
        METRICS.bmp_sessions_active.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        METRICS.bmp_sessions_active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Accepts BMP sessions until the task is aborted. Dropping the future aborts
/// every session task.
pub async fn run(listener: TcpListener, allowed: HashSet<IpAddr>, tx: mpsc::Sender<Event>) {
    let mut sessions = JoinSet::new();
    let mut by_router: HashMap<IpAddr, AbortHandle> = HashMap::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, addr) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(error = %e, "BMP accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let router = addr.ip().to_canonical();
                if !allowed.contains(&router) {
                    inc(&METRICS.bmp_sessions_rejected);
                    warn!(%router, "rejected BMP connection: address not in allowed_peers");
                    continue;
                }
                // A router reconnecting replaces its previous (possibly half-open) session.
                if let Some(old) = by_router.remove(&router) {
                    old.abort();
                }
                let handle = sessions.spawn(session(stream, router, tx.clone()));
                by_router.insert(router, handle);
            }
            Some(_) = sessions.join_next() => {}
        }
    }
}

async fn session(stream: TcpStream, router: IpAddr, tx: mpsc::Sender<Event>) {
    let _active = ActiveSession::new();
    info!(%router, "BMP session established");
    if tx.send(Event::RouterUp(router)).await.is_err() {
        return;
    }
    let reason = read_session(stream, router, &tx).await;
    let _ = tx.send(Event::RouterDown { router, reason }).await;
}

/// Reads until the session ends; returns why it ended.
async fn read_session(mut stream: TcpStream, router: IpAddr, tx: &mpsc::Sender<Event>) -> String {
    let mut state = SessionState::default();
    loop {
        let frame = match bmp::read_frame(&mut stream).await {
            Ok(Some(f)) => f,
            Ok(None) => {
                info!(%router, "BMP session closed by router");
                return "BMP session closed by router".into();
            }
            Err(e) => {
                inc(&METRICS.bmp_parse_errors);
                warn!(%router, error = %e, "BMP stream error, closing session");
                return format!("BMP stream error: {e}");
            }
        };
        match state.parse(&frame) {
            Ok(msg) => {
                inc(&METRICS.bmp_messages);
                if tx.send(Event::Message { router, msg }).await.is_err() {
                    return "shutting down".into();
                }
            }
            Err(e) => {
                inc(&METRICS.bmp_parse_errors);
                warn!(%router, error = %e, "malformed BMP message, closing session");
                return format!("malformed BMP message: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn accepts_allowlisted_router_and_closes_on_garbage() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let allowed = HashSet::from(["127.0.0.1".parse().unwrap()]);
        let task = tokio::spawn(run(listener, allowed, tx));

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&initiation("r1", "test")).await.unwrap();
        s.write_all(&announce(
            "192.0.2.1",
            64501,
            1,
            "198.51.100.0/24",
            &[64501, 64500],
        ))
        .await
        .unwrap();
        s.write_all(&[9, 9, 9, 9, 9, 9]).await.unwrap();
        assert!(matches!(rx.recv().await.unwrap(), Event::RouterUp(_)));
        let Event::Message { router, msg } = rx.recv().await.unwrap() else {
            panic!("expected a message");
        };
        assert_eq!(router, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(matches!(msg, Message::Initiation { .. }));
        assert!(matches!(
            rx.recv().await.unwrap(),
            Event::Message {
                msg: Message::RouteMonitoring { .. },
                ..
            }
        ));
        match rx.recv().await.unwrap() {
            Event::RouterDown { reason, .. } => assert!(reason.contains("version"), "{reason}"),
            other => panic!("unexpected {other:?}"),
        }
        // The bad version byte closes the session; the server side drops the socket.
        let mut buf = [0u8; 1];
        let n = tokio::io::AsyncReadExt::read(&mut s, &mut buf)
            .await
            .unwrap_or(0);
        assert_eq!(n, 0);
        task.abort();
    }

    #[tokio::test]
    async fn rejects_unknown_router() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let allowed = HashSet::from(["192.0.2.1".parse().unwrap()]);
        let task = tokio::spawn(run(listener, allowed, tx));
        let mut s = TcpStream::connect(addr).await.unwrap();
        let _ = s.write_all(&initiation("r1", "test")).await;
        let mut buf = [0u8; 1];
        let n = tokio::io::AsyncReadExt::read(&mut s, &mut buf)
            .await
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert!(rx.try_recv().is_err());
        task.abort();
    }
}
