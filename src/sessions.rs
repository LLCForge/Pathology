//! Session health: BMP router sessions, BMP peers and passive BGP sessions.
//! A session going down raises `session_down` (resolved when it comes back);
//! repeated downs inside a window raise `peer_flap`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

use crate::detector::{format_timestamp, Severity};

/// BMP Peer Down reason 5: the peer was de-configured (intentional).
const REASON_DECONFIGURED: u8 = 5;
const MAX_TRACKED: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    SessionDown,
    PeerFlap,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionKind::SessionDown => "session_down",
            SessionKind::PeerFlap => "peer_flap",
        }
    }
}

/// Which session: a router's BMP feed (`peer = None`) or one of its peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct SessionId {
    pub router: IpAddr,
    pub peer: Option<IpAddr>,
    pub loc_rib: bool,
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.peer {
            None => write!(f, "BMP session of router {}", self.router),
            Some(_) if self.loc_rib => write!(f, "Loc-RIB of router {}", self.router),
            Some(p) if p == self.router => write!(f, "BGP session with {p}"),
            Some(p) if self.router.is_unspecified() => write!(f, "peer {p}"),
            Some(p) => write!(f, "peer {p} on router {}", self.router),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionEvent {
    pub kind: SessionKind,
    pub severity: Severity,
    pub session: SessionId,
    pub peer_asn: Option<u32>,
    pub resolved: bool,
    pub timestamp: u64,
    pub message: String,
}

impl SessionEvent {
    /// Alert resource: the peer address, or the router for its BMP feed.
    pub fn resource(&self) -> String {
        self.session
            .peer
            .filter(|_| !self.session.loc_rib)
            .unwrap_or(self.session.router)
            .to_string()
    }
}

impl fmt::Display for SessionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = if self.resolved {
            "RESOLVED".to_string()
        } else {
            self.severity.as_str().to_uppercase()
        };
        write!(
            f,
            "{} {:<8} {:<13} {}: {}",
            format_timestamp(self.timestamp),
            sev,
            self.kind.as_str(),
            self.session,
            self.message
        )
    }
}

#[derive(Debug)]
pub struct SessionTracker {
    flap_threshold: usize,
    flap_window: u64,
    downs: HashMap<SessionId, VecDeque<u64>>,
    down: HashSet<SessionId>,
    events: Vec<SessionEvent>,
}

impl SessionTracker {
    pub fn new(flap_threshold: u32, flap_window: u64) -> Self {
        SessionTracker {
            flap_threshold: usize::try_from(flap_threshold).unwrap_or(usize::MAX),
            flap_window,
            downs: HashMap::new(),
            down: HashSet::new(),
            events: Vec::new(),
        }
    }

    pub fn reconfigure(&mut self, flap_threshold: u32, flap_window: u64) {
        self.flap_threshold = usize::try_from(flap_threshold).unwrap_or(usize::MAX);
        self.flap_window = flap_window;
    }

    pub fn up(&mut self, id: SessionId, peer_asn: Option<u32>, ts: u64) {
        if self.down.remove(&id) {
            self.events.push(SessionEvent {
                kind: SessionKind::SessionDown,
                severity: Severity::Warning,
                session: id,
                peer_asn,
                resolved: true,
                timestamp: ts,
                message: "session is up again".into(),
            });
        }
    }

    /// `reason` is the BMP Peer Down reason when known.
    pub fn down(
        &mut self,
        id: SessionId,
        peer_asn: Option<u32>,
        reason: Option<u8>,
        ts: u64,
        why: &str,
    ) {
        if reason == Some(REASON_DECONFIGURED) {
            return;
        }
        if self.down.len() < MAX_TRACKED {
            self.down.insert(id);
        }
        self.events.push(SessionEvent {
            kind: SessionKind::SessionDown,
            severity: Severity::Warning,
            session: id,
            peer_asn,
            resolved: false,
            timestamp: ts,
            message: why.to_string(),
        });
        if self.downs.len() >= MAX_TRACKED && !self.downs.contains_key(&id) {
            let window = self.flap_window;
            self.downs
                .retain(|_, d| d.back().is_some_and(|t| ts.saturating_sub(*t) < window));
            if self.downs.len() >= MAX_TRACKED {
                return;
            }
        }
        let d = self.downs.entry(id).or_default();
        d.push_back(ts);
        while d
            .front()
            .is_some_and(|t| ts.saturating_sub(*t) >= self.flap_window)
        {
            d.pop_front();
        }
        while d.len() > self.flap_threshold.max(1) {
            d.pop_front();
        }
        if self.flap_threshold > 0 && d.len() >= self.flap_threshold {
            self.events.push(SessionEvent {
                kind: SessionKind::PeerFlap,
                severity: Severity::Warning,
                session: id,
                peer_asn,
                resolved: false,
                timestamp: ts,
                message: format!("{} session downs within {}s", d.len(), self.flap_window),
            });
            d.clear();
        }
    }

    pub fn drain(&mut self) -> Vec<SessionEvent> {
        std::mem::take(&mut self.events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> SessionId {
        SessionId {
            router: "192.0.2.254".parse().unwrap(),
            peer: Some("192.0.2.3".parse().unwrap()),
            loc_rib: false,
        }
    }

    #[test]
    fn down_up_and_flap() {
        let mut t = SessionTracker::new(3, 600);
        t.up(id(), Some(64503), 0);
        assert!(t.drain().is_empty(), "up without a prior down is silent");
        t.down(id(), Some(64503), Some(4), 10, "remote closed");
        t.up(id(), Some(64503), 20);
        let ev = t.drain();
        assert_eq!(ev.len(), 2);
        assert!(!ev[0].resolved && ev[1].resolved);
        assert_eq!(ev[0].resource(), "192.0.2.3");
        assert!(ev[0].to_string().contains("session_down"));
        t.down(id(), None, None, 100, "x");
        t.down(id(), None, None, 200, "x");
        let ev = t.drain();
        assert_eq!(ev.last().unwrap().kind, SessionKind::PeerFlap);
        // Outside the window the counter starts over.
        t.down(id(), None, None, 2000, "x");
        assert!(t.drain().iter().all(|e| e.kind == SessionKind::SessionDown));
        // De-configured peers are not alarmed.
        t.down(id(), None, Some(5), 3000, "x");
        assert!(t.drain().is_empty());
    }
}
