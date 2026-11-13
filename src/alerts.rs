//! Turns findings and session events into `llcforge.alert.v1` alerts and hands
//! them to the llcforge-beacon dispatcher (sinks, dedup, silences, queue).
//!
//! Every finding is also logged. When Notary is configured, a finding with an
//! origin ASN gets its RPKI state attached first; the lookup runs in its own
//! task and is time-boxed, so the detector loop never waits for it.

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use llcforge_beacon::{Alert, AlertHandle};
use tracing::{error, info, warn};

use crate::detector::{Finding, Severity};
use crate::metrics::{inc, METRICS};
use crate::notary::NotaryClient;
use crate::rib::{self, unix_to_utc};
use crate::sessions::SessionEvent;

pub const TOOL: &str = "pathology";

fn when(ts: u64) -> DateTime<Utc> {
    if ts == 0 {
        Utc::now()
    } else {
        unix_to_utc(ts)
    }
}

/// The always-on log sink: every finding becomes a structured log event.
pub fn log_finding(f: &Finding) {
    METRICS.finding(f.severity);
    macro_rules! emit {
        ($level:ident) => {
            $level!(
                kind = f.kind.as_str(),
                prefix = %f.prefix,
                peer = %f.peer,
                origin = %f.origin_asn.map_or_else(String::new, |o| o.to_string()),
                path = %f.as_path,
                learning = f.learning,
                resolved = f.resolved,
                "{}",
                f.message
            )
        };
    }
    match f.severity {
        _ if f.resolved => emit!(info),
        Severity::Critical => emit!(error),
        Severity::Warning => emit!(warn),
        Severity::Info => emit!(info),
    }
}

pub fn log_session(s: &SessionEvent) {
    inc(&METRICS.session_events);
    if s.resolved {
        info!(kind = s.kind.as_str(), session = %s.session, "{}", s.message);
    } else {
        warn!(kind = s.kind.as_str(), session = %s.session, "{}", s.message);
    }
}

pub fn finding_alert(f: &Finding) -> Alert {
    let mut a = Alert::new(
        TOOL,
        f.kind.as_str(),
        f.severity,
        format!("{} {}", f.kind.as_str().replace('_', " "), f.prefix),
    )
    .resource(f.prefix.to_string())
    .id(f.alert_id())
    .summary(f.message.clone())
    .field("watch", f.watch)
    .field("router", f.router)
    .field(
        if f.loc_rib { "source" } else { "peer" },
        if f.loc_rib {
            "loc-rib".to_string()
        } else {
            f.peer.to_string()
        },
    )
    .field("peer_asn", format!("AS{}", f.peer_asn));
    if let Some(o) = f.origin_asn {
        a = a.field("origin", format!("AS{o}"));
    }
    if let Some(u) = f.upstream_asn {
        a = a.field("upstream", format!("AS{u}"));
    }
    if !f.as_path.is_empty() {
        a = a.field("as_path", &f.as_path);
    }
    if !f.communities.is_empty() {
        a = a.field("communities", f.communities.join(" "));
    }
    if !f.large_communities.is_empty() {
        a = a.field("large_communities", f.large_communities.join(" "));
    }
    if let Some(r) = &f.rpki {
        a = a.field("rpki", &r.state);
        if r.stale {
            a = a.field("rpki_stale", "true");
        }
    }
    if f.learning {
        a = a.field("baseline", "learning");
    }
    let t = when(f.timestamp);
    a.first_seen(t)
        .last_seen(t)
        .resolved(f.resolved)
        .link("RIPEstat", format!("https://stat.ripe.net/{}", f.prefix))
}

pub fn session_alert(s: &SessionEvent) -> Alert {
    let mut a = Alert::new(
        TOOL,
        s.kind.as_str(),
        s.severity,
        format!("{} {}", s.kind.as_str().replace('_', " "), s.session),
    )
    .resource(s.resource())
    .id(format!(
        "{TOOL}:{}:{}:{}",
        s.kind.as_str(),
        s.session.router,
        s.session.peer.map_or_else(
            || "bmp".to_string(),
            |p| if s.session.loc_rib {
                "loc-rib".into()
            } else {
                p.to_string()
            }
        )
    ))
    .summary(s.message.clone())
    .field("router", s.session.router);
    if let Some(asn) = s.peer_asn {
        a = a.field("peer_asn", format!("AS{asn}"));
    }
    let t = when(s.timestamp);
    a.first_seen(t).last_seen(t).resolved(s.resolved)
}

/// Cloneable alert front end; survives configuration reloads (the dispatcher
/// handle and Notary client are swapped in place).
#[derive(Clone)]
pub struct Alerter {
    handle: Arc<RwLock<AlertHandle>>,
    notary: Arc<RwLock<Option<Arc<NotaryClient>>>>,
}

impl Alerter {
    pub fn new(handle: AlertHandle, notary: Option<Arc<NotaryClient>>) -> Self {
        Alerter {
            handle: Arc::new(RwLock::new(handle)),
            notary: Arc::new(RwLock::new(notary)),
        }
    }

    pub fn replace(&self, handle: AlertHandle, notary: Option<Arc<NotaryClient>>) {
        *rib::write(&self.handle) = handle;
        *rib::write(&self.notary) = notary;
    }

    fn send(&self, alert: Alert) {
        if !rib::read(&self.handle).send(alert) {
            inc(&METRICS.alerts_rejected);
            error!("alert not accepted by the dispatcher (intake full or stopped)");
        }
    }

    pub fn session(&self, s: &SessionEvent) {
        log_session(s);
        self.send(session_alert(s));
    }

    /// Logs the finding and sends it, after an RPKI lookup when Notary is set.
    /// Must be called inside a Tokio runtime when Notary is configured.
    pub fn finding(&self, mut f: Finding) {
        let notary = rib::read(&self.notary).clone();
        match (notary, f.origin_asn) {
            (Some(n), Some(origin)) => {
                let this = self.clone();
                tokio::spawn(async move {
                    f.rpki = n.validity(f.prefix, origin).await;
                    log_finding(&f);
                    this.send(finding_alert(&f));
                });
            }
            _ => {
                log_finding(&f);
                self.send(finding_alert(&f));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::FindingKind;
    use crate::notary::RpkiState;
    use crate::sessions::{SessionId, SessionKind};

    fn finding(kind: FindingKind, severity: Severity, origin: u32) -> Finding {
        Finding {
            kind,
            severity,
            learning: false,
            resolved: false,
            watch: "198.51.100.0/24".parse().unwrap(),
            prefix: "198.51.100.0/24".parse().unwrap(),
            router: "192.0.2.254".parse().unwrap(),
            peer: "192.0.2.1".parse().unwrap(),
            peer_asn: 64501,
            loc_rib: false,
            origin_asn: Some(origin),
            upstream_asn: Some(64501),
            as_path: format!("64501 {origin}"),
            communities: vec!["64500:100".into()],
            large_communities: vec![],
            timestamp: 1_772_323_200,
            message: "test".into(),
            key: format!("AS{origin}"),
            rpki: None,
        }
    }

    fn field<'a>(a: &'a Alert, k: &str) -> Option<&'a str> {
        a.fields
            .iter()
            .find(|f| f.key == k)
            .map(|f| f.value.as_str())
    }

    #[test]
    fn finding_to_alert() {
        let mut f = finding(FindingKind::NewOrigin, Severity::Critical, 64510);
        f.rpki = Some(RpkiState {
            state: "invalid".into(),
            stale: false,
        });
        let a = finding_alert(&f);
        assert_eq!(a.id, "pathology:new_origin:198.51.100.0/24:AS64510");
        assert_eq!(a.tool, "pathology");
        assert_eq!(a.kind, "new_origin");
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.resource.as_deref(), Some("198.51.100.0/24"));
        assert_eq!(field(&a, "origin"), Some("AS64510"));
        assert_eq!(field(&a, "rpki"), Some("invalid"));
        assert_eq!(field(&a, "communities"), Some("64500:100"));
        assert_eq!(a.first_seen.to_rfc3339(), "2026-03-01T00:00:00+00:00");
        assert!(f.to_string().contains("[rpki invalid]"));
        // Different origins are different conditions.
        let b = finding_alert(&finding(FindingKind::NewOrigin, Severity::Critical, 64511));
        assert_ne!(a.id, b.id);
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["schema"], "llcforge.alert.v1");
    }

    #[test]
    fn session_to_alert() {
        let s = SessionEvent {
            kind: SessionKind::SessionDown,
            severity: Severity::Warning,
            session: SessionId {
                router: "192.0.2.254".parse().unwrap(),
                peer: Some("192.0.2.3".parse().unwrap()),
                loc_rib: false,
            },
            peer_asn: Some(64503),
            resolved: true,
            timestamp: 0,
            message: "up".into(),
        };
        let a = session_alert(&s);
        assert_eq!(a.id, "pathology:session_down:192.0.2.254:192.0.2.3");
        assert!(a.resolved);
        assert_eq!(a.resource.as_deref(), Some("192.0.2.3"));
    }

    #[tokio::test]
    async fn alerter_without_dispatcher_never_blocks() {
        let al = Alerter::new(AlertHandle::disabled(TOOL), None);
        al.finding(finding(FindingKind::NewUpstream, Severity::Warning, 64500));
        let n = NotaryClient::new(
            "http://127.0.0.1:9/",
            None,
            std::time::Duration::from_millis(100),
        )
        .unwrap();
        al.replace(AlertHandle::disabled(TOOL), Some(Arc::new(n)));
        al.finding(finding(FindingKind::NewOrigin, Severity::Critical, 64510));
    }
}
