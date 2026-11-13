//! Compares route events against the learned baseline and static expectations,
//! keeps the shared RIB and route history current, and tracks session health.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use ipnet::IpNet;
use serde::Serialize;
use tracing::{debug, info};

use crate::baseline::{community_keys, Baseline, PrefixBaseline};
use crate::bgp::{
    collapse_prepends, community_to_string, large_community_to_string, Attributes, Nlri,
};
use crate::bmp::{Message, FLAG_ADJ_RIB_OUT};
use crate::config::Watch;
use crate::leak::AsRelationships;
use crate::notary::RpkiState;
use crate::rib::{self, EventKind, History, Rib, RouteEvent, SharedHistory, SharedRib, Source};
use crate::sessions::{SessionEvent, SessionId, SessionTracker};

pub use llcforge_alert::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    NewOrigin,
    NewUpstream,
    PathChange,
    PrependChange,
    PathLengthChange,
    CommunityChange,
    MoreSpecific,
    Withdrawn,
    RouteLeak,
    UpstreamLost,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::NewOrigin => "new_origin",
            FindingKind::NewUpstream => "new_upstream",
            FindingKind::PathChange => "path_change",
            FindingKind::PrependChange => "prepend_change",
            FindingKind::PathLengthChange => "path_length_change",
            FindingKind::CommunityChange => "community_change",
            FindingKind::MoreSpecific => "more_specific",
            FindingKind::Withdrawn => "withdrawn",
            FindingKind::RouteLeak => "route_leak",
            FindingKind::UpstreamLost => "upstream_lost",
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    /// True when the severity was lowered because the baseline is still learning.
    pub learning: bool,
    /// The condition cleared (e.g. a lost upstream is back).
    #[serde(skip_serializing_if = "is_false")]
    pub resolved: bool,
    pub watch: IpNet,
    pub prefix: IpNet,
    pub router: IpAddr,
    pub peer: IpAddr,
    pub peer_asn: u32,
    /// The route came from the router's Loc-RIB (RFC 9069), not from a peer.
    #[serde(skip_serializing_if = "is_false")]
    pub loc_rib: bool,
    pub origin_asn: Option<u32>,
    pub upstream_asn: Option<u32>,
    pub as_path: String,
    pub communities: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub large_communities: Vec<String>,
    pub timestamp: u64,
    pub message: String,
    /// What distinguishes two findings of the same kind for one prefix
    /// (origin, upstream, path, ...); part of the alert id.
    #[serde(skip)]
    pub key: String,
    /// RPKI origin validation via Notary, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpki: Option<RpkiState>,
}

impl Finding {
    /// Stable alert id: the same condition always yields the same id.
    pub fn alert_id(&self) -> String {
        format!(
            "pathology:{}:{}:{}",
            self.kind.as_str(),
            self.prefix,
            self.key
        )
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = if self.resolved {
            "RESOLVED".to_string()
        } else {
            self.severity.as_str().to_uppercase()
        };
        let via = if self.loc_rib {
            format!("loc-rib of {}", self.router)
        } else {
            self.peer.to_string()
        };
        write!(
            f,
            "{} {:<8} {:<13} {} via {} (AS{}): {}",
            format_timestamp(self.timestamp),
            sev,
            self.kind.as_str(),
            self.prefix,
            via,
            self.peer_asn,
            self.message
        )?;
        if let Some(r) = &self.rpki {
            write!(
                f,
                " [rpki {}{}]",
                r.state,
                if r.stale { ", stale" } else { "" }
            )?;
        }
        if self.learning {
            f.write_str(" [baseline learning]")?;
        }
        Ok(())
    }
}

/// Formats Unix seconds as RFC 3339 UTC (`2026-03-16T09:00:00Z`).
pub fn format_timestamp(ts: u64) -> String {
    let days = i64::try_from(ts / 86_400).unwrap_or(0);
    let secs = ts % 86_400;
    // Civil-from-days (H. Hinnant), valid for the whole u64 range we care about.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn join_asns(a: &[u32]) -> String {
    a.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
}

/// Detection settings that can change on configuration reload.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    pub watches: Vec<Watch>,
    pub learning_window: u64,
    pub min_observations: u64,
    /// Baseline half-life in seconds (`None`: no decay).
    pub half_life: Option<u64>,
    /// Minimum AS path length difference to every known length that turns a
    /// path change into `path_length_change`.
    pub path_length_delta: u32,
    pub community_changes: bool,
    pub relationships: Option<Arc<AsRelationships>>,
    /// The monitoring network's ASN, appended as the receiver for leak checks.
    pub local_asn: Option<u32>,
    /// Record history for every prefix, not just watched ones.
    pub history_all: bool,
    pub flap_threshold: u32,
    pub flap_window: u64,
}

impl DetectorConfig {
    pub fn new(watches: Vec<Watch>, learning_window: u64, min_observations: u64) -> Self {
        DetectorConfig {
            watches,
            learning_window,
            min_observations,
            half_life: None,
            path_length_delta: 2,
            community_changes: true,
            relationships: None,
            local_asn: None,
            history_all: false,
            flap_threshold: 3,
            flap_window: 600,
        }
    }
}

#[derive(Clone, Copy)]
struct Ctx {
    src: Source,
    ts: u64,
}

pub struct Detector {
    cfg: DetectorConfig,
    baseline: Baseline,
    rib: SharedRib,
    history: SharedHistory,
    sessions: SessionTracker,
    /// Current first-hop upstreams per watched prefix.
    upstreams: HashMap<IpNet, BTreeSet<u32>>,
    /// Upstreams reported lost and not yet back, per watched prefix.
    lost: HashMap<IpNet, BTreeSet<u32>>,
}

type Found = (FindingKind, Severity, bool, String, String);

impl Detector {
    /// Detector with an in-memory RIB and history (replay, tests).
    pub fn new(
        watches: Vec<Watch>,
        baseline: Baseline,
        learning_window: u64,
        min_observations: u64,
    ) -> Self {
        Self::with(
            DetectorConfig::new(watches, learning_window, min_observations),
            baseline,
            Arc::new(RwLock::new(Rib::new(usize::MAX))),
            Arc::new(RwLock::new(History::memory(100_000, u64::MAX))),
        )
    }

    pub fn with(
        cfg: DetectorConfig,
        baseline: Baseline,
        rib: SharedRib,
        history: SharedHistory,
    ) -> Self {
        Detector {
            sessions: SessionTracker::new(cfg.flap_threshold, cfg.flap_window),
            cfg,
            baseline,
            rib,
            history,
            upstreams: HashMap::new(),
            lost: HashMap::new(),
        }
    }

    pub fn reconfigure(&mut self, cfg: DetectorConfig) {
        self.sessions
            .reconfigure(cfg.flap_threshold, cfg.flap_window);
        self.cfg = cfg;
    }

    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    pub fn rib(&self) -> SharedRib {
        self.rib.clone()
    }

    pub fn history(&self) -> SharedHistory {
        self.history.clone()
    }

    /// Applies baseline decay up to `now`.
    pub fn decay(&mut self, now: u64) {
        self.baseline.decay(now, self.cfg.half_life);
    }

    /// Session events (down, up, flap) produced since the last call.
    pub fn drain_sessions(&mut self) -> Vec<SessionEvent> {
        self.sessions.drain()
    }

    /// The BMP TCP session of `router` was established.
    pub fn router_up(&mut self, router: IpAddr, now: u64) {
        let id = SessionId {
            router,
            peer: None,
            loc_rib: false,
        };
        self.sessions.up(id, None, now);
    }

    /// The BMP TCP session of `router` ended: its routes are gone.
    pub fn router_down(&mut self, router: IpAddr, why: &str, now: u64) -> Vec<Finding> {
        let id = SessionId {
            router,
            peer: None,
            loc_rib: false,
        };
        self.sessions.down(id, None, None, now, why);
        let src = Source {
            router,
            peer: router,
            peer_asn: 0,
            loc_rib: false,
        };
        let affected = rib::write(&self.rib).drop_source(router, None);
        let mut out = Vec::new();
        self.check_upstreams(affected, Ctx { src, ts: now }, &mut out);
        out
    }

    /// Feeds one BMP message from `router`; `now` is Unix seconds.
    pub fn handle(&mut self, router: IpAddr, msg: &Message, now: u64) -> Vec<Finding> {
        let src = |p: &crate::bmp::PeerHeader| Source {
            router,
            peer: p.address,
            peer_asn: p.asn,
            loc_rib: p.is_loc_rib(),
        };
        match msg {
            Message::RouteMonitoring { peer, update } => {
                if peer.flags & FLAG_ADJ_RIB_OUT != 0 && !peer.is_loc_rib() {
                    // Routes the router sends, not routes it receives.
                    return Vec::new();
                }
                let ctx = Ctx {
                    src: src(peer),
                    ts: now,
                };
                let mut out = Vec::new();
                let mut touched = BTreeSet::new();
                for n in &update.withdrawn {
                    self.withdraw(ctx, n, &mut touched, &mut out);
                }
                for n in &update.announced {
                    self.announce(ctx, n, &update.attrs, &mut touched, &mut out);
                }
                self.check_upstreams(touched, ctx, &mut out);
                out
            }
            Message::PeerUp { peer, .. } => {
                info!(%router, peer = %peer.address, peer_asn = peer.asn, "BMP peer up");
                let s = src(peer);
                self.sessions.up(session_id(s), Some(peer.asn), now);
                Vec::new()
            }
            Message::PeerDown { peer, reason } => {
                info!(%router, peer = %peer.address, reason, "BMP peer down");
                let s = src(peer);
                self.sessions.down(
                    session_id(s),
                    Some(peer.asn),
                    Some(*reason),
                    now,
                    &format!("peer down (BMP reason {reason})"),
                );
                let affected = rib::write(&self.rib).drop_source(router, Some((s.peer, s.loc_rib)));
                let mut out = Vec::new();
                self.check_upstreams(affected, Ctx { src: s, ts: now }, &mut out);
                out
            }
            Message::Initiation { info } | Message::Termination { info } => {
                debug!(%router, ?info, "BMP session information");
                Vec::new()
            }
            Message::Statistics { .. } | Message::Other { .. } => Vec::new(),
        }
    }

    fn finding(
        &self,
        c: Ctx,
        kind: FindingKind,
        watch: IpNet,
        prefix: IpNet,
        attrs: Option<&Attributes>,
        message: String,
    ) -> Finding {
        let (origin_asn, upstream_asn, as_path, communities, large_communities) = match attrs {
            Some(a) => (
                a.as_path.origin(),
                a.as_path.first_hop(),
                a.as_path.to_string(),
                a.communities
                    .iter()
                    .map(|c| community_to_string(*c))
                    .collect(),
                a.large_communities
                    .iter()
                    .map(large_community_to_string)
                    .collect(),
            ),
            None => (None, None, String::new(), Vec::new(), Vec::new()),
        };
        Finding {
            kind,
            severity: Severity::Info,
            learning: false,
            resolved: false,
            watch,
            prefix,
            router: c.src.router,
            peer: c.src.peer,
            peer_asn: c.src.peer_asn,
            loc_rib: c.src.loc_rib,
            origin_asn,
            upstream_asn,
            as_path,
            communities,
            large_communities,
            timestamp: c.ts,
            message,
            key: String::new(),
            rpki: None,
        }
    }

    fn mature(&self, b: Option<&PrefixBaseline>, now: u64) -> bool {
        b.is_some_and(|b| b.is_mature(now, self.cfg.learning_window, self.cfg.min_observations))
    }

    fn related(&self, prefix: &IpNet) -> bool {
        self.cfg.watches.iter().any(|w| w.prefix.contains(prefix))
    }

    /// Classifies an unknown AS path for an exact watched prefix.
    fn classify_path(&self, known: Option<&PrefixBaseline>, path: &str, len: usize) -> Found {
        if let Some(k) = known {
            let collapsed = collapse_prepends(path);
            if let Some(old) = k.paths.keys().find(|p| collapse_prepends(p) == collapsed) {
                return (
                    FindingKind::PrependChange,
                    Severity::Warning,
                    true,
                    path.to_string(),
                    format!("AS path prepending changed: {path} (baseline {old})"),
                );
            }
            let delta = k
                .path_lengths
                .keys()
                .map(|l| (i64::from(*l) - len as i64).unsigned_abs())
                .min();
            if let Some(d) = delta.filter(|d| *d >= u64::from(self.cfg.path_length_delta.max(1))) {
                let known: Vec<String> = k.path_lengths.keys().map(u32::to_string).collect();
                return (
                    FindingKind::PathLengthChange,
                    Severity::Warning,
                    true,
                    path.to_string(),
                    format!(
                        "AS path length {len} differs by {d} from every baseline length [{}] (path {path})",
                        known.join(", ")
                    ),
                );
            }
        }
        (
            FindingKind::PathChange,
            Severity::Warning,
            true,
            path.to_string(),
            format!("AS path {path} never seen in baseline"),
        )
    }

    fn announce(
        &mut self,
        c: Ctx,
        n: &Nlri,
        attrs: &Attributes,
        touched: &mut BTreeSet<IpNet>,
        out: &mut Vec<Finding>,
    ) {
        let prefix = n.prefix;
        let related = self.related(&prefix);
        let stored = rib::write(&self.rib).announce(
            c.src,
            prefix,
            n.path_id.unwrap_or(0),
            attrs,
            c.ts,
            related,
        );
        if stored && (related || self.cfg.history_all) {
            rib::write(&self.history).record(RouteEvent::new(
                c.src,
                prefix,
                EventKind::Announce,
                Some(attrs),
                c.ts,
            ));
        }
        if !related {
            return;
        }
        let path = attrs.as_path.to_string();
        let origin = attrs.as_path.origin();
        let upstream = attrs.as_path.first_hop();
        let mut learned = false;

        for w in &self.cfg.watches {
            let known = self.baseline.prefixes.get(&w.prefix);
            let mature = self.mature(known, c.ts);
            let mut found: Vec<Found> = Vec::new();

            if w.prefix == prefix {
                let mut flagged = false;
                if let Some(o) = origin {
                    if !w.expected_origins.is_empty() {
                        if !w.expected_origins.contains(&o) {
                            found.push((
                                FindingKind::NewOrigin,
                                Severity::Critical,
                                false,
                                format!("AS{o}"),
                                format!(
                                    "origin AS{o} is not in expected_origins [{}] (path {path})",
                                    join_asns(&w.expected_origins)
                                ),
                            ));
                            flagged = true;
                        }
                    } else if !known.is_some_and(|b| b.origins.contains_key(&o)) {
                        found.push((
                            FindingKind::NewOrigin,
                            Severity::Critical,
                            true,
                            format!("AS{o}"),
                            format!("origin AS{o} never seen in baseline (path {path})"),
                        ));
                        flagged = true;
                    }
                }
                if let Some(u) = upstream {
                    if !known.is_some_and(|b| b.upstreams.contains_key(&u)) {
                        found.push((
                            FindingKind::NewUpstream,
                            Severity::Warning,
                            true,
                            format!("AS{u}"),
                            format!(
                                "first-hop upstream AS{u} never seen in baseline (path {path})"
                            ),
                        ));
                        flagged = true;
                    }
                }
                if !flagged && !known.is_some_and(|b| b.paths.contains_key(&path)) {
                    found.push(self.classify_path(known, &path, attrs.as_path.path_len()));
                }
                if self.cfg.community_changes {
                    if let Some(k) = known {
                        let new: Vec<String> = community_keys(attrs)
                            .into_iter()
                            .filter(|c| !k.communities.contains_key(c))
                            .collect();
                        if !new.is_empty() {
                            found.push((
                                FindingKind::CommunityChange,
                                Severity::Warning,
                                true,
                                new.join(","),
                                format!(
                                    "communities never seen in baseline: {} (path {path})",
                                    new.join(" ")
                                ),
                            ));
                        }
                    }
                }
                learned = true;
                touched.insert(prefix);
            } else if w.prefix.contains(&prefix) && prefix.prefix_len() > w.prefix.prefix_len() {
                let origin_txt = origin.map_or_else(|| "unknown".to_string(), |o| format!("AS{o}"));
                let message = format!(
                    "more-specific of watched {} announced, origin {origin_txt} (path {path})",
                    w.prefix
                );
                let (severity, baseline_based) = match origin {
                    Some(o) if w.expected_origins.contains(&o) => (Severity::Info, false),
                    _ if !w.expected_origins.is_empty() => (Severity::Critical, false),
                    Some(o) if known.is_some_and(|b| b.origins.contains_key(&o)) => {
                        (Severity::Info, true)
                    }
                    _ => (Severity::Critical, true),
                };
                found.push((
                    FindingKind::MoreSpecific,
                    severity,
                    baseline_based,
                    origin_txt,
                    message,
                ));
            }

            for (kind, severity, baseline_based, key, message) in found {
                let mut f = self.finding(c, kind, w.prefix, prefix, Some(attrs), message);
                f.severity = severity;
                f.key = key;
                if baseline_based && !mature && severity > Severity::Info {
                    f.severity = Severity::Info;
                    f.learning = true;
                }
                out.push(f);
            }
        }

        if let Some(f) = self.leak(c, prefix, attrs) {
            out.push(f);
        }
        if learned {
            self.baseline
                .prefixes
                .entry(prefix)
                .or_default()
                .record_route(attrs, c.ts, 1.0);
        }
    }

    fn leak(&self, c: Ctx, prefix: IpNet, attrs: &Attributes) -> Option<Finding> {
        let rels = self.cfg.relationships.as_ref()?;
        let mut hops = attrs.as_path.hops()?;
        if let Some(local) = self.cfg.local_asn {
            if hops.first() != Some(&local) {
                hops.insert(0, local);
            }
        }
        let leak = rels.valley_free_violation(&hops)?;
        let watch = self
            .cfg
            .watches
            .iter()
            .filter(|w| w.prefix.contains(&prefix))
            .max_by_key(|w| w.prefix.prefix_len())?
            .prefix;
        let mut f = self.finding(
            c,
            FindingKind::RouteLeak,
            watch,
            prefix,
            Some(attrs),
            format!(
                "valley-free violation: AS{} passed a route from AS{} on to AS{} (path {})",
                leak.leaker, leak.from, leak.to, attrs.as_path
            ),
        );
        f.severity = Severity::Warning;
        f.key = format!("AS{}", leak.leaker);
        Some(f)
    }

    fn withdraw(
        &mut self,
        c: Ctx,
        n: &Nlri,
        touched: &mut BTreeSet<IpNet>,
        out: &mut Vec<Finding>,
    ) {
        let prefix = n.prefix;
        if rib::write(&self.rib)
            .withdraw(c.src, prefix, n.path_id.unwrap_or(0))
            .is_none()
        {
            return;
        }
        let related = self.related(&prefix);
        if related || self.cfg.history_all {
            rib::write(&self.history).record(RouteEvent::new(
                c.src,
                prefix,
                EventKind::Withdraw,
                None,
                c.ts,
            ));
        }
        if !self.cfg.watches.iter().any(|w| w.prefix == prefix) {
            return;
        }
        touched.insert(prefix);
        let mature = self.mature(self.baseline.prefixes.get(&prefix), c.ts);
        let mut f = self.finding(
            c,
            FindingKind::Withdrawn,
            prefix,
            prefix,
            None,
            "watched prefix withdrawn by this peer".to_string(),
        );
        f.key = format!("{}{}", c.src.router, c.src.peer);
        f.severity = if mature {
            Severity::Warning
        } else {
            f.learning = true;
            Severity::Info
        };
        out.push(f);
    }

    /// Reports upstreams a watched prefix is no longer reachable through, and
    /// resolves them when they come back.
    fn check_upstreams(&mut self, prefixes: BTreeSet<IpNet>, c: Ctx, out: &mut Vec<Finding>) {
        for prefix in prefixes {
            if !self.cfg.watches.iter().any(|w| w.prefix == prefix) {
                continue;
            }
            let now_set = rib::read(&self.rib).upstreams(&prefix);
            let prev = self
                .upstreams
                .insert(prefix, now_set.clone())
                .unwrap_or_default();
            let mature = self.mature(self.baseline.prefixes.get(&prefix), c.ts);
            let lost = self.lost.entry(prefix).or_default();
            let mut found = Vec::new();
            for u in prev.difference(&now_set) {
                lost.insert(*u);
                found.push((*u, false));
            }
            for u in &now_set {
                if lost.remove(u) {
                    found.push((*u, true));
                }
            }
            for (u, resolved) in found {
                let msg = if resolved {
                    format!("reachable via upstream AS{u} again")
                } else {
                    format!("no longer reachable via upstream AS{u}")
                };
                let mut f = self.finding(c, FindingKind::UpstreamLost, prefix, prefix, None, msg);
                f.upstream_asn = Some(u);
                f.key = format!("AS{u}");
                f.resolved = resolved;
                if mature {
                    f.severity = Severity::Warning;
                } else {
                    f.learning = true;
                }
                out.push(f);
            }
        }
    }
}

fn session_id(s: Source) -> SessionId {
    SessionId {
        router: s.router,
        peer: Some(s.peer),
        loc_rib: s.loc_rib,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bmp::parse_message;
    use crate::sessions::SessionKind;
    use crate::testutil::*;

    const DAY: u64 = 86_400;

    fn watch(prefix: &str, expected: &[u32]) -> Watch {
        Watch {
            prefix: prefix.parse().unwrap(),
            expected_origins: expected.to_vec(),
        }
    }

    fn router() -> IpAddr {
        "192.0.2.254".parse().unwrap()
    }

    fn feed(d: &mut Detector, raw: &[u8], now: u64) -> Vec<Finding> {
        d.handle(router(), &parse_message(raw).unwrap(), now)
    }

    /// Detector whose baseline for 198.51.100.0/24 and 2001:db8:100::/48 is mature.
    fn trained() -> Detector {
        let mut d = Detector::new(
            vec![
                watch("198.51.100.0/24", &[64500]),
                watch("2001:db8:100::/48", &[]),
            ],
            Baseline::default(),
            14 * DAY,
            3,
        );
        for day in 0..4 {
            let ts = day * 5 * DAY;
            feed(
                &mut d,
                &announce("192.0.2.1", 64501, 0, "198.51.100.0/24", &[64501, 64500]),
                ts,
            );
            feed(
                &mut d,
                &announce("192.0.2.1", 64501, 0, "2001:db8:100::/48", &[64501, 64500]),
                ts,
            );
        }
        d
    }

    const NOW: u64 = 16 * DAY;

    #[test]
    fn known_route_is_quiet() {
        let mut d = trained();
        let f = feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "198.51.100.0/24", &[64501, 64500]),
            NOW,
        );
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn unexpected_origin_is_critical() {
        let mut d = trained();
        let f = feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "198.51.100.0/24", &[64501, 64510]),
            NOW,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::NewOrigin);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].origin_asn, Some(64510));
        assert!(f[0].message.contains("expected_origins [64500]"));
        assert_eq!(
            f[0].alert_id(),
            "pathology:new_origin:198.51.100.0/24:AS64510"
        );
    }

    #[test]
    fn baseline_origin_check_without_expected_origins() {
        let mut d = trained();
        let f = feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "2001:db8:100::/48", &[64501, 64509]),
            NOW,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].kind, f[0].severity),
            (FindingKind::NewOrigin, Severity::Critical)
        );
    }

    #[test]
    fn new_upstream_and_path_change() {
        let mut d = trained();
        let f = feed(
            &mut d,
            &announce("192.0.2.3", 64503, 0, "198.51.100.0/24", &[64503, 64500]),
            NOW,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].kind, f[0].severity),
            (FindingKind::NewUpstream, Severity::Warning)
        );

        let f = feed(
            &mut d,
            &announce(
                "192.0.2.1",
                64501,
                0,
                "198.51.100.0/24",
                &[64501, 64496, 64500],
            ),
            NOW,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].kind, f[0].severity),
            (FindingKind::PathChange, Severity::Warning)
        );
        assert_eq!(f[0].as_path, "64501 64496 64500");
    }

    #[test]
    fn prepend_and_length_changes() {
        let mut d = trained();
        let f = feed(
            &mut d,
            &announce(
                "192.0.2.1",
                64501,
                0,
                "198.51.100.0/24",
                &[64501, 64500, 64500, 64500],
            ),
            NOW,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::PrependChange);
        assert!(
            f[0].message.contains("baseline 64501 64500"),
            "{}",
            f[0].message
        );

        let f = feed(
            &mut d,
            &announce(
                "192.0.2.1",
                64501,
                0,
                "198.51.100.0/24",
                &[64501, 64496, 64497, 64498, 64499, 64502, 64500],
            ),
            NOW,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::PathLengthChange);
        assert!(f[0].message.contains("length 7"), "{}", f[0].message);
    }

    #[test]
    fn community_deviation() {
        let mut d = trained();
        let p: IpNet = "198.51.100.0/24".parse().unwrap();
        let mut attrs = vec![
            origin_attr(0),
            as_path_attr(&[(2, &[64501, 64500])]),
            next_hop_attr([192, 0, 2, 1]),
            communities_attr(&[(64500 << 16) | 666]),
            large_communities_attr(&[[64500, 1, 1]]),
        ];
        let raw = route_monitoring(
            "192.0.2.1".parse().unwrap(),
            64501,
            0,
            &update_v4(&[], &attrs, &[&p.to_string()]),
        );
        let f = feed(&mut d, &raw, NOW);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::CommunityChange);
        assert!(
            f[0].message.contains("64500:666 64500:1:1"),
            "{}",
            f[0].message
        );
        assert_eq!(f[0].large_communities, ["64500:1:1"]);
        // Learned now: the same communities are quiet next time.
        assert!(feed(&mut d, &raw, NOW).is_empty());
        attrs.pop();
        let raw = route_monitoring(
            "192.0.2.1".parse().unwrap(),
            64501,
            0,
            &update_v4(&[], &attrs, &[&p.to_string()]),
        );
        assert!(
            feed(&mut d, &raw, NOW).is_empty(),
            "a missing community is not a deviation"
        );
    }

    #[test]
    fn more_specific_severity_depends_on_origin() {
        let mut d = trained();
        let f = feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "198.51.100.128/25", &[64501, 64510]),
            NOW,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].kind, f[0].severity),
            (FindingKind::MoreSpecific, Severity::Critical)
        );
        assert_eq!(f[0].watch, "198.51.100.0/24".parse::<IpNet>().unwrap());

        let f = feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "198.51.100.0/25", &[64501, 64500]),
            NOW,
        );
        assert_eq!(f[0].severity, Severity::Info, "own deaggregation");

        // Less-specific and unrelated prefixes are ignored.
        assert!(feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "198.51.0.0/16", &[64501, 64510]),
            NOW
        )
        .is_empty());
        assert!(feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "203.0.113.0/24", &[64501, 64510]),
            NOW
        )
        .is_empty());
        // ...but they are in the RIB for the API.
        let rib = d.rib();
        assert_eq!(
            rib::read(&rib).originated_by(64510, 10).len(),
            3,
            "/25, /16 and unrelated /24"
        );
    }

    #[test]
    fn withdrawal_only_for_seen_routes() {
        let mut d = trained();
        let f = feed(
            &mut d,
            &withdraw("192.0.2.1", 64501, 0, "198.51.100.0/24"),
            NOW,
        );
        assert_eq!(
            (f[0].kind, f[0].severity),
            (FindingKind::Withdrawn, Severity::Warning)
        );
        assert_eq!(f[1].kind, FindingKind::UpstreamLost, "only upstream gone");
        assert!(feed(
            &mut d,
            &withdraw("192.0.2.1", 64501, 0, "198.51.100.0/24"),
            NOW
        )
        .is_empty());
        assert!(feed(
            &mut d,
            &withdraw("192.0.2.2", 64502, 0, "198.51.100.0/24"),
            NOW
        )
        .is_empty());
        // History holds the announcements and the withdrawal.
        let h = d.history();
        let ev = rib::read(&h).query(Some("198.51.100.0/24".parse().unwrap()), None, 100);
        assert_eq!(ev.len(), 5);
        assert_eq!(ev[4].kind, EventKind::Withdraw);
    }

    #[test]
    fn upstream_loss_and_recovery() {
        let mut d = trained();
        feed(
            &mut d,
            &announce("192.0.2.2", 64502, 0, "198.51.100.0/24", &[64502, 64500]),
            NOW,
        );
        let f = feed(
            &mut d,
            &withdraw("192.0.2.2", 64502, 0, "198.51.100.0/24"),
            NOW,
        );
        let lost: Vec<_> = f
            .iter()
            .filter(|f| f.kind == FindingKind::UpstreamLost)
            .collect();
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].upstream_asn, Some(64502));
        assert!(!lost[0].resolved);
        assert_eq!(
            lost[0].alert_id(),
            "pathology:upstream_lost:198.51.100.0/24:AS64502"
        );
        let f = feed(
            &mut d,
            &announce("192.0.2.2", 64502, 0, "198.51.100.0/24", &[64502, 64500]),
            NOW,
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].resolved && f[0].kind == FindingKind::UpstreamLost);
        assert!(f[0].to_string().contains("RESOLVED"));
    }

    #[test]
    fn route_leak_detection() {
        let mut d = trained();
        let mut cfg = d.cfg.clone();
        // 64501 is our provider; 64510 is 64501's provider; 64500 peers with 64510.
        cfg.relationships = Some(Arc::new(
            AsRelationships::parse(
                "64501|64496|-1\n64510|64501|-1\n64510|64500|0\n64511|64500|-1\n",
            )
            .unwrap(),
        ));
        cfg.local_asn = Some(64496);
        d.reconfigure(cfg);
        // Valid: 64500 -> peer 64510 -> customer 64501 -> customer 64496.
        let f = feed(
            &mut d,
            &announce(
                "192.0.2.1",
                64501,
                0,
                "198.51.100.0/24",
                &[64501, 64510, 64500],
            ),
            NOW,
        );
        assert!(f.iter().all(|f| f.kind != FindingKind::RouteLeak), "{f:?}");
        // Leak: 64500 -> provider 64511 ... -> 64510 via peer? 64511 is unknown to 64510,
        // so test the classic case: 64501 hands a provider route to its customer is fine,
        // but 64500 sends a provider-learned route to its peer 64510.
        let f = feed(
            &mut d,
            &announce(
                "192.0.2.1",
                64501,
                0,
                "198.51.100.0/24",
                &[64501, 64510, 64500, 64511],
            ),
            NOW,
        );
        let leak = f
            .iter()
            .find(|f| f.kind == FindingKind::RouteLeak)
            .expect("leak");
        assert!(
            leak.message
                .contains("AS64500 passed a route from AS64511 on to AS64510"),
            "{}",
            leak.message
        );
        assert_eq!(leak.severity, Severity::Warning);
    }

    #[test]
    fn immature_baseline_downgrades_to_info_but_not_expected_origins() {
        let mut d = Detector::new(
            vec![watch("198.51.100.0/24", &[64500])],
            Baseline::default(),
            14 * DAY,
            3,
        );
        let f = feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "198.51.100.0/24", &[64501, 64500]),
            0,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].kind, f[0].severity, f[0].learning),
            (FindingKind::NewUpstream, Severity::Info, true)
        );

        let f = feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "198.51.100.0/24", &[64501, 64510]),
            DAY,
        );
        assert_eq!(
            (f[0].kind, f[0].severity),
            (FindingKind::NewOrigin, Severity::Critical)
        );
    }

    #[test]
    fn peer_down_raises_session_alarm_and_upstream_loss() {
        let mut d = trained();
        let raw = peer_down("192.0.2.1".parse().unwrap(), 64501, 0, 4);
        let f = feed(&mut d, &raw, NOW);
        assert_eq!(f.len(), 2, "both watched prefixes lost AS64501");
        assert!(f.iter().all(|f| f.kind == FindingKind::UpstreamLost));
        let s = d.drain_sessions();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].kind, SessionKind::SessionDown);
        // No withdrawal alerts for stale routes.
        assert!(f.iter().all(|f| f.kind != FindingKind::Withdrawn));
        feed(
            &mut d,
            &peer_up("192.0.2.1".parse().unwrap(), 64501, 0),
            NOW,
        );
        assert!(d.drain_sessions()[0].resolved);
        // A router BMP session drop empties its RIB.
        feed(
            &mut d,
            &announce("192.0.2.1", 64501, 0, "198.51.100.0/24", &[64501, 64500]),
            NOW,
        );
        let f = d.router_down(router(), "closed", NOW);
        assert_eq!(f.len(), 1);
        assert!(rib::read(&d.rib()).is_empty());
    }

    #[test]
    fn adj_rib_out_is_ignored() {
        let mut d = trained();
        let upd = update_v4(
            &[],
            &[origin_attr(0), as_path_attr(&[(2, &[64496, 64510])])],
            &["198.51.100.0/24"],
        );
        let mut body = per_peer("192.0.2.1".parse().unwrap(), 64501, 0);
        body[1] |= FLAG_ADJ_RIB_OUT;
        body.extend(upd);
        assert!(feed(&mut d, &bmp(0, &body), NOW).is_empty());
    }

    #[test]
    fn timestamp_formatting() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_timestamp(u64::from(DEMO_BASE)),
            "2026-03-01T00:00:00Z"
        );
        assert_eq!(format_timestamp(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_timestamp(1_767_225_599), "2025-12-31T23:59:59Z");
    }
}
