//! Current routes as seen by every router/peer ([`Rib`]) and the persisted
//! announce/withdraw history ([`History`]) behind the read-only API.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs;
use std::io::{BufRead, BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::bgp::{community_to_string, large_community_to_string, Attributes};
use crate::metrics::{inc, METRICS};

/// One route held by one router from one peer (or the router's Loc-RIB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RibRoute {
    pub router: IpAddr,
    pub peer: IpAddr,
    pub peer_asn: u32,
    pub loc_rib: bool,
    pub path_id: u32,
    pub as_path: Box<[u32]>,
    pub path_len: u32,
    pub origin: Option<u32>,
    pub upstream: Option<u32>,
    pub communities: Box<[u32]>,
    pub large_communities: Box<[[u32; 3]]>,
    pub since: u64,
}

impl RibRoute {
    fn same_slot(&self, router: IpAddr, peer: IpAddr, loc_rib: bool, path_id: u32) -> bool {
        self.router == router
            && self.peer == peer
            && self.loc_rib == loc_rib
            && self.path_id == path_id
    }
}

/// Identifies the session a route belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    pub router: IpAddr,
    pub peer: IpAddr,
    pub peer_asn: u32,
    pub loc_rib: bool,
}

#[derive(Debug, Default)]
pub struct Rib {
    routes: HashMap<IpNet, Vec<RibRoute>>,
    count: usize,
    max_routes: usize,
}

pub type SharedRib = Arc<RwLock<Rib>>;

/// Poison-tolerant lock helpers: a panicked writer must not take the API down.
pub fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|p| p.into_inner())
}

pub fn write<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|p| p.into_inner())
}

impl Rib {
    pub fn new(max_routes: usize) -> Self {
        Rib {
            max_routes,
            ..Self::default()
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn publish(&self) {
        METRICS
            .rib_routes
            .store(self.count as u64, Ordering::Relaxed);
    }

    /// Inserts or replaces a route. `force` bypasses the size cap (watched
    /// prefixes are always kept). Returns false when the cap rejected it.
    pub fn announce(
        &mut self,
        src: Source,
        prefix: IpNet,
        path_id: u32,
        attrs: &Attributes,
        ts: u64,
        force: bool,
    ) -> bool {
        let slot = self.routes.entry(prefix).or_default();
        let existing = slot
            .iter()
            .position(|r| r.same_slot(src.router, src.peer, src.loc_rib, path_id));
        let since = match existing {
            Some(i) => {
                let old = &slot[i];
                // `since` tracks when this path (not the slot) appeared.
                if old.as_path.as_ref() == attrs.as_path.flatten().as_slice() {
                    old.since
                } else {
                    ts
                }
            }
            None => {
                if !force && self.count >= self.max_routes {
                    if slot.is_empty() {
                        self.routes.remove(&prefix);
                    }
                    inc(&METRICS.rib_routes_rejected);
                    return false;
                }
                ts
            }
        };
        let route = RibRoute {
            router: src.router,
            peer: src.peer,
            peer_asn: src.peer_asn,
            loc_rib: src.loc_rib,
            path_id,
            as_path: attrs.as_path.flatten().into(),
            path_len: u32::try_from(attrs.as_path.path_len()).unwrap_or(u32::MAX),
            origin: attrs.as_path.origin(),
            upstream: attrs.as_path.first_hop(),
            communities: attrs.communities.clone().into(),
            large_communities: attrs.large_communities.clone().into(),
            since,
        };
        match existing {
            Some(i) => slot[i] = route,
            None => {
                slot.push(route);
                self.count += 1;
            }
        }
        self.publish();
        true
    }

    pub fn withdraw(&mut self, src: Source, prefix: IpNet, path_id: u32) -> Option<RibRoute> {
        let slot = self.routes.get_mut(&prefix)?;
        let i = slot
            .iter()
            .position(|r| r.same_slot(src.router, src.peer, src.loc_rib, path_id))?;
        let r = slot.swap_remove(i);
        if slot.is_empty() {
            self.routes.remove(&prefix);
        }
        self.count -= 1;
        self.publish();
        Some(r)
    }

    /// Drops every route of a peer (or, with `peer = None`, of a router).
    /// Returns the affected prefixes.
    pub fn drop_source(&mut self, router: IpAddr, peer: Option<(IpAddr, bool)>) -> BTreeSet<IpNet> {
        let mut affected = BTreeSet::new();
        let mut removed = 0;
        self.routes.retain(|prefix, slot| {
            let before = slot.len();
            slot.retain(|r| {
                !(r.router == router && peer.is_none_or(|(p, l)| r.peer == p && r.loc_rib == l))
            });
            if slot.len() != before {
                removed += before - slot.len();
                affected.insert(*prefix);
            }
            !slot.is_empty()
        });
        self.count -= removed;
        self.publish();
        affected
    }

    pub fn routes(&self, prefix: &IpNet) -> &[RibRoute] {
        self.routes.get(prefix).map_or(&[], Vec::as_slice)
    }

    /// One route per (router, peer): the shortest AS path, then the lowest
    /// path id (ADD-PATH peers send several).
    pub fn best_per_peer(&self, prefix: &IpNet) -> Vec<&RibRoute> {
        let mut best: HashMap<(IpAddr, IpAddr, bool), &RibRoute> = HashMap::new();
        for r in self.routes(prefix) {
            let e = best.entry((r.router, r.peer, r.loc_rib)).or_insert(r);
            if (r.path_len, r.path_id) < (e.path_len, e.path_id) {
                *e = r;
            }
        }
        let mut out: Vec<&RibRoute> = best.into_values().collect();
        out.sort_by_key(|r| (r.router, r.loc_rib, r.peer));
        out
    }

    /// First-hop upstream ASNs currently used for `prefix`.
    pub fn upstreams(&self, prefix: &IpNet) -> BTreeSet<u32> {
        self.routes(prefix)
            .iter()
            .filter_map(|r| r.upstream)
            .collect()
    }

    /// Prefixes currently originated by `asn`, at most `limit`.
    pub fn originated_by(&self, asn: u32, limit: usize) -> BTreeSet<IpNet> {
        let mut out = BTreeSet::new();
        for (p, slot) in &self.routes {
            if slot.iter().any(|r| r.origin == Some(asn)) {
                out.insert(*p);
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Announce,
    Withdraw,
}

/// One history entry, serialised exactly as `/v1/routes` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEvent {
    pub time: DateTime<Utc>,
    pub router: IpAddr,
    pub peer: IpAddr,
    pub peer_asn: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub loc_rib: bool,
    pub prefix: IpNet,
    pub kind: EventKind,
    pub as_path: Vec<u32>,
    pub origin: Option<u32>,
    pub communities: Vec<String>,
    pub large_communities: Vec<String>,
}

pub fn unix_to_utc(ts: u64) -> DateTime<Utc> {
    DateTime::from_timestamp(i64::try_from(ts).unwrap_or(i64::MAX), 0).unwrap_or_default()
}

impl RouteEvent {
    pub fn new(
        src: Source,
        prefix: IpNet,
        kind: EventKind,
        attrs: Option<&Attributes>,
        ts: u64,
    ) -> Self {
        let empty = Attributes::default();
        let a = attrs.unwrap_or(&empty);
        RouteEvent {
            time: unix_to_utc(ts),
            router: src.router,
            peer: src.peer,
            peer_asn: src.peer_asn,
            loc_rib: src.loc_rib,
            prefix,
            kind,
            as_path: a.as_path.flatten(),
            origin: a.as_path.origin(),
            communities: a
                .communities
                .iter()
                .map(|c| community_to_string(*c))
                .collect(),
            large_communities: a
                .large_communities
                .iter()
                .map(large_community_to_string)
                .collect(),
        }
    }
}

/// Per-day file size cap; events beyond it stay in memory only.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Longest accepted line when loading history files.
const MAX_LINE: usize = 64 * 1024;
const FILE_PREFIX: &str = "routes-";
const FILE_SUFFIX: &str = ".jsonl";

struct DayFile {
    day: NaiveDate,
    out: BufWriter<fs::File>,
    bytes: u64,
}

/// Bounded in-memory event log, appended to one JSON-lines file per UTC day.
pub struct History {
    events: VecDeque<RouteEvent>,
    max_events: usize,
    retention_secs: u64,
    dir: Option<PathBuf>,
    file: Option<DayFile>,
}

pub type SharedHistory = Arc<RwLock<History>>;

fn day_of(path: &Path) -> Option<NaiveDate> {
    let name = path.file_name()?.to_str()?;
    let d = name.strip_prefix(FILE_PREFIX)?.strip_suffix(FILE_SUFFIX)?;
    NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()
}

impl History {
    /// In-memory only (replay, tests).
    pub fn memory(max_events: usize, retention_secs: u64) -> Self {
        History {
            events: VecDeque::new(),
            max_events,
            retention_secs,
            dir: None,
            file: None,
        }
    }

    /// Opens `dir`, loading events younger than the retention window.
    pub fn open(dir: PathBuf, max_events: usize, retention_secs: u64, now: u64) -> Result<Self> {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut h = Self::memory(max_events, retention_secs);
        let cutoff = unix_to_utc(now.saturating_sub(retention_secs));
        let mut files: Vec<(NaiveDate, PathBuf)> = fs::read_dir(&dir)
            .with_context(|| format!("listing {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter_map(|p| day_of(&p).map(|d| (d, p)))
            .collect();
        files.sort();
        for (day, path) in files {
            if day < cutoff.date_naive() {
                continue;
            }
            let f = fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
            let mut skipped = 0usize;
            for line in std::io::BufReader::new(f).split(b'\n') {
                let line = line.with_context(|| format!("reading {}", path.display()))?;
                if line.len() > MAX_LINE {
                    skipped += 1;
                    continue;
                }
                match serde_json::from_slice::<RouteEvent>(&line) {
                    Ok(ev) if ev.time >= cutoff => h.push(ev),
                    Ok(_) => {}
                    Err(_) if line.iter().all(u8::is_ascii_whitespace) => {}
                    // A torn last line after a crash is expected; skip it.
                    Err(_) => skipped += 1,
                }
            }
            if skipped > 0 {
                warn!(file = %path.display(), skipped, "skipped unreadable history lines");
            }
        }
        h.dir = Some(dir);
        Ok(h)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn push(&mut self, ev: RouteEvent) {
        if self.max_events == 0 {
            return;
        }
        while self.events.len() >= self.max_events {
            self.events.pop_front();
        }
        self.events.push_back(ev);
        METRICS
            .history_events
            .store(self.events.len() as u64, Ordering::Relaxed);
    }

    /// Records an event in memory and appends it to the day file.
    pub fn record(&mut self, ev: RouteEvent) {
        if let Err(e) = self.append(&ev) {
            inc(&METRICS.history_write_errors);
            warn!(error = %format!("{e:#}"), "writing route history failed");
            self.file = None;
        }
        self.push(ev);
    }

    fn append(&mut self, ev: &RouteEvent) -> Result<()> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        let day = ev.time.date_naive();
        if self.file.as_ref().is_none_or(|f| f.day != day) {
            if let Some(mut f) = self.file.take() {
                f.out.flush()?;
            }
            let path = dir.join(format!(
                "{FILE_PREFIX}{}{FILE_SUFFIX}",
                day.format("%Y-%m-%d")
            ));
            let file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .with_context(|| format!("opening {}", path.display()))?;
            let bytes = file.metadata().map_or(0, |m| m.len());
            self.file = Some(DayFile {
                day,
                out: BufWriter::new(file),
                bytes,
            });
        }
        let Some(f) = self.file.as_mut() else {
            return Ok(());
        };
        let mut line = serde_json::to_vec(ev)?;
        line.push(b'\n');
        if f.bytes + line.len() as u64 > MAX_FILE_BYTES {
            return Ok(());
        }
        f.out.write_all(&line)?;
        f.bytes += line.len() as u64;
        Ok(())
    }

    pub fn flush(&mut self) {
        if let Some(f) = self.file.as_mut() {
            if let Err(e) = f.out.flush() {
                inc(&METRICS.history_write_errors);
                warn!(error = %e, "flushing route history failed");
            }
        }
    }

    /// Forgets events and deletes day files older than the retention window.
    pub fn prune(&mut self, now: u64) {
        let cutoff = unix_to_utc(now.saturating_sub(self.retention_secs));
        while self.events.front().is_some_and(|e| e.time < cutoff) {
            self.events.pop_front();
        }
        METRICS
            .history_events
            .store(self.events.len() as u64, Ordering::Relaxed);
        let Some(dir) = &self.dir else {
            return;
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for p in entries.filter_map(|e| e.ok().map(|e| e.path())) {
            if day_of(&p).is_some_and(|d| d < cutoff.date_naive()) {
                if let Err(e) = fs::remove_file(&p) {
                    warn!(file = %p.display(), error = %e, "removing old history file failed");
                }
            }
        }
    }

    /// Events for `prefix` (and its more-specifics) at or after `since`,
    /// oldest first. Without `since` the most recent `limit` events.
    pub fn query(
        &self,
        prefix: Option<IpNet>,
        since: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Vec<RouteEvent> {
        let matches = |e: &&RouteEvent| {
            prefix.is_none_or(|p| p.contains(&e.prefix)) && since.is_none_or(|s| e.time >= s)
        };
        if since.is_some() {
            self.events
                .iter()
                .filter(matches)
                .take(limit)
                .cloned()
                .collect()
        } else {
            let mut v: Vec<RouteEvent> = self
                .events
                .iter()
                .rev()
                .filter(matches)
                .take(limit)
                .cloned()
                .collect();
            v.reverse();
            v
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::{AsPath, Segment};

    fn src(peer: &str) -> Source {
        Source {
            router: "192.0.2.254".parse().unwrap(),
            peer: peer.parse().unwrap(),
            peer_asn: 64501,
            loc_rib: false,
        }
    }

    fn attrs(path: &[u32]) -> Attributes {
        Attributes {
            as_path: AsPath(vec![Segment::Sequence(path.to_vec())]),
            communities: vec![(64500 << 16) | 1],
            ..Attributes::default()
        }
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn rib_lifecycle() {
        let mut rib = Rib::new(3);
        let p = net("198.51.100.0/24");
        assert!(rib.announce(src("192.0.2.1"), p, 0, &attrs(&[64501, 64500]), 10, false));
        // Same path again keeps `since`.
        assert!(rib.announce(src("192.0.2.1"), p, 0, &attrs(&[64501, 64500]), 20, false));
        assert_eq!(rib.routes(&p)[0].since, 10);
        // ADD-PATH: a second path from the same peer.
        assert!(rib.announce(
            src("192.0.2.1"),
            p,
            7,
            &attrs(&[64501, 64499, 64500]),
            30,
            false
        ));
        assert!(rib.announce(src("192.0.2.2"), p, 0, &attrs(&[64502, 64500]), 30, false));
        assert_eq!(rib.len(), 3);
        // Cap reached: new routes are refused unless forced.
        assert!(!rib.announce(
            src("192.0.2.3"),
            net("203.0.113.0/24"),
            0,
            &attrs(&[64503]),
            1,
            false
        ));
        assert!(rib.announce(
            src("192.0.2.3"),
            net("203.0.113.0/24"),
            0,
            &attrs(&[64503]),
            1,
            true
        ));
        let best = rib.best_per_peer(&p);
        assert_eq!(best.len(), 2);
        assert_eq!(best[0].as_path.as_ref(), &[64501, 64500]);
        assert_eq!(rib.upstreams(&p), BTreeSet::from([64501, 64502]));
        assert_eq!(rib.originated_by(64500, 10), BTreeSet::from([p]));
        assert!(rib.withdraw(src("192.0.2.1"), p, 7).is_some());
        assert!(rib.withdraw(src("192.0.2.1"), p, 7).is_none());
        let affected = rib.drop_source(
            "192.0.2.254".parse().unwrap(),
            Some(("192.0.2.2".parse().unwrap(), false)),
        );
        assert_eq!(affected, BTreeSet::from([p]));
        assert_eq!(rib.len(), 2);
        rib.drop_source("192.0.2.254".parse().unwrap(), None);
        assert!(rib.is_empty());
    }

    #[test]
    fn history_persists_queries_and_prunes() {
        let dir = std::env::temp_dir().join(format!("pathology-history-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let day = 86_400;
        let t0 = 1_772_323_200; // 2026-03-01
        let p = net("198.51.100.0/24");
        {
            let mut h = History::open(dir.clone(), 100, 7 * day, t0).unwrap();
            h.record(RouteEvent::new(
                src("192.0.2.1"),
                p,
                EventKind::Announce,
                Some(&attrs(&[64501, 64500])),
                t0,
            ));
            h.record(RouteEvent::new(
                src("192.0.2.1"),
                net("198.51.100.128/25"),
                EventKind::Announce,
                Some(&attrs(&[64501, 64510])),
                t0 + 60,
            ));
            h.record(RouteEvent::new(
                src("192.0.2.1"),
                p,
                EventKind::Withdraw,
                None,
                t0 + day,
            ));
            h.record(RouteEvent::new(
                src("192.0.2.1"),
                net("203.0.113.0/24"),
                EventKind::Withdraw,
                None,
                t0 + day,
            ));
            h.flush();
        }
        let mut h = History::open(dir.clone(), 100, 7 * day, t0 + day).unwrap();
        assert_eq!(h.len(), 4);
        let q = h.query(Some(p), None, 10);
        assert_eq!(q.len(), 3, "prefix plus more-specifics");
        assert_eq!(q[2].kind, EventKind::Withdraw);
        assert_eq!(
            h.query(Some(p), None, 1)[0].kind,
            EventKind::Withdraw,
            "latest"
        );
        let since = unix_to_utc(t0 + 30);
        assert_eq!(
            h.query(Some(p), Some(since), 1)[0].prefix,
            net("198.51.100.128/25")
        );
        let json = serde_json::to_value(&q[0]).unwrap();
        assert_eq!(json["kind"], "announce");
        assert_eq!(json["as_path"], serde_json::json!([64501, 64500]));
        assert_eq!(json["communities"], serde_json::json!(["64500:1"]));
        assert_eq!(json["time"], "2026-03-01T00:00:00Z");
        // A torn line is skipped on load.
        let f = dir.join("routes-2026-03-02.jsonl");
        fs::OpenOptions::new()
            .append(true)
            .open(&f)
            .unwrap()
            .write_all(b"{\"time\":")
            .unwrap();
        assert_eq!(
            History::open(dir.clone(), 100, 7 * day, t0 + day)
                .unwrap()
                .len(),
            4
        );
        // Retention: everything from day 0 goes, the files too.
        h.prune(t0 + 8 * day);
        assert_eq!(h.len(), 2);
        assert!(!dir.join("routes-2026-03-01.jsonl").exists());
        // The in-memory cap holds.
        let mut small = History::memory(2, day);
        for i in 0..5 {
            small.record(RouteEvent::new(
                src("192.0.2.1"),
                p,
                EventKind::Withdraw,
                None,
                i,
            ));
        }
        assert_eq!(small.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }
}
