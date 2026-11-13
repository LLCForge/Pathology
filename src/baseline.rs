//! Per-prefix baseline histograms, persisted as JSON with an atomic temp-file + rename.
//!
//! Every histogram value is a weight. Each observation adds 1.0; with a
//! configured half-life the weights decay exponentially and keys whose weight
//! falls below [`FORGET_BELOW`] are forgotten, so paths that have not been
//! seen for a long time stop counting as "known".

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::bgp::{community_to_string, large_community_to_string, Attributes};

/// Version 1 stored integer counts; version 2 stores weights and adds
/// communities and path lengths. Version 1 files load unchanged.
const FORMAT_VERSION: u32 = 2;
/// Cap on distinct keys per histogram so a flapping or hostile feed cannot grow
/// the store without bound. Keys beyond the cap are counted as observations
/// but never become "known", so they keep raising (deduplicated) findings.
const MAX_KEYS: usize = 4096;
/// Weight under which a decayed key is forgotten (three half-lives after a
/// single observation).
pub const FORGET_BELOW: f64 = 0.125;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PrefixBaseline {
    pub first_seen: u64,
    pub last_seen: u64,
    pub observations: u64,
    pub origins: BTreeMap<u32, f64>,
    pub upstreams: BTreeMap<u32, f64>,
    pub paths: BTreeMap<String, f64>,
    /// Standard (`a:b`) and large (`a:b:c`) communities.
    #[serde(default)]
    pub communities: BTreeMap<String, f64>,
    /// AS path lengths (RFC 4271 counting).
    #[serde(default)]
    pub path_lengths: BTreeMap<u32, f64>,
}

fn bump<K: Ord>(map: &mut BTreeMap<K, f64>, key: K, w: f64) {
    if let Some(c) = map.get_mut(&key) {
        *c += w;
    } else if map.len() < MAX_KEYS {
        map.insert(key, w);
    }
}

fn decay_map<K: Ord>(map: &mut BTreeMap<K, f64>, factor: f64) {
    map.retain(|_, w| {
        *w *= factor;
        *w >= FORGET_BELOW
    });
}

/// All communities of a route rendered as baseline keys.
pub fn community_keys(attrs: &Attributes) -> Vec<String> {
    attrs
        .communities
        .iter()
        .map(|c| community_to_string(*c))
        .chain(
            attrs
                .large_communities
                .iter()
                .map(large_community_to_string),
        )
        .collect()
}

impl PrefixBaseline {
    pub fn record(&mut self, origin: Option<u32>, upstream: Option<u32>, path: &str, ts: u64) {
        self.record_weighted(origin, upstream, path, &[], None, ts, 1.0);
    }

    /// Records one announcement with all its attributes.
    pub fn record_route(&mut self, attrs: &Attributes, ts: u64, weight: f64) {
        let len = u32::try_from(attrs.as_path.path_len()).ok();
        self.record_weighted(
            attrs.as_path.origin(),
            attrs.as_path.first_hop(),
            &attrs.as_path.to_string(),
            &community_keys(attrs),
            len,
            ts,
            weight,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_weighted(
        &mut self,
        origin: Option<u32>,
        upstream: Option<u32>,
        path: &str,
        communities: &[String],
        path_len: Option<u32>,
        ts: u64,
        w: f64,
    ) {
        if self.observations == 0 {
            self.first_seen = ts;
        }
        self.first_seen = self.first_seen.min(ts);
        self.last_seen = self.last_seen.max(ts);
        self.observations = self.observations.saturating_add(1);
        if let Some(o) = origin {
            bump(&mut self.origins, o, w);
        }
        if let Some(u) = upstream {
            bump(&mut self.upstreams, u, w);
        }
        bump(&mut self.paths, path.to_string(), w);
        for c in communities {
            bump(&mut self.communities, c.clone(), w);
        }
        if let Some(l) = path_len {
            bump(&mut self.path_lengths, l, w);
        }
    }

    /// Mature once the learning window has elapsed and enough observations exist.
    pub fn is_mature(&self, now: u64, learning_window: u64, min_observations: u64) -> bool {
        self.observations >= min_observations
            && now.saturating_sub(self.first_seen) >= learning_window
    }

    fn decay(&mut self, factor: f64) {
        decay_map(&mut self.origins, factor);
        decay_map(&mut self.upstreams, factor);
        decay_map(&mut self.paths, factor);
        decay_map(&mut self.communities, factor);
        decay_map(&mut self.path_lengths, factor);
    }
}

/// `0.5^(age / half_life)`; 1.0 when no half-life is configured.
pub fn decay_factor(age: u64, half_life: Option<u64>) -> f64 {
    match half_life {
        Some(h) if h > 0 => 0.5f64.powf(age as f64 / h as f64),
        _ => 1.0,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    /// Unix seconds of the last decay pass (0: never decayed).
    #[serde(default)]
    pub decayed_at: u64,
    pub prefixes: BTreeMap<IpNet, PrefixBaseline>,
}

impl Default for Baseline {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            decayed_at: 0,
            prefixes: BTreeMap::new(),
        }
    }
}

impl Baseline {
    /// Applies exponential decay up to `now` (no-op without a half-life).
    pub fn decay(&mut self, now: u64, half_life: Option<u64>) {
        if half_life.is_none() || self.decayed_at == 0 || now <= self.decayed_at {
            self.decayed_at = self.decayed_at.max(now);
            return;
        }
        let factor = decay_factor(now - self.decayed_at, half_life);
        for p in self.prefixes.values_mut() {
            p.decay(factor);
        }
        self.decayed_at = now;
    }

    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join("baseline.json")
    }

    /// Loads the baseline, or returns an empty one if the file does not exist.
    /// A corrupt file is an error: silently starting over would hide anomalies.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let mut b: Baseline = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "parsing baseline {} (move it aside to start learning from scratch)",
                path.display()
            )
        })?;
        anyhow::ensure!(
            b.version == 1 || b.version == FORMAT_VERSION,
            "baseline {} has unsupported format version {}",
            path.display(),
            b.version
        );
        b.version = FORMAT_VERSION;
        Ok(b)
    }

    /// Writes to `<path>.tmp`, fsyncs, then renames over `path`, so a crash
    /// never leaves a half-written baseline behind.
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec_pretty(self).context("serialising baseline")?;
        {
            let mut f =
                fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(&data)
                .and_then(|()| f.sync_all())
                .with_context(|| format!("writing {}", tmp.display()))?;
        }
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pathology-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn maturity_needs_window_and_observations() {
        let mut p = PrefixBaseline::default();
        p.record(Some(64500), Some(64501), "64501 64500", 100);
        assert_eq!(p.first_seen, 100);
        assert!(!p.is_mature(100 + 50, 10, 2), "too few observations");
        p.record(Some(64500), Some(64501), "64501 64500", 105);
        assert!(!p.is_mature(105, 10, 2), "window not elapsed");
        assert!(p.is_mature(110, 10, 2));
        assert_eq!(p.origins[&64500], 2.0);
        assert_eq!(p.paths["64501 64500"], 2.0);
    }

    #[test]
    fn histogram_is_bounded() {
        let mut p = PrefixBaseline::default();
        for i in 0..(MAX_KEYS as u64 + 10) {
            p.record(None, None, &i.to_string(), 1);
        }
        assert_eq!(p.paths.len(), MAX_KEYS);
        assert_eq!(p.observations, MAX_KEYS as u64 + 10);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = temp_dir("roundtrip");
        let path = Baseline::path_in(&dir);
        assert_eq!(Baseline::load(&path).unwrap(), Baseline::default());

        let mut b = Baseline::default();
        b.prefixes
            .entry("198.51.100.0/24".parse().unwrap())
            .or_default()
            .record(Some(64500), Some(64501), "64501 64500", 42);
        b.save(&path).unwrap();
        b.save(&path).unwrap(); // overwriting an existing file must work on every OS
        assert_eq!(Baseline::load(&path).unwrap(), b);
        assert!(!path.with_extension("json.tmp").exists());

        // Version 1 files (integer counts) still load.
        fs::write(
            &path,
            br#"{"version":1,"prefixes":{"198.51.100.0/24":{"first_seen":1,"last_seen":2,"observations":3,"origins":{"64500":3},"upstreams":{},"paths":{"64501 64500":3}}}}"#,
        )
        .unwrap();
        let v1 = Baseline::load(&path).unwrap();
        assert_eq!(v1.version, FORMAT_VERSION);
        assert_eq!(v1.prefixes.values().next().unwrap().origins[&64500], 3.0);

        fs::write(&path, b"{not json").unwrap();
        assert!(Baseline::load(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decay_forgets_old_keys() {
        let mut b = Baseline::default();
        let p: IpNet = "198.51.100.0/24".parse().unwrap();
        let e = b.prefixes.entry(p).or_default();
        e.record(Some(64500), Some(64501), "64501 64500", 0);
        for _ in 0..7 {
            e.record(Some(64500), Some(64502), "64502 64500", 0);
        }
        let day = 86_400;
        // Without a half-life nothing changes.
        b.decay(day, None);
        b.decay(10 * day, None);
        assert_eq!(b.prefixes[&p].paths.len(), 2);
        b.decay(14 * day, Some(day));
        let e = &b.prefixes[&p];
        // 1 * 0.5^4 < 0.125 is forgotten; 7 * 0.5^4 stays.
        assert!(!e.paths.contains_key("64501 64500"));
        assert!((e.paths["64502 64500"] - 7.0 / 16.0).abs() < 1e-9);
        assert!(e.upstreams.contains_key(&64502) && !e.upstreams.contains_key(&64501));
        assert_eq!(e.observations, 8, "maturity counters do not decay");
        assert!((decay_factor(day, Some(day)) - 0.5).abs() < 1e-12);
    }
}
