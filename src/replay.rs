//! Offline replay of a raw BMP byte stream (concatenated BMP messages, as
//! written by e.g. `nc -l 11019 > capture.bmp`), and MRT import into the baseline.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{Context, Result};

use crate::baseline::{decay_factor, Baseline};
use crate::bmp::{parse_common_header, SessionState};
use crate::config::Watch;
use crate::detector::{Detector, Finding};
use crate::mrt::{self, MrtStats};
use crate::sessions::SessionEvent;

/// Upper bound for a capture file read into memory.
pub const MAX_CAPTURE_BYTES: u64 = 256 * 1024 * 1024;

pub struct ReplayResult {
    pub messages: usize,
    pub findings: Vec<Finding>,
    pub sessions: Vec<SessionEvent>,
}

/// Feeds every message to the detector, using the per-peer header timestamp
/// as the clock so baselines mature exactly as they would have live.
pub fn replay(data: &[u8], detector: &mut Detector) -> Result<ReplayResult> {
    let router = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let mut state = SessionState::default();
    let mut offset = 0usize;
    let mut now = 0u64;
    let mut result = ReplayResult {
        messages: 0,
        findings: Vec::new(),
        sessions: Vec::new(),
    };
    while let Some(rest) = data.get(offset..).filter(|r| !r.is_empty()) {
        let header = parse_common_header(rest)
            .with_context(|| format!("message at byte offset {offset}"))?;
        let frame = rest
            .get(..header.length)
            .with_context(|| format!("message at byte offset {offset} is truncated"))?;
        let msg = state
            .parse(frame)
            .with_context(|| format!("message at byte offset {offset}"))?;
        if let Some(ts) = msg
            .peer()
            .map(|p| u64::from(p.timestamp))
            .filter(|t| *t > 0)
        {
            now = ts;
        }
        result.findings.extend(detector.handle(router, &msg, now));
        result.sessions.extend(detector.drain_sessions());
        result.messages += 1;
        offset += header.length;
    }
    Ok(result)
}

/// Adds every announcement of a watched prefix in the MRT files to `baseline`.
/// With a half-life, older routes are weighted down as if they had decayed
/// until `now`. Returns per-file statistics and the number of routes learned.
pub fn import_mrt(
    files: &[impl AsRef<Path>],
    watches: &[Watch],
    baseline: &mut Baseline,
    half_life: Option<u64>,
    now: u64,
) -> Result<(MrtStats, u64)> {
    let mut total = MrtStats::default();
    let mut learned = 0u64;
    for file in files {
        let file = file.as_ref();
        let stats = mrt::open(file)?
            .for_each(|r| {
                if r.withdraw || !watches.iter().any(|w| w.prefix == r.prefix) {
                    return;
                }
                let w = decay_factor(now.saturating_sub(r.timestamp), half_life);
                baseline.prefixes.entry(r.prefix).or_default().record_route(
                    &r.attrs,
                    r.timestamp,
                    w,
                );
                learned += 1;
            })
            .with_context(|| format!("importing {}", file.display()))?;
        total.records += stats.records;
        total.routes += stats.routes;
        total.skipped += stats.skipped;
        total.ignored += stats.ignored;
    }
    baseline.decayed_at = baseline.decayed_at.max(now);
    Ok((total, learned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::detector::{FindingKind, Severity};
    use crate::sessions::SessionKind;
    use crate::testutil::{demo_capture, mrt_rib_dump, DEMO_BASE};

    const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/demo.bmp.bin");

    #[test]
    fn checked_in_fixture_matches_encoder() {
        let generated = demo_capture();
        if std::env::var_os("PATHOLOGY_REGENERATE_FIXTURES").is_some() {
            std::fs::write(FIXTURE, &generated).unwrap();
        }
        let on_disk = std::fs::read(FIXTURE)
            .expect("fixture missing; run with PATHOLOGY_REGENERATE_FIXTURES=1");
        assert_eq!(on_disk, generated);
    }

    #[test]
    fn demo_capture_produces_expected_findings() {
        let cfg = Config::parse(include_str!("../pathology.example.toml")).unwrap();
        let mut d = Detector::new(
            cfg.watch,
            Baseline::default(),
            cfg.baseline.learning_window.as_secs(),
            cfg.baseline.min_observations,
        );
        let r = replay(&demo_capture(), &mut d).unwrap();
        let alerts: Vec<(FindingKind, Severity, bool)> = r
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Warning)
            .map(|f| (f.kind, f.severity, f.resolved))
            .collect();
        assert_eq!(
            alerts,
            vec![
                (FindingKind::PathChange, Severity::Warning, false),
                (FindingKind::NewUpstream, Severity::Warning, false),
                (FindingKind::MoreSpecific, Severity::Critical, false),
                (FindingKind::NewOrigin, Severity::Critical, false),
                (FindingKind::Withdrawn, Severity::Warning, false),
                (FindingKind::UpstreamLost, Severity::Warning, false),
                (FindingKind::NewOrigin, Severity::Critical, false),
                (FindingKind::UpstreamLost, Severity::Warning, true),
                (FindingKind::UpstreamLost, Severity::Warning, false),
            ]
        );
        assert!(r.findings.iter().any(|f| f.learning));
        assert_eq!(r.messages, 24);
        assert_eq!(r.sessions.len(), 1);
        assert_eq!(r.sessions[0].kind, SessionKind::SessionDown);
    }

    #[test]
    fn truncated_capture_is_an_error() {
        let data = demo_capture();
        let mut d = Detector::new(vec![], Baseline::default(), 0, 1);
        let err = replay(&data[..data.len() - 1], &mut d).err().unwrap();
        assert!(format!("{err:#}").contains("truncated"));
    }

    #[test]
    fn mrt_import_seeds_the_baseline() {
        let dir = std::env::temp_dir().join(format!("pathology-import-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("rib.mrt");
        std::fs::write(&file, mrt_rib_dump()).unwrap();
        let watches = vec![Watch {
            prefix: "198.51.100.0/24".parse().unwrap(),
            expected_origins: vec![],
        }];
        let mut b = Baseline::default();
        let now = u64::from(DEMO_BASE) + 86_400;
        let (stats, learned) = import_mrt(&[&file], &watches, &mut b, Some(86_400), now).unwrap();
        assert_eq!((stats.routes, learned), (3, 2));
        let p = &b.prefixes[&watches[0].prefix];
        assert_eq!(p.observations, 2);
        assert!(
            (p.paths["64501 64500"] - 0.5).abs() < 1e-9,
            "one half-life old"
        );
        assert!(p.upstreams.contains_key(&64502));
        assert_eq!(b.decayed_at, now);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
