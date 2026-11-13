//! TOML configuration, parsed with serde and validated at startup.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use ipnet::IpNet;
use llcforge_beacon::{AlertsConfig, HealthConfig, SilencesConfig};
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub collector: CollectorConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub baseline: BaselineConfig,
    #[serde(default)]
    pub detect: DetectConfig,
    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub watch: Vec<Watch>,
    #[serde(default)]
    pub rib: RibConfig,
    #[serde(default)]
    pub history: HistoryConfig,
    #[serde(default)]
    pub api: ApiConfig,
    pub notary: Option<NotaryConfig>,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub silences: SilencesConfig,
    #[serde(default)]
    pub health: HealthConfig,
    pub metrics: Option<MetricsConfig>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default)]
    pub level: LogLevel,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub bmp: Option<BmpConfig>,
    pub bgp: Option<BgpConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmpConfig {
    #[serde(default = "default_bmp_listen")]
    pub listen: SocketAddr,
    pub allowed_peers: Vec<IpAddr>,
}

fn default_bmp_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 11019))
}

/// Passive, receive-only BGP sessions for routers without BMP.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpConfig {
    #[serde(default = "default_bgp_listen")]
    pub listen: SocketAddr,
    pub local_asn: u32,
    pub router_id: Ipv4Addr,
    #[serde(default = "default_hold_time")]
    pub hold_time: u16,
    #[serde(rename = "peer")]
    pub peers: Vec<BgpPeer>,
}

fn default_bgp_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 179))
}

fn default_hold_time() -> u16 {
    90
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpPeer {
    pub address: IpAddr,
    pub asn: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Defaults to the platform data directory (`STATE_DIRECTORY` under systemd).
    pub data_dir: Option<PathBuf>,
    #[serde(default = "default_save_interval", deserialize_with = "de_duration")]
    pub save_interval: Duration,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: None,
            save_interval: default_save_interval(),
        }
    }
}

impl StorageConfig {
    pub fn data_dir(&self) -> PathBuf {
        self.data_dir
            .clone()
            .unwrap_or_else(|| llcforge_beacon::default_data_dir("pathology"))
    }
}

fn default_save_interval() -> Duration {
    Duration::from_secs(60)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfig {
    #[serde(default = "default_learning_window", deserialize_with = "de_duration")]
    pub learning_window: Duration,
    #[serde(default = "default_min_observations")]
    pub min_observations: u64,
    /// Exponential decay of baseline weights; unset keeps everything forever.
    #[serde(default, deserialize_with = "de_opt_duration")]
    pub half_life: Option<Duration>,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            learning_window: default_learning_window(),
            min_observations: default_min_observations(),
            half_life: None,
        }
    }
}

fn default_learning_window() -> Duration {
    Duration::from_secs(14 * 86_400)
}

fn default_min_observations() -> u64 {
    3
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectConfig {
    /// Report communities a watched prefix never carried before.
    #[serde(default = "yes")]
    pub community_changes: bool,
    /// An unknown path whose length differs from every baseline length by at
    /// least this much is reported as `path_length_change`.
    #[serde(default = "default_length_delta")]
    pub path_length_delta: u32,
    /// CAIDA as-rel file enabling route leak detection.
    pub relationships_file: Option<PathBuf>,
    /// Your ASN (the receiver of every route) for leak checks; defaults to
    /// `collector.bgp.local_asn`.
    pub local_asn: Option<u32>,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            community_changes: true,
            path_length_delta: default_length_delta(),
            relationships_file: None,
            local_asn: None,
        }
    }
}

fn yes() -> bool {
    true
}

fn default_length_delta() -> u32 {
    2
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionsConfig {
    /// `peer_flap` after this many downs inside `flap_window` (0 disables).
    #[serde(default = "default_flap_threshold")]
    pub flap_threshold: u32,
    #[serde(default = "default_flap_window", deserialize_with = "de_duration")]
    pub flap_window: Duration,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            flap_threshold: default_flap_threshold(),
            flap_window: default_flap_window(),
        }
    }
}

fn default_flap_threshold() -> u32 {
    3
}

fn default_flap_window() -> Duration {
    Duration::from_secs(600)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watch {
    pub prefix: IpNet,
    #[serde(default)]
    pub expected_origins: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RibConfig {
    /// Routes beyond this are not stored (watched prefixes always are).
    #[serde(default = "default_max_routes")]
    pub max_routes: usize,
}

impl Default for RibConfig {
    fn default() -> Self {
        Self {
            max_routes: default_max_routes(),
        }
    }
}

fn default_max_routes() -> usize {
    2_000_000
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HistoryScope {
    /// Watched prefixes and their more-specifics.
    #[default]
    Watched,
    /// Every prefix (large on full tables).
    All,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryConfig {
    #[serde(default)]
    pub scope: HistoryScope,
    #[serde(default = "default_retention", deserialize_with = "de_duration")]
    pub retention: Duration,
    /// Events kept in memory for `/v1/routes`.
    #[serde(default = "default_max_events")]
    pub max_events: usize,
    /// Write events to `<data_dir>/history/` (one JSON-lines file per day).
    #[serde(default = "yes")]
    pub persist: bool,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            scope: HistoryScope::Watched,
            retention: default_retention(),
            max_events: default_max_events(),
            persist: true,
        }
    }
}

fn default_retention() -> Duration {
    Duration::from_secs(7 * 86_400)
}

fn default_max_events() -> usize {
    100_000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "default_api_listen")]
    pub listen: SocketAddr,
    /// Environment variable with a bearer token required on `/v1/*`.
    pub token_env: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_api_listen(),
            token_env: None,
        }
    }
}

fn default_api_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8180))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryConfig {
    /// Base URL of a Notary API, e.g. `http://127.0.0.1:8181/`.
    pub url: String,
    pub token_env: Option<String>,
    #[serde(default = "default_notary_timeout")]
    pub timeout_ms: u64,
}

fn default_notary_timeout() -> u64 {
    1000
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Management listener: `/metrics`, `/healthz`, `/readyz`, `/v1/silences`, `/v1/reload`.
    pub listen: SocketAddr,
}

/// Parses `30s`, `10m`, `1h`, `14d`.
pub fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration {s:?}: expected e.g. 30s, 10m, 1h, 14d"))?;
    let mul = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(format!("invalid duration unit in {s:?}: use s, m, h or d")),
    };
    n.checked_mul(mul)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("duration {s:?} is too large"))
}

fn de_duration<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

fn de_opt_duration<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Duration>, D::Error> {
    let s = String::deserialize(d)?;
    parse_duration(&s)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Where `/metrics`, health, silences and reload are served.
    pub fn management_listen(&self) -> Option<SocketAddr> {
        self.metrics
            .as_ref()
            .map(|m| m.listen)
            .or(self.health.listen)
    }

    /// ASN used as the receiver in leak checks.
    pub fn local_asn(&self) -> Option<u32> {
        self.detect
            .local_asn
            .or(self.collector.bgp.as_ref().map(|b| b.local_asn))
    }

    fn validate(&self) -> Result<()> {
        let c = &self.collector;
        ensure!(
            c.bmp.is_some() || c.bgp.is_some(),
            "configure at least one collector: [collector.bmp] or [collector.bgp]"
        );
        if let Some(bmp) = &c.bmp {
            ensure!(
                !bmp.allowed_peers.is_empty(),
                "collector.bmp.allowed_peers is empty; list the router addresses allowed to connect"
            );
        }
        if let Some(bgp) = &c.bgp {
            ensure!(bgp.local_asn != 0, "collector.bgp.local_asn must not be 0");
            ensure!(
                !bgp.router_id.is_unspecified(),
                "collector.bgp.router_id must not be 0.0.0.0"
            );
            ensure!(
                bgp.hold_time == 0 || bgp.hold_time >= 3,
                "collector.bgp.hold_time must be 0 or at least 3 seconds"
            );
            ensure!(
                !bgp.peers.is_empty(),
                "collector.bgp has no [[collector.bgp.peer]] entries"
            );
            let mut seen = HashSet::new();
            for p in &bgp.peers {
                ensure!(
                    p.asn != 0,
                    "collector.bgp.peer {}: asn must not be 0",
                    p.address
                );
                ensure!(
                    seen.insert(p.address.to_canonical()),
                    "collector.bgp.peer {} is listed twice",
                    p.address
                );
            }
        }

        ensure!(!self.watch.is_empty(), "no [[watch]] entries configured");
        let mut seen = HashSet::new();
        for w in &self.watch {
            ensure!(
                w.prefix == w.prefix.trunc(),
                "watch prefix {} has host bits set; did you mean {}?",
                w.prefix,
                w.prefix.trunc()
            );
            ensure!(
                seen.insert(w.prefix),
                "watch prefix {} is listed twice",
                w.prefix
            );
            ensure!(
                !w.expected_origins.contains(&0),
                "watch {}: AS0 is not a valid expected origin",
                w.prefix
            );
        }

        ensure!(
            self.baseline.min_observations >= 1,
            "baseline.min_observations must be at least 1"
        );
        if let Some(h) = self.baseline.half_life {
            ensure!(
                h >= Duration::from_secs(3600),
                "baseline.half_life must be at least 1h"
            );
        }
        ensure!(
            self.storage.save_interval >= Duration::from_secs(1),
            "storage.save_interval must be at least 1s"
        );
        ensure!(
            self.rib.max_routes >= 1,
            "rib.max_routes must be at least 1"
        );
        ensure!(
            self.history.max_events <= 10_000_000,
            "history.max_events must be at most 10000000"
        );

        for (what, env) in [
            ("api.token_env", self.api.token_env.as_deref()),
            (
                "notary.token_env",
                self.notary.as_ref().and_then(|n| n.token_env.as_deref()),
            ),
            (
                "silences.api_token_env",
                self.silences.api_token_env.as_deref(),
            ),
            (
                "health.admin_token_env",
                self.health.admin_token_env.as_deref(),
            ),
        ] {
            if let Some(env) = env {
                ensure!(
                    valid_env_name(env),
                    "{what} {env:?} is not a valid variable name (A-Z, 0-9, _)"
                );
            }
        }
        if let Some(n) = &self.notary {
            let url = reqwest::Url::parse(&n.url)
                .with_context(|| format!("notary.url {:?} is not a valid URL", n.url))?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!("notary.url must use http:// or https://");
            }
            ensure!(
                (50..=10_000).contains(&n.timeout_ms),
                "notary.timeout_ms must be between 50 and 10000"
            );
        }
        if let (Some(m), Some(h)) = (&self.metrics, self.health.listen) {
            ensure!(
                m.listen == h,
                "metrics.listen and health.listen are the same management listener; set only one"
            );
        }

        let mut listeners: Vec<(&str, SocketAddr)> = Vec::new();
        if let Some(b) = &c.bmp {
            listeners.push(("collector.bmp.listen", b.listen));
        }
        if let Some(b) = &c.bgp {
            listeners.push(("collector.bgp.listen", b.listen));
        }
        if let Some(m) = self.management_listen() {
            listeners.push(("metrics.listen", m));
        }
        if self.api.enabled {
            listeners.push(("api.listen", self.api.listen));
        }
        for (i, (a, x)) in listeners.iter().enumerate() {
            for (b, y) in &listeners[i + 1..] {
                ensure!(
                    x.port() != y.port() || x.ip() != y.ip(),
                    "{a} and {b} must differ"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[collector.bmp]
allowed_peers = ["192.0.2.1"]

[[watch]]
prefix = "198.51.100.0/24"
"#;

    #[test]
    fn example_config_is_valid() {
        let cfg = Config::parse(include_str!("../pathology.example.toml")).unwrap();
        assert!(!cfg.watch.is_empty());
        assert!(cfg.collector.bmp.is_some());
    }

    #[test]
    fn defaults() {
        let cfg = Config::parse(MINIMAL).unwrap();
        let bmp = cfg.collector.bmp.as_ref().unwrap();
        assert_eq!(bmp.listen, "0.0.0.0:11019".parse().unwrap());
        assert_eq!(
            cfg.baseline.learning_window,
            Duration::from_secs(14 * 86_400)
        );
        assert_eq!(cfg.baseline.min_observations, 3);
        assert_eq!(cfg.baseline.half_life, None);
        assert!(cfg.storage.data_dir().ends_with("pathology"));
        assert!(cfg.metrics.is_none());
        assert!(cfg.api.enabled);
        assert_eq!(cfg.api.listen, "127.0.0.1:8180".parse().unwrap());
        assert_eq!(cfg.history.scope, HistoryScope::Watched);
        assert_eq!(cfg.sessions.flap_threshold, 3);
        assert!(cfg.notary.is_none());
        assert!(cfg.alerts.sinks.is_empty());
    }

    #[test]
    fn passive_bgp_only() {
        let cfg = Config::parse(
            r#"
[collector.bgp]
local_asn = 64496
router_id = "192.0.2.254"
[[collector.bgp.peer]]
address = "192.0.2.1"
asn = 64501
[[watch]]
prefix = "198.51.100.0/24"
"#,
        )
        .unwrap();
        let bgp = cfg.collector.bgp.as_ref().unwrap();
        assert_eq!(bgp.listen.port(), 179);
        assert_eq!(bgp.hold_time, 90);
        assert_eq!(cfg.local_asn(), Some(64496));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("10m"), Ok(Duration::from_secs(600)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(parse_duration("14d"), Ok(Duration::from_secs(14 * 86_400)));
        for bad in ["", "d", "10", "10x", "-1d", "99999999999999999999d", "1.5h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    fn rejects(extra: &str, base: &str) {
        let text = format!("{base}\n{extra}");
        assert!(Config::parse(&text).is_err(), "accepted:\n{text}");
    }

    #[test]
    fn rejects_invalid_configs() {
        let no_peers =
            "[collector.bmp]\nallowed_peers = []\n[[watch]]\nprefix = \"198.51.100.0/24\"\n";
        rejects("", no_peers);
        rejects("", "[collector.bmp]\nallowed_peers = [\"192.0.2.1\"]\n");
        rejects("", "[collector]\n[[watch]]\nprefix = \"198.51.100.0/24\"\n");
        rejects("[[watch]]\nprefix = \"198.51.100.0/24\"", MINIMAL);
        rejects("[[watch]]\nprefix = \"203.0.113.1/24\"", MINIMAL);
        rejects(
            "[[watch]]\nprefix = \"203.0.113.0/24\"\nexpected_origins = [0]",
            MINIMAL,
        );
        rejects("[baseline]\nlearning_window = \"14 days\"", MINIMAL);
        rejects("[baseline]\nmin_observations = 0", MINIMAL);
        rejects("[baseline]\nhalf_life = \"10m\"", MINIMAL);
        rejects("[notary]\nurl = \"ftp://notary.example.net\"", MINIMAL);
        rejects(
            "[notary]\nurl = \"http://127.0.0.1:8181\"\ntimeout_ms = 1",
            MINIMAL,
        );
        rejects("[api]\ntoken_env = \"bad-name\"", MINIMAL);
        rejects("[metrics]\nlisten = \"0.0.0.0:11019\"", MINIMAL);
        rejects("[api]\nlisten = \"0.0.0.0:11019\"", MINIMAL);
        rejects("[collector.bmp.unknown]\nx = 1", MINIMAL);
        // The pre-llcforge-beacon alert keys are rejected with a clear error.
        rejects("[alerts]\nmin_severity = \"warning\"", MINIMAL);
        rejects("typo_key = 1", MINIMAL);
        let bgp = "[collector.bgp]\nlocal_asn = 64496\nrouter_id = \"192.0.2.254\"\n";
        rejects(&format!("{bgp}peer = []"), MINIMAL);
        rejects(
            &format!(
                "{bgp}hold_time = 2\n[[collector.bgp.peer]]\naddress = \"192.0.2.1\"\nasn = 1"
            ),
            MINIMAL,
        );
        rejects(
            &format!("{bgp}[[collector.bgp.peer]]\naddress = \"192.0.2.1\"\nasn = 0"),
            MINIMAL,
        );
    }
}
