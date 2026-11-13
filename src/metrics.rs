//! Process-wide counters rendered in the Prometheus text format. The HTTP
//! endpoint lives on the management listener (see `main.rs`), next to
//! `/healthz`, `/readyz` and the llcforge-alert metrics.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::detector::Severity;

pub struct Metrics {
    pub bmp_messages: AtomicU64,
    pub bmp_parse_errors: AtomicU64,
    pub bmp_sessions_active: AtomicU64,
    pub bmp_sessions_rejected: AtomicU64,
    pub bgp_messages: AtomicU64,
    pub bgp_sessions_established: AtomicU64,
    pub bgp_sessions_rejected: AtomicU64,
    pub bgp_session_errors: AtomicU64,
    pub findings_info: AtomicU64,
    pub findings_warning: AtomicU64,
    pub findings_critical: AtomicU64,
    pub session_events: AtomicU64,
    pub rib_routes: AtomicU64,
    pub rib_routes_rejected: AtomicU64,
    pub history_events: AtomicU64,
    pub history_write_errors: AtomicU64,
    pub notary_ok: AtomicU64,
    pub notary_cached: AtomicU64,
    pub notary_errors: AtomicU64,
    pub notary_skipped: AtomicU64,
    pub alerts_rejected: AtomicU64,
    pub baseline_saves_failed: AtomicU64,
    pub api_requests: AtomicU64,
}

pub static METRICS: Metrics = Metrics {
    bmp_messages: AtomicU64::new(0),
    bmp_parse_errors: AtomicU64::new(0),
    bmp_sessions_active: AtomicU64::new(0),
    bmp_sessions_rejected: AtomicU64::new(0),
    bgp_messages: AtomicU64::new(0),
    bgp_sessions_established: AtomicU64::new(0),
    bgp_sessions_rejected: AtomicU64::new(0),
    bgp_session_errors: AtomicU64::new(0),
    findings_info: AtomicU64::new(0),
    findings_warning: AtomicU64::new(0),
    findings_critical: AtomicU64::new(0),
    session_events: AtomicU64::new(0),
    rib_routes: AtomicU64::new(0),
    rib_routes_rejected: AtomicU64::new(0),
    history_events: AtomicU64::new(0),
    history_write_errors: AtomicU64::new(0),
    notary_ok: AtomicU64::new(0),
    notary_cached: AtomicU64::new(0),
    notary_errors: AtomicU64::new(0),
    notary_skipped: AtomicU64::new(0),
    alerts_rejected: AtomicU64::new(0),
    baseline_saves_failed: AtomicU64::new(0),
    api_requests: AtomicU64::new(0),
};

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl Metrics {
    pub fn finding(&self, s: Severity) {
        inc(match s {
            Severity::Info => &self.findings_info,
            Severity::Warning => &self.findings_warning,
            Severity::Critical => &self.findings_critical,
        });
    }

    pub fn render(&self) -> String {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let mut out = String::new();
        let mut metric = |name: &str, kind: &str, help: &str, samples: &[(&str, u64)]| {
            let _ = writeln!(
                out,
                "# HELP pathology_{name} {help}\n# TYPE pathology_{name} {kind}"
            );
            for (labels, v) in samples {
                let _ = writeln!(out, "pathology_{name}{labels} {v}");
            }
        };
        metric(
            "bmp_messages_total",
            "counter",
            "BMP messages parsed.",
            &[("", get(&self.bmp_messages))],
        );
        metric(
            "bmp_parse_errors_total",
            "counter",
            "Malformed BMP messages (session closed).",
            &[("", get(&self.bmp_parse_errors))],
        );
        metric(
            "bmp_sessions_active",
            "gauge",
            "Connected BMP sessions.",
            &[("", get(&self.bmp_sessions_active))],
        );
        metric(
            "bmp_sessions_rejected_total",
            "counter",
            "Connections refused because the source is not in allowed_peers.",
            &[("", get(&self.bmp_sessions_rejected))],
        );
        metric(
            "bgp_messages_total",
            "counter",
            "BGP messages received on passive sessions.",
            &[("", get(&self.bgp_messages))],
        );
        metric(
            "bgp_sessions_established",
            "gauge",
            "Passive BGP sessions in Established state.",
            &[("", get(&self.bgp_sessions_established))],
        );
        metric(
            "bgp_sessions_rejected_total",
            "counter",
            "BGP connections refused (address not a configured peer).",
            &[("", get(&self.bgp_sessions_rejected))],
        );
        metric(
            "bgp_session_errors_total",
            "counter",
            "Passive BGP sessions closed because of an error.",
            &[("", get(&self.bgp_session_errors))],
        );
        metric(
            "findings_total",
            "counter",
            "Findings produced by the detector.",
            &[
                ("{severity=\"info\"}", get(&self.findings_info)),
                ("{severity=\"warning\"}", get(&self.findings_warning)),
                ("{severity=\"critical\"}", get(&self.findings_critical)),
            ],
        );
        metric(
            "session_events_total",
            "counter",
            "Session down / up / flap events.",
            &[("", get(&self.session_events))],
        );
        metric(
            "rib_routes",
            "gauge",
            "Routes held in the RIB (all routers and peers).",
            &[("", get(&self.rib_routes))],
        );
        metric(
            "rib_routes_rejected_total",
            "counter",
            "Routes not stored because rib.max_routes was reached.",
            &[("", get(&self.rib_routes_rejected))],
        );
        metric(
            "history_events",
            "gauge",
            "Route events held in memory for /v1/routes.",
            &[("", get(&self.history_events))],
        );
        metric(
            "history_write_errors_total",
            "counter",
            "Failed writes to the route history files.",
            &[("", get(&self.history_write_errors))],
        );
        metric(
            "notary_lookups_total",
            "counter",
            "RPKI lookups against Notary by result.",
            &[
                ("{result=\"ok\"}", get(&self.notary_ok)),
                ("{result=\"cached\"}", get(&self.notary_cached)),
                ("{result=\"error\"}", get(&self.notary_errors)),
                ("{result=\"skipped\"}", get(&self.notary_skipped)),
            ],
        );
        metric(
            "alerts_rejected_total",
            "counter",
            "Alerts the dispatcher did not accept (intake full or alerting stopped).",
            &[("", get(&self.alerts_rejected))],
        );
        metric(
            "baseline_saves_failed_total",
            "counter",
            "Failed baseline writes.",
            &[("", get(&self.baseline_saves_failed))],
        );
        metric(
            "api_requests_total",
            "counter",
            "Requests to the read-only route API.",
            &[("", get(&self.api_requests))],
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_has_all_families() {
        METRICS.finding(Severity::Critical);
        let text = METRICS.render();
        for name in [
            "pathology_bmp_messages_total",
            "pathology_bmp_sessions_active",
            "pathology_bgp_sessions_established",
            "pathology_findings_total{severity=\"critical\"}",
            "pathology_rib_routes",
            "pathology_notary_lookups_total{result=\"error\"}",
        ] {
            assert!(text.contains(name), "{name} missing");
        }
    }
}
