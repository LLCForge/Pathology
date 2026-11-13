//! Optional RPKI origin validation through a Notary instance
//! (`GET /v1/validity?prefix=<p>&asn=<n>` → `{"state": "valid|invalid|not_found", "stale": bool}`).
//!
//! Lookups are cached, concurrency-limited and time-boxed: a slow or missing
//! Notary only means the finding carries no RPKI state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::metrics::{inc, METRICS};

const CACHE_TTL: Duration = Duration::from_secs(300);
const CACHE_MAX: usize = 10_000;
const MAX_CONCURRENT: usize = 16;
const MAX_BODY: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpkiState {
    /// `valid`, `invalid` or `not_found`.
    pub state: String,
    pub stale: bool,
}

#[derive(Deserialize)]
struct ValidityResponse {
    state: String,
    #[serde(default)]
    stale: bool,
}

pub struct NotaryClient {
    http: reqwest::Client,
    base: reqwest::Url,
    token: Option<String>,
    timeout: Duration,
    permits: Arc<Semaphore>,
    cache: Mutex<HashMap<(IpNet, u32), (Instant, RpkiState)>>,
}

impl NotaryClient {
    pub fn new(url: &str, token: Option<String>, timeout: Duration) -> Result<Self> {
        let mut base = reqwest::Url::parse(url).with_context(|| format!("notary.url {url:?}"))?;
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        anyhow::ensure!(
            matches!(base.scheme(), "http" | "https"),
            "notary.url must be http:// or https://"
        );
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("pathology/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building Notary HTTP client")?;
        Ok(NotaryClient {
            http,
            base,
            token,
            timeout,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn cached(&self, key: (IpNet, u32)) -> Option<RpkiState> {
        let c = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        c.get(&key)
            .filter(|(t, _)| t.elapsed() < CACHE_TTL)
            .map(|(_, s)| s.clone())
    }

    /// RPKI state of (prefix, origin), or `None` when Notary did not answer
    /// in time, answered with an error, or too many lookups are in flight.
    pub async fn validity(&self, prefix: IpNet, asn: u32) -> Option<RpkiState> {
        if let Some(s) = self.cached((prefix, asn)) {
            inc(&METRICS.notary_cached);
            return Some(s);
        }
        let Ok(_permit) = self.permits.try_acquire() else {
            inc(&METRICS.notary_skipped);
            return None;
        };
        match tokio::time::timeout(self.timeout, self.fetch(prefix, asn)).await {
            Ok(Ok(s)) => {
                inc(&METRICS.notary_ok);
                let mut c = self.cache.lock().unwrap_or_else(|p| p.into_inner());
                if c.len() >= CACHE_MAX {
                    c.retain(|_, (t, _)| t.elapsed() < CACHE_TTL);
                    if c.len() >= CACHE_MAX {
                        c.clear();
                    }
                }
                c.insert((prefix, asn), (Instant::now(), s.clone()));
                Some(s)
            }
            Ok(Err(e)) => {
                inc(&METRICS.notary_errors);
                tracing::debug!(error = %format!("{e:#}"), "Notary lookup failed");
                None
            }
            Err(_) => {
                inc(&METRICS.notary_errors);
                tracing::debug!("Notary lookup timed out");
                None
            }
        }
    }

    async fn fetch(&self, prefix: IpNet, asn: u32) -> Result<RpkiState> {
        let mut url = self.base.join("v1/validity")?;
        url.query_pairs_mut()
            .append_pair("prefix", &prefix.to_string())
            .append_pair("asn", &asn.to_string());
        let mut req = self.http.get(url);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.map_err(|e| e.without_url())?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| e.without_url())?;
        anyhow::ensure!(status.is_success(), "Notary returned HTTP {status}");
        anyhow::ensure!(body.len() <= MAX_BODY, "Notary response too large");
        let v: ValidityResponse =
            serde_json::from_slice(&body).context("decoding Notary response")?;
        anyhow::ensure!(
            matches!(v.state.as_str(), "valid" | "invalid" | "not_found"),
            "unexpected RPKI state"
        );
        Ok(RpkiState {
            state: v.state,
            stale: v.stale,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Query;
    use axum::routing::get;

    #[derive(Deserialize)]
    struct Q {
        prefix: String,
        asn: u32,
    }

    #[tokio::test]
    async fn lookup_cache_and_timeout() {
        let app = axum::Router::new().route(
            "/v1/validity",
            get(|Query(q): Query<Q>| async move {
                if q.asn == 64999 {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                let state = if q.asn == 64500 { "valid" } else { "invalid" };
                axum::Json(serde_json::json!({"state": state, "stale": q.prefix.contains(':')}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let n = NotaryClient::new(&format!("http://{addr}/"), None, Duration::from_millis(300))
            .unwrap();
        let p: IpNet = "198.51.100.0/24".parse().unwrap();
        let s = n.validity(p, 64500).await.unwrap();
        assert_eq!((s.state.as_str(), s.stale), ("valid", false));
        assert_eq!(n.validity(p, 64510).await.unwrap().state, "invalid");
        assert!(n.cached((p, 64500)).is_some());
        let t = Instant::now();
        assert!(n.validity(p, 64999).await.is_none());
        assert!(t.elapsed() < Duration::from_secs(2), "time-boxed");
        // Unreachable Notary: no state, no error.
        let dead =
            NotaryClient::new("http://127.0.0.1:9/", None, Duration::from_millis(300)).unwrap();
        assert!(dead.validity(p, 64500).await.is_none());
        assert!(NotaryClient::new("ftp://example.net/", None, Duration::from_secs(1)).is_err());
    }
}
