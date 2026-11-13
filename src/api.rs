//! HTTP surfaces:
//!
//! * the read-only route API (default `127.0.0.1:8180`): `/v1/routes`,
//!   `/v1/prefixes/<prefix>/paths`, `/v1/origins` and the embedded web UI;
//! * the management router (`/metrics` plus llcforge-alert health,
//!   silences and reload routes) served on `metrics.listen`.
//!
//! Every response carries security headers; `/v1/*` optionally requires a
//! bearer token; requests are concurrency-limited, time-boxed and body-less.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use llcforge_alert::ApiToken;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::metrics::{inc, METRICS};
use crate::rib::{self, unix_to_utc, SharedHistory, SharedRib};

const MAX_CONCURRENT: usize = 64;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;
const MAX_ORIGIN_PREFIXES: usize = 100_000;

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const APP_CSS: &str = include_str!("../web/app.css");

#[derive(Clone)]
struct ApiState {
    rib: SharedRib,
    history: SharedHistory,
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn bad_request(msg: impl Into<String>) -> Response {
    error(StatusCode::BAD_REQUEST, msg)
}

fn parse_prefix(s: &str) -> Result<IpNet, String> {
    let p = IpNet::from_str(s.trim()).map_err(|_| format!("invalid prefix {s:?}"))?;
    if p != p.trunc() {
        return Err(format!("prefix {p} has host bits set"));
    }
    Ok(p)
}

fn parse_asn(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let digits = t
        .strip_prefix("AS")
        .or_else(|| t.strip_prefix("as"))
        .unwrap_or(t);
    digits
        .parse::<u32>()
        .map_err(|_| format!("invalid ASN {s:?}"))
}

#[derive(Deserialize)]
struct RoutesQuery {
    prefix: Option<String>,
    since: Option<String>,
    limit: Option<usize>,
}

async fn routes(State(s): State<ApiState>, Query(q): Query<RoutesQuery>) -> Response {
    let prefix = match q.prefix.as_deref().map(parse_prefix).transpose() {
        Ok(p) => p,
        Err(e) => return bad_request(e),
    };
    let since = match q
        .since
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(t) => t.map(|t| t.with_timezone(&Utc)),
        Err(_) => return bad_request("since must be an RFC 3339 time, e.g. 2026-03-16T09:00:00Z"),
    };
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let events = rib::read(&s.history).query(prefix, since, limit);
    Json(json!({ "events": events })).into_response()
}

#[derive(Serialize)]
struct PathOut {
    router: IpAddr,
    peer: String,
    peer_asn: u32,
    as_path: Vec<u32>,
    origin: Option<u32>,
    upstream_asn: Option<u32>,
    since: DateTime<Utc>,
}

/// `/v1/prefixes/<prefix>/paths`; the prefix itself contains a `/`, so the
/// whole tail is captured (a `%2F`-encoded slash works too).
async fn prefix_paths(State(s): State<ApiState>, Path(rest): Path<String>) -> Response {
    let Some(p) = rest.strip_suffix("/paths") else {
        return error(StatusCode::NOT_FOUND, "use /v1/prefixes/<prefix>/paths");
    };
    let prefix = match parse_prefix(&p.replace("%2F", "/").replace("%2f", "/")) {
        Ok(p) => p,
        Err(e) => return bad_request(e),
    };
    let rib = rib::read(&s.rib);
    let paths: Vec<PathOut> = rib
        .best_per_peer(&prefix)
        .into_iter()
        .map(|r| PathOut {
            router: r.router,
            peer: if r.loc_rib {
                "loc-rib".to_string()
            } else {
                r.peer.to_string()
            },
            peer_asn: r.peer_asn,
            as_path: r.as_path.to_vec(),
            origin: r.origin,
            upstream_asn: r.upstream,
            since: unix_to_utc(r.since),
        })
        .collect();
    Json(json!({ "prefix": prefix, "paths": paths })).into_response()
}

#[derive(Deserialize)]
struct OriginsQuery {
    asn: Option<String>,
}

async fn origins(State(s): State<ApiState>, Query(q): Query<OriginsQuery>) -> Response {
    let Some(asn) = q.asn else {
        return bad_request("asn is required, e.g. /v1/origins?asn=64500");
    };
    let asn = match parse_asn(&asn) {
        Ok(a) => a,
        Err(e) => return bad_request(e),
    };
    let prefixes = rib::read(&s.rib).originated_by(asn, MAX_ORIGIN_PREFIXES);
    Json(json!({ "asn": asn, "prefixes": prefixes })).into_response()
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    for (k, v) in [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    ] {
        h.insert(k, HeaderValue::from_static(v));
    }
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    resp
}

/// Concurrency cap + per-request timeout.
async fn limits(State(permits): State<Arc<Semaphore>>, req: Request, next: Next) -> Response {
    let Ok(_permit) = permits.try_acquire() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many concurrent requests",
        );
    };
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(r) => r,
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "request timed out"),
    }
}

async fn count(req: Request, next: Next) -> Response {
    inc(&METRICS.api_requests);
    next.run(req).await
}

/// Applies the shared hardening layers to `router`.
fn harden(router: Router) -> Router {
    router
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(MAX_CONCURRENT)),
            limits,
        ))
        .layer(middleware::from_fn(security_headers))
}

/// The read-only route API plus the embedded web UI.
pub fn api_router(rib: SharedRib, history: SharedHistory, token: Option<ApiToken>) -> Router {
    let mut v1 = Router::new()
        .route("/v1/routes", get(routes))
        .route("/v1/prefixes/{*rest}", get(prefix_paths))
        .route("/v1/origins", get(origins))
        .with_state(ApiState { rib, history })
        .layer(middleware::from_fn(count));
    if let Some(t) = token {
        v1 = v1.layer(middleware::from_fn_with_state(
            t,
            llcforge_alert::auth::require_bearer,
        ));
    }
    let ui = Router::new()
        .route(
            "/",
            get(|| async { asset("text/html; charset=utf-8", INDEX_HTML) }),
        )
        .route(
            "/app.js",
            get(|| async { asset("text/javascript; charset=utf-8", APP_JS) }),
        )
        .route(
            "/app.css",
            get(|| async { asset("text/css; charset=utf-8", APP_CSS) }),
        );
    harden(
        v1.merge(ui)
            .fallback(|| async { error(StatusCode::NOT_FOUND, "not found") }),
    )
}

/// Shared slot for the dispatcher metrics (replaced on configuration reload).
pub type AlertMetrics = Arc<RwLock<Arc<llcforge_alert::Metrics>>>;

/// `/metrics` merged with the llcforge-alert admin routes in `extra`.
pub fn management_router(alert_metrics: AlertMetrics, extra: Router) -> Router {
    let metrics = Router::new().route(
        "/metrics",
        get(move || {
            let m = alert_metrics.clone();
            async move {
                let mut body = METRICS.render();
                rib::read(&m).render_prometheus(&mut body);
                (
                    [(
                        header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    body,
                )
            }
        }),
    );
    harden(metrics.merge(extra))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::{AsPath, Attributes, Segment};
    use crate::rib::{EventKind, History, Rib, RouteEvent, Source};
    use axum::body::Body;
    use tower::ServiceExt;

    fn state() -> (SharedRib, SharedHistory) {
        let src = Source {
            router: "192.0.2.254".parse().unwrap(),
            peer: "192.0.2.1".parse().unwrap(),
            peer_asn: 64501,
            loc_rib: false,
        };
        let attrs = Attributes {
            as_path: AsPath(vec![Segment::Sequence(vec![64501, 64500])]),
            ..Attributes::default()
        };
        let p: IpNet = "198.51.100.0/24".parse().unwrap();
        let mut rib = Rib::new(100);
        rib.announce(src, p, 0, &attrs, 1_772_323_200, false);
        let mut h = History::memory(100, u64::MAX);
        h.record(RouteEvent::new(
            src,
            p,
            EventKind::Announce,
            Some(&attrs),
            1_772_323_200,
        ));
        h.record(RouteEvent::new(
            src,
            p,
            EventKind::Withdraw,
            None,
            1_772_323_260,
        ));
        (Arc::new(RwLock::new(rib)), Arc::new(RwLock::new(h)))
    }

    async fn get_json(
        app: &Router,
        uri: &str,
        token: Option<&str>,
    ) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
        let mut req = Request::get(uri);
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null),
            headers,
        )
    }

    #[tokio::test]
    async fn contract_endpoints() {
        let (rib, h) = state();
        let app = api_router(rib, h, None);
        let (st, v, hdr) = get_json(&app, "/v1/routes?prefix=198.51.100.0/24&limit=10", None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(hdr["x-content-type-options"], "nosniff");
        let ev = &v["events"];
        assert_eq!(ev.as_array().unwrap().len(), 2);
        for k in [
            "time",
            "peer",
            "peer_asn",
            "prefix",
            "kind",
            "as_path",
            "origin",
            "communities",
            "large_communities",
        ] {
            assert!(ev[0].get(k).is_some(), "missing {k}");
        }
        assert_eq!(ev[0]["kind"], "announce");
        assert_eq!(ev[1]["kind"], "withdraw");
        let (_, v, _) = get_json(
            &app,
            "/v1/routes?prefix=198.51.100.0/24&since=2026-03-01T00:00:30Z",
            None,
        )
        .await;
        assert_eq!(v["events"].as_array().unwrap().len(), 1);

        let (st, v, _) = get_json(&app, "/v1/prefixes/198.51.100.0/24/paths", None).await;
        assert_eq!(st, StatusCode::OK);
        let p = &v["paths"][0];
        assert_eq!(p["peer"], "192.0.2.1");
        assert_eq!(p["peer_asn"], 64501);
        assert_eq!(p["as_path"], json!([64501, 64500]));
        assert_eq!(p["origin"], 64500);
        assert_eq!(p["upstream_asn"], 64501);
        assert_eq!(p["since"], "2026-03-01T00:00:00Z");
        let (_, v, _) = get_json(&app, "/v1/prefixes/198.51.100.0%2F24/paths", None).await;
        assert_eq!(v["paths"].as_array().unwrap().len(), 1);

        let (st, v, _) = get_json(&app, "/v1/origins?asn=AS64500", None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["prefixes"], json!(["198.51.100.0/24"]));
        let (_, v, _) = get_json(&app, "/v1/origins?asn=64999", None).await;
        assert_eq!(v["prefixes"], json!([]));
    }

    #[tokio::test]
    async fn errors_auth_and_ui() {
        let (rib, h) = state();
        let token = ApiToken::new("0123456789abcdef0123").unwrap();
        let app = api_router(rib, h, Some(token));
        for uri in [
            "/v1/routes?prefix=198.51.100.1/24",
            "/v1/routes?since=yesterday",
            "/v1/origins",
            "/v1/origins?asn=x",
            "/v1/prefixes/not-a-prefix/paths",
        ] {
            let (st, v, _) = get_json(&app, uri, Some("0123456789abcdef0123")).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{uri}");
            assert!(v["error"].is_string());
        }
        let (st, _, _) = get_json(&app, "/v1/routes", None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _, _) = get_json(&app, "/v1/routes", Some("wrong-token-wrong-token")).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let (st, _, _) = get_json(&app, "/nope", None).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        // The UI is static and needs no token.
        for (uri, ct) in [
            ("/", "text/html"),
            ("/app.js", "text/javascript"),
            ("/app.css", "text/css"),
        ] {
            let resp = app
                .clone()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(resp.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(ct));
            assert!(resp.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("script-src 'self'"));
        }
    }

    #[tokio::test]
    async fn management_metrics() {
        let m: AlertMetrics = Arc::new(RwLock::new(
            llcforge_alert::AlertHandle::disabled("pathology").metrics(),
        ));
        let app = management_router(
            m,
            llcforge_alert::health_router(llcforge_alert::Readiness::new()),
        );
        let resp = app
            .clone()
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8(b.to_vec()).unwrap();
        assert!(text.contains("pathology_rib_routes"));
        assert!(text.contains("llcforge_alert_"), "{text}");
        let (st, _, _) = get_json(&app, "/healthz", None).await;
        assert_eq!(st, StatusCode::OK);
    }
}
