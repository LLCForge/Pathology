# Pathology Architecture

BGP route monitor for your own routers and BMP feeds. Learns the AS paths and origins your prefixes normally use, then alerts on any deviation.

This document describes how Pathology is put together, where its trust boundaries are and how it behaves when things go wrong. It is the starting point for contributors; keep it up to date when you change the design.

## Design principles

- **Self-hosted, single binary.** No SaaS dependency, no external database. State lives in a local data directory (`baseline.json`, `history/`, `alert-queue/`, `silences.json`).
- **Fail safe and loud.** Malformed input, failed deliveries and failed writes are logged and counted; a corrupt baseline stops startup instead of being silently discarded.
- **Untrusted input everywhere.** Network data, MRT files and relationship files are parsed defensively with explicit size limits. The crate forbids `unsafe` code.
- **Receive-only.** Pathology never advertises routes; the passive BGP listener sends only OPEN, KEEPALIVE and NOTIFICATION.
- **Optional neighbours never block.** The Notary lookup is cached, concurrency-limited and time-boxed; alert delivery runs in the llcforge-alert dispatcher, off the detector loop.
- **Secrets from the environment.** Tokens and keys are read from environment variables, never from config files or logs.
- **Portable.** Linux, macOS and Windows; no OpenSSL or other C libraries (rustls/ring).

## Data flow

```mermaid
flowchart LR
  R1[Router A] -- BMP/TCP --> C[collector.rs]
  R2[Router B] -- BGP/TCP receive-only --> G[bgp_listener.rs]
  F[(BMP capture)] --> P[replay.rs]
  MRT[(MRT dumps)] --> I[mrt.rs import] --> B
  C -- bmp.rs + bgp.rs --> Q[[bounded channel]]
  G -- bgp.rs --> Q
  Q --> D[detector.rs]
  P --> D
  B[(baseline.json)] <--> D
  REL[(CAIDA as-rel)] --> D
  D --> RIB[rib.rs RIB + history]
  RIB --> H[(history/*.jsonl)]
  RIB --> API[api.rs /v1/* + web UI]
  D --> AL[alerts.rs]
  AL -. time-boxed .-> N[Notary /v1/validity]
  AL --> K[llcforge-alert dispatcher, queue, sinks]
  D --> M[/metrics /healthz /readyz]
```

## Modules

| File | Responsibility |
|---|---|
| `src/main.rs` | CLI (`run`, `check`, `replay`, `import-mrt`, `silence`, `service`), daemon wiring, event loop, periodic save + decay + history prune, configuration reload, graceful shutdown. |
| `src/config.rs` | TOML config via serde (`deny_unknown_fields`), durations, startup validation (collectors, peers, prefixes, listener collisions, `*_env` names, Notary URL). Embeds llcforge-alert `[alerts]`, `[silences]`, `[health]`. |
| `src/collector.rs` | BMP TCP listener; allowlist, one task per router, per-session `SessionState`, router up/down events. |
| `src/bgp_listener.rs` | Passive BGP: OPEN negotiation (4-byte AS, MP, ADD-PATH receive), peer ASN / hold time / BGP ID checks, keepalives from a separate reader task, UPDATEs turned into the same events as BMP Route Monitoring. |
| `src/bmp.rs` | RFC 7854 framing and parsing, Loc-RIB peer type (RFC 9069), Peer Up OPEN decoding and per-peer ADD-PATH / AS4 state, fallback ADD-PATH detection. |
| `src/bgp.rs` | UPDATE / OPEN parsing: attributes (`ORIGIN`, `AS_PATH`, `AS4_PATH` merge, `COMMUNITIES`, `LARGE_COMMUNITY`, MP_REACH / MP_UNREACH), ADD-PATH NLRI, capabilities incl. RFC 9072; OPEN / KEEPALIVE / NOTIFICATION encoders. |
| `src/wire.rs` | Bounds-checked big-endian cursor shared by all parsers. |
| `src/baseline.rs` | Weighted per-prefix histograms (origins, upstreams, paths, path lengths, communities), key cap, exponential decay, JSON persistence (temp file + `fsync` + rename). |
| `src/detector.rs` | Findings (see below), RIB and history updates, upstream tracking, leak checks, session tracking. |
| `src/leak.rs` | CAIDA as-rel parser and valley-free check. |
| `src/sessions.rs` | Session down / up / flap tracking. |
| `src/rib.rs` | Current routes per router/peer/path id (size-capped, watched prefixes always kept) and the bounded, day-file-persisted route history. |
| `src/notary.rs` | Notary client: cache (5 min, 10k entries), 16 concurrent lookups, per-lookup timeout, response size and value checks. |
| `src/alerts.rs` | Finding / session event to `llcforge.alert.v1` conversion with stable ids, logging, RPKI enrichment task, reload-safe handle. |
| `src/api.rs` | Read-only route API, embedded web UI (`web/`), management router; security headers, concurrency cap, timeouts, optional bearer token. |
| `src/mrt.rs` | MRT reader (TABLE_DUMP_V2 incl. ADD-PATH subtypes, BGP4MP / BGP4MP_ET), gzip, 16 MiB record cap. |
| `src/replay.rs` | Offline BMP replay and MRT import into the baseline. |
| `src/metrics.rs` | Pathology counters in Prometheus text format. |
| `crates/llcforge-alert` | Vendored shared kit (sinks, queue, silences, health, reload, logging, service). Updated with `sync.py`, not edited here. |

## Detection rules

| Finding | Trigger | Severity |
|---|---|---|
| `new_origin` | Origin not in `expected_origins` (when set) | `critical`, never downgraded |
| `new_origin` | No `expected_origins`, origin never seen in the baseline | `critical` |
| `new_upstream` | First-hop ASN never seen in the baseline | `warning` |
| `prepend_change` | Unknown path that equals a known path once prepends are collapsed | `warning` |
| `path_length_change` | Unknown path whose length differs from every known length by `path_length_delta`+ | `warning` |
| `path_change` | Any other unknown path (origin and upstream known) | `warning` |
| `community_change` | Standard / large community never seen on the prefix | `warning` |
| `more_specific` | Announcement inside a watched prefix with a longer mask | `critical`, or `info` if the origin is expected / known |
| `withdrawn` | A peer withdraws a watched prefix it had announced | `warning` |
| `route_leak` | Valley-free violation on a watched prefix (or more-specific) | `warning` |
| `upstream_lost` | A first-hop upstream disappears from all current routes of a watched prefix; resolved when it returns | `warning` |
| `session_down` | BMP router feed closed, BMP Peer Down (except "de-configured"), passive BGP session closed; resolved on reconnect | `warning` |
| `peer_flap` | `flap_threshold` downs inside `flap_window` | `warning` |

A baseline is mature once `learning_window` has elapsed since the first observation and at least `min_observations` announcements were seen; baseline-based findings are `info` (`learning = true`) before that. New values are learned as they are observed, so a deviation is reported once (subject to dedup) and then becomes part of the baseline. With `half_life` every weight decays by `0.5^(age / half_life)` at each save, and keys below 0.125 are forgotten.

Alert ids are stable per condition (`pathology:<kind>:<prefix>:<discriminator>`), so the dispatcher deduplicates repeats and pairs resolutions with their alerts. When Notary is configured, a finding with an origin ASN is enriched in a spawned task (time-boxed by `notary.timeout_ms`) before it is sent; findings without RPKI state are still sent.

## Trust boundaries

- Router -> BMP collector: BMP has no authentication. Only `allowed_peers` may connect (deny by default); run it on a management network or behind an ACL.
- Router -> passive BGP listener: only configured peer addresses are accepted and the OPEN must carry the configured ASN; TCP-MD5 is not available (see README Roadmap), so restrict the port with ACLs / firewalls.
- Parsers: every BMP / BGP / MRT length is checked before allocation; malformed input closes that session (or skips that MRT record), never the process.
- Route API (`127.0.0.1:8180` by default): read-only, optional bearer token (constant-time digest comparison), strict CSP and other security headers, 64 concurrent requests, 10 s timeout, 1 KiB body limit, query results capped (1000 events, 100k prefixes). It exposes routing data your routers already see; treat it as internal.
- Web UI: static files embedded at build time; DOM built with `textContent` only (no HTML injection), no external requests; the token stays in page memory.
- Management listener: `/metrics`, `/healthz`, `/readyz` are unauthenticated; `/v1/silences` and `/v1/reload` require bearer tokens and are only mounted when configured.
- Notary: outbound only, no redirects, response size and value validated; the bearer token comes from the environment.
- Alert sinks: see the llcforge-alert README (HTTPS, HMAC signing, secrets from the environment, URLs stripped from errors).

## Failure modes

| Situation | Behaviour |
|---|---|
| BMP router disconnects | `session_down` alert; its routes leave the RIB (upstream loss is evaluated); reconnect resolves the alert and replays the RIB. |
| BMP Peer Down | `session_down` for that peer; its routes leave the RIB; no `withdrawn` alerts for stale routes. |
| Passive BGP error (bad OPEN, hold timer, malformed UPDATE) | NOTIFICATION sent, session closed, `session_down` alert if it had been established. |
| Malformed or oversized BMP message | Session closed, `pathology_bmp_parse_errors_total` incremented; other sessions unaffected. |
| RIB reaches `rib.max_routes` | New routes for unwatched prefixes are not stored (counted); watched prefixes are always stored. |
| History write fails | Logged and counted; events stay in memory; the day file is reopened on the next event. |
| Notary slow or down | Lookup times out (`notary.timeout_ms`), finding sent without RPKI state, counted in `pathology_notary_lookups_total{result="error"}`. |
| Alert sink unreachable | Retries, persistent queue and redelivery in llcforge-alert; the detector loop is never blocked. |
| Invalid configuration on reload | Error logged; the running configuration stays active. Listener or `data_dir` changes need a restart. |
| Corrupt `baseline.json` | Startup fails with a clear error instead of silently relearning. |

## Runtime model

- Tokio multi-threaded runtime; one task per BMP session and per BGP session (plus a reader task so keepalives never interrupt a partial read).
- A single detector loop owns the baseline and session state; collectors feed it through a bounded channel (capacity 4096), which applies TCP backpressure instead of dropping routes. The RIB and history are shared with the API through `RwLock`s with short critical sections.
- Periodic save (`storage.save_interval`): baseline decay + atomic write, history flush and retention prune.
- Graceful shutdown on Ctrl+C / `SIGTERM` / service stop: listeners stop, the baseline and history are saved, the alert dispatcher drains (10 s limit).

## Known limitations

See the Roadmap section of the README: no TCP-MD5, no RFC 7606 treat-as-withdraw, passive accept-only BGP, no MRT bzip2 / TABLE_DUMP v1, no BMP Route Mirroring. Pre-policy and post-policy feeds of the same peer are both counted as observations.

## Repository layout

```
Pathology/
├── .github/workflows/        CI (Linux, macOS, Windows), release, dependabot
├── assets/                   logos, icons, README images
├── crates/llcforge-alert/    vendored shared alerting kit (sync.py)
├── deploy/                   Grafana dashboard, Prometheus rules, Helm chart
├── packaging/                deb/rpm metadata, systemd, launchd, Homebrew, Scoop, winget, Windows service
├── src/                      application source (see Modules)
├── tests/fixtures/           demo BMP capture used by replay and tests
├── web/                      embedded web UI (HTML, JS, CSS)
├── Dockerfile, docker-compose.yml
├── pathology.example.toml    example configuration
├── ARCHITECTURE.md           this file
├── README.md                 English documentation
└── README.tr.md              Turkish documentation
```

## Related tools

- [Vigil](https://github.com/LLCForge/Vigil): Real-time origin hijack detection over public RIPE RIS and RouteViews feeds.
- [Notary](https://github.com/LLCForge/Notary): RPKI Route Origin Validation; Pathology calls its `/v1/validity`, Notary reads Pathology's `/v1/origins`.
- [Catchment](https://github.com/LLCForge/Catchment): anycast catchment monitor; reads Pathology's `/v1/routes` on a catchment shift.
- [Event Horizon](https://github.com/LLCForge/Event-Horizon): Automated RTBH; may read Pathology's API to verify blackhole propagation.
