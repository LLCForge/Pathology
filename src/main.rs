#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use llcforge_beacon::cli::{run_silence_command, ServiceCommand, SilenceCommand};
use llcforge_beacon::{
    health_router, reload_router, run_service_command, silences_router, ApiToken, Dispatcher,
    DispatcherOptions, Readiness, ReloadSignal, ServiceSpec, Shutdown, SilenceStore,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use pathology::alerts::{Alerter, TOOL};
use pathology::api::{self, AlertMetrics};
use pathology::baseline::Baseline;
use pathology::bgp_listener::{self, ListenerConfig};
use pathology::collector::{self, Event};
use pathology::config::{Config, HistoryScope, LogFormat};
use pathology::detector::{Detector, DetectorConfig, Severity};
use pathology::leak::AsRelationships;
use pathology::metrics::{inc, METRICS};
use pathology::notary::NotaryClient;
use pathology::replay;
use pathology::rib::{self, History, Rib};

const SPEC: ServiceSpec = ServiceSpec {
    bin: "pathology",
    display_name: "Pathology",
    description: "BGP route monitor for your own routers: BMP and passive BGP collector, learned baselines, deviation alerts",
};

#[derive(Parser)]
#[command(
    name = "pathology",
    version,
    about = "BGP route monitor for your own routers (BMP and passive BGP)"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, global = true, default_value = "pathology.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the collectors, detector, API and alerting in the foreground (default).
    Run,
    /// Validate the configuration and every referenced secret, then exit.
    Check,
    /// Replay a raw BMP capture file offline and print findings.
    Replay {
        /// File containing concatenated BMP messages.
        file: PathBuf,
        /// Print every finding, including info-level ones.
        #[arg(long)]
        all: bool,
    },
    /// Seed the baseline from MRT RIB dumps / update files (TABLE_DUMP_V2,
    /// BGP4MP; .gz accepted). Stop the running service first.
    ImportMrt {
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Manage alert silences / maintenance windows.
    Silence {
        #[command(subcommand)]
        cmd: SilenceCommand,
    },
    /// Install, remove or run as a system service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCommand,
    },
}

fn init_logging(cfg: &Config, quiet: bool) -> Result<()> {
    let format = match cfg.log.format {
        LogFormat::Text => llcforge_beacon::LogFormat::Text,
        LogFormat::Json => llcforge_beacon::LogFormat::Json,
    };
    let level = if quiet {
        "warn"
    } else {
        cfg.log.level.as_str()
    };
    llcforge_beacon::init_logging(format, level, None)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = dispatch(cli);
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            init_logging(&Config::load(&cli.config)?, false)?;
            llcforge_beacon::service::run_foreground(cli.config, daemon)
        }
        Command::Service { cmd } => {
            if !matches!(cmd, ServiceCommand::Uninstall) {
                let cfg = Config::load(&cli.config)?;
                // Under the service manager logging is configured once, here.
                if matches!(cmd, ServiceCommand::Run) {
                    init_logging(&cfg, false)?;
                }
            }
            let config = std::path::absolute(&cli.config).unwrap_or(cli.config);
            run_service_command(&SPEC, cmd.into_action(config), daemon)
        }
        Command::Check => check(&Config::load(&cli.config)?),
        Command::Replay { file, all } => {
            let cfg = Config::load(&cli.config)?;
            init_logging(&cfg, true)?;
            replay_file(&cfg, &file, all)
        }
        Command::ImportMrt { files } => {
            let cfg = Config::load(&cli.config)?;
            init_logging(&cfg, true)?;
            import_mrt(&cfg, &files)
        }
        Command::Silence { cmd } => {
            let cfg = Config::load(&cli.config)?;
            run_silence_command(cmd, &cfg.silences.path_or(&cfg.storage.data_dir()))
        }
    }
}

fn detector_config(cfg: &Config) -> Result<DetectorConfig> {
    let mut d = DetectorConfig::new(
        cfg.watch.clone(),
        cfg.baseline.learning_window.as_secs(),
        cfg.baseline.min_observations,
    );
    d.half_life = cfg.baseline.half_life.map(|h| h.as_secs());
    d.path_length_delta = cfg.detect.path_length_delta;
    d.community_changes = cfg.detect.community_changes;
    d.local_asn = cfg.local_asn();
    d.history_all = cfg.history.scope == HistoryScope::All;
    d.flap_threshold = cfg.sessions.flap_threshold;
    d.flap_window = cfg.sessions.flap_window.as_secs();
    if let Some(path) = &cfg.detect.relationships_file {
        let rels = AsRelationships::load(path)?;
        info!(file = %path.display(), links = rels.len(), "AS relationships loaded");
        d.relationships = Some(Arc::new(rels));
    }
    Ok(d)
}

fn notary_client(cfg: &Config) -> Result<Option<Arc<NotaryClient>>> {
    let Some(n) = &cfg.notary else {
        return Ok(None);
    };
    let token = n
        .token_env
        .as_deref()
        .map(llcforge_beacon::env_secret)
        .transpose()?;
    Ok(Some(Arc::new(NotaryClient::new(
        &n.url,
        token,
        Duration::from_millis(n.timeout_ms),
    )?)))
}

fn start_dispatcher(
    cfg: &Config,
    data_dir: &Path,
    silences: &Arc<SilenceStore>,
) -> Result<Dispatcher> {
    Dispatcher::start(
        &cfg.alerts,
        DispatcherOptions {
            tool: TOOL.into(),
            data_dir: Some(data_dir.to_path_buf()),
            silences: Some(silences.clone()),
            http: None,
        },
    )
    .context("starting alert dispatcher")
}

fn check(cfg: &Config) -> Result<()> {
    detector_config(cfg)?;
    notary_client(cfg)?;
    if let Some(var) = &cfg.api.token_env {
        ApiToken::from_env(var).with_context(|| format!("api.token_env {var}"))?;
    }
    for var in [&cfg.silences.api_token_env, &cfg.health.admin_token_env]
        .into_iter()
        .flatten()
    {
        ApiToken::from_env(var).with_context(|| format!("admin token {var}"))?;
    }
    // Building the dispatcher reads every sink secret; nothing is sent.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut alerts = cfg.alerts.clone();
        alerts.queue.persistent = false;
        let d = Dispatcher::start(
            &alerts,
            DispatcherOptions {
                tool: TOOL.into(),
                ..DispatcherOptions::default()
            },
        )
        .context("alert sinks")?;
        d.shutdown(Duration::from_millis(100)).await;
        anyhow::Ok(())
    })?;
    println!(
        "config OK: {} watched prefixes, {} BMP routers, {} passive BGP peers, {} alert sinks",
        cfg.watch.len(),
        cfg.collector
            .bmp
            .as_ref()
            .map_or(0, |b| b.allowed_peers.len()),
        cfg.collector.bgp.as_ref().map_or(0, |b| b.peers.len()),
        cfg.alerts.sinks.len()
    );
    Ok(())
}

fn replay_file(cfg: &Config, file: &Path, all: bool) -> Result<()> {
    let size = std::fs::metadata(file)
        .with_context(|| format!("reading {}", file.display()))?
        .len();
    anyhow::ensure!(
        size <= replay::MAX_CAPTURE_BYTES,
        "{} is larger than {} bytes",
        file.display(),
        replay::MAX_CAPTURE_BYTES
    );
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    // Replay never touches the persisted baseline or history and never sends alerts.
    let mut dcfg = detector_config(cfg)?;
    dcfg.half_life = None;
    let mut detector = Detector::with(
        dcfg,
        Baseline::default(),
        Arc::new(RwLock::new(Rib::new(cfg.rib.max_routes))),
        Arc::new(RwLock::new(History::memory(
            cfg.history.max_events,
            u64::MAX,
        ))),
    );
    let result = replay::replay(&data, &mut detector)?;
    let min = if all {
        Severity::Info
    } else {
        Severity::Warning
    };
    let mut lines: Vec<(u64, String)> = result
        .findings
        .iter()
        .filter(|f| f.severity >= min)
        .map(|f| (f.timestamp, f.to_string()))
        .chain(result.sessions.iter().map(|s| (s.timestamp, s.to_string())))
        .collect();
    lines.sort_by_key(|(t, _)| *t);
    for (_, l) in &lines {
        println!("{l}");
    }
    let count = |s: Severity| result.findings.iter().filter(|f| f.severity == s).count();
    println!(
        "replayed {} BMP messages: {} critical, {} warning, {} info, {} session events ({} shown, min_severity={})",
        result.messages,
        count(Severity::Critical),
        count(Severity::Warning),
        count(Severity::Info),
        result.sessions.len(),
        lines.len(),
        min.as_str()
    );
    Ok(())
}

fn import_mrt(cfg: &Config, files: &[PathBuf]) -> Result<()> {
    let data_dir = cfg.storage.data_dir();
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    let path = Baseline::path_in(&data_dir);
    let mut baseline = Baseline::load(&path)?;
    let (stats, learned) = replay::import_mrt(
        files,
        &cfg.watch,
        &mut baseline,
        cfg.baseline.half_life.map(|h| h.as_secs()),
        unix_now(),
    )?;
    baseline.save(&path)?;
    println!(
        "imported {} files: {} MRT records, {} routes, {} learned for watched prefixes ({} records skipped, {} ignored); baseline saved to {}",
        files.len(),
        stats.records,
        stats.routes,
        learned,
        stats.skipped,
        stats.ignored,
        path.display()
    );
    Ok(())
}

fn daemon(config: PathBuf, shutdown: Shutdown) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting Tokio runtime")?
        .block_on(run(config, shutdown))
}

fn save_state(detector: &mut Detector, path: &Path) {
    detector.decay(unix_now());
    if let Err(e) = detector.baseline().save(path) {
        inc(&METRICS.baseline_saves_failed);
        error!(error = %format!("{e:#}"), "saving baseline failed");
    }
    let h = detector.history();
    let mut h = rib::write(&h);
    h.flush();
    h.prune(unix_now());
}

async fn bind(what: &str, addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {what} listener {addr}"))
}

fn listeners(cfg: &Config) -> Vec<Option<SocketAddr>> {
    vec![
        cfg.collector.bmp.as_ref().map(|b| b.listen),
        cfg.collector.bgp.as_ref().map(|b| b.listen),
        cfg.api.enabled.then_some(cfg.api.listen),
        cfg.management_listen(),
    ]
}

async fn run(path: PathBuf, mut shutdown: Shutdown) -> Result<()> {
    let mut cfg = Config::load(&path)?;
    let data_dir = cfg.storage.data_dir();
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;
    let baseline_path = Baseline::path_in(&data_dir);
    let now = unix_now();
    let rib = Arc::new(RwLock::new(Rib::new(cfg.rib.max_routes)));
    let retention = cfg.history.retention.as_secs();
    let history = if cfg.history.persist {
        History::open(
            data_dir.join("history"),
            cfg.history.max_events,
            retention,
            now,
        )?
    } else {
        History::memory(cfg.history.max_events, retention)
    };
    let history = Arc::new(RwLock::new(history));
    let mut detector = Detector::with(
        detector_config(&cfg)?,
        Baseline::load(&baseline_path)?,
        rib.clone(),
        history.clone(),
    );
    detector.decay(now);

    let silences = Arc::new(SilenceStore::open(cfg.silences.path_or(&data_dir))?);
    let readiness = Readiness::new();
    readiness.register("collector");
    let mut dispatcher = Some(start_dispatcher(&cfg, &data_dir, &silences)?);
    let alert_metrics: AlertMetrics = Arc::new(RwLock::new(
        dispatcher
            .as_ref()
            .map(Dispatcher::metrics)
            .context("dispatcher")?,
    ));
    let alerter = Alerter::new(
        dispatcher
            .as_ref()
            .map(Dispatcher::handle)
            .context("dispatcher")?,
        notary_client(&cfg)?,
    );
    let mut reload = ReloadSignal::standard(Some(path.clone()))?;

    let stop = |s: &Shutdown| {
        let mut s = s.clone();
        async move { s.wait().await }
    };
    if let Some(addr) = cfg.management_listen() {
        let mut admin = health_router(readiness.clone());
        if let Some(var) = &cfg.silences.api_token_env {
            admin = admin.merge(silences_router(silences.clone(), ApiToken::from_env(var)?));
        }
        if let Some(var) = &cfg.health.admin_token_env {
            admin = admin.merge(reload_router(reload.trigger(), ApiToken::from_env(var)?));
        }
        let listener = bind("management", addr).await?;
        info!(listen = %addr, "management endpoint ready: /metrics /healthz /readyz");
        let router = api::management_router(alert_metrics.clone(), admin);
        let sd = stop(&shutdown);
        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(sd)
                .await
        });
    }
    if cfg.api.enabled {
        let token = cfg
            .api
            .token_env
            .as_deref()
            .map(ApiToken::from_env)
            .transpose()?;
        let listener = bind("API", cfg.api.listen).await?;
        info!(listen = %cfg.api.listen, auth = token.is_some(), "route API and web UI ready");
        let router = api::api_router(rib.clone(), history.clone(), token);
        let sd = stop(&shutdown);
        tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(sd)
                .await
        });
    }

    let (tx, mut rx) = mpsc::channel(4096);
    let mut tasks = Vec::new();
    if let Some(bmp) = &cfg.collector.bmp {
        let listener = bind("BMP", bmp.listen).await?;
        let allowed = bmp.allowed_peers.iter().map(|a| a.to_canonical()).collect();
        info!(listen = %bmp.listen, routers = bmp.allowed_peers.len(), "BMP collector listening");
        tasks.push(tokio::spawn(collector::run(listener, allowed, tx.clone())));
    }
    if let Some(bgp) = &cfg.collector.bgp {
        let listener = bind("BGP", bgp.listen).await.context(
            "port 179 needs CAP_NET_BIND_SERVICE or root on Linux; use a port above 1023 or grant the capability",
        )?;
        let lc = ListenerConfig {
            local_asn: bgp.local_asn,
            router_id: bgp.router_id,
            hold_time: bgp.hold_time,
            peers: bgp
                .peers
                .iter()
                .map(|p| (p.address.to_canonical(), p.asn))
                .collect::<HashMap<_, _>>(),
        };
        info!(listen = %bgp.listen, peers = bgp.peers.len(), "passive BGP listener ready (receive-only)");
        tasks.push(tokio::spawn(bgp_listener::run(listener, lc, tx.clone())));
    }
    drop(tx);
    readiness.set("collector", true);
    info!(watches = cfg.watch.len(), data_dir = %data_dir.display(), "Pathology running");

    let mut save_tick = tokio::time::interval(cfg.storage.save_interval);
    save_tick.tick().await;
    loop {
        tokio::select! {
            () = shutdown.wait() => break,
            Some(ev) = rx.recv() => {
                let now = unix_now();
                let findings = match ev {
                    Event::Message { router, msg } => detector.handle(router, &msg, now),
                    Event::RouterUp(router) => {
                        detector.router_up(router, now);
                        Vec::new()
                    }
                    Event::RouterDown { router, reason } => detector.router_down(router, &reason, now),
                };
                for f in findings {
                    alerter.finding(f);
                }
                for s in detector.drain_sessions() {
                    alerter.session(&s);
                }
            }
            _ = save_tick.tick() => save_state(&mut detector, &baseline_path),
            Some(reason) = reload.recv() => {
                info!(?reason, "reloading configuration");
                let new = Config::load(&path).and_then(|c| {
                    let d = detector_config(&c)?;
                    let n = notary_client(&c)?;
                    Ok((c, d, n))
                });
                let (new, dcfg, notary) = match new {
                    Ok(x) => x,
                    Err(e) => {
                        error!(error = %format!("{e:#}"), "invalid configuration; keeping the running one");
                        continue;
                    }
                };
                if listeners(&new) != listeners(&cfg) || new.storage.data_dir() != data_dir {
                    warn!("listener addresses or data_dir changed; restart Pathology to apply them");
                }
                if let Some(d) = dispatcher.take() {
                    d.shutdown(Duration::from_secs(5)).await;
                }
                let d = match start_dispatcher(&new, &data_dir, &silences) {
                    Ok(d) => {
                        detector.reconfigure(dcfg);
                        alerter.replace(d.handle(), notary);
                        cfg = new;
                        d
                    }
                    Err(e) => {
                        error!(error = %format!("{e:#}"), "new alert configuration failed; keeping the running one");
                        let d = start_dispatcher(&cfg, &data_dir, &silences)?;
                        alerter.replace(d.handle(), notary_client(&cfg)?);
                        d
                    }
                };
                *rib::write(&alert_metrics) = d.metrics();
                dispatcher = Some(d);
                info!("configuration reloaded");
            }
        }
    }

    info!("shutting down");
    readiness.set("collector", false);
    for t in &tasks {
        t.abort();
    }
    save_state(&mut detector, &baseline_path);
    if let Some(d) = dispatcher {
        d.shutdown(Duration::from_secs(10)).await;
    }
    Ok(())
}
