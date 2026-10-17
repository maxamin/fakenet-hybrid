//! fakenet-nucleus: runs the listeners, links to the Camel daemon, captures everything

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use fakenet_capture::Capture;
use fakenet_cli::{serve_health, Config};
use fakenet_diverter::Diverter;
use fakenet_link::Link;
use fakenet_listeners::{Context, Server, TlsAuthority};
use serde_json::json;

#[derive(Parser)]
#[command(version, about = "The FakeNet hybrid nucleus (lab use only)")]
struct Args {
    /// The TOML config
    #[arg(short, long, default_value = "config/fakenet.toml")]
    config: PathBuf,
    /// Validate the config and exit
    #[arg(long)]
    check: bool,
    /// Remove any diversion left by a run that was killed, and exit
    #[arg(long)]
    restore_network: bool,
    /// Render an events.jsonl as an HTML report (to --output, default report.html), and exit
    #[arg(long, value_name = "EVENTS")]
    report: Option<PathBuf>,
    /// Output file for --report or --import-fakenet-ini
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Convert a FakeNet-NG config (default.ini) to this nucleus's TOML (to --output, default
    /// stdout), and exit
    #[arg(long, value_name = "INI")]
    import_fakenet_ini: Option<PathBuf>,
    /// Write a new link secret to PATH (for `[daemon] secret_file` and the daemon's
    /// fakenet.link.secret-file), and exit
    #[arg(long, value_name = "PATH")]
    generate_secret: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    if let Some(ini) = &args.import_fakenet_ini {
        let text = std::fs::read_to_string(ini).with_context(|| format!("reading {}", ini.display()))?;
        let toml = fakenet_cli::import::convert(&text, ini.parent().unwrap_or(std::path::Path::new(".")))?;
        match &args.output {
            Some(path) => std::fs::write(path, toml).with_context(|| format!("writing {}", path.display()))?,
            None => print!("{toml}"),
        }
        return Ok(());
    }
    if let Some(events) = &args.report {
        let output = args.output.clone().unwrap_or_else(|| PathBuf::from("report.html"));
        fakenet_cli::write_report(std::slice::from_ref(events), &output)?;
        println!("Wrote {}", output.display());
        return Ok(());
    }
    if let Some(path) = &args.generate_secret {
        fakenet_cli::generate_secret(path)?;
        println!("Wrote a new link secret to {}", path.display());
        return Ok(());
    }
    if args.restore_network {
        fakenet_diverter::restore()?;
        println!("Network diversion removed");
        return Ok(());
    }
    let config = Config::load(&args.config)?;
    let secret = config.secret()?;
    if secret.is_none() {
        tracing::warn!("No [daemon] secret_file: the link to the daemon is unauthenticated");
    }
    if args.check {
        println!("{} is valid ({} listeners)", args.config.display(), config.listeners.len());
        return Ok(());
    }

    let capture = Capture::open_with(&config.nucleus.capture_dir, config.capture_limits())?;
    let _wire = match config.nucleus.wire_capture {
        true => {
            let sink = capture.clone();
            Some(fakenet_diverter::wire::WireCapture::start(Arc::new(move |packet: &[u8]| sink.wire_packet(packet)))?)
        }
        false => None,
    };
    let tls = Arc::new(TlsAuthority::generate()?);
    // Analysts install this in the analysis VM so HTTPS interception is trusted
    let ca_path = capture.dir().join("ca.pem");
    std::fs::write(&ca_path, tls.ca_pem()).with_context(|| format!("writing {}", ca_path.display()))?;

    // From here on, dropping `diverter` (also on an early error return) restores the network
    let diverter = match config.diverter.enabled {
        true => Some(Diverter::start(&config.diverter, config.plan())?),
        false => None,
    };
    let explorer = match config.explorer.enabled {
        true => {
            let explorer = Arc::new(fakenet_explorer::Explorer::load(config.explorer.clone())?);
            let map = explorer.map();
            tracing::info!("Explorer on (rate {}); hints: {}", explorer.config().rate, map["hints"]);
            Some(explorer)
        }
        false => None,
    };
    let link = Link::start(config.link(secret.as_deref()));
    let ctx = Arc::new(Context {
        link: link.clone(),
        capture: capture.clone(),
        defaults: config.defaults.clone(),
        tls,
        timeout: Duration::from_millis(config.nucleus.timeout_ms),
        first_data_timeout: Duration::from_millis(config.nucleus.first_data_timeout_ms),
        original: diverter.as_ref().and_then(Diverter::original_lookup),
        explorer: explorer.clone(),
    });
    let server = Server::start(ctx, config.nucleus.bind, &config.listeners).await?;
    for (name, transport, address) in &server.bound {
        tracing::info!("{name}: {transport:?} {address}");
    }
    let health = tokio::net::TcpListener::bind(config.nucleus.health)
        .await
        .with_context(|| format!("binding the health endpoint to {}", config.nucleus.health))?;
    tracing::info!("health: http://{}/health; CA certificate: {}", config.nucleus.health, ca_path.display());
    let health_task = tokio::spawn(serve_health(health, link.clone(), Arc::new(server.bound.clone()), secret.clone()));
    let mut background = Vec::new();
    if let Some(explorer) = &explorer {
        if let Some(dir) = config.explorer.coverage_dir.clone() {
            background.push(tokio::spawn(fakenet_cli::watch_coverage(explorer.clone(), dir, capture.clone())));
        }
        // The map, kept current for analysts (and the report)
        let (explorer, path) = (explorer.clone(), capture.dir().join("explorer-map.json"));
        background.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let _ = std::fs::write(&path, serde_json::to_string_pretty(&explorer.map()).unwrap_or_default());
            }
        }));
    }
    capture.log("nucleus_started", json!({ "listeners": server.bound.len(), "daemon": link.health() }));

    shutdown_signal().await;
    tracing::info!("shutting down");
    health_task.abort();
    drop(server);
    if let Some(diverter) = diverter {
        diverter.stop()?;
    }
    for task in background {
        task.abort();
    }
    if let Some(explorer) = &explorer {
        let path = capture.dir().join("explorer-map.json");
        if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&explorer.map()).unwrap_or_default()) {
            tracing::warn!("Could not write {}: {e}", path.display());
        }
    }
    capture.log("nucleus_stopped", json!({ "daemon": link.health() }));
    let report = capture.dir().join("report.html");
    match fakenet_cli::write_report(&capture.event_files(), &report) {
        Ok(()) => tracing::info!("Report: {}", report.display()),
        Err(e) => tracing::warn!("Could not write the report: {e:#}"),
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
