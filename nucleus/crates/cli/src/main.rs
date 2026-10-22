//! fakenet-nucleus: runs the listeners, links to the Camel daemon, captures everything

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use fakenet_capture::Capture;
use fakenet_cli::{serve_control, Config, Control};
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
    /// Remove any diversion left by a run that was killed, and the outbound block that
    /// `[diverter] block_after_stop` leaves after a stop, and exit
    #[arg(long)]
    restore_network: bool,
    /// With --restore-network: remove the diversion only, keeping outbound traffic blocked
    #[arg(long, requires = "restore_network")]
    keep_block: bool,
    /// Render an events.jsonl as an HTML report (to --output, default report.html), and exit
    #[arg(long, value_name = "EVENTS")]
    report: Option<PathBuf>,
    /// Write an events.jsonl's indicators (CSV, STIX 2.1, MISP) to the --output folder
    /// (default: the events file's folder), and exit
    #[arg(long, value_name = "EVENTS")]
    indicators: Option<PathBuf>,
    /// Output file for --report or --import-fakenet-ini (a folder for --indicators)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Convert a FakeNet-NG config (default.ini) to this nucleus's TOML (to --output, default
    /// stdout), and exit
    #[arg(long, value_name = "INI")]
    import_fakenet_ini: Option<PathBuf>,
    /// Analyse one sample: start everything, run SAMPLE, stop when it exits (plus a grace
    /// period) or at --timeout, in a capture folder of its own with a run.json summary.
    /// This RUNS the sample: only inside the analysis VM.
    #[arg(long, value_name = "SAMPLE")]
    run: Option<PathBuf>,
    /// Seconds before a --run sample is killed and the run ends
    #[arg(long, default_value_t = 120, requires = "run")]
    timeout: u64,
    /// An argument for the --run sample (repeat for several)
    #[arg(long = "sample-arg", value_name = "ARG", requires = "run")]
    sample_args: Vec<String>,
    /// The user the --run sample runs as (Unix). Required when the nucleus runs as root;
    /// `--run-as root` keeps root explicitly
    #[arg(long, value_name = "USER", requires = "run")]
    run_as: Option<String>,
    /// Generate a Camel rule (YAML) replaying a HAR recording (to --output, default stdout)
    #[arg(long, value_name = "HAR")]
    rules_from_har: Option<PathBuf>,
    /// Send a capture's events to the daemon and print what the current rules decide
    #[arg(long, value_name = "EVENTS")]
    replay: Option<PathBuf>,
    /// Compare two runs (capture folders or events.jsonl files): what only one of them
    /// contacted, asked, sent or triggered; JSON to --output if given; and exit
    #[arg(long, num_args = 2, value_names = ["A", "B"])]
    diff: Vec<PathBuf>,
    /// Infer the structure of unknown (raw) client messages per destination: magic, length
    /// field, counter, encodings, XOR key; with --output, Wireshark Lua dissectors go there
    #[arg(long, value_name = "EVENTS")]
    infer: Option<PathBuf>,
    /// With --infer or --decode: every protocol, not only raw
    #[arg(long)]
    all_protocols: bool,
    /// Decode the client payloads of a capture with --transform steps, into --output
    /// (default: decoded/ next to the events)
    #[arg(long, value_name = "EVENTS")]
    decode: Option<PathBuf>,
    /// A --decode step, applied in order: base64, hex, xor:KEY, rc4:KEY (KEY hex or text:...),
    /// skip:N
    #[arg(long = "transform", value_name = "STEP")]
    transforms: Vec<String>,
    /// With --decode: only the destinations containing this (e.g. ":4444")
    #[arg(long = "only", value_name = "TEXT")]
    only: Option<String>,
    /// Write a new link secret to PATH (for `[daemon] secret_file` and the daemon's
    /// fakenet.link.secret-file), and exit
    #[arg(long, value_name = "PATH")]
    generate_secret: Option<PathBuf>,
    /// Learn a traffic model from pcap files or capture folders (their traffic*.pcap and
    /// wire*.pcap), written to --output (default model.json) for a `model` responder
    #[arg(long, num_args = 1.., value_name = "PCAP")]
    learn: Vec<PathBuf>,
    /// With --learn: add to this existing pack (and write there unless --output is given)
    #[arg(long, value_name = "PACK", requires = "learn")]
    merge: Option<PathBuf>,
    /// Summarise a model pack (protocols, exchanges, most frequent requests), and exit
    #[arg(long, value_name = "PACK")]
    model_info: Option<PathBuf>,
    /// Run the link to the daemon without a shared secret (any local process can then read
    /// the events or pose as the daemon); without it the nucleus refuses to start
    #[arg(long)]
    insecure_link: bool,
    /// Windows, internal: wait for process PID to exit, then block outbound traffic (the
    /// guard a diverting nucleus starts for itself)
    #[arg(long, value_name = "PID", hide = true)]
    block_after_exit: Option<u32>,
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
    if let Some(har) = &args.rules_from_har {
        let text = std::fs::read_to_string(har).with_context(|| format!("reading {}", har.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text).with_context(|| format!("parsing {}", har.display()))?;
        let yaml = fakenet_cli::har::rules(&value, &har.display().to_string())?;
        match &args.output {
            Some(path) => std::fs::write(path, yaml).with_context(|| format!("writing {}", path.display()))?,
            None => print!("{yaml}"),
        }
        return Ok(());
    }
    if let Some(events) = &args.replay {
        let config = Config::load(&args.config)?;
        let link = Link::start(config.link(config.secret()?.as_deref()));
        tokio::time::sleep(Duration::from_millis(500)).await; // Let the WebSocket connect
        let text = std::fs::read_to_string(events).with_context(|| format!("reading {}", events.display()))?;
        let records = text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok());
        for line in fakenet_cli::replay::replay(&link, records).await {
            println!("{line}");
        }
        return Ok(());
    }
    if let Some(events) = &args.report {
        let output = args.output.clone().unwrap_or_else(|| PathBuf::from("report.html"));
        fakenet_cli::write_report(&fakenet_capture::with_rotations(events), &output)?;
        println!("Wrote {}", output.display());
        return Ok(());
    }
    if !args.learn.is_empty() {
        let files = fakenet_cli::learn_inputs(&args.learn)?;
        anyhow::ensure!(!files.is_empty(), "no pcap files found in {:?}", args.learn);
        // With --transform, requests (of --only's "<protocol> :<port>" matches) are keyed by
        // their decoded content; a model responder then needs the same key_transforms
        let transforms = args.transforms.iter().map(|t| fakenet_model::transform::parse_transform(t)).collect::<anyhow::Result<Vec<_>>>()?;
        let only = args.only.clone();
        let decode = move |protocol: &str, port: u16, request: &[u8]| -> Option<Vec<u8>> {
            if transforms.is_empty() || only.as_deref().is_some_and(|o| !format!("{protocol} :{port}").contains(o)) {
                return None;
            }
            fakenet_model::transform::apply(&transforms, request).ok()
        };
        let mut pack = fakenet_model::learn_with(&files, &decode)?;
        let mut learned = None;
        if let Some(base) = &args.merge {
            learned = Some(pack.protocols.values().map(|p| p.exchanges).sum::<u64>());
            let mut merged = fakenet_model::Pack::load(base)?;
            merged.merge(&pack);
            merged.created = pack.created.clone();
            pack = merged;
        }
        let output = args.output.clone().or_else(|| args.merge.clone()).unwrap_or_else(|| PathBuf::from("model.json"));
        std::fs::write(&output, serde_json::to_string_pretty(&pack)?).with_context(|| format!("writing {}", output.display()))?;
        let exchanges: u64 = pack.protocols.values().map(|p| p.exchanges).sum();
        match learned {
            Some(new) => println!("Learned {new} exchanges from {} files; {} now holds {exchanges} ({} protocols)", files.len(), output.display(), pack.protocols.len()),
            None => println!("Learned {exchanges} exchanges ({} protocols) from {} files into {}", pack.protocols.len(), files.len(), output.display()),
        }
        return Ok(());
    }
    if let Some(path) = &args.model_info {
        println!("{}", serde_json::to_string_pretty(&fakenet_model::Pack::load(path)?.summary())?);
        return Ok(());
    }
    if let [a, b] = &args.diff[..] {
        let read = |path: &PathBuf| fakenet_cli::read_records(&fakenet_cli::diff::capture_files(path).into_iter().filter(|f| f.exists()).collect::<Vec<_>>());
        let (records_a, records_b) = (read(a)?, read(b)?);
        anyhow::ensure!(!records_a.is_empty() && !records_b.is_empty(), "no records in {} or {}", a.display(), b.display());
        let diff = fakenet_cli::diff::compare(&fakenet_cli::diff::behaviour(&records_a), &fakenet_cli::diff::behaviour(&records_b));
        if let Some(output) = &args.output {
            std::fs::write(output, serde_json::to_string_pretty(&diff)?)?;
        }
        print!("{}", fakenet_cli::diff::render(&diff, &a.display().to_string(), &b.display().to_string()));
        return Ok(());
    }
    if let Some(events) = &args.infer {
        let records = fakenet_cli::read_records(&fakenet_capture::with_rotations(events))?;
        let found = fakenet_cli::infer::infer(&records, args.all_protocols, args.output.as_deref())?;
        if found.as_object().is_none_or(|o| o.is_empty()) {
            println!("No {} client messages in {}", if args.all_protocols { "" } else { "raw" }, events.display());
        }
        println!("{}", serde_json::to_string_pretty(&found)?);
        return Ok(());
    }
    anyhow::ensure!(args.transforms.is_empty() && args.only.is_none() || args.decode.is_some() || !args.learn.is_empty(), "--transform and --only go with --decode or --learn");
    if let Some(events) = &args.decode {
        anyhow::ensure!(!args.transforms.is_empty(), "--decode needs at least one --transform (base64, hex, xor:KEY, rc4:KEY, skip:N)");
        let transforms = args.transforms.iter().map(|t| fakenet_cli::infer::parse_transform(t)).collect::<anyhow::Result<Vec<_>>>()?;
        let records = fakenet_cli::read_records(&fakenet_capture::with_rotations(events))?;
        let out = args.output.clone().unwrap_or_else(|| events.parent().unwrap_or(Path::new(".")).join("decoded"));
        let index = fakenet_cli::infer::decode(&records, &transforms, args.only.as_deref(), &out)?;
        let entries = index.as_array().map(Vec::len).unwrap_or(0);
        let failed = index.as_array().map(|a| a.iter().filter(|e| e["error"].is_string()).count()).unwrap_or(0);
        println!("Decoded {} of {entries} payloads into {} (index.json lists them)", entries - failed, out.display());
        return Ok(());
    }
    if let Some(events) = &args.indicators {
        let dir = args.output.clone().or_else(|| events.parent().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("."));
        let count = fakenet_cli::write_indicators(&fakenet_capture::with_rotations(events), &dir, None)?;
        println!("Wrote {count} indicators to {}/indicators.{{csv,stix.json,misp.json}}", dir.display());
        return Ok(());
    }
    if let Some(path) = &args.generate_secret {
        fakenet_cli::generate_secret(path)?;
        println!("Wrote a new link secret to {}", path.display());
        let absolute = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        println!("Use it on both sides:\n  nucleus config, [daemon]:  secret_file = \"{}\"\n  daemon:                    -Dfakenet.link.secret-file={}", absolute.display(), absolute.display());
        return Ok(());
    }
    if let Some(pid) = args.block_after_exit {
        return fakenet_diverter::block_after_exit(pid);
    }
    if args.restore_network {
        fakenet_diverter::restore(args.keep_block)?;
        println!("{}", if args.keep_block { "Network diversion removed (outbound traffic stays blocked)" } else { "Network diversion and outbound block removed" });
        return Ok(());
    }
    let mut config = Config::load(&args.config)?;
    let sample = match &args.run {
        Some(path) => Some(fakenet_cli::run::Sample::inspect(path, args.sample_args.clone())?),
        None => None,
    };
    let run_as = match &args.run_as {
        Some(name) => Some(fakenet_cli::run::RunAs::resolve(name)?),
        None => None,
    };
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions
    if sample.is_some() && run_as.is_none() && unsafe { libc::geteuid() } == 0 {
        anyhow::bail!("--run as root would give the sample root's power over the diversion and the capture: add --run-as USER (or --run-as root to accept that)");
    }
    if let Some(sample) = &sample {
        // Each run gets its own folder: <time>-<name>-<sha256 prefix>
        config.nucleus.capture_dir = config.nucleus.capture_dir.join(sample.folder_name());
        if config.explorer.enabled && config.explorer.samples.is_empty() {
            config.explorer.samples.push(sample.path.clone());
        }
    }
    let secret = config.secret()?;
    let link_configured = !config.daemon.websocket_url.is_empty() || !config.daemon.http_url.is_empty();
    if secret.is_none() && link_configured {
        anyhow::ensure!(
            args.insecure_link,
            "No [daemon] secret_file: any local process could read the events or pose as the daemon. Create a secret with \
             `fakenet-nucleus --generate-secret PATH`, set secret_file to it (and the daemon's fakenet.link.secret-file), \
             or pass --insecure-link"
        );
        tracing::warn!("--insecure-link: the link to the daemon is unauthenticated");
    }
    if args.check {
        config.known_fingerprints()?;
        if !config.yara.rules.is_empty() {
            let files = fakenet_capture::yara::rule_files(&config.yara.rules)?;
            let compiled = std::env::temp_dir().join(format!("fakenet-check-{}.yarc", std::process::id()));
            let result = fakenet_capture::yara::compile(&config.yara.yarac, &files, &compiled);
            let _ = std::fs::remove_file(&compiled);
            result.context("[yara]")?;
        }
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
    if !config.yara.rules.is_empty() {
        capture.enable_yara(&config.yara.rules, &config.yara.yara, &config.yara.yarac).context("[yara]")?;
    }
    let tls = Arc::new(match (&config.nucleus.ca_cert, &config.nucleus.ca_key) {
        (Some(cert), Some(key)) => {
            let (tls, created) = TlsAuthority::load_or_create(cert, key).context("[nucleus] ca_cert / ca_key")?;
            match created {
                true => tracing::info!("New interception CA saved to {} (install it in the VM once)", cert.display()),
                false => tracing::info!("Interception CA loaded from {}", cert.display()),
            }
            tls
        }
        _ => {
            tracing::warn!("No [nucleus] ca_cert / ca_key: a new interception CA this start; the VM must trust this start's ca.pem");
            TlsAuthority::generate()?
        }
    });
    // Analysts install this in the analysis VM so HTTPS interception is trusted
    let ca_path = capture.dir().join("ca.pem");
    std::fs::write(&ca_path, tls.ca_pem()).with_context(|| format!("writing {}", ca_path.display()))?;
    if config.nucleus.tls_keylog {
        let keys = capture.dir().join("tls-keys.log");
        tls.log_keys_to(&keys).with_context(|| format!("opening {}", keys.display()))?;
    }

    // From here on, dropping `diverter` (also on an early error return) restores the network
    let diverter = match config.diverter.enabled {
        true => Some(Diverter::start(&config.diverter, config.plan())?),
        false => None,
    };
    #[cfg(windows)]
    if diverter.is_some() && config.diverter.block_after_stop {
        start_exit_guard()?;
    }
    let explorer = match config.explorer.enabled {
        true => {
            let explorer = Arc::new(fakenet_explorer::Explorer::load(config.explorer.clone())?);
            let map = explorer.map();
            tracing::info!("Explorer on (rate {}); hints: {}", explorer.config().rate, map["hints"]);
            Some(explorer)
        }
        false => None,
    };
    let manual = config.manual.enabled.then(|| Arc::new(fakenet_listeners::manual::Manual::new(config.manual.clone())));
    if manual.is_some() {
        tracing::warn!("Live manual mode: matching requests wait up to {} ms for an answer from the dashboard", config.manual.timeout_ms);
    }
    let hooks = (!config.hooks.is_empty()).then(|| Arc::new(fakenet_listeners::hooks::Hooks::new(config.hooks.clone())));
    let link = Link::start(config.link(secret.as_deref()));
    let limits = Arc::new(fakenet_listeners::Limits::new(&config.limits));
    let ctx = Arc::new(Context {
        link: link.clone(),
        capture: capture.clone(),
        defaults: arc_swap::ArcSwap::from_pointee(config.defaults.clone()),
        tls,
        timeout: Duration::from_millis(config.nucleus.timeout_ms),
        first_data_timeout: Duration::from_millis(config.nucleus.first_data_timeout_ms),
        original: diverter.as_ref().and_then(Diverter::original_lookup),
        explorer: explorer.clone(),
        limits: limits.clone(),
        known_fingerprints: Arc::new(config.known_fingerprints()?),
        manual: manual.clone(),
        hooks: hooks.clone(),
        responders: fakenet_listeners::responders::build(&config.responders)?,
    });
    let server = Server::start(ctx.clone(), config.nucleus.bind, &config.listeners).await?;
    for (name, transport, address) in &server.bound {
        tracing::info!("{name}: {transport:?} {address}");
    }
    let health = tokio::net::TcpListener::bind(config.nucleus.health)
        .await
        .with_context(|| format!("binding the health endpoint to {}", config.nucleus.health))?;
    tracing::info!("health: http://{}/health; CA certificate: {}", config.nucleus.health, ca_path.display());
    let control = Arc::new(Control {
        link: link.clone(),
        listeners: server.bound.clone(),
        secret: secret.clone(),
        capture: capture.clone(),
        explorer: explorer.clone(),
        limits,
        manual: manual.clone(),
        hooks: hooks.clone(),
        sessions: Default::default(),
    });
    tracing::info!("dashboard: http://{}/dashboard{}", config.nucleus.health, if secret.is_some() { "?token=<the link secret>" } else { "" });
    let health_task = tokio::spawn(serve_control(health, control));
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

    // SIGHUP reloads [defaults] (the built-in responses) from the config file, live — no
    // restart, no dropped connections. Structural changes (listeners, bind, diverter, the
    // link, limits) still need a restart, and are reported as ignored.
    #[cfg(unix)]
    {
        let (ctx, config_path) = (ctx.clone(), args.config.clone());
        background.push(tokio::spawn(async move {
            let Ok(mut hangups) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else { return };
            while hangups.recv().await.is_some() {
                match Config::load(&config_path) {
                    Ok(reloaded) => {
                        ctx.defaults.store(std::sync::Arc::new(reloaded.defaults));
                        ctx.capture.log("config_reloaded", json!({ "source": config_path.display().to_string() }));
                        tracing::info!("Reloaded [defaults] from {} (structural changes need a restart)", config_path.display());
                    }
                    Err(e) => tracing::warn!("Ignoring the reload; {} is invalid: {e:#}", config_path.display()),
                }
            }
        }));
    }

    let outcome = match &sample {
        Some(sample) => Some(fakenet_cli::run::execute(sample, Duration::from_secs(args.timeout), &capture, run_as.as_ref(), shutdown_signal()).await),
        None => {
            shutdown_signal().await;
            None
        }
    };
    tracing::info!("shutting down");
    // Held requests get their proposed answers; paused processes stay paused (safer)
    if let Some(manual) = &manual {
        manual.release_all();
    }
    if let Some(hooks) = &hooks {
        for paused in hooks.paused() {
            tracing::warn!("Still paused by a hook (SIGSTOP): pid {}; resume with `kill -CONT {}`", paused["pid"], paused["pid"]);
        }
    }
    health_task.abort();
    drop(server);
    // A failure here must not cost the report, run.json or the indicators: report it, finish
    // the outputs, and fail at the end
    let mut stop_error = None;
    if let Some(diverter) = diverter {
        if let Err(e) = diverter.stop() {
            tracing::error!("Removing the diversion failed (check `iptables -t nat -S`): {e:#}");
            stop_error = Some(e);
        }
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
    // Payloads saved until the listeners stopped are scanned before the report
    capture.finish_scans();
    capture.log("nucleus_stopped", json!({ "daemon": link.health() }));
    let report = capture.dir().join("report.html");
    match fakenet_cli::write_report(&capture.event_files(), &report) {
        Ok(()) => tracing::info!("Report: {}", report.display()),
        Err(e) => tracing::warn!("Could not write the report: {e:#}"),
    }
    if let (Some(sample), Some(outcome)) = (&sample, &outcome) {
        let summary = fakenet_cli::run::summary(sample, outcome, &capture);
        std::fs::write(capture.dir().join("run.json"), serde_json::to_string_pretty(&summary)?)?;
    }
    // After run.json: the sample is linked to its indicators
    match fakenet_cli::write_indicators(&capture.event_files(), capture.dir(), None) {
        Ok(count) => tracing::info!("Indicators: {count} in {}", capture.dir().join("indicators.*").display()),
        Err(e) => tracing::warn!("Could not write the indicators: {e:#}"),
    }
    if let Some(outcome) = &outcome {
        println!("Run finished ({}): {}", outcome.reason, capture.dir().display());
    }
    // Background tasks may still hold the capture: write its queue out now
    capture.flush();
    match stop_error {
        Some(e) => Err(e.context("removing the diversion")),
        None => Ok(()),
    }
}

/// Windows: a detached copy of this executable that waits for us to exit, however we exit,
/// and then blocks outbound traffic (block_after_stop survives a crash or a kill)
#[cfg(windows)]
fn start_exit_guard() -> anyhow::Result<()> {
    use std::os::windows::process::CommandExt as _;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let exe = std::env::current_exe().context("finding this executable for the exit guard")?;
    let spawn = |flags: u32| {
        std::process::Command::new(&exe)
            .arg("--block-after-exit")
            .arg(std::process::id().to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(flags)
            .spawn()
    };
    // Out of our job if allowed (a scheduled task's job would kill it with us), else in it
    let guard = spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
        .or_else(|_| spawn(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP))
        .context("starting the exit guard (block_after_stop)")?;
    tracing::info!("Exit guard running (pid {}): if the nucleus dies, outbound traffic gets blocked", guard.id());
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
