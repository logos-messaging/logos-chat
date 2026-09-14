mod app;
mod transport;
mod ui;
mod utils;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use crossbeam_channel::Receiver;
use logos_chat::{
    AccountDirectory, ChatClient, ConversationStore, Event, GroupV2Config, LogosConfig, P2pConfig,
    RegistrationService, RegistryPublishMode, Transport,
};

use app::ChatApp;

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum TransportKind {
    File,
    LogosDelivery,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum GroupCommit {
    /// Fast on `file`, library default on the network.
    Auto,
    /// Always use fast commit timers.
    Fast,
    /// Always use the de-mls library default timing.
    Default,
}

/// Fast GroupV2 timing so `/add` commits in ~1s instead of ~60s — for local
/// demos and tests. These are the vetted values from the library's group
/// tests; they are deliberately aggressive and not appropriate for a
/// high-latency network (hence `--group-commit auto` keeps defaults there).
fn fast_group_v2_config() -> GroupV2Config {
    GroupV2Config {
        voting_delay: Duration::from_millis(50),
        consensus_timeout: Duration::from_millis(250),
        commit_batch_window: Duration::from_millis(500),
        freeze_duration: Duration::from_millis(500),
        proposal_expiration: Duration::from_millis(4000),
        ..GroupV2Config::default()
    }
}

/// Decide whether to override GroupV2 timing with fast commits: always for
/// `Fast`, never for `Default`, and — for `Auto` — only on the local file
/// transport.
fn group_v2_override(mode: GroupCommit, transport: TransportKind) -> Option<GroupV2Config> {
    let fast = match mode {
        GroupCommit::Fast => true,
        GroupCommit::Default => false,
        GroupCommit::Auto => matches!(transport, TransportKind::File),
    };
    fast.then(fast_group_v2_config)
}

#[derive(Parser, Debug)]
#[command(name = "chat-cli", about = "End-to-end encrypted terminal chat")]
struct Cli {
    /// Your identity name.
    #[arg(long, short)]
    name: String,

    /// Which delivery transport to use.
    #[arg(long, value_enum, default_value_t = TransportKind::File)]
    transport: TransportKind,

    /// How quickly group membership changes commit. `fast` makes `/add` commit
    /// in ~1s (great for local demos); `default` uses production de-mls timing.
    /// `auto` (the default) picks `fast` for `--transport file` and `default`
    /// otherwise, since fast timers are too aggressive for a high-latency network.
    #[arg(long, value_enum, default_value_t = GroupCommit::Auto)]
    group_commit: GroupCommit,

    /// Data directory (used for UI state and the default SQLite path).
    #[arg(long, default_value = "tmp/chat-cli-data")]
    data: PathBuf,

    /// Override the SQLite database path (defaults to `<data>/<name>.db`).
    #[arg(long)]
    db: Option<PathBuf>,

    // ── logos-delivery transport options ──────────────────────────────────────
    /// logos-delivery network preset (e.g. `logos.test`). When omitted, the
    /// preconfigured network preset is used.
    #[arg(long)]
    preset: Option<String>,

    /// TCP port for the embedded logos-delivery node. When omitted, the
    /// preconfigured port is used.
    #[arg(long)]
    port: Option<u16>,

    /// Write logs to a file instead of stderr (keeps TUI output clean).
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Initialize and immediately exit without launching the TUI (for CI).
    #[arg(long)]
    smoketest: bool,

    /// Override the Logos registry endpoint (account + keypackage store). When
    /// omitted, the preconfigured endpoint is used.
    /// Example: `--registry-url http://127.0.0.1:18080`.
    #[arg(long)]
    registry_url: Option<String>,

    /// How keypackage and account bundles are submitted to the store: over its
    /// HTTP POST API, or published on the delivery network for the store to
    /// pick up by subscription. Queries always use the HTTP API.
    #[arg(long, value_enum, default_value_t = RegistryPublishKind::Http)]
    registry_publish: RegistryPublishKind,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum RegistryPublishKind {
    Http,
    Delivery,
}

impl From<RegistryPublishKind> for RegistryPublishMode {
    fn from(kind: RegistryPublishKind) -> Self {
        match kind {
            RegistryPublishKind::Http => RegistryPublishMode::Http,
            RegistryPublishKind::Delivery => RegistryPublishMode::Delivery,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_logging(cli.log_file.as_deref())?;

    std::fs::create_dir_all(&cli.data).context("failed to create data directory")?;

    let db_str = db_path(&cli)?;

    match cli.transport {
        TransportKind::LogosDelivery => {
            let mut p2p_config = P2pConfig::default();
            if let Some(port) = cli.port {
                p2p_config.port = port;
            }
            if let Some(preset) = cli.preset.as_deref() {
                p2p_config.preset = preset.to_string();
            }

            println!(
                "Starting logos-delivery node (preset={})...",
                p2p_config.preset
            );
            println!("This may take a few seconds while connecting to the network.");

            let mut config = LogosConfig::new(db_str, "chat-cli");
            if let Some(registry_url) = cli.registry_url.as_deref() {
                config.set_registry_url(registry_url);
            }
            config.set_registry_publish_mode(cli.registry_publish.into());
            config.set_p2p_config(p2p_config);
            if let Some(group_v2) = group_v2_override(cli.group_commit, cli.transport) {
                // Demo/test-only fast timers; migrates once the library's
                // wallclock/timer abstraction replaces this raw config.
                #[allow(deprecated)]
                config.set_group_v2_config(group_v2);
            }
            let (client, events) = logos_chat::open(config)
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open chat client")?;

            println!("Node connected.");
            launch_tui(client, events, &cli)
        }
        // The file transport is a local-only path: it reuses the Logos service
        // stack (delegate identity, HTTP registry, encrypted storage) but swaps
        // the transport in via `open_with_transport`.
        TransportKind::File => {
            let transport_dir = cli.data.join("transport");
            let transport = transport::file::FileTransport::new(&transport_dir)
                .context("failed to create file transport")?;

            let mut config = LogosConfig::new(db_str, "chat-cli");
            if let Some(registry_url) = cli.registry_url.as_deref() {
                config.set_registry_url(registry_url);
            }
            config.set_registry_publish_mode(cli.registry_publish.into());
            if let Some(group_v2) = group_v2_override(cli.group_commit, cli.transport) {
                // Demo/test-only fast timers; migrates once the library's
                // wallclock/timer abstraction replaces this raw config.
                #[allow(deprecated)]
                config.set_group_v2_config(group_v2);
            }
            let (client, events) = logos_chat::open_with_transport(config, transport)
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open chat client")?;

            launch_tui(client, events, &cli)
        }
    }
}

/// Resolve the SQLite database path: `--db` if given, else `<data>/<name>.db`.
fn db_path(cli: &Cli) -> Result<String> {
    let path = cli
        .db
        .clone()
        .unwrap_or_else(|| cli.data.join(format!("{}.db", cli.name)));
    Ok(path
        .to_str()
        .context("db path contains non-UTF-8 characters")?
        .to_string())
}

fn launch_tui<T, R, S>(
    client: ChatClient<T, R, S>,
    events: Receiver<Event>,
    cli: &Cli,
) -> Result<()>
where
    T: Transport,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ConversationStore + Send,
{
    let mut app = ChatApp::new(client, events, &cli.name, &cli.data)?;

    if cli.smoketest {
        return Ok(());
    }

    let mut terminal = ui::init().context("failed to initialize terminal")?;
    let result = run_app(&mut terminal, &mut app);
    ui::restore().context("failed to restore terminal")?;
    result
}

fn run_app<T, R, S>(terminal: &mut ui::Tui, app: &mut ChatApp<T, R, S>) -> Result<()>
where
    T: Transport,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ConversationStore + Send,
{
    loop {
        app.process_incoming()?;
        terminal.draw(|frame| ui::draw(frame, app))?;
        if !ui::handle_events(app)? {
            break;
        }
    }
    Ok(())
}

fn setup_logging(log_file: Option<&Path>) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    if let Some(path) = log_file {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to create log file: {}", path.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(file)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("off"))
            .init();
    }

    Ok(())
}
