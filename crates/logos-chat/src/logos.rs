//! The opinionated Logos client.
//!
//! [`open`] commits to the Logos service stack so independently built clients
//! share the same production services instead of each re-deriving them: a
//! installation identity, the keypackage + account registry (queried over HTTP,
//! with submissions over HTTP or the delivery network), and encrypted
//! on-disk storage. The stack is generic over the transport — any
//! [`Transport`] can be injected via [`open_with_transport`] — and the
//! concrete [`LogosChatClient`] commits to the embedded logos-delivery node,
//! whose native `liblogosdelivery` link keeps this crate outside the
//! workspace's default members.
//!
//! [`LogosChatClient`] points at `ChatClient`, which lives in
//! `logos-generic-chat`, so Rust's inherent-impl rule keeps the open
//! constructors off the alias; they are crate-level functions ([`open`],
//! [`open_with_transport`]) taking the all-inclusive [`LogosConfig`] instead.

use components::{ContactRegistry, HttpAuthClient, RegistryPublishMode};
use crossbeam_channel::Receiver;
use embedded_logos_delivery::{EmbeddedLogosDelivery, P2pConfig};
use logos_account::AccountError;
use logos_account::AccountProvider;
use logos_account::AccountPublisher;
use logos_account::Ed25519VerifyingKey;

use logos_account::CHATSIGNER_CONTEXT;
use logos_generic_chat::SqliteStore;
use logos_generic_chat::StorageConfig;
use logos_generic_chat::{
    ChatClient, ChatClientBuilder, ClientError, DbKey, Event, GroupV2Config, IdentityMode,
    IdentityStore, Installation, PendingInstallation, Transport,
};

/// The endpoint for the account and keypackage registration service.
pub const REGISTRY_ENDPOINT: &str = "https://devnet.chat-kc.logos.co";

/// Configuration for opening a Logos client.
///
/// `db_path` (a per-client location) and `db_key` (a secret) are required and
/// never baked into the library. Everything else defaults: the identity to
/// [`IdentityMode::LoadOrCreate`], so reopening the same database reopens the
/// same installation; the registry endpoint to the baked-in Logos value; the
/// embedded node's p2p settings to [`P2pConfig::default`]; and the GroupV2
/// timing to the de-mls library defaults. Override them with
/// [`set_identity_mode`](Self::set_identity_mode),
/// [`set_registry_url`](Self::set_registry_url),
/// [`set_p2p_config`](Self::set_p2p_config), and
/// [`set_group_v2_config`](Self::set_group_v2_config).
pub struct LogosConfig {
    db_path: String,
    db_key: DbKey,
    identity_mode: IdentityMode,
    registry_url: String,
    registry_publish_mode: RegistryPublishMode,
    p2p_config: P2pConfig,
    group_v2_config: Option<GroupV2Config>,
}

impl LogosConfig {
    /// Config for the required per-client `db_path` and `db_key`. The registry
    /// endpoint defaults to the baked-in Logos value; override it with
    /// [`set_registry_url`](Self::set_registry_url).
    ///
    /// `db_key` is the 32 bytes the database is encrypted with, not a
    /// passphrase: deriving those bytes is the application's, since it is what
    /// knows whether they came from a prompt, a keychain or a hardware token.
    pub fn new(db_path: impl Into<String>, db_key: DbKey) -> Self {
        Self {
            db_path: db_path.into(),
            db_key,
            identity_mode: IdentityMode::default(),
            registry_url: REGISTRY_ENDPOINT.to_string(),
            registry_publish_mode: RegistryPublishMode::default(),
            p2p_config: P2pConfig::default(),
            group_v2_config: None,
        }
    }

    /// Choose how this client comes by the installation it runs as (defaults to
    /// [`IdentityMode::LoadOrCreate`]).
    ///
    /// [`IdentityMode::Ephemeral`] ignores `db_path` and keeps everything in
    /// memory: an installation that is not stored cannot sign for conversations
    /// that are, so persisting one without the other is of no use.
    pub fn set_identity_mode(&mut self, mode: IdentityMode) {
        self.identity_mode = mode;
    }

    /// Override the registry endpoint (account + keypackage store; defaults to
    /// the baked-in [`REGISTRY_ENDPOINT`]).
    pub fn set_registry_url(&mut self, registry_url: impl Into<String>) {
        self.registry_url = registry_url.into();
    }

    /// Choose how keypackage and account bundles are submitted to the store:
    /// HTTP POST (the default) or published over the delivery transport for the
    /// store to pick up by subscription. Reads always use the HTTP query API.
    pub fn set_registry_publish_mode(&mut self, mode: RegistryPublishMode) {
        self.registry_publish_mode = mode;
    }

    /// Override the embedded node's p2p settings (defaults to
    /// [`P2pConfig::default`]). Only [`open`] starts an embedded node, so
    /// [`open_with_transport`] ignores this.
    pub fn set_p2p_config(&mut self, p2p_config: P2pConfig) {
        self.p2p_config = p2p_config;
    }

    /// Override the GroupV2 timing/policy this client creates or joins groups
    /// with (defaults to the de-mls library defaults).
    ///
    /// # Deprecated
    ///
    /// This is not a supported pathway for future use. Exposing the raw GroupV2
    /// timing parameters to applications is a temporary workaround for slow
    /// group startup: the values are interdependent (wrong combinations can
    /// deadlock) and are not something an application can reasonably choose in a
    /// way that stays interoperable across applications and future group
    /// versions. The intended replacement is a wallclock/timer abstraction that
    /// controls DeMLS wait timers without leaking these parameters, so do not
    /// build on this method — it will be removed once that lands.
    #[deprecated(
        note = "unsupported pathway; exposing raw GroupV2 timing parameters is a \
                temporary workaround and will be removed once a wallclock/timer \
                abstraction replaces it"
    )]
    pub fn set_group_v2_config(&mut self, group_v2_config: GroupV2Config) {
        self.group_v2_config = Some(group_v2_config);
    }
}

/// Open a client on the Logos stack per `config`, starting an embedded
/// logos-delivery node per its p2p settings as the transport. A convenience
/// over [`open_with_transport`] that commits to the [`LogosChatClient`]
/// transport.
pub fn open(config: LogosConfig) -> Result<(LogosChatClient, Receiver<Event>), ClientError> {
    let transport = EmbeddedLogosDelivery::start(config.p2p_config.clone())
        .map_err(|e| ClientError::Transport(e.to_string()))?;
    open_with_transport(config, transport)
}

/// Open a client on the Logos stack per `config` with the injected transport,
/// persisting to the encrypted database.
///
/// The registry publishes per `config`'s
/// [`registry publish mode`](LogosConfig::set_registry_publish_mode): over
/// HTTP (the default), or over a clone of `transport` — sharing the client's
/// own delivery stack, which is why the transport must be `Clone`.
#[allow(clippy::type_complexity)]
pub fn open_with_transport<T: Transport + Clone>(
    config: LogosConfig,
    transport: T,
) -> Result<
    (
        ChatClient<T, ContactRegistry<T>, HttpAuthClient, SqliteStore>,
        Receiver<Event>,
    ),
    ClientError,
> {
    let registry = ContactRegistry::new(
        transport.clone(),
        config.registry_url.clone(),
        config.registry_publish_mode,
    );

    // Auth uses the same server as registry for the time being
    let auth = HttpAuthClient::new(config.registry_url);

    // The store comes first: which installation this client runs as is a question only the
    // store can answer, and the client is built from the answer.
    let storage = match config.identity_mode {
        IdentityMode::Ephemeral => StorageConfig::InMemory,
        IdentityMode::LoadOrCreate => StorageConfig::EncryptedWithKey {
            path: config.db_path,
            key: config.db_key,
        },
    };
    let mut store = SqliteStore::new(storage)?;

    let installation = open_installation(&mut store, auth.clone(), config.identity_mode)?;

    let mut builder = ChatClientBuilder::new(installation)
        .transport(transport)
        .registration(registry)
        .auth(auth)
        .storage(store);
    if let Some(group_v2) = config.group_v2_config {
        builder = builder.group_v2_config(group_v2);
    }
    builder.build()
}

/// The installation this store belongs to, per `mode`.
///
/// A stored one is reused as it stands and **nothing is republished**: an account log refuses
/// to endorse one key twice, so re-running registration for an installation already on the log
/// fails the open outright. The stored record is therefore the registration flag, and it is
/// written only once a publish has landed — see [`register_account`].
fn open_installation<S, A>(
    store: &mut S,
    auth: A,
    mode: IdentityMode,
) -> Result<Installation, ClientError>
where
    S: IdentityStore,
    A: AccountPublisher + AccountProvider,
{
    if mode == IdentityMode::Ephemeral {
        return Ok(register_account(auth)?);
    }
    Installation::load_or_create(store, || Ok(register_account(auth)?))
}

/// The Logos client: a [`ChatClient`] wired to the Logos service stack —
/// the [`Installation`](logos_generic_chat::Installation) its store holds, the keypackage +
/// account registry ([`ContactRegistry`], the keypackage store; it queries
/// over HTTP and submits over HTTP or the delivery network per
/// [`LogosConfig::set_registry_publish_mode`]),
/// and encrypted [`SqliteStore`] — running an embedded logos-delivery node as
/// its transport. Open one with [`open`], or swap the transport via
/// [`open_with_transport`].
pub type LogosChatClient = ChatClient<
    EmbeddedLogosDelivery,
    ContactRegistry<EmbeddedLogosDelivery>,
    HttpAuthClient,
    SqliteStore,
>;

/// Mints an installation and publishes its endorsement, in that order: a crash after the publish
/// re-runs registration harmlessly, while a record stored before it would leave a client nobody
/// can invite. The cost of that order is that a save which fails afterwards leaves an account on
/// the registry nothing will use again.
///
/// The account is still fresh per call and its key dropped at the end, so this installation is
/// the only one that account will ever endorse. Account custody belongs wherever an account's
/// key lives (`Account::from_signing_key` is the way back in), not in chat.
fn register_account<A: AccountPublisher + AccountProvider>(
    auth_client: A,
) -> Result<Installation, AccountError> {
    let pending = PendingInstallation::generate();

    let mut account = logos_account::Account::new(auth_client);
    let key = Ed25519VerifyingKey::from_canonical_slice(&pending.endorsement_request())?;

    let _ = account
        .update()
        .endorse_ed25519_key(CHATSIGNER_CONTEXT.clone(), &key)
        .publish()?;

    Ok(pending.complete(account.addr()))
}
