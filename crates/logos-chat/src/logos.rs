//! The opinionated Logos client.
//!
//! [`open`] commits to the Logos service stack so independently built clients
//! share the same production services instead of each re-deriving them: a
//! delegate identity, the keypackage + account registry (queried over HTTP,
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

use components::{ContactRegistry, RegistryPublishMode};
use crossbeam_channel::Receiver;
use embedded_logos_delivery::{EmbeddedLogosDelivery, P2pConfig};
use libchat::{SqliteStore, StorageConfig};
use logos_account::TestLogosAccount;

use logos_generic_chat::{
    ChatClient, ChatClientBuilder, ClientError, DelegateSigner, Event, GroupV2Config, Transport,
};

/// The endpoint for the account and keypackage registration service.
pub const REGISTRY_ENDPOINT: &str = "https://devnet.chat-kc.logos.co";

/// Configuration for opening a Logos client.
///
/// `db_path` (a per-client location) and `db_key` (a secret) are required and
/// never baked into the library. Everything else defaults: the registry
/// endpoint to the baked-in Logos value, the embedded node's p2p settings to
/// [`P2pConfig::default`], and the GroupV2 timing to the de-mls library
/// defaults; override them with [`set_registry_url`](Self::set_registry_url),
/// [`set_p2p_config`](Self::set_p2p_config), and
/// [`set_group_v2_config`](Self::set_group_v2_config).
pub struct LogosConfig {
    db_path: String,
    db_key: String,
    registry_url: String,
    registry_publish_mode: RegistryPublishMode,
    p2p_config: P2pConfig,
    group_v2_config: Option<GroupV2Config>,
}

impl LogosConfig {
    /// Config for the required per-client `db_path` and `db_key`. The registry
    /// endpoint defaults to the baked-in Logos value; override it with
    /// [`set_registry_url`](Self::set_registry_url).
    pub fn new(db_path: impl Into<String>, db_key: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
            db_key: db_key.into(),
            registry_url: REGISTRY_ENDPOINT.to_string(),
            registry_publish_mode: RegistryPublishMode::default(),
            p2p_config: P2pConfig::default(),
            group_v2_config: None,
        }
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
        ChatClient<T, ContactRegistry<T>, SqliteStore>,
        Receiver<Event>,
    ),
    ClientError,
> {
    // A fresh account endorsing a fresh delegate each open: the account
    // key is dropped after publishing the bundle, so devices cannot be
    // added later. A caller-supplied, custody-holding account replaces
    // this once the platform provides one.
    let account = TestLogosAccount::new();
    let delegate = DelegateSigner::random();
    let mut registry = ContactRegistry::new(
        transport.clone(),
        config.registry_url,
        config.registry_publish_mode,
    );
    account
        .add_delegate_signer(&mut registry, delegate.public_key())
        .map_err(|e| ClientError::BundlePublish(e.to_string()))?;
    let mut builder = ChatClientBuilder::new(account.address())
        .ident(delegate)
        .transport(transport)
        .registration(registry)
        .storage_config(StorageConfig::Encrypted {
            path: config.db_path,
            key: config.db_key,
        });
    if let Some(group_v2) = config.group_v2_config {
        builder = builder.group_v2_config(group_v2);
    }
    builder.build()
}

/// The Logos client: a [`ChatClient`] wired to the Logos service stack — a
/// [`DelegateSigner`] identity acting for a fresh dev account, the keypackage +
/// account registry ([`ContactRegistry`], which is both the keypackage store
/// and the account → device directory; it queries over HTTP and submits over
/// HTTP or the delivery network per [`LogosConfig::set_registry_publish_mode`]),
/// and encrypted [`SqliteStore`] — running an embedded logos-delivery node as
/// its transport. Open one with [`open`], or swap the transport via
/// [`open_with_transport`].
pub type LogosChatClient =
    ChatClient<EmbeddedLogosDelivery, ContactRegistry<EmbeddedLogosDelivery>, SqliteStore>;
