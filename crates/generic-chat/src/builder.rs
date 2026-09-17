use components::EphemeralRegistry;
use crossbeam_channel::Receiver;
use libchat::{
    AuthService, ChatError, ChatStorage, GroupV2Config, RegistrationService, StorageConfig,
};
use storage::ConversationStore;

use crate::Transport;
use crate::client::ChatClient;
use crate::errors::ClientError;
use crate::event::Event;
use crate::installation::Installation;

/// Marker for a builder field that has not been configured; the corresponding
/// component will be filled in with a sensible default when `build()` is called.
pub struct Unset;

pub struct ChatClientBuilder<T = Unset, R = Unset, A = Unset, S = Unset> {
    installation: Installation,
    transport: T,
    registration: R,
    auth: A,
    storage: S,
    group_v2: Option<GroupV2Config>,
}

impl ChatClientBuilder {
    /// Every client runs as an installation its account endorsed: `build`
    /// fails unless the auth service confirms that endorsement. The account
    /// becomes the client's shareable address ([`ChatClient::addr`]).
    pub fn new(installation: Installation) -> Self {
        Self {
            installation,
            transport: Unset,
            registration: Unset,
            auth: Unset,
            storage: Unset,
            group_v2: None,
        }
    }
}

impl<T, R, A, S> ChatClientBuilder<T, R, A, S> {
    pub fn transport<NT>(self, transport: NT) -> ChatClientBuilder<NT, R, A, S> {
        ChatClientBuilder {
            installation: self.installation,
            transport,
            registration: self.registration,
            auth: self.auth,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn registration<NR>(self, registration: NR) -> ChatClientBuilder<T, NR, A, S> {
        ChatClientBuilder {
            installation: self.installation,
            transport: self.transport,
            registration,
            auth: self.auth,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn auth<NA>(self, auth: NA) -> ChatClientBuilder<T, R, NA, S> {
        ChatClientBuilder {
            installation: self.installation,
            transport: self.transport,
            registration: self.registration,
            auth,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn storage<NS>(self, storage: NS) -> ChatClientBuilder<T, R, A, NS> {
        ChatClientBuilder {
            installation: self.installation,
            transport: self.transport,
            registration: self.registration,
            auth: self.auth,
            storage,
            group_v2: self.group_v2,
        }
    }

    pub fn storage_config(self, config: StorageConfig) -> ChatClientBuilder<T, R, A, ChatStorage> {
        let storage = ChatStorage::new(config)
            .map_err(ChatError::from)
            .expect("Storage config file should be valid");

        ChatClientBuilder {
            installation: self.installation,
            transport: self.transport,
            registration: self.registration,
            auth: self.auth,
            storage,
            group_v2: self.group_v2,
        }
    }

    /// Timing/policy for GroupV2 conversations this client creates or joins.
    /// Defaults to the de-mls library defaults; the creator's phase durations
    /// travel to joiners with the welcome and overwrite theirs (vote delays
    /// and policy fields stay local).
    pub fn group_v2_config(mut self, config: GroupV2Config) -> Self {
        self.group_v2 = Some(config);
        self
    }
}

type Built<T, R, A, S> = Result<(ChatClient<T, R, A, S>, Receiver<Event>), ClientError>;

// Everything provided.
impl<T, R, A, S> ChatClientBuilder<T, R, A, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Clone + Send + 'static,
    A: AuthService + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn build(self) -> Built<T, R, A, S> {
        ChatClient::new(
            self.installation,
            self.transport,
            self.registration,
            self.auth,
            self.storage,
            self.group_v2,
        )
    }
}

// R and S default.
impl<T, A> ChatClientBuilder<T, Unset, A, Unset>
where
    T: Transport + Send + 'static,
    A: AuthService + Send + 'static,
{
    pub fn build(self) -> Built<T, EphemeralRegistry, A, ChatStorage> {
        ChatClient::new(
            self.installation,
            self.transport,
            EphemeralRegistry::new(),
            self.auth,
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// S defaults.
impl<T, R, A> ChatClientBuilder<T, R, A, Unset>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Clone + Send + 'static,
    A: AuthService + Send + 'static,
{
    pub fn build(self) -> Built<T, R, A, ChatStorage> {
        ChatClient::new(
            self.installation,
            self.transport,
            self.registration,
            self.auth,
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// R defaults.
impl<T, A, S> ChatClientBuilder<T, Unset, A, S>
where
    T: Transport + Send + 'static,
    A: AuthService + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn build(self) -> Built<T, EphemeralRegistry, A, S> {
        ChatClient::new(
            self.installation,
            self.transport,
            EphemeralRegistry::new(),
            self.auth,
            self.storage,
            self.group_v2,
        )
    }
}
