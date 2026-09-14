use components::EphemeralRegistry;
use crossbeam_channel::Receiver;
use libchat::{ChatError, ChatStorage, GroupV2Config, RegistrationService, StorageConfig};
use logos_account::AccountDirectory;
use storage::ConversationStore;

use crate::Transport;
use crate::client::ChatClient;
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;

/// Marker for a builder field that has not been configured; the corresponding
/// component will be filled in with a sensible default when `build()` is called.
pub struct Unset;

pub struct ChatClientBuilder<I = Unset, T = Unset, R = Unset, S = Unset> {
    ident: I,
    account: String,
    transport: T,
    registration: R,
    storage: S,
    group_v2: Option<GroupV2Config>,
}

impl ChatClientBuilder {
    /// Every client acts for an account, so the builder starts from its
    /// address. It becomes the client's shareable address
    /// ([`ChatClient::addr`]) and the account claim in the wire credential;
    /// the account must endorse the signer in the directory for peers to
    /// verify that claim.
    pub fn new(account: impl Into<String>) -> Self {
        Self {
            ident: Unset,
            account: account.into(),
            transport: Unset,
            registration: Unset,
            storage: Unset,
            group_v2: None,
        }
    }
}

impl<I, T, R, S> ChatClientBuilder<I, T, R, S> {
    pub fn ident(self, ident: DelegateSigner) -> ChatClientBuilder<DelegateSigner, T, R, S> {
        ChatClientBuilder {
            ident,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn transport<NT>(self, transport: NT) -> ChatClientBuilder<I, NT, R, S> {
        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
            transport,
            registration: self.registration,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn registration<NR>(self, registration: NR) -> ChatClientBuilder<I, T, NR, S> {
        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
            transport: self.transport,
            registration,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn storage<NS>(self, storage: NS) -> ChatClientBuilder<I, T, R, NS> {
        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            storage,
            group_v2: self.group_v2,
        }
    }

    pub fn storage_config(self, config: StorageConfig) -> ChatClientBuilder<I, T, R, ChatStorage> {
        let storage = ChatStorage::new(config)
            .map_err(ChatError::from)
            .expect("Storage config file should be valid");

        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
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

type Built<T, R, S> = Result<(ChatClient<T, R, S>, Receiver<Event>), ClientError>;

// All four explicitly provided.
impl<T, R, S> ChatClientBuilder<DelegateSigner, T, R, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn build(self) -> Built<T, R, S> {
        ChatClient::new(
            self.ident,
            self.account,
            self.transport,
            self.registration,
            self.storage,
            self.group_v2,
        )
    }
}

// Transport only; I, R, S all default.
impl<T: Transport + Send + 'static> ChatClientBuilder<Unset, T, Unset, Unset> {
    pub fn build(self) -> Built<T, EphemeralRegistry, ChatStorage> {
        ChatClient::new(
            DelegateSigner::random(),
            self.account,
            self.transport,
            EphemeralRegistry::new(),
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// I and T; R and S default.
impl<T> ChatClientBuilder<DelegateSigner, T, Unset, Unset>
where
    T: Transport + Send + 'static,
{
    pub fn build(self) -> Built<T, EphemeralRegistry, ChatStorage> {
        ChatClient::new(
            self.ident,
            self.account,
            self.transport,
            EphemeralRegistry::new(),
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T and R; I and S default.
impl<T, R> ChatClientBuilder<Unset, T, R, Unset>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
{
    pub fn build(self) -> Built<T, R, ChatStorage> {
        ChatClient::new(
            DelegateSigner::random(),
            self.account,
            self.transport,
            self.registration,
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T and S; I and R default.
impl<T, S> ChatClientBuilder<Unset, T, Unset, S>
where
    T: Transport + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn build(self) -> Built<T, EphemeralRegistry, S> {
        ChatClient::new(
            DelegateSigner::random(),
            self.account,
            self.transport,
            EphemeralRegistry::new(),
            self.storage,
            self.group_v2,
        )
    }
}

// I, T, and R; S defaults.
impl<T, R> ChatClientBuilder<DelegateSigner, T, R, Unset>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
{
    pub fn build(self) -> Built<T, R, ChatStorage> {
        ChatClient::new(
            self.ident,
            self.account,
            self.transport,
            self.registration,
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T, R, and S; I defaults.
impl<T, R, S> ChatClientBuilder<Unset, T, R, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn build(self) -> Built<T, R, S> {
        ChatClient::new(
            DelegateSigner::random(),
            self.account,
            self.transport,
            self.registration,
            self.storage,
            self.group_v2,
        )
    }
}

// I, T, and S; R defaults.
impl<T, S> ChatClientBuilder<DelegateSigner, T, Unset, S>
where
    T: Transport + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn build(self) -> Built<T, EphemeralRegistry, S> {
        ChatClient::new(
            self.ident,
            self.account,
            self.transport,
            EphemeralRegistry::new(),
            self.storage,
            self.group_v2,
        )
    }
}
