use components::EphemeralRegistry;
use crossbeam_channel::Receiver;
use libchat::{
    AuthService, ChatError, ChatStorage, GroupV2Config, RegistrationService, StorageConfig,
};
use logos_account_legacy::AccountDirectory;
use storage::ConversationStore;

use crate::Transport;
use crate::client::ChatClient;
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;

/// Marker for a builder field that has not been configured; the corresponding
/// component will be filled in with a sensible default when `build()` is called.
pub struct Unset;

pub struct ChatClientBuilder<I = Unset, T = Unset, R = Unset, A = Unset, S = Unset> {
    ident: I,
    account: String,
    transport: T,
    registration: R,
    auth: A,
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
            auth: Unset,
            storage: Unset,
            group_v2: None,
        }
    }
}

impl<I, T, R, A, S> ChatClientBuilder<I, T, R, A, S> {
    pub fn ident(self, ident: DelegateSigner) -> ChatClientBuilder<DelegateSigner, T, R, A, S> {
        ChatClientBuilder {
            ident,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            auth: self.auth,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn transport<NT>(self, transport: NT) -> ChatClientBuilder<I, NT, R, A, S> {
        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
            transport,
            registration: self.registration,
            auth: self.auth,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn registration<NR>(self, registration: NR) -> ChatClientBuilder<I, T, NR, A, S> {
        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
            transport: self.transport,
            registration,
            auth: self.auth,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    /// The service that checks whether a signer really acts for the
    /// participant it claims. Required: `build()` is not available until it is
    /// supplied, so no client runs without an answer to that question.
    pub fn auth<NA>(self, auth: NA) -> ChatClientBuilder<I, T, R, NA, S> {
        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            auth,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn storage<NS>(self, storage: NS) -> ChatClientBuilder<I, T, R, A, NS> {
        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            auth: self.auth,
            storage,
            group_v2: self.group_v2,
        }
    }

    pub fn storage_config(
        self,
        config: StorageConfig,
    ) -> ChatClientBuilder<I, T, R, A, ChatStorage> {
        let storage = ChatStorage::new(config)
            .map_err(ChatError::from)
            .expect("Storage config file should be valid");

        ChatClientBuilder {
            ident: self.ident,
            account: self.account,
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

// All four explicitly provided.
impl<T, R, A, S> ChatClientBuilder<DelegateSigner, T, R, A, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    A: AuthService + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn build(self) -> Built<T, R, A, S> {
        ChatClient::new(
            self.ident,
            self.account,
            self.auth,
            self.transport,
            self.registration,
            self.storage,
            self.group_v2,
        )
    }
}

// Transport only; I, R, S all default.
impl<T: Transport + Send + 'static, A: AuthService + Send + 'static>
    ChatClientBuilder<Unset, T, Unset, A, Unset>
{
    pub fn build(self) -> Built<T, EphemeralRegistry, A, ChatStorage> {
        ChatClient::new(
            DelegateSigner::random(),
            self.account,
            self.auth,
            self.transport,
            EphemeralRegistry::new(),
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// I and T; R and S default.
impl<T, A> ChatClientBuilder<DelegateSigner, T, Unset, A, Unset>
where
    T: Transport + Send + 'static,
    A: AuthService + Send + 'static,
{
    pub fn build(self) -> Built<T, EphemeralRegistry, A, ChatStorage> {
        ChatClient::new(
            self.ident,
            self.account,
            self.auth,
            self.transport,
            EphemeralRegistry::new(),
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T and R; I and S default.
impl<T, R, A> ChatClientBuilder<Unset, T, R, A, Unset>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    A: AuthService + Send + 'static,
{
    pub fn build(self) -> Built<T, R, A, ChatStorage> {
        ChatClient::new(
            DelegateSigner::random(),
            self.account,
            self.auth,
            self.transport,
            self.registration,
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T and S; I and R default.
impl<T, A, S> ChatClientBuilder<Unset, T, Unset, A, S>
where
    T: Transport + Send + 'static,
    S: ConversationStore + Send + 'static,
    A: AuthService + Send + 'static,
{
    pub fn build(self) -> Built<T, EphemeralRegistry, A, S> {
        ChatClient::new(
            DelegateSigner::random(),
            self.account,
            self.auth,
            self.transport,
            EphemeralRegistry::new(),
            self.storage,
            self.group_v2,
        )
    }
}

// I, T, and R; S defaults.
impl<T, R, A> ChatClientBuilder<DelegateSigner, T, R, A, Unset>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    A: AuthService + Send + 'static,
{
    pub fn build(self) -> Built<T, R, A, ChatStorage> {
        ChatClient::new(
            self.ident,
            self.account,
            self.auth,
            self.transport,
            self.registration,
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T, R, and S; I defaults.
impl<T, R, A, S> ChatClientBuilder<Unset, T, R, A, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    A: AuthService + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn build(self) -> Built<T, R, A, S> {
        ChatClient::new(
            DelegateSigner::random(),
            self.account,
            self.auth,
            self.transport,
            self.registration,
            self.storage,
            self.group_v2,
        )
    }
}

// I, T, and S; R defaults.
impl<T, A, S> ChatClientBuilder<DelegateSigner, T, Unset, A, S>
where
    T: Transport + Send + 'static,
    S: ConversationStore + Send + 'static,
    A: AuthService + Send + 'static,
{
    pub fn build(self) -> Built<T, EphemeralRegistry, A, S> {
        ChatClient::new(
            self.ident,
            self.account,
            self.auth,
            self.transport,
            EphemeralRegistry::new(),
            self.storage,
            self.group_v2,
        )
    }
}
