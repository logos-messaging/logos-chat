use crate::causal_history::{CausalHistoryStore, DeliveryAck, MissingMessage};
use crate::conversation::{
    ConversationIdRef, DirectV1Convo, GroupV1Convo, GroupV2Convo, Identified, MessageId,
};
use crate::service_context::{ExternalServices, ServiceContext};
use crate::types::ConvoMetadata;
use crate::{
    DeliveryService, GroupV2Clock, GroupV2Config, IdentityProvider, RegistrationService,
    WakeupService,
};
use crate::{
    conversation::{Convo, GroupConvo},
    errors::ChatError,
    inbox_v2::{InboxV2, MlsEphemeralPqProvider, MlsIdentityProvider},
    outcomes::{ConvoOutcome, InboxOutcome, PayloadOutcome},
    proto::{EncryptedPayload, EnvelopeV1, Message},
};
use openmls::group::GroupId;
use shared_traits::{IdentId, IdentIdRef};
use std::collections::HashMap;
use std::fmt::Debug;
use storage::{ConversationKind, ConversationStore};
use tracing::{info, instrument};

pub use crate::conversation::ConversationId;

// This is the main entry point to the conversations api.
// `Core` manages lifetimes of objects to process and generate payloads.
//
// Fully synchronous and single-threaded: it owns its services outright (no
// interior mutability, no shared ownership) and drives the inbox/conversation
// primitives with plain `&mut self`.
pub struct Core<S: ExternalServices> {
    services: ServiceContext<S>,
    pq_inbox: InboxV2,
    // Cache of loaded conversations
    cached_convos: HashMap<String, ConvoTypeOwned<S>>,
}

// Constructors live on the `(DS, RS, CS)` form: `S` can't be inferred backwards
// through `S::DS`, so the bundle is built from the three args here.
impl<IP, DS, RS, WS, CS> Core<(IP, DS, RS, WS, CS)>
where
    IP: IdentityProvider + 'static,
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
    WS: WakeupService + 'static,
    CS: ConversationStore + 'static,
{
    /// Opens or creates a `Core` over the given store.
    pub fn new_from_store(
        ident: IP,
        delivery: DS,
        registration: RS,
        wakeup_service: WS,
        store: CS,
    ) -> Result<Self, ChatError> {
        Self::assemble(ident, delivery, registration, wakeup_service, store)
    }

    /// Creates a new in-memory `Core` (for testing).
    ///
    /// Uses in-memory SQLite database. Each call creates a new isolated database.
    pub fn new_with_name(
        ident: IP,
        delivery: DS,
        registration: RS,
        wakeup_service: WS,
        store: CS,
    ) -> Result<Self, ChatError> {
        let mut core = Self::assemble(ident, delivery, registration, wakeup_service, store)?;

        core.register_keypackage()?;
        Ok(core)
    }

    pub fn set_group_v2_clock(&mut self, clock: GroupV2Clock) {
        self.services.demls_clock = clock;
    }

    /// Overrides the GroupV2 (de-mls) timing/policy config. Applies to
    /// conversations created/joined after the call; a creator's phase
    /// durations reach joiners inside the welcome's `ConversationSync`.
    pub fn set_group_v2_config(&mut self, config: GroupV2Config) {
        self.services.demls_config = config;
    }

    /// Builds the inbox/account/MLS/causal state, subscribes both inbound
    /// addresses, and assembles the service bundle — shared by both constructors.
    fn assemble(
        ident: IP,
        mut delivery: DS,
        registration: RS,
        wakeup_service: WS,
        store: CS,
    ) -> Result<Self, ChatError> {
        // InboxV2 rendezvous is signer-scoped: it subscribes under the hex of
        // the signer's verifying key — the same string the account → device
        // directory lists and the registries key key-packages under, so it is
        // exactly what an inviter can derive for this installation. The MLS
        // credential below still carries the full `id()`.
        let ident_id = IdentId::new(hex::encode(ident.public_key().as_ref()));
        let mls_identity = MlsIdentityProvider::new(ident);
        let mls_provider = MlsEphemeralPqProvider::new().map_err(ChatError::generic)?;
        let causal = CausalHistoryStore::new();
        let pq_inbox = InboxV2::new(ident_id);

        // Subscribe to the InboxV2 rendezvous address.
        delivery
            .subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            services: ServiceContext {
                ds: delivery,
                registry: registration,
                store,
                mls_identity,
                mls_provider,
                causal,
                wakeup_service,
                demls_clock: GroupV2Clock::default(),
                demls_config: GroupV2Config::default(),
            },
            pq_inbox,
            cached_convos: HashMap::new(),
        })
    }
}

impl<'a, S: ExternalServices + 'static> Core<S> {
    pub fn ds(&mut self) -> &mut S::DS {
        &mut self.services.ds
    }

    pub fn store(&self) -> &S::CS {
        &self.services.store
    }

    /// The signer id this core receives InboxV2 invites under — the hex of the
    /// signer's verifying key.
    pub fn ident_id(&'a self) -> IdentIdRef<'a> {
        self.pq_inbox.ident_id()
    }

    /// Submit the local account's MLS KeyPackage to the registration service.
    /// Idempotent on the server side (registries that retain history will keep
    /// the most recent N submissions; older entries are pruned).
    pub fn register_keypackage(&mut self) -> Result<(), ChatError> {
        self.pq_inbox.register(&mut self.services)
    }

    pub fn installation_name(&self) -> &str {
        self.services.mls_identity.id().as_str()
    }

    pub fn create_direct_convo(
        &mut self,
        members: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        self.create_direct_convo_v1(members)
    }

    pub fn create_direct_convo_v1(
        &mut self,
        members: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        let convo = DirectV1Convo::new(&mut self.services, members)?;
        let convo_id = convo.id().to_string();
        self.register_convo(ConvoTypeOwned::Direct(Box::new(convo)))?;

        Ok(convo_id)
    }

    pub fn create_group_convo(
        &mut self,
        participants: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        self.create_group_convo_v2(participants, "", "")
    }

    pub fn create_group_convo_v1(
        &mut self,
        participants: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        // TODO: (P1) Ensure errors are handled properly. This is a high chance for
        // desynchronized state: MlsGroup persistence, conversation persistence, and
        // invite delivery all happen separately.
        let mut convo = GroupV1Convo::new(&mut self.services)?;
        self.services
            .store
            .save_conversation(&storage::ConversationMeta {
                local_convo_id: convo.id().to_string(),
                kind: ConversationKind::GroupV1,
            })?;
        convo.add_member(&mut self.services, participants)?;
        let convo_id = convo.id().to_string();

        self.register_convo(ConvoTypeOwned::Group(Box::new(convo)))?;

        Ok(convo_id)
    }

    pub fn create_group_convo_v2(
        &mut self,
        participants: &[IdentIdRef],
        name: &str,
        desc: &str,
    ) -> Result<ConversationId, ChatError> {
        // TODO: (P1) Ensure errors are handled properly. This is a high chance for
        // desynchronized state: MlsGroup persistence, conversation persistence, and
        // invite delivery all happen separately.
        let convo = GroupV2Convo::new(&mut self.services, name, desc, participants)?;
        let convo_id = convo.id().to_string();

        self.register_convo(ConvoTypeOwned::Group(Box::new(convo)))?;

        Ok(convo_id)
    }

    /// Add members to an existing group conversation.
    pub fn group_add_member(
        &mut self,
        convo_id: &str,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        let convo = self
            .cached_convos
            .get_mut(convo_id)
            .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

        match convo {
            ConvoTypeOwned::Group(group_convo) => {
                group_convo.add_member(&mut self.services, members)
            }
            ConvoTypeOwned::Direct(convo) => Err(ChatError::UnsupportedFunction(
                convo.id().into(),
                "Add Member".into(),
            )),
        }
    }

    /// Each member's MLS leaf-credential content (hex-encoded), for a direct
    /// conversation as for a group.
    pub fn group_members(&mut self, convo_id: &str) -> Result<Vec<Vec<u8>>, ChatError> {
        let convo = self
            .cached_convos
            .get(convo_id)
            .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

        convo.members()
    }

    /// Each member invited here and still awaiting the group's commit, in the
    /// same encoding as [`Self::group_members`]. A direct conversation has no
    /// pending members and reports none.
    pub fn group_pending_members(&mut self, convo_id: &str) -> Result<Vec<Vec<u8>>, ChatError> {
        let convo = self
            .cached_convos
            .get(convo_id)
            .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

        match convo {
            ConvoTypeOwned::Group(group_convo) => group_convo.pending_members(),
            ConvoTypeOwned::Direct(_) => Ok(Vec::new()),
        }
    }

    /// Every conversation this client knows — persisted or loaded this session.
    /// Membership in this list means the conversation *exists*; it says nothing
    /// about whether content can be sent or retrieved (see [`Self::can_send`] /
    /// [`Self::can_receive`] and [`Self::list_sendable_conversations`]).
    pub fn list_all_conversations(&self) -> Result<Vec<ConversationId>, ChatError> {
        // Check Legacy load_convo store
        let records = self.services.store.load_conversations()?;
        let mut convos: Vec<ConversationId> =
            records.into_iter().map(|r| r.local_convo_id).collect();

        // Add cached mls convos
        for convo in self.cached_convos.keys() {
            convos.push(convo.to_string());
        }

        // A conversation can live in both the store and the in-memory cache (a
        // DirectV1 join persists to the store and is also cached), so drop
        // duplicates across the two. `Vec::dedup` only removes *consecutive*
        // repeats and `cached_convos` iterates in nondeterministic HashMap
        // order, so dedup through a set instead.
        let mut seen = std::collections::HashSet::new();
        convos.retain(|c| seen.insert(c.clone()));
        Ok(convos)
    }

    /// The subset of [`Self::list_all_conversations`] that content can currently
    /// be sent to — the "sendable" roster a UI usually wants.
    pub fn list_sendable_conversations(&self) -> Result<Vec<ConversationId>, ChatError> {
        Ok(self
            .list_all_conversations()?
            .into_iter()
            .filter(|id| self.can_send(id))
            .collect())
    }

    /// Whether content can currently be submitted to `convo_id`: it is loaded
    /// this session and the local identity is still a member with send rights.
    ///
    /// Distinct from "the conversation exists" — a known conversation
    /// ([`Self::list_all_conversations`]) may not be sendable, e.g. one restored
    /// from a previous session that has not been reloaded, or one we were
    /// removed from.
    pub fn can_send(&self, convo_id: &str) -> bool {
        self.cached_convos
            .get(convo_id)
            .map(|c| c.can_send())
            .unwrap_or(false)
    }

    /// Whether `convo_id` can be read/received from: it is known to this client,
    /// either loaded this session or persisted in the store. Broader than
    /// [`Self::can_send`] — a conversation can be received from yet not sent to.
    pub fn can_receive(&self, convo_id: &str) -> bool {
        self.cached_convos.contains_key(convo_id)
            || self
                .services
                .store
                .has_conversation(convo_id)
                .unwrap_or(false)
    }

    pub fn take_missing_messages(&self) -> Vec<MissingMessage> {
        self.services.causal.take_missing()
    }

    /// Drain the acknowledgements observed since the last call: peers that
    /// referenced one of our messages, and so demonstrably hold it.
    pub fn take_acks(&self) -> Vec<DeliveryAck> {
        self.services.causal.take_acks()
    }

    /// Encrypt and publish `content` to an existing conversation, returning the
    /// id assigned to the message so later acknowledgements can be matched to
    /// it.
    pub fn send_content(&mut self, convo_id: &str, content: &[u8]) -> Result<MessageId, ChatError> {
        if self.cached_convos.contains_key(convo_id) {
            let convo = self
                .cached_convos
                .get_mut(convo_id)
                .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;
            convo.send_content(&mut self.services, content)
        } else {
            let mut convo = self.load_convo(convo_id)?;
            convo.send_content(&mut self.services, content)
        }
    }

    // Decode bytes and send to protocol for processing.
    #[instrument(name = "core.handle_frame", skip_all, fields(user_id = %self.services.mls_identity.display_name()))]
    pub fn handle_payload(&mut self, payload: &[u8]) -> Result<PayloadOutcome, ChatError> {
        let env = EnvelopeV1::decode(payload)?;

        // TODO: Impl Conversation hinting
        let convo_id = env.conversation_hint;

        match convo_id {
            c if c == self.pq_inbox.id() => self.dispatch_to_inbox2(&env.payload),
            c if self.cached_convos.contains_key(&c) => {
                self.dispatch_to_convo(&c, &env.payload).map(Into::into)
            }
            c if self.services.store.has_conversation(&c)? => {
                self.dispatch_to_convo(&c, &env.payload).map(Into::into)
            }
            _ => Ok(PayloadOutcome::Empty),
        }
    }

    // Dispatch encrypted payload to the post-quantum inbox.
    fn dispatch_to_inbox2(&mut self, payload: &[u8]) -> Result<PayloadOutcome, ChatError> {
        if let Some((convo, class)) = self.pq_inbox.handle_frame(&mut self.services, payload)? {
            let convo_id = convo.id().to_string();
            // Cache convos created by InboxV2
            self.register_convo(ConvoTypeOwned::Group(convo))?;

            Ok(PayloadOutcome::Inbox(InboxOutcome {
                new_conversation: crate::NewConversation { convo_id, class },
                initial: None,
            }))
        } else {
            Ok(PayloadOutcome::Empty)
        }
    }

    // Dispatch encrypted payload to its corresponding conversation.
    fn dispatch_to_convo(
        &mut self,
        convo_id: &str,
        enc_payload_bytes: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;

        if self.cached_convos.contains_key(convo_id) {
            let convo_type = self
                .cached_convos
                .get_mut(convo_id)
                .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

            convo_type.handle_frame(&mut self.services, enc_payload)
        } else {
            let mut convo = self.load_convo(convo_id)?;
            convo.handle_frame(&mut self.services, enc_payload)
        }
    }

    pub fn wakeup(&mut self, convo_id: ConversationIdRef) -> Result<PayloadOutcome, ChatError> {
        info!(convos = ?self.cached_convos.keys().collect::<Vec<_>>(), id = ?self.services.mls_identity.id(), "Cached Convos");

        match convo_id {
            c if c == self.pq_inbox.id() => todo!(),
            c if self.cached_convos.contains_key(c) => self.wakeup_convo(c).map(Into::into),
            _ => Ok(PayloadOutcome::Empty),
        }
    }

    // Dispatch encrypted payload to its corresponding conversation
    fn wakeup_convo(&mut self, convo_id: ConversationIdRef) -> Result<ConvoOutcome, ChatError> {
        let Some(convo) = self.cached_convos.get_mut(convo_id) else {
            return Err(ChatError::generic("No Convo Found"));
        };
        let convo = match convo {
            ConvoTypeOwned::Group(c) => c.as_mut(),
            ConvoTypeOwned::Direct(c) => c.as_mut(),
        };

        convo.wakeup(&mut self.services)
    }

    fn register_convo(&mut self, convo: ConvoTypeOwned<S>) -> Result<(), ChatError> {
        let res = self.cached_convos.insert(convo.id().to_string(), convo);

        match res {
            Some(_) => Err(ChatError::generic("Convo already exists. Cannot save")),
            None => Ok(()),
        }
    }

    /// Rebuilds a conversation from storage — the one site that branches on
    /// `ConversationKind`.
    fn load_convo(&mut self, convo_id: &str) -> Result<Box<dyn Convo<S>>, ChatError> {
        let record = self.load_conversation_meta(convo_id)?;
        Ok(match record.kind {
            ConversationKind::GroupV1 => Box::new(self.load_mls_convo(&record.local_convo_id)?),
            ConversationKind::Unknown(_) => {
                return Err(ChatError::UnsupportedConvoType(record.kind.as_str().into()));
            }
        })
    }

    /// Rebuilds a group conversation from storage so an operation can run against it.
    fn load_mls_convo(&mut self, convo_id: &str) -> Result<GroupV1Convo, ChatError> {
        let group_id_bytes = hex::decode(convo_id).map_err(ChatError::generic)?;
        let group_id = GroupId::from_slice(&group_id_bytes);
        GroupV1Convo::load(&mut self.services, convo_id.to_string(), group_id)
    }

    /// Loads a conversation's metadata from storage.
    fn load_conversation_meta(
        &self,
        convo_id: &str,
    ) -> Result<storage::ConversationMeta, ChatError> {
        self.services
            .store
            .load_conversation(convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))
    }

    pub fn convo_metadata(&self, convo_id: ConversationIdRef) -> Result<ConvoMetadata, ChatError> {
        match self.cached_convos.get(convo_id) {
            Some(ConvoTypeOwned::Group(group_convo)) => {
                group_convo
                    .metadata()
                    .ok_or(ChatError::UnsupportedConvoType(
                        "metadata is not available for this legacy convo_type".into(),
                    ))
            }
            Some(ConvoTypeOwned::Direct(_)) => Err(ChatError::UnsupportedFunction(
                convo_id.into(),
                "implementation coming".into(),
            )),
            None => Err(ChatError::NoConvo(convo_id.into())),
        }
    }
}

enum ConvoTypeOwned<S: ExternalServices> {
    Direct(Box<dyn Convo<S>>),
    Group(Box<dyn GroupConvo<S>>),
}

impl<S: ExternalServices> Debug for ConvoTypeOwned<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(arg0) => f.debug_tuple("Pairwise").field(&arg0.id()).finish(),
            Self::Group(arg0) => f.debug_tuple("Group").field(&arg0.id()).finish(),
        }
    }
}

impl<S: ExternalServices> Identified for ConvoTypeOwned<S> {
    fn id(&self) -> ConversationIdRef<'_> {
        match self {
            ConvoTypeOwned::Direct(convo) => convo.id(),
            ConvoTypeOwned::Group(group_convo) => group_convo.id(),
        }
    }
}

impl<S: ExternalServices> Convo<S> for ConvoTypeOwned<S> {
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<MessageId, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.send_content(cx, content),
            ConvoTypeOwned::Direct(convo) => convo.send_content(cx, content),
        }
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        enc: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.handle_frame(cx, enc),
            ConvoTypeOwned::Direct(convo) => convo.handle_frame(cx, enc),
        }
    }

    fn wakeup(&mut self, service_ctx: &mut ServiceContext<S>) -> Result<ConvoOutcome, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.wakeup(service_ctx),
            ConvoTypeOwned::Direct(convo) => convo.wakeup(service_ctx),
        }
    }

    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.members(),
            ConvoTypeOwned::Direct(convo) => convo.members(),
        }
    }

    fn can_send(&self) -> bool {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.can_send(),
            ConvoTypeOwned::Direct(convo) => convo.can_send(),
        }
    }
}
