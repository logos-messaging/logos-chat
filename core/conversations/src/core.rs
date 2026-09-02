use crate::ConversationKind;
use crate::causal_history::{CausalHistoryStore, DeliveryAck, MissingMessage};
use crate::conversation::{
    ConversationIdRef, ConvoTypeOwned, DirectV1Convo, GroupV1Convo, GroupV2Convo, Identified,
    MessageId,
};
use crate::kv::{KvTransaction, ScopedKvStore};
use crate::service_context::{ExternalServices, ServiceContext};
use crate::staged_delivery::StagedDelivery;
use crate::storage::{ConversationMeta, ConversationStore};
use crate::types::ConvoMetadata;
use crate::{
    DeliveryService, GroupV2Clock, GroupV2Config, IdentityProvider, KvStore, RegistrationService,
    WakeupService,
};
use crate::{
    conversation::{Convo, GroupConvo},
    errors::ChatError,
    inbox_v2::{InboxV2, Joined, MlsIdentityProvider},
    outcomes::{ConvoOutcome, InboxOutcome, PayloadOutcome},
    proto::{EncryptedPayload, EnvelopeV1, Message},
};
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use shared_traits::{IdentId, IdentIdRef};
use std::collections::HashMap;
use tracing::{info, instrument};

pub use crate::conversation::ConversationId;

// This is the main entry point to the conversations api.
// `Core` manages lifetimes of objects to process and generate payloads.
//
// Fully synchronous and single-threaded: it owns its services outright (no
// interior mutability, no shared ownership) and drives the inbox/conversation
// primitives with plain `&mut self`.
pub struct Core<S: ExternalServices> {
    store: S::CS,
    services: ServiceContext<S>,
    pq_inbox: InboxV2,
    // Cache of loaded conversations
    cached_convos: HashMap<String, ScopedConvo<S>>,
}

// Constructors live on the `(DS, RS, CS)` form: `S` can't be inferred backwards
// through `S::DS`, so the bundle is built from the three args here.
impl<IP, DS, RS, WS, CS> Core<(IP, DS, RS, WS, CS)>
where
    IP: IdentityProvider + 'static,
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
    WS: WakeupService + 'static,
    CS: KvStore + ConversationStore + 'static,
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
        let crypto = LibcruxCryptoProvider::new().map_err(ChatError::generic)?;
        let causal = CausalHistoryStore::new();
        let pq_inbox = InboxV2::new(ident_id);

        // Subscribe to the InboxV2 rendezvous address.
        delivery
            .subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            store,
            services: ServiceContext {
                ds: StagedDelivery::new(delivery),
                registry: registration,
                mls_identity,
                crypto,
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
        self.services.ds.inner_mut()
    }

    pub fn store(&self) -> &S::CS {
        &self.store
    }

    /// The signer id this core receives InboxV2 invites under — the hex of the
    /// signer's verifying key.
    pub fn ident_id(&'a self) -> IdentIdRef<'a> {
        self.pq_inbox.ident_id()
    }

    /// Submit the local account's MLS KeyPackage to the registration service.
    /// Idempotent on the server side (registries that retain history will keep
    /// the most recent N submissions; older entries are pruned).
    ///
    /// Submitted only once the transaction holding its private keys has landed, so the registry
    /// never serves a package whose welcome this installation could not open.
    pub fn register_keypackage(&mut self) -> Result<(), ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let minted = self.pq_inbox.register(&mut self.services, &tx);
        let key_package = Self::commit(&mut self.services, tx, minted)?;
        self.services
            .registry
            .register(&self.services.mls_identity, key_package)
            .map_err(ChatError::generic)
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
        let convo_id = DirectV1Convo::mint_id(&self.services.crypto);

        let tx = KvTransaction::begin(&self.store)?;
        let created = DirectV1Convo::new(
            &mut self.services,
            tx.scope(ConversationKind::DirectV1, &convo_id),
            convo_id.clone(),
            members,
        );
        let convo = Self::commit(&mut self.services, tx, created)?;
        self.register_convo(
            ConversationKind::DirectV1,
            ConvoTypeOwned::Direct(Box::new(convo)),
        )?;
        self.publish()?;

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
        let convo_id = GroupV1Convo::mint_id(&self.services.crypto);

        let tx = KvTransaction::begin(&self.store)?;
        let created = Self::build_group_v1(
            &mut self.services,
            tx.scope(ConversationKind::GroupV1, &convo_id),
            convo_id.clone(),
            participants,
        );
        let convo = Self::commit(&mut self.services, tx, created)?;
        self.record(ConversationKind::GroupV1, &convo_id)?;
        self.register_convo(
            ConversationKind::GroupV1,
            ConvoTypeOwned::Group(Box::new(convo)),
        )?;
        self.publish()?;

        Ok(convo_id)
    }

    pub fn create_group_convo_v2(
        &mut self,
        participants: &[IdentIdRef],
        name: &str,
        desc: &str,
    ) -> Result<ConversationId, ChatError> {
        let convo_id = GroupV2Convo::mint_id();

        let tx = KvTransaction::begin(&self.store)?;
        let created = GroupV2Convo::new(
            &mut self.services,
            tx.scope(ConversationKind::GroupV2, &convo_id),
            convo_id.clone(),
            name,
            desc,
            participants,
        );
        let convo = Self::commit(&mut self.services, tx, created)?;
        self.register_convo(
            ConversationKind::GroupV2,
            ConvoTypeOwned::Group(Box::new(convo)),
        )?;
        self.publish()?;

        Ok(convo_id)
    }

    /// Add members to an existing group conversation.
    pub fn group_add_member(
        &mut self,
        convo_id: &str,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        let scoped = self
            .cached_convos
            .get_mut(convo_id)
            .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

        let tx = KvTransaction::begin(&self.store)?;
        let kind = scoped.kind;
        let added = match &mut scoped.convo {
            ConvoTypeOwned::Group(group_convo) => {
                let kv = tx.scope(kind, convo_id);
                group_convo.add_member(&mut self.services, kv, members)
            }
            ConvoTypeOwned::Direct(convo) => Err(ChatError::UnsupportedFunction(
                convo.id().into(),
                "Add Member".into(),
            )),
        };
        Self::commit(&mut self.services, tx, added)?;
        self.publish()
    }

    /// Remove members from an existing group conversation, naming them by
    /// signer (installation) id exactly as [`Self::group_add_member`] does.
    pub fn group_remove_member(
        &mut self,
        convo_id: &str,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        let scoped = self
            .cached_convos
            .get_mut(convo_id)
            .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

        let tx = KvTransaction::begin(&self.store)?;
        let kind = scoped.kind;
        let removed = match &mut scoped.convo {
            ConvoTypeOwned::Group(group_convo) => {
                let kv = tx.scope(kind, convo_id);
                group_convo.remove_member(&mut self.services, kv, members)
            }
            ConvoTypeOwned::Direct(convo) => Err(ChatError::UnsupportedFunction(
                convo.id().into(),
                "Remove Member".into(),
            )),
        };
        Self::commit(&mut self.services, tx, removed)?;
        self.publish()
    }

    /// Each member's MLS leaf-credential content (hex-encoded), for a direct
    /// conversation as for a group.
    pub fn group_members(&mut self, convo_id: &str) -> Result<Vec<Vec<u8>>, ChatError> {
        let scoped = self
            .cached_convos
            .get(convo_id)
            .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

        scoped.convo.members()
    }

    /// Each member invited here and still awaiting the group's commit, in the
    /// same encoding as [`Self::group_members`]. A direct conversation has no
    /// pending members and reports none.
    pub fn group_pending_members(&mut self, convo_id: &str) -> Result<Vec<Vec<u8>>, ChatError> {
        let scoped = self
            .cached_convos
            .get(convo_id)
            .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

        match &scoped.convo {
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
        let mut convos: Vec<ConversationId> = self
            .store
            .load_conversations()?
            .into_iter()
            .map(|record| record.local_convo_id)
            .collect();

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
            .map(|scoped| scoped.convo.can_send())
            .unwrap_or(false)
    }

    /// Whether `convo_id` can be read/received from: it is known to this client,
    /// either loaded this session or persisted in the store. Broader than
    /// [`Self::can_send`] — a conversation can be received from yet not sent to.
    pub fn can_receive(&self, convo_id: &str) -> bool {
        self.cached_convos.contains_key(convo_id) || self.listed(convo_id).unwrap_or(false)
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
        let tx = KvTransaction::begin(&self.store)?;
        let mut loaded;
        let scoped = match self.cached_convos.get_mut(convo_id) {
            Some(scoped) => scoped,
            None => {
                loaded = Self::load_convo(&mut self.services, &self.store, &tx, convo_id)?;
                &mut loaded
            }
        };

        let kv = tx.scope(scoped.kind, convo_id);
        let sent = scoped.convo.send_content(&mut self.services, kv, content);
        let message_id = Self::commit(&mut self.services, tx, sent)?;
        self.publish()?;

        Ok(message_id)
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
            c if self.listed(&c)? => self.dispatch_to_convo(&c, &env.payload).map(Into::into),
            _ => Ok(PayloadOutcome::Empty),
        }
    }

    fn listed(&self, convo_id: &str) -> Result<bool, ChatError> {
        Ok(self.store.has_conversation(convo_id)?)
    }

    // Dispatch encrypted payload to the post-quantum inbox.
    fn dispatch_to_inbox2(&mut self, payload: &[u8]) -> Result<PayloadOutcome, ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let handled = self.pq_inbox.handle_frame(&mut self.services, &tx, payload);
        let Some(Joined { convo, kind }) = Self::commit(&mut self.services, tx, handled)? else {
            return Ok(PayloadOutcome::Empty);
        };

        let convo_id = convo.id().to_string();
        let class = convo.class();
        self.record(kind, &convo_id)?;
        // Cache convos created by InboxV2
        self.register_convo(kind, convo)?;
        self.publish()?;

        Ok(PayloadOutcome::Inbox(InboxOutcome {
            new_conversation: crate::NewConversation { convo_id, class },
            initial: None,
        }))
    }

    // Dispatch encrypted payload to its corresponding conversation.
    fn dispatch_to_convo(
        &mut self,
        convo_id: &str,
        enc_payload_bytes: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;

        let tx = KvTransaction::begin(&self.store)?;
        let mut loaded;
        let scoped = match self.cached_convos.get_mut(convo_id) {
            Some(scoped) => scoped,
            None => {
                loaded = Self::load_convo(&mut self.services, &self.store, &tx, convo_id)?;
                &mut loaded
            }
        };

        let kv = tx.scope(scoped.kind, convo_id);
        let handled = scoped
            .convo
            .handle_frame(&mut self.services, kv, enc_payload);
        let outcome = Self::commit(&mut self.services, tx, handled)?;
        self.publish()?;

        Ok(outcome)
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
        let Some(scoped) = self.cached_convos.get_mut(convo_id) else {
            return Err(ChatError::generic("No Convo Found"));
        };

        let tx = KvTransaction::begin(&self.store)?;
        let kv = tx.scope(scoped.kind, convo_id);
        let woken = scoped.convo.wakeup(&mut self.services, kv);
        let outcome = Self::commit(&mut self.services, tx, woken)?;
        self.publish()?;

        Ok(outcome)
    }

    /// A GroupV1 create in one transaction: the group, then the invites its participants need.
    fn build_group_v1(
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        convo_id: ConversationId,
        participants: &[IdentIdRef],
    ) -> Result<GroupV1Convo, ChatError> {
        let mut convo = GroupV1Convo::new(cx, kv, convo_id)?;
        convo.add_member(cx, kv, participants)?;
        Ok(convo)
    }

    /// Lands the operation's transaction. A failure discards the transaction and the frames the
    /// operation staged alike, so a failed operation announces nothing.
    fn commit<T>(
        cx: &mut ServiceContext<S>,
        tx: KvTransaction<'_>,
        outcome: Result<T, ChatError>,
    ) -> Result<T, ChatError> {
        let outcome = outcome.and_then(|value| {
            tx.commit()?;
            Ok(value)
        });
        if outcome.is_err() {
            cx.ds.discard();
        }
        outcome
    }

    /// Publishes what the operation staged, now that the state behind it has landed.
    fn publish(&mut self) -> Result<(), ChatError> {
        self.services
            .ds
            .flush()
            .map_err(|e| ChatError::Delivery(e.to_string()))
    }

    /// Lists a conversation under the kind whose scope holds its state, once the transaction
    /// writing that state has landed. What is still staged is dropped if the record cannot be
    /// written: a conversation the store does not list must not announce itself.
    fn record(&mut self, kind: ConversationKind, convo_id: &str) -> Result<(), ChatError> {
        let record = ConversationMeta {
            local_convo_id: convo_id.to_string(),
            kind,
        };
        if let Err(err) = self.store.save_conversation(&record) {
            self.services.ds.discard();
            return Err(err.into());
        }
        Ok(())
    }

    fn stored_kind(store: &S::CS, convo_id: &str) -> Result<ConversationKind, ChatError> {
        let record = store
            .load_conversation(convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))?;
        Ok(record.kind)
    }

    /// Caches a conversation under the kind whose scope holds its state. The core does this
    /// once the transaction creating it has committed and its record is written, since those are
    /// what make it real: a publish that fails afterwards must not cost it its place in memory.
    fn register_convo(
        &mut self,
        kind: ConversationKind,
        convo: ConvoTypeOwned<S>,
    ) -> Result<(), ChatError> {
        let scoped = ScopedConvo { kind, convo };
        let res = self
            .cached_convos
            .insert(scoped.convo.id().to_string(), scoped);

        match res {
            Some(_) => Err(ChatError::generic("Convo already exists. Cannot save")),
            None => Ok(()),
        }
    }

    /// Rebuilds a conversation from storage — the one site that branches on
    /// `ConversationKind`.
    fn load_convo(
        cx: &mut ServiceContext<S>,
        store: &S::CS,
        tx: &KvTransaction<'_>,
        convo_id: &str,
    ) -> Result<ScopedConvo<S>, ChatError> {
        let kind = Self::stored_kind(store, convo_id)?;
        match kind {
            ConversationKind::GroupV1 => Ok(ScopedConvo {
                kind,
                convo: ConvoTypeOwned::Group(Box::new(Self::load_mls_convo(cx, tx, convo_id)?)),
            }),
            other => Err(ChatError::UnsupportedConvoType(other.as_str().into())),
        }
    }

    /// Rebuilds a group conversation from storage so an operation can run against it.
    fn load_mls_convo(
        cx: &mut ServiceContext<S>,
        tx: &KvTransaction<'_>,
        convo_id: &str,
    ) -> Result<GroupV1Convo, ChatError> {
        GroupV1Convo::load(
            cx,
            tx.scope(ConversationKind::GroupV1, convo_id),
            convo_id.to_string(),
        )
    }

    pub fn convo_metadata(&self, convo_id: ConversationIdRef) -> Result<ConvoMetadata, ChatError> {
        match self.cached_convos.get(convo_id).map(|scoped| &scoped.convo) {
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

/// A conversation and the kind whose scope holds its state.
struct ScopedConvo<S: ExternalServices> {
    kind: ConversationKind,
    convo: ConvoTypeOwned<S>,
}
