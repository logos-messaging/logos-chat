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
use tracing::{info, instrument, warn};

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
    ///
    /// Conversations are rebuilt from the store before this installation's key package is
    /// published.
    pub fn new_from_store(
        ident: IP,
        delivery: DS,
        registration: RS,
        wakeup_service: WS,
        store: CS,
    ) -> Result<Self, ChatError> {
        let mut core = Self::assemble(ident, delivery, registration, wakeup_service, store)?;

        core.hydrate()?;
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
    /// addresses, and assembles the service bundle.
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

    /// Rebuilds the conversations the store lists, which also restores the delivery subscription
    /// each one holds. A record whose kind has no load path stays in the store and reports
    /// `UnsupportedConvoType` the next time it is addressed. Every other failure is returned: a
    /// listed record has state behind it, so a rebuild that fails says the store cannot be read.
    fn hydrate(&mut self) -> Result<(), ChatError> {
        let records = self.store.load_conversations()?;
        let tx = KvTransaction::begin(&self.store)?;
        for record in records {
            match Self::build_convo(&mut self.services, &tx, record.kind, &record.local_convo_id) {
                Ok(scoped) => {
                    self.cached_convos.insert(record.local_convo_id, scoped);
                }
                Err(ChatError::UnsupportedConvoType(_)) => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(())
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
        self.record(ConversationKind::DirectV1, &convo_id)?;
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
        self.record(ConversationKind::GroupV2, &convo_id)?;
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
        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        // A conversation that takes no members is turned away before the transaction stages
        // anything, so there is nothing to reload.
        let kind = scoped.kind;
        let ConvoTypeOwned::Group(group_convo) = &mut scoped.convo else {
            return Err(ChatError::UnsupportedFunction(
                convo_id.into(),
                "Add Member".into(),
            ));
        };

        let kv = tx.scope(kind, convo_id);
        let added = group_convo.add_member(&mut self.services, kv, members);
        let committed = Self::commit(&mut self.services, tx, added);
        self.reload_on_error(convo_id, committed)?;
        self.publish()
    }

    /// Remove members from an existing group conversation, naming them by
    /// signer (installation) id exactly as [`Self::group_add_member`] does.
    pub fn group_remove_member(
        &mut self,
        convo_id: &str,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        let kind = scoped.kind;
        let ConvoTypeOwned::Group(group_convo) = &mut scoped.convo else {
            return Err(ChatError::UnsupportedFunction(
                convo_id.into(),
                "Remove Member".into(),
            ));
        };

        let kv = tx.scope(kind, convo_id);
        let removed = group_convo.remove_member(&mut self.services, kv, members);
        let committed = Self::commit(&mut self.services, tx, removed);
        self.reload_on_error(convo_id, committed)?;
        self.publish()
    }

    /// Each member's MLS leaf-credential content (hex-encoded), for a direct
    /// conversation as for a group.
    pub fn group_members(&mut self, convo_id: &str) -> Result<Vec<Vec<u8>>, ChatError> {
        self.read_convo(convo_id)?.convo.members()
    }

    /// Each member invited here and still awaiting the group's commit, in the
    /// same encoding as [`Self::group_members`]. A direct conversation has no
    /// pending members and reports none.
    pub fn group_pending_members(&mut self, convo_id: &str) -> Result<Vec<Vec<u8>>, ChatError> {
        match &self.read_convo(convo_id)?.convo {
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
    /// ([`Self::list_all_conversations`]) may not be sendable, e.g. one rebuilt
    /// under a signer its own leaf does not name, one whose kind cannot be
    /// rebuilt yet, or one we were removed from.
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

    /// Removes a conversation: the record listing it, then everything its scope holds. Removing
    /// one already gone succeeds, so a removal that fails partway can be run again.
    pub fn remove_conversation(&mut self, convo_id: &str) -> Result<(), ChatError> {
        // Out of the cache first, so nothing writes to a conversation half removed. The record
        // goes before the scope: a crash between the two leaves state no record names, where the
        // reverse order leaves a record whose scope is empty and no conversation can be rebuilt
        // from. Once the record is gone nothing names the kind, so the scope goes under each one.
        self.cached_convos.remove(convo_id);
        self.store.remove_conversation(convo_id)?;

        let tx = KvTransaction::begin(&self.store)?;
        for kind in ConversationKind::ALL {
            tx.delete_scope(kind, convo_id)?;
        }
        tx.commit()?;
        Ok(())
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
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        let kv = tx.scope(scoped.kind, convo_id);
        let sent = scoped.convo.send_content(&mut self.services, kv, content);
        let committed = Self::commit(&mut self.services, tx, sent);
        let message_id = self.reload_on_error(convo_id, committed)?;
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
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        let kv = tx.scope(scoped.kind, convo_id);
        let handled = scoped
            .convo
            .handle_frame(&mut self.services, kv, enc_payload);
        let committed = Self::commit(&mut self.services, tx, handled);
        let outcome = self.reload_on_error(convo_id, committed)?;
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
        let committed = Self::commit(&mut self.services, tx, woken);
        let outcome = self.reload_on_error(convo_id, committed)?;
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

    /// Rebuilds the conversation a failed operation touched from the state the store kept: what
    /// the operation ran in memory is a step ahead of what landed. A rebuild that fails too leaves
    /// the conversation uncached, for the next operation addressing it to rebuild.
    ///
    /// A GroupV2 conversation cannot be rebuilt yet (#135), so it stays cached and keeps that
    /// step of lead over the store.
    fn reload_on_error<T>(
        &mut self,
        convo_id: &str,
        outcome: Result<T, ChatError>,
    ) -> Result<T, ChatError> {
        if outcome.is_err()
            && self
                .cached_convos
                .get(convo_id)
                .is_some_and(|scoped| scoped.kind != ConversationKind::GroupV2)
        {
            self.cached_convos.remove(convo_id);
            if let Err(err) = self.reload(convo_id) {
                warn!(convo_id, %err, "conversation left uncached after a failed reload");
            }
        }
        outcome
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

    /// The conversation an operation addresses, rebuilt from the store and cached again when the
    /// cache does not hold it, as after a failed operation whose reload failed too.
    fn cached_or_loaded<'c>(
        cached_convos: &'c mut HashMap<String, ScopedConvo<S>>,
        cx: &mut ServiceContext<S>,
        store: &S::CS,
        tx: &KvTransaction<'_>,
        convo_id: &str,
    ) -> Result<&'c mut ScopedConvo<S>, ChatError> {
        if !cached_convos.contains_key(convo_id) {
            let scoped = Self::load_convo(cx, store, tx, convo_id)?;
            cached_convos.insert(convo_id.to_string(), scoped);
        }

        Ok(cached_convos
            .get_mut(convo_id)
            .expect("the conversation was just cached"))
    }

    /// The conversation a read addresses. Only a rebuild reaches the store, so a cache hit opens
    /// no transaction: a store is free to make one exclusive, and a read holding it would block
    /// writers for nothing.
    fn read_convo(&mut self, convo_id: &str) -> Result<&ScopedConvo<S>, ChatError> {
        if !self.cached_convos.contains_key(convo_id) {
            self.reload(convo_id)?;
        }

        Ok(&self.cached_convos[convo_id])
    }

    /// Rebuilds a conversation from the store and caches it.
    fn reload(&mut self, convo_id: &str) -> Result<(), ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::load_convo(&mut self.services, &self.store, &tx, convo_id)?;
        self.cached_convos.insert(convo_id.to_string(), scoped);
        Ok(())
    }

    fn load_convo(
        cx: &mut ServiceContext<S>,
        store: &S::CS,
        tx: &KvTransaction<'_>,
        convo_id: &str,
    ) -> Result<ScopedConvo<S>, ChatError> {
        let kind = Self::stored_kind(store, convo_id)?;
        Self::build_convo(cx, tx, kind, convo_id)
    }

    /// Rebuilds a conversation from its record, the one site that turns the kind a record
    /// names into its conversation type.
    fn build_convo(
        cx: &mut ServiceContext<S>,
        tx: &KvTransaction<'_>,
        kind: ConversationKind,
        convo_id: &str,
    ) -> Result<ScopedConvo<S>, ChatError> {
        let kv = tx.scope(kind, convo_id);
        let convo = match kind {
            ConversationKind::GroupV1 => {
                ConvoTypeOwned::Group(Box::new(GroupV1Convo::load(cx, kv, convo_id.to_string())?))
            }
            ConversationKind::DirectV1 => {
                ConvoTypeOwned::Direct(Box::new(DirectV1Convo::load(cx, kv, convo_id.to_string())?))
            }
            // GroupV2 state is durable, but de-mls offers no way to resume a conversation from
            // it yet (#135).
            ConversationKind::GroupV2 => {
                return Err(ChatError::UnsupportedConvoType(kind.as_str().into()));
            }
        };
        Ok(ScopedConvo { kind, convo })
    }

    pub fn convo_metadata(
        &mut self,
        convo_id: ConversationIdRef,
    ) -> Result<ConvoMetadata, ChatError> {
        match &self.read_convo(convo_id)?.convo {
            ConvoTypeOwned::Group(group_convo) => {
                group_convo
                    .metadata()
                    .ok_or(ChatError::UnsupportedConvoType(
                        "metadata is not available for this legacy convo_type".into(),
                    ))
            }
            ConvoTypeOwned::Direct(_) => Err(ChatError::UnsupportedFunction(
                convo_id.into(),
                "implementation coming".into(),
            )),
        }
    }
}

/// A conversation and the kind whose scope holds its state.
struct ScopedConvo<S: ExternalServices> {
    kind: ConversationKind,
    convo: ConvoTypeOwned<S>,
}
