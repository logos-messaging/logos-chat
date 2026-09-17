use std::collections::HashSet;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use components::{ThreadedWakeupService, WakeupEvent};
use crossbeam_channel::{Receiver, Sender, select};
use libchat::{
    AuthService, AuthStatus, AuthenticatedMember, ConversationId, ConvoMetadata, ConvoOutcome,
    Core, DeliveryAck, DeliveryService, ExternalIdentifier, GroupV2Config, InboxOutcome,
    Membership, MembershipState, MessageId, MissingMessage, PayloadOutcome, RegistrationService,
    Signer, SignerRef,
};
use logos_account::AccountAddr;
use parking_lot::Mutex;
use storage::ConversationStore;

use crate::delegate::{DelegateCredential, DelegateIdentity, DelegateSigner};
use crate::errors::ClientError;
use crate::event::{Event, MessageSender};

type ClientCore<T, R, A, S> = Core<(DelegateIdentity, A, T, R, ThreadedWakeupService, S)>;
type AccountAddressRef<'a> = &'a str;
type LocalSigner = Signer;

/// A member of a group conversation's roster.
///
/// Shares [`MessageSender`]'s field semantics: `account` is set only when the
/// member's credential claimed an account *and* the directory confirmed this
/// device belongs to it. Unlike a message sender, an unconfirmable claim does
/// not hide the member: a committed member is cryptographically in the group,
/// so it is listed by `local_identity` (its device) with `account: None`.
///
/// `pending` marks a member whose add the group has not committed yet, so it
/// cannot read the conversation. Only invites this client sent are reported;
/// an add another member proposed is invisible until it commits. The flag
/// clears when the commit admitting the member lands, and an invite the group
/// never commits stays pending for the life of the conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub account: Option<AccountAddr>,
    pub local_identity: Signer,
    pub pending: bool,
    /// The core's verdict on this member. A committed member that is not
    /// `Valid` can still read the conversation.
    pub auth: AuthStatus,
}

/// Metadata a caller supplies when creating a group: its shared name and
/// description. Distinct from [`ConvoMetadata`], the type a conversation
/// reports back — the two carry different concerns and evolve independently
/// (the reported metadata may grow fields a caller cannot set).
#[derive(Debug, Clone)]
pub struct GroupMetadata {
    pub name: String,
    pub desc: String,
}

impl GroupMetadata {
    pub fn new(name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            desc: desc.into(),
        }
    }
}

/// The transport as the client sees it: a [`DeliveryService`] for outbound
/// publishing plus the inbound payload stream the worker drains. One object owns
/// both directions of the boundary.
pub trait Transport: DeliveryService + Send + 'static {
    /// Hand over the inbound payload stream. Called once, at client construction,
    /// before the [`Core`] takes ownership of the service.
    fn inbound(&mut self) -> Receiver<Vec<u8>>;
}

/// High-level chat client.
///
/// Owns the synchronous [`Core`] behind an `Arc<Mutex<…>>` and a background
/// worker that consumes inbound payloads off the transport's channel, drives
/// the core, and forwards observations as [`Event`]s. Construction returns the
/// handle together with the `Receiver<Event>` the application drains on its own
/// schedule.
///
/// Outbound calls (`send_message`, `create_conversation`, …) run on the
/// caller's thread: they briefly lock the core, invoke it, and return — no
/// message-passing round-trip. The `Arc`/`Mutex`/threads live entirely here;
/// the core never mentions threads.
pub struct ChatClient<T, R, A, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Clone + Send + 'static,
    A: AuthService + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    /// `parking_lot::Mutex` for its eventual fairness: an inbound burst can't
    /// starve caller operations of the lock.
    core: Arc<Mutex<ClientCore<T, R, A, S>>>,

    /// Dropped on `Drop` to wake the worker's `select!` and shut it down.
    shutdown: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
    address: String,
}

// -- GenericChatClient
impl<T, R, A, S> ChatClient<T, R, A, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Clone + Send + 'static,
    A: AuthService + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn new(
        ident: DelegateSigner,
        account: String,
        mut transport: T,
        reg: R,
        auth: A,
        storage: S,
        group_v2: Option<GroupV2Config>,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let inbound = transport.inbound();

        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let ident = DelegateIdentity::new(ident, &account);
        let mut core = Core::new_with_name(ident, auth, transport, reg, wakeup_service, storage)?;
        if let Some(config) = group_v2 {
            core.set_group_v2_config(config);
        }
        Ok(Self::spawn(core, account, inbound, wakeup_rx))
    }

    fn spawn(
        core: ClientCore<T, R, A, S>,
        address: String,
        inbound: Receiver<Vec<u8>>,
        wakeup_events: Receiver<WakeupEvent>,
    ) -> (Self, Receiver<Event>) {
        let core = Arc::new(Mutex::new(core));
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(0);

        let worker = thread::spawn({
            let core = Arc::clone(&core);
            move || worker_loop(core, inbound, wakeup_events, shutdown_rx, event_tx)
        });

        (
            Self {
                core,
                shutdown: Some(shutdown_tx),
                worker: Some(worker),
                address,
            },
            event_rx,
        )
    }

    /// The account address peers use to reach this client.
    pub fn addr(&self) -> &str {
        &self.address
    }

    /// Returns the installation name (identity label) of this client.
    pub fn installation_name(&self) -> String {
        self.core.lock().installation_name().to_string()
    }

    // Creates a conversation between two Accounts.
    pub fn create_direct_conversation(
        &mut self,
        account: AccountAddressRef,
    ) -> Result<ConversationId, ClientError> {
        let signers = self.signers_from_account(account)?;
        let signer_refs: Vec<SignerRef> = signers.iter().collect();

        self.core
            .lock()
            .create_direct_convo(&signer_refs)
            .map_err(Into::into)
    }

    /// Create a GroupV2 conversation with the given accounts' devices. Each
    /// account resolves to the signer ids its directory bundle endorses; the
    /// group invite goes to every one of them. An empty slice creates a group
    /// with only this client, to grow via [`Self::add_group_members`].
    /// `metadata` becomes the group's shared name and description, carried to
    /// every joiner in the welcome and readable via [`Self::group_metadata`];
    /// both fields may be empty.
    pub fn create_group_conversation(
        &mut self,
        accounts: &[AccountAddressRef],
        metadata: GroupMetadata,
    ) -> Result<ConversationId, ClientError> {
        let signers = self.signers_from_accounts(accounts)?;
        let signer_refs: Vec<SignerRef> = signers.iter().collect();

        self.core
            .lock()
            .create_group_convo_v2(&signer_refs, &metadata.name, &metadata.desc)
            .map_err(Into::into)
    }

    /// Add accounts' devices to an existing group conversation. The add is
    /// staged as an MLS proposal and merged by the group's next commit (driven
    /// asynchronously by the wakeup loop); each joiner's welcome is sent when
    /// that commit lands, not when this call returns.
    pub fn add_group_members(
        &mut self,
        convo_id: &str,
        accounts: &[AccountAddressRef],
    ) -> Result<(), ClientError> {
        let signers = self.signers_from_accounts(accounts)?;
        let signer_refs: Vec<SignerRef> = signers.iter().collect();

        self.core
            .lock()
            .group_add_member(convo_id, &signer_refs)
            .map_err(Into::into)
    }

    /// The conversation's roster, one [`GroupMember`] per account (self
    /// included), for a direct conversation as for a group: committed members
    /// first and this client's uncommitted invites after them, flagged
    /// `pending`. An account's several devices collapse to a single entry
    /// surfacing that account; a member whose account claim the directory can't
    /// confirm stays on the roster individually, keyed by its device. An account
    /// that is both committed and pending collapses to its committed entry.
    /// Costs one directory lookup per member that claims an account, the same
    /// per-member cost a received message's sender check pays.
    pub fn group_members(&mut self, convo_id: &str) -> Result<Vec<GroupMember>, ClientError> {
        let memberships = self.core.lock().memberships(convo_id)?;
        Ok(dedup_members(memberships.into_iter().map(roster_member)))
    }

    /// The group's shared metadata (name and description), set at creation and
    /// carried to every joiner in the welcome. Both fields may be empty. Fails
    /// for a direct conversation and for a legacy group that carries no metadata.
    pub fn group_metadata(&self, convo_id: &str) -> Result<ConvoMetadata, ClientError> {
        self.core
            .lock()
            .convo_metadata(convo_id)
            .map_err(Into::into)
    }

    /// Every conversation ID known to this client, whether or not it can
    /// currently be sent to or read. Existence only — see [`Self::can_send`] /
    /// [`Self::can_receive`] to act on one, or [`Self::list_sendable_conversations`]
    /// for the pre-filtered roster a UI usually wants.
    pub fn list_all_conversations(&self) -> Result<Vec<ConversationId>, ClientError> {
        self.core
            .lock()
            .list_all_conversations()
            .map_err(Into::into)
    }

    /// The subset of [`Self::list_all_conversations`] content can currently be
    /// sent to.
    pub fn list_sendable_conversations(&self) -> Result<Vec<ConversationId>, ClientError> {
        self.core
            .lock()
            .list_sendable_conversations()
            .map_err(Into::into)
    }

    /// Whether this client can currently submit content to `convo_id`: it is
    /// usable this session and the local identity is still a member with send
    /// rights.
    ///
    /// Deliberately distinct from existence: a conversation can be *known*
    /// ([`Self::list_all_conversations`]) yet not sendable — restored from a
    /// previous session and not reloaded, or one we were removed from. Send
    /// permission (read-only / broadcast conversations) will refine this once
    /// roles carry it; today it reflects live MLS membership.
    pub fn can_send(&self, convo_id: &str) -> bool {
        self.core.lock().can_send(convo_id)
    }

    /// Whether `convo_id` can be read/received from: it is known to this client
    /// (loaded this session or persisted). Broader than [`Self::can_send`] — a
    /// conversation can be received from yet not sent to.
    pub fn can_receive(&self, convo_id: &str) -> bool {
        self.core.lock().can_receive(convo_id)
    }

    /// Encrypt and send `content` to an existing conversation. The core
    /// publishes the outbound envelope.
    ///
    /// Returns the message's id, which later [`Event::MessageAcked`] events
    /// carry — hold onto it to show which peers have the message.
    pub fn send_message(
        &mut self,
        convo_id: &str,
        content: &[u8],
    ) -> Result<MessageId, ClientError> {
        self.core
            .lock()
            .send_content(convo_id, content)
            .map_err(Into::into)
    }

    /// Resolve an account address to its signer (device) ids.
    fn signers_from_account(
        &self,
        account: AccountAddressRef,
    ) -> Result<Vec<LocalSigner>, ClientError> {
        // TODO: resolving an account to its devices went with the device-bundle
        // directory and has no replacement yet.
        unimplemented!("account resolution for {account}")
    }

    /// Resolve each account to its signer ids and flatten them, failing on the
    /// first unresolvable account.
    fn signers_from_accounts(
        &self,
        accounts: &[AccountAddressRef],
    ) -> Result<Vec<LocalSigner>, ClientError> {
        let mut signers = Vec::new();
        for account in accounts {
            signers.extend(self.signers_from_account(account)?);
        }
        Ok(signers)
    }
}

impl<T, R, A, S> Drop for ChatClient<T, R, A, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Clone + Send + 'static,
    A: AuthService + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    fn drop(&mut self) {
        // Dropping the sender disconnects the worker's shutdown channel, waking
        // its `select!` so it can exit; then we join it.
        self.shutdown.take();
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

/// Background loop: block until an inbound payload or shutdown arrives, drive
/// the core on each payload, and forward events. No polling — `select!` parks
/// the thread until one of the channels is ready.
fn worker_loop<T, R, A, S: ConversationStore + 'static>(
    core: Arc<Mutex<ClientCore<T, R, A, S>>>,
    inbound: Receiver<Vec<u8>>,
    wakeup_events: Receiver<WakeupEvent>,
    shutdown: Receiver<()>,
    event_tx: Sender<Event>,
) where
    T: DeliveryService + Send + 'static,
    R: RegistrationService + Send + 'static,
    A: AuthService + Send + 'static,
{
    loop {
        select! {
            recv(inbound) -> msg => {
                let Ok(bytes) = msg else {
                    return; // transport's sender dropped
                };
                let events = {
                    let mut core = core.lock();
                    let mut events = match core.handle_payload(&bytes) {
                        Ok(outcome) => events_from_inbound(outcome),
                        Err(e) => {
                            tracing::warn!("inbound handle_payload failed: {e:?}");
                            vec![Event::InboundError {
                                message: e.to_string(),
                            }]
                        }
                    };
                    events.extend(delivery_ack_events(core.take_acks()));
                    events.extend(missing_events(core.take_missing_messages()));
                    events
                };
                for event in events {
                    if event_tx.send(event).is_err() {
                        return; // application dropped the receiver
                    }
                }
            }
            recv(wakeup_events) -> msg => {
                let Ok(WakeupEvent { convo_id }) = msg else {
                    return; // wakeup service's sender dropped
                };
                // A wakeup can drive the steward's own commit, so it yields events too.
                let events = {
                    let mut core = core.lock();
                    let mut events = match core.wakeup(&convo_id) {
                        Ok(outcome) => events_from_inbound(outcome),
                        Err(e) => {
                            tracing::warn!("wakeup failed: {e:?}");
                            Vec::new()
                        }
                    };
                    events.extend(delivery_ack_events(core.take_acks()));
                    events.extend(missing_events(core.take_missing_messages()));
                    events
                };
                for event in events {
                    if event_tx.send(event).is_err() {
                        return; // application dropped the receiver
                    }
                }
            }
            recv(shutdown) -> _ => return,
        }
    }
}

/// Walk a [`PayloadOutcome`] in causal order and emit one `Event` per
/// observation. For an `Inbox` outcome, [`Event::ConversationStarted`]
/// precedes the message event. The convo id is wrapped into `Arc<str>` once
/// per outcome and shared across the events it produces.
fn events_from_inbound(result: PayloadOutcome) -> Vec<Event> {
    match result {
        PayloadOutcome::Empty => Vec::new(),
        PayloadOutcome::Convo(co) => convo_events(co),
        PayloadOutcome::Inbox(io) => inbox_events(io),
    }
}

/// Map the acknowledgements the core observed while processing one payload onto
/// [`Event::MessageAcked`], one per peer per message.
///
/// Drained from the same place as [`missing_events`]: the causal history of the
/// message just processed is what carried the acknowledgement.
fn delivery_ack_events(acks: Vec<DeliveryAck>) -> Vec<Event> {
    acks.into_iter()
        .map(|a| Event::MessageAcked {
            convo_id: Arc::from(a.conversation_id),
            message_id: a.message_id,
            acked_by: a.acked_by,
        })
        .collect()
}

/// Map the causal-history gaps the core detected while processing one payload
/// onto [`Event::MessageMissing`].
///
/// Drained right after each drive of the core, so a gap arrives with the batch
/// of events for the message that revealed it — and after them, so a gap on a
/// conversation this payload just started still follows its
/// [`Event::ConversationStarted`].
fn missing_events(missing: Vec<MissingMessage>) -> Vec<Event> {
    missing
        .into_iter()
        .map(|m| Event::MessageMissing {
            convo_id: Arc::from(m.conversation_id),
            message_id: m.frontier.message_id().to_owned(),
            sender_hint: m.frontier.sender().clone(),
        })
        .collect()
}

/// The account a credential claims, if any. Only meaningful for a member the
/// core has authenticated: that is what makes the claim trustworthy.
fn claimed_account(external_id: &ExternalIdentifier) -> Option<AccountAddr> {
    DelegateCredential::try_from(external_id.as_bytes().to_vec())
        .ok()?
        .account_addr()?
        .parse()
        .ok()
}

/// The app-facing sender of delivered content: its MLS-verified device, and
/// the account its credential claims.
fn message_sender(sender: AuthenticatedMember) -> MessageSender {
    MessageSender {
        account: claimed_account(sender.external_id()),
        local_identity: sender.signer().clone(),
    }
}

/// A roster entry for one membership. The account is reported only when the
/// core found the member valid; any other verdict leaves the device alone.
fn roster_member(membership: Membership) -> GroupMember {
    let Membership {
        member,
        state,
        auth,
    } = membership;
    GroupMember {
        account: (auth == AuthStatus::Valid)
            .then(|| claimed_account(&member.external_id))
            .flatten(),
        local_identity: member.signer,
        pending: state == MembershipState::Pending,
        auth,
    }
}

/// The key that decides whether two roster entries are the same member: a
/// verified account, so an account's several devices count once; or, for a
/// member with no confirmed account, its device — unique per MLS leaf, so it
/// never merges with another.
fn member_key(member: &GroupMember) -> String {
    match &member.account {
        Some(account) => account.to_string(),
        None => member.local_identity.to_string(),
    }
}

/// Collapse a roster to one entry per account (keeping the first-seen device as
/// the account's representative) while leaving account-less members individual,
/// order preserved.
fn dedup_members(members: impl IntoIterator<Item = GroupMember>) -> Vec<GroupMember> {
    let mut seen = HashSet::new();
    members
        .into_iter()
        .filter(|member| seen.insert(member_key(member).to_owned()))
        .collect()
}

fn convo_events(outcome: ConvoOutcome) -> Vec<Event> {
    let ConvoOutcome {
        convo_id,
        content,
        members_changed,
    } = outcome;
    let convo_id: Arc<str> = Arc::from(convo_id);
    let mut events = Vec::new();
    if let Some(c) = content {
        events.push(Event::MessageReceived {
            convo_id: Arc::clone(&convo_id),
            content: c.bytes,
            sender: message_sender(c.sender),
        });
    }
    if members_changed {
        events.push(Event::ConversationMembersChanged { convo_id });
    }
    events
}

fn inbox_events(outcome: InboxOutcome) -> Vec<Event> {
    let InboxOutcome {
        new_conversation,
        initial,
    } = outcome;
    let id: Arc<str> = Arc::from(new_conversation.convo_id);
    let mut events = Vec::with_capacity(2);
    events.push(Event::ConversationStarted {
        convo_id: Arc::clone(&id),
        class: new_conversation.class,
    });
    if let Some(c) = initial.and_then(|co| co.content) {
        events.push(Event::MessageReceived {
            convo_id: Arc::clone(&id),
            content: c.bytes,
            sender: message_sender(c.sender),
        });
    }
    events
}

#[cfg(test)]
mod sender_check_tests {
    use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};

    use super::{
        AccountAddr, AuthStatus, Event, GroupMember, Signer, dedup_members, delivery_ack_events,
        member_key, missing_events,
    };
    use libchat::{DeliveryAck, Frontier, MissingMessage};

    fn key() -> Ed25519VerifyingKey {
        Ed25519SigningKey::generate().verifying_key()
    }

    fn local_id(k: &Ed25519VerifyingKey) -> Signer {
        Signer::from(k.clone())
    }

    /// The same key an account is known by, as an address.
    fn addr(k: &Ed25519VerifyingKey) -> AccountAddr {
        AccountAddr::try_from(k.as_ref()).expect("a generated key is an address")
    }

    /// The roster collapses an account's several devices into one entry (keeping
    /// the first device seen) while leaving account-less members individual,
    /// order preserved.
    #[test]
    fn dedup_collapses_account_devices_and_keeps_unknowns() {
        let (alice, bob) = (addr(&key()), addr(&key()));
        let (alice_dev_1, alice_dev_2) = (local_id(&key()), local_id(&key()));
        let bob_dev_1 = local_id(&key());
        let (orphan_x, orphan_y) = (local_id(&key()), local_id(&key()));
        let with_account = |account: &AccountAddr, device: &Signer| GroupMember {
            account: Some(account.clone()),
            local_identity: device.clone(),
            pending: false,
            auth: AuthStatus::Valid,
        };
        let device_only = |device: &Signer| GroupMember {
            account: None,
            local_identity: device.clone(),
            pending: false,
            auth: AuthStatus::Valid,
        };
        let roster = dedup_members(vec![
            with_account(&alice, &alice_dev_1),
            with_account(&alice, &alice_dev_2),
            device_only(&orphan_x),
            with_account(&bob, &bob_dev_1),
            device_only(&orphan_y),
        ]);
        let keys: Vec<String> = roster.iter().map(member_key).collect();
        assert_eq!(
            keys,
            [
                alice.to_string(),
                orphan_x.to_string(),
                bob.to_string(),
                orphan_y.to_string(),
            ]
        );
        // Alice's collapsed entry keeps her first-seen device.
        assert_eq!(roster[0].local_identity, alice_dev_1);
    }

    /// An account that is both committed and pending collapses to its committed
    /// entry: `group_members` chains committed members first, and dedup keeps
    /// the first entry per account.
    #[test]
    fn dedup_collapses_a_pending_duplicate_into_the_committed_member() {
        let alice = addr(&key());
        let committed = GroupMember {
            account: Some(alice.clone()),
            local_identity: local_id(&key()),
            pending: false,
            auth: AuthStatus::Valid,
        };
        let pending = GroupMember {
            account: Some(alice),
            local_identity: local_id(&key()),
            pending: true,
            auth: AuthStatus::Valid,
        };
        assert_eq!(
            dedup_members(vec![committed.clone(), pending]),
            vec![committed]
        );
    }

    /// A gap reported by the causal history, as the core hands it over.
    fn gap(sender_hint: &Signer) -> MissingMessage {
        MissingMessage {
            conversation_id: "convo".to_owned(),
            frontier: Frontier::new(sender_hint.clone(), "msg-id".to_owned()),
        }
    }

    /// The gap is reported with the device the causal history names.
    #[test]
    fn missing_message_hint_names_the_device() {
        let device = local_id(&key());

        match <[Event; 1]>::try_from(missing_events(vec![gap(&device)]))
            .expect("one gap produces one event")
            .into_iter()
            .next()
            .unwrap()
        {
            Event::MessageMissing {
                convo_id,
                message_id,
                sender_hint,
            } => {
                assert_eq!(&*convo_id, "convo");
                assert_eq!(message_id, "msg-id");
                assert_eq!(sender_hint, device);
            }
            other => panic!("expected MessageMissing, got {other:?}"),
        }
    }

    /// One acknowledgement per peer per message, each naming the peer an
    /// application would list against the message.
    #[test]
    fn acks_name_the_peers_that_hold_the_message() {
        let device = local_id(&key());

        let events = delivery_ack_events(vec![DeliveryAck {
            conversation_id: "convo".to_owned(),
            message_id: "msg-id".to_owned(),
            acked_by: device.clone(),
        }]);

        match <[Event; 1]>::try_from(events)
            .expect("one ack produces one event")
            .into_iter()
            .next()
            .unwrap()
        {
            Event::MessageAcked {
                convo_id,
                message_id,
                acked_by,
            } => {
                assert_eq!(&*convo_id, "convo");
                assert_eq!(message_id, "msg-id");
                assert_eq!(acked_by, device);
            }
            other => panic!("expected MessageAcked, got {other:?}"),
        }
    }
}
