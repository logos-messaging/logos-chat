use std::collections::HashSet;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use components::{ThreadedWakeupService, WakeupEvent};
use crossbeam_channel::{Receiver, Sender, select};
use crypto::Ed25519VerifyingKey;
use libchat::{
    ConversationId, ConvoMetadata, ConvoOutcome, Core, DeliveryAck, DeliveryService, GroupV2Config,
    IdentId, IdentIdRef, InboxOutcome, MessageId, MissingMessage, PayloadOutcome,
    RegistrationService,
};
use logos_account::{AccountDirectory, resolve_device_ids};
use parking_lot::Mutex;
use storage::ConversationStore;

use crate::delegate::{DelegateCredential, DelegateIdentity, DelegateSigner};
use crate::errors::ClientError;
use crate::event::{Event, MessageSender};

type ClientCore<T, R, S> = Core<(DelegateIdentity, T, R, ThreadedWakeupService, S)>;
type AccountAddressRef<'a> = &'a str;
type LocalSignerId = IdentId;

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
    pub account: Option<IdentId>,
    pub local_identity: IdentId,
    pub pending: bool,
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
pub struct ChatClient<T, R, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    /// `parking_lot::Mutex` for its eventual fairness: an inbound burst can't
    /// starve caller operations of the lock.
    core: Arc<Mutex<ClientCore<T, R, S>>>,
    /// The account → device directory. On testnet the registration service
    /// doubles as the directory (one deployed registry serves both roles), so
    /// the client keeps its own clone of `R`; the core sees key packages only.
    directory: R,
    /// Dropped on `Drop` to wake the worker's `select!` and shut it down.
    shutdown: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
    address: String,
}

// -- GenericChatClient
impl<T, R, S> ChatClient<T, R, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ConversationStore + Send + 'static,
{
    pub fn new(
        ident: DelegateSigner,
        account: String,
        mut transport: T,
        reg: R,
        storage: S,
        group_v2: Option<GroupV2Config>,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let inbound = transport.inbound();

        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let directory = reg.clone();
        let ident = DelegateIdentity::new(ident, &account);
        let mut core = Core::new_with_name(ident, transport, reg, wakeup_service, storage)?;
        if let Some(config) = group_v2 {
            core.set_group_v2_config(config);
        }
        Ok(Self::spawn(core, directory, account, inbound, wakeup_rx))
    }

    fn spawn(
        core: ClientCore<T, R, S>,
        directory: R,
        address: String,
        inbound: Receiver<Vec<u8>>,
        wakeup_events: Receiver<WakeupEvent>,
    ) -> (Self, Receiver<Event>) {
        let core = Arc::new(Mutex::new(core));
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(0);

        let worker = thread::spawn({
            let core = Arc::clone(&core);
            let directory = directory.clone();
            move || {
                worker_loop(
                    core,
                    directory,
                    inbound,
                    wakeup_events,
                    shutdown_rx,
                    event_tx,
                )
            }
        });

        (
            Self {
                core,
                directory,
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
        let signer_refs: Vec<IdentIdRef> = signers.iter().collect();

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
        let signer_refs: Vec<IdentIdRef> = signers.iter().collect();

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
        let signer_refs: Vec<IdentIdRef> = signers.iter().collect();

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
        let (committed, pending) = {
            let mut core = self.core.lock();
            (
                core.group_members(convo_id)?,
                core.group_pending_members(convo_id)?,
            )
        };
        let members = committed
            .iter()
            .filter_map(|credential| roster_member(&self.directory, credential))
            .chain(pending.iter().filter_map(|credential| {
                roster_member(&self.directory, credential).map(|member| GroupMember {
                    pending: true,
                    ..member
                })
            }));
        Ok(dedup_members(members))
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

    /// Resolve an account address to the signer (device) ids its published
    /// directory bundle endorses. A reachable account has published at least
    /// one signer; anything else is an error.
    fn signers_from_account(
        &self,
        account: AccountAddressRef,
    ) -> Result<Vec<LocalSignerId>, ClientError> {
        let account = IdentId::new(account.to_string());
        let device_ids = resolve_device_ids(&self.directory, &account)
            .map_err(|e| ClientError::AccountResolution(e.to_string()))?;
        Ok(device_ids.into_iter().map(IdentId::new).collect())
    }

    /// Resolve each account to its signer ids and flatten them, failing on the
    /// first unresolvable account.
    fn signers_from_accounts(
        &self,
        accounts: &[AccountAddressRef],
    ) -> Result<Vec<LocalSignerId>, ClientError> {
        let mut signers = Vec::new();
        for account in accounts {
            signers.extend(self.signers_from_account(account)?);
        }
        Ok(signers)
    }
}

impl<T, R, S> Drop for ChatClient<T, R, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
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
fn worker_loop<T, R, S: ConversationStore + 'static>(
    core: Arc<Mutex<ClientCore<T, R, S>>>,
    directory: R,
    inbound: Receiver<Vec<u8>>,
    wakeup_events: Receiver<WakeupEvent>,
    shutdown: Receiver<()>,
    event_tx: Sender<Event>,
) where
    T: DeliveryService + Send + 'static,
    R: RegistrationService + AccountDirectory + Send + 'static,
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
                        Ok(outcome) => events_from_inbound(outcome, &directory),
                        Err(e) => {
                            tracing::warn!("inbound handle_payload failed: {e:?}");
                            vec![Event::InboundError {
                                message: e.to_string(),
                            }]
                        }
                    };
                    events.extend(delivery_ack_events(core.take_acks(), &directory));
                    events.extend(missing_events(core.take_missing_messages(), &directory));
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
                        Ok(outcome) => events_from_inbound(outcome, &directory),
                        Err(e) => {
                            tracing::warn!("wakeup failed: {e:?}");
                            Vec::new()
                        }
                    };
                    events.extend(delivery_ack_events(core.take_acks(), &directory));
                    events.extend(missing_events(core.take_missing_messages(), &directory));
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
fn events_from_inbound(result: PayloadOutcome, directory: &impl AccountDirectory) -> Vec<Event> {
    match result {
        PayloadOutcome::Empty => Vec::new(),
        PayloadOutcome::Convo(co) => convo_events(co, directory),
        PayloadOutcome::Inbox(io) => inbox_events(io, directory),
    }
}

/// Map the acknowledgements the core observed while processing one payload onto
/// [`Event::MessageAcked`], one per peer per message.
///
/// Drained from the same place as [`missing_events`]: the causal history of the
/// message just processed is what carried the acknowledgement.
fn delivery_ack_events(acks: Vec<DeliveryAck>, directory: &impl AccountDirectory) -> Vec<Event> {
    acks.into_iter()
        .map(|a| Event::MessageAcked {
            convo_id: Arc::from(a.conversation_id),
            message_id: a.message_id,
            acked_by: sender_hint(directory, &a.acked_by),
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
fn missing_events(missing: Vec<MissingMessage>, directory: &impl AccountDirectory) -> Vec<Event> {
    missing
        .into_iter()
        .map(|m| Event::MessageMissing {
            convo_id: Arc::from(m.conversation_id),
            message_id: m.frontier.message_id().to_owned(),
            sender_hint: sender_hint(directory, m.frontier.sender_id()),
        })
        .collect()
}

/// Resolve a participant a causal-history observation named — the author of a
/// message we never saw, or the peer acknowledging one of ours.
///
/// Same credential decoding as a delivered message's sender, but the claim is
/// self-asserted rather than authenticated, so an unconfirmable account yields
/// the device alone rather than dropping the observation. `None` when the value
/// is not a credential at all.
fn sender_hint(directory: &impl AccountDirectory, encoded: &str) -> Option<MessageSender> {
    let (device, claim) = parse_credential(directory, encoded.as_bytes()).ok()?;
    Some(MessageSender {
        account: match claim {
            AccountClaim::Verified(account) => Some(account),
            AccountClaim::None | AccountClaim::Unverified(_) => None,
        },
        local_identity: device,
    })
}

/// Interpret a hex account address as an Ed25519 account verifying key.
fn account_key_from_hex(addr: &str) -> Option<Ed25519VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(addr).ok()?.try_into().ok()?;
    Ed25519VerifyingKey::from_bytes(&bytes).ok()
}

/// Why a message's sender could not be accepted, so the message is dropped.
#[derive(Debug, PartialEq, Eq)]
enum SenderError {
    /// No credential at all, so no sender can be attributed. Every delivered
    /// message must carry an explicit sender.
    Missing,
    /// Credential bytes were not valid hex.
    NotHex,
    /// Credential bytes did not decode to a delegate credential.
    Malformed,
    /// The claimed account address is not an Ed25519 verifying key.
    AccountNotAKey,
    /// The account → device mapping is wrong or could not be confirmed: the
    /// device is not in the account's published set, the account published none,
    /// or the directory lookup failed.
    Unverified,
}

/// The resolution of a credential's account claim against the directory.
enum AccountClaim {
    /// The credential claimed no account.
    None,
    /// Confirmed: the directory lists this device under the claimed account.
    Verified(IdentId),
    /// An account was claimed but could not be confirmed (see [`SenderError`]).
    Unverified(SenderError),
}

/// Parse a wire credential into the device it names and the resolution of any
/// account claim, checked against the account → device directory. `Err` only
/// when no device can be attributed at all (missing or unparseable credential).
///
/// The account-claim policy is left to the caller: a message drops on an
/// unconfirmable claim, a roster entry keeps the device and forgoes the account.
fn parse_credential(
    directory: &impl AccountDirectory,
    encoded: &[u8],
) -> Result<(IdentId, AccountClaim), SenderError> {
    // No credential at all: there is no device to attribute.
    if encoded.is_empty() {
        return Err(SenderError::Missing);
    }
    let Ok(data) = hex::decode(encoded) else {
        tracing::warn!("credential is not valid hex");
        return Err(SenderError::NotHex);
    };
    let Ok(cred) = DelegateCredential::try_from(data) else {
        tracing::warn!("malformed credential");
        return Err(SenderError::Malformed);
    };
    let device = IdentId::new(hex::encode(cred.delegate_id().as_ref()));
    // An unassociated delegate asserts no account → device mapping.
    let Some(account_addr) = cred.account_addr() else {
        return Ok((device, AccountClaim::None));
    };
    let Some(account_key) = account_key_from_hex(account_addr) else {
        tracing::warn!(account_addr, "account address is not a verifying key");
        return Ok((
            device,
            AccountClaim::Unverified(SenderError::AccountNotAKey),
        ));
    };
    let claim = match directory.fetch(&account_key) {
        Ok(Some(set)) if set.devices.iter().any(|d| d.as_str() == device.as_str()) => {
            AccountClaim::Verified(IdentId::new(account_addr.to_string()))
        }
        _ => {
            tracing::warn!(account_addr, device = %device.as_str(), "account → device mapping is wrong or unconfirmable");
            AccountClaim::Unverified(SenderError::Unverified)
        }
    };
    Ok((device, claim))
}

/// Decode and verify a message's sender from its credential, checked against the
/// account → device directory (our account store).
///
/// `Ok(sender)` — deliver with the sender; its `account` is set only when the
/// directory confirmed the device, so it is always verified. `Err` — drop the
/// message (including when no credential is present, since every delivered
/// message must carry an explicit sender).
fn decode_sender(
    directory: &impl AccountDirectory,
    encoded: &[u8],
) -> Result<MessageSender, SenderError> {
    let (device, claim) = parse_credential(directory, encoded)?;
    match claim {
        AccountClaim::None => Ok(MessageSender {
            account: None,
            local_identity: device,
        }),
        AccountClaim::Verified(account) => Ok(MessageSender {
            account: Some(account),
            local_identity: device,
        }),
        // An unconfirmable account claim drops the message: every delivered
        // message must carry a verified sender.
        AccountClaim::Unverified(err) => Err(err),
    }
}

/// Map a group member's credential (as reported by MLS, in the same hex-encoded
/// form a message carries as its sender) to a roster entry, tolerating an
/// unconfirmable account claim by listing the device without an account. `None`
/// only when the credential cannot be parsed, which does not happen for a real
/// MLS leaf.
fn roster_member(directory: &impl AccountDirectory, encoded: &[u8]) -> Option<GroupMember> {
    let (device, claim) = parse_credential(directory, encoded).ok()?;
    let account = match claim {
        AccountClaim::Verified(account) => Some(account),
        AccountClaim::None | AccountClaim::Unverified(_) => None,
    };
    Some(GroupMember {
        account,
        local_identity: device,
        pending: false,
    })
}

/// The key that decides whether two roster entries are the same member: a
/// verified account, so an account's several devices count once; or, for a
/// member with no confirmed account, its device — unique per MLS leaf, so it
/// never merges with another.
fn member_key(member: &GroupMember) -> &str {
    member
        .account
        .as_ref()
        .unwrap_or(&member.local_identity)
        .as_str()
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

fn convo_events(outcome: ConvoOutcome, directory: &impl AccountDirectory) -> Vec<Event> {
    let ConvoOutcome {
        convo_id,
        content,
        members_changed,
    } = outcome;
    let convo_id: Arc<str> = Arc::from(convo_id);
    let mut events = Vec::new();
    if let Some(c) = content
        && let Ok(sender) = decode_sender(directory, &c.encoded_credential)
    {
        events.push(Event::MessageReceived {
            convo_id: Arc::clone(&convo_id),
            content: c.bytes,
            sender,
            message_id: c.message_id,
        });
    }
    if members_changed {
        events.push(Event::ConversationMembersChanged { convo_id });
    }
    events
}

fn inbox_events(outcome: InboxOutcome, directory: &impl AccountDirectory) -> Vec<Event> {
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
    if let Some(c) = initial.and_then(|co| co.content)
        && let Ok(sender) = decode_sender(directory, &c.encoded_credential)
    {
        events.push(Event::MessageReceived {
            convo_id: Arc::clone(&id),
            content: c.bytes,
            sender,
            message_id: c.message_id,
        });
    }
    events
}

#[cfg(test)]
mod sender_check_tests {
    use std::collections::HashMap;

    use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
    use libchat::IdentId;
    use logos_account::{DeviceSet, SignedDeviceBundle};

    use super::{
        Event, GroupMember, MessageSender, SenderError, decode_sender, dedup_members,
        delivery_ack_events, member_key, missing_events, roster_member,
    };
    use crate::delegate::DelegateCredential;
    use libchat::{DeliveryAck, Frontier, MissingMessage};

    /// In-test account → device directory. Holds device id sets keyed by the hex
    /// account key, and can be made to fail to simulate a directory outage.
    #[derive(Debug, Default)]
    struct FakeDir {
        bundles: HashMap<String, Vec<String>>,
        fail: bool,
    }

    impl FakeDir {
        /// Publish `devices` (verifying keys) as `account`'s device set.
        fn with_devices(account: &Ed25519VerifyingKey, devices: &[&Ed25519VerifyingKey]) -> Self {
            let mut bundles = HashMap::new();
            bundles.insert(
                hex::encode(account.as_ref()),
                devices.iter().map(|d| hex::encode(d.as_ref())).collect(),
            );
            Self {
                bundles,
                fail: false,
            }
        }
    }

    impl logos_account::AccountDirectory for FakeDir {
        type Error = &'static str;

        fn publish(&mut self, _: &SignedDeviceBundle) -> Result<(), Self::Error> {
            Ok(())
        }

        fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error> {
            if self.fail {
                return Err("directory unavailable");
            }
            Ok(self
                .bundles
                .get(&hex::encode(account.as_ref()))
                .map(|devices| DeviceSet {
                    lamport: 1,
                    devices: devices.clone(),
                }))
        }
    }

    fn key() -> Ed25519VerifyingKey {
        Ed25519SigningKey::generate().verifying_key()
    }

    /// Encode a credential exactly as it travels on the wire: the hex of the
    /// serialized TLV, matching the MLS leaf credential's content bytes.
    fn encoded(cred: DelegateCredential) -> Vec<u8> {
        hex::encode(cred.serialize()).into_bytes()
    }

    fn local_id(k: &Ed25519VerifyingKey) -> IdentId {
        IdentId::new(hex::encode(k.as_ref()))
    }

    /// The account published a device set that includes the sending device — the
    /// claim checks out, so the message is delivered with a verified account.
    #[test]
    fn verified_sender_surfaces_account_and_device() {
        let account = key();
        let device = key();
        let dir = FakeDir::with_devices(&account, &[&device]);
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Ok(MessageSender {
                account: Some(local_id(&account)),
                local_identity: local_id(&device),
            })
        );
    }

    /// The account published a device set that does NOT include the sending
    /// device — a spoofed account claim, so the message is dropped.
    #[test]
    fn contradicted_claim_is_dropped() {
        let account = key();
        let endorsed = key();
        let spoofer = key();
        let dir = FakeDir::with_devices(&account, &[&endorsed]);
        let cred = DelegateCredential::associated(&spoofer, &hex::encode(account.as_ref()));
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::Unverified)
        );
    }

    /// A delegate that claims no account surfaces its device but no account.
    #[test]
    fn unassociated_sender_surfaces_device_only() {
        let dir = FakeDir::default();
        let device = key();
        let cred = DelegateCredential::unassociated(&device);
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Ok(MessageSender {
                account: None,
                local_identity: local_id(&device),
            })
        );
    }

    /// The claimed account has never published a device set — the mapping is
    /// missing, so the message is dropped.
    #[test]
    fn unpublished_account_is_dropped() {
        let account = key();
        let device = key();
        let dir = FakeDir::default(); // nothing published
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::Unverified)
        );
    }

    /// A directory outage leaves the mapping unconfirmed, so the message is
    /// dropped rather than delivered on an unverified claim.
    #[test]
    fn directory_error_is_dropped() {
        let account = key();
        let device = key();
        let dir = FakeDir {
            fail: true,
            ..Default::default()
        };
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::Unverified)
        );
    }

    /// An empty credential leaves no sender to attribute, so the message is dropped.
    #[test]
    fn empty_credential_is_dropped() {
        let dir = FakeDir::default();
        assert_eq!(decode_sender(&dir, b""), Err(SenderError::Missing));
    }

    /// Bytes that aren't a well-formed credential leave the sender's mapping
    /// undeterminable, so the message is dropped.
    #[test]
    fn malformed_credential_is_dropped() {
        let dir = FakeDir::default();
        assert_eq!(decode_sender(&dir, b"not hex"), Err(SenderError::NotHex));
        assert_eq!(
            decode_sender(&dir, hex::encode([0u8; 4]).as_bytes()),
            Err(SenderError::Malformed)
        );
    }

    /// An account address that isn't a verifying key can't be looked up, so the
    /// claim is unconfirmable and the message is dropped.
    #[test]
    fn non_key_account_address_is_dropped() {
        let dir = FakeDir::default();
        let cred = DelegateCredential::associated(&key(), "user@example.com");
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::AccountNotAKey)
        );
    }

    /// A verified account claim surfaces the member's account and device — the
    /// same happy path as a message sender.
    #[test]
    fn roster_verified_member_surfaces_account() {
        let account = key();
        let device = key();
        let dir = FakeDir::with_devices(&account, &[&device]);
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert_eq!(
            roster_member(&dir, &encoded(cred)),
            Some(GroupMember {
                account: Some(local_id(&account)),
                local_identity: local_id(&device),
                pending: false,
            })
        );
    }

    /// Unlike a message sender, a spoofed account claim does not hide the
    /// member: the device is cryptographically in the group, so it is listed
    /// with no account rather than dropped.
    #[test]
    fn roster_contradicted_claim_lists_device_without_account() {
        let account = key();
        let endorsed = key();
        let spoofer = key();
        let dir = FakeDir::with_devices(&account, &[&endorsed]);
        let cred = DelegateCredential::associated(&spoofer, &hex::encode(account.as_ref()));
        assert_eq!(
            roster_member(&dir, &encoded(cred)),
            Some(GroupMember {
                account: None,
                local_identity: local_id(&spoofer),
                pending: false,
            })
        );
    }

    /// A member whose credential claims no account is listed by device only.
    #[test]
    fn roster_unassociated_member_lists_device_without_account() {
        let dir = FakeDir::default();
        let device = key();
        let cred = DelegateCredential::unassociated(&device);
        assert_eq!(
            roster_member(&dir, &encoded(cred)),
            Some(GroupMember {
                account: None,
                local_identity: local_id(&device),
                pending: false,
            })
        );
    }

    /// A directory outage leaves the account unconfirmed, but the member stays
    /// on the roster by device (a message would drop here).
    #[test]
    fn roster_directory_outage_lists_device_without_account() {
        let account = key();
        let device = key();
        let dir = FakeDir {
            fail: true,
            ..Default::default()
        };
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert_eq!(
            roster_member(&dir, &encoded(cred)),
            Some(GroupMember {
                account: None,
                local_identity: local_id(&device),
                pending: false,
            })
        );
    }

    /// A non-key account address can't be confirmed, so the member is listed by
    /// device without an account.
    #[test]
    fn roster_non_key_account_lists_device_without_account() {
        let dir = FakeDir::default();
        let device = key();
        let cred = DelegateCredential::associated(&device, "user@example.com");
        assert_eq!(
            roster_member(&dir, &encoded(cred)),
            Some(GroupMember {
                account: None,
                local_identity: local_id(&device),
                pending: false,
            })
        );
    }

    /// The roster collapses an account's several devices into one entry (keeping
    /// the first device seen) while leaving account-less members individual,
    /// order preserved.
    #[test]
    fn dedup_collapses_account_devices_and_keeps_unknowns() {
        let with_account = |account: &str, device: &str| GroupMember {
            account: Some(IdentId::new(account.to_string())),
            local_identity: IdentId::new(device.to_string()),
            pending: false,
        };
        let device_only = |device: &str| GroupMember {
            account: None,
            local_identity: IdentId::new(device.to_string()),
            pending: false,
        };
        let roster = dedup_members(vec![
            with_account("alice", "alice-dev-1"),
            with_account("alice", "alice-dev-2"),
            device_only("orphan-x"),
            with_account("bob", "bob-dev-1"),
            device_only("orphan-y"),
        ]);
        let keys: Vec<&str> = roster.iter().map(member_key).collect();
        assert_eq!(keys, ["alice", "orphan-x", "bob", "orphan-y"]);
        // Alice's collapsed entry keeps her first-seen device.
        assert_eq!(roster[0].local_identity.as_str(), "alice-dev-1");
    }

    /// An account that is both committed and pending collapses to its committed
    /// entry: `group_members` chains committed members first, and dedup keeps
    /// the first entry per account.
    #[test]
    fn dedup_collapses_a_pending_duplicate_into_the_committed_member() {
        let committed = GroupMember {
            account: Some(IdentId::new("alice")),
            local_identity: IdentId::new("alice-dev-1"),
            pending: false,
        };
        let pending = GroupMember {
            account: Some(IdentId::new("alice")),
            local_identity: IdentId::new("alice-dev-2"),
            pending: true,
        };
        assert_eq!(
            dedup_members(vec![committed.clone(), pending]),
            vec![committed]
        );
    }

    /// A gap reported by the causal history, as the core hands it over: the
    /// sender hint travels in the same encoding a message's credential does.
    fn gap(sender_hint: &str) -> MissingMessage {
        MissingMessage {
            conversation_id: "convo".to_owned(),
            frontier: Frontier::new(sender_hint.to_owned(), "msg-id".to_owned()),
        }
    }

    fn hex_cred(cred: DelegateCredential) -> String {
        hex::encode(cred.serialize())
    }

    /// Unwrap the single `MessageMissing` a one-gap batch produces.
    fn only_missing(events: Vec<Event>) -> (String, Option<MessageSender>) {
        match <[Event; 1]>::try_from(events)
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
                (message_id, sender_hint)
            }
            other => panic!("expected MessageMissing, got {other:?}"),
        }
    }

    /// An account claim the directory contradicts drops a *delivered* message,
    /// but a gap is still worth reporting: the hint keeps the device and
    /// forgoes the account, since nothing about an unseen message is verifiable
    /// anyway.
    #[test]
    fn missing_message_hint_keeps_the_device_when_the_account_claim_fails() {
        let account = key();
        let endorsed = key();
        let spoofer = key();
        let dir = FakeDir::with_devices(&account, &[&endorsed]);
        let cred = DelegateCredential::associated(&spoofer, &hex::encode(account.as_ref()));

        let (_, sender) = only_missing(missing_events(vec![gap(&hex_cred(cred))], &dir));
        assert_eq!(
            sender,
            Some(MessageSender {
                account: None,
                local_identity: local_id(&spoofer),
            })
        );
    }

    /// A hint that is not a credential at all still reports the gap — the
    /// message id is the part the application needs.
    #[test]
    fn missing_message_without_a_resolvable_hint_is_still_reported() {
        let (message_id, sender) =
            only_missing(missing_events(vec![gap("saro")], &FakeDir::default()));
        assert_eq!(message_id, "msg-id");
        assert_eq!(sender, None);
    }

    /// One acknowledgement per peer per message, each naming the peer an
    /// application would list against the message.
    #[test]
    fn acks_name_the_peers_that_hold_the_message() {
        let account = key();
        let device = key();
        let dir = FakeDir::with_devices(&account, &[&device]);
        let peer = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));

        let events = delivery_ack_events(
            vec![DeliveryAck {
                conversation_id: "convo".to_owned(),
                message_id: "msg-id".to_owned(),
                acked_by: hex_cred(peer),
            }],
            &dir,
        );

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
                assert_eq!(
                    acked_by,
                    Some(MessageSender {
                        account: Some(local_id(&account)),
                        local_identity: local_id(&device),
                    })
                );
            }
            other => panic!("expected MessageAcked, got {other:?}"),
        }
    }
}
