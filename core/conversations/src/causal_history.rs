//! Causal-history tracking for group conversations.
//!
//! Implements the *causal history* subset of the Scalable Data Sync (SDS)
//! protocol. Every outbound message carries a Lamport timestamp and the IDs of the
//! messages its sender had most recently seen. A receiver that finds a
//! referenced ID it has never delivered knows a message is missing.
//!
//! Scope:
//!  - assign a deterministic message ID + Lamport timestamp to outbound msgs
//!  - attach a bounded causal-history frontier to each outbound message
//!  - on receive, detect referenced-but-unseen message IDs (gaps)
//!  - on receive, detect references to *our own* messages (acknowledgements)
//!
//! Out of scope here: bloom-filter acknowledgements,
//! resend / outgoing buffer, incoming reorder buffer, Store-based recovery.
//! This is detection only — an out-of-order message is still delivered to
//! the application, but the gap it implies is reported.
//!
//! The same references also show who received our messages: a peer that names
//! one of ours must have had it. Nothing is sent back — the acknowledgement
//! rides on whatever the peer says next — so a silent peer never acknowledges,
//! and neither does one that speaks after our message has dropped out of its
//! [`CAUSAL_HISTORY_LEN`]-entry frontier.
//!
//! State is in-memory and session-scoped, matching the crate's current
//! in-memory MLS state.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::identity::SignerKey;

use crate::proto::{Bytes, HistoryEntry, ReliablePayload};
use crate::utils::{blake2b_hex, hash_size};

/// Frontier includes the message's metadata which can be referened by other
/// messages inside a conversation.
///
/// Carries the sender's signer alongside a deterministic
/// content/Lamport hash, so receivers can attribute referenced-but-unseen
/// IDs to a peer without consulting local state. The sender component is a
/// **routing hint, not authoritative**: when a missing message is recovered,
/// authorship is verified against the MLS leaf credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Frontier {
    sender: SignerKey,
    message_id: String,
}

impl Frontier {
    /// Construct a fresh `Frontier` for an outbound message.
    pub fn new(sender: SignerKey, message_id: String) -> Self {
        Self { sender, message_id }
    }

    /// The sender the message claims. Treat as a routing hint only.
    pub fn sender(&self) -> &SignerKey {
        &self.sender
    }

    /// Deterministic hash of `(channel, sender, lamport, content)`.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }
}

/// Number of most-recently-seen message IDs attached to each outbound message.
const CAUSAL_HISTORY_LEN: usize = 10;

/// A message detected as missing: referenced by a delivered message's causal
/// history but never seen locally.
///
/// This is the hook point for the future client event system (issue #97);
/// until that lands, callers drain these via [`CausalHistoryStore::take_missing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingMessage {
    pub conversation_id: String,
    pub frontier: Frontier,
}

/// A peer acknowledging one of our messages: it named that message in the
/// causal history of a message it sent, so it held ours at the time.
///
/// Evidence of *delivery to a peer's client*, not of a human reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryAck {
    pub conversation_id: String,
    /// The message of ours the peer acknowledged.
    pub message_id: String,
    /// The acknowledging peer, as its payload claims —
    /// self-asserted like [`Frontier::sender`], not bound to the MLS
    /// identity that sent the payload.
    pub acked_by: SignerKey,
}

/// Per-conversation causal state.
#[derive(Debug, Default)]
struct ConvoState {
    /// Lamport logical clock.
    lamport_clock: i32,
    /// Every message ID delivered locally (own sends + received).
    seen: HashSet<Frontier>,
    /// Bounded frontier of recently-seen IDs (oldest first) attached to
    /// outbound messages as causal history.
    frontiers: VecDeque<Frontier>,
    /// Missing IDs already reported, so a gap is surfaced exactly once.
    reported_missing: HashSet<Frontier>,
    /// IDs of messages we authored: a reference to one is an acknowledgement.
    own: HashSet<String>,
    /// Which peers have acknowledged each of our messages, so each is
    /// surfaced exactly once.
    acked_by: HashMap<String, HashSet<SignerKey>>,
}

impl ConvoState {
    fn record_seen(&mut self, info: Frontier) {
        if self.seen.insert(info.clone()) {
            self.frontiers.push_back(info);
            while self.frontiers.len() > CAUSAL_HISTORY_LEN {
                self.frontiers.pop_front();
            }
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    convos: HashMap<String, ConvoState>,
    /// Detected gaps, drained by the client (future #97 event bus).
    missing: Vec<MissingMessage>,
    /// Detected acknowledgements of our own messages, drained alongside
    /// `missing`.
    acks: Vec<DeliveryAck>,
}

/// Session-scoped causal-history store shared by every `GroupV1Convo`
/// instance.
///
/// Convos are rebuilt from storage on every inbound message, so this state
/// cannot live on the convo struct — it is shared through `ServiceContext`, the
/// same way the MLS provider is.
#[derive(Debug, Default)]
pub struct CausalHistoryStore {
    inner: RefCell<Inner>,
}

impl CausalHistoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the reliability envelope for an outbound message: advance the
    /// Lamport clock, derive a deterministic ID, and attach the causal
    /// frontier.
    pub fn on_send(
        &self,
        conversation_id: &str,
        sender: &SignerKey,
        content: &[u8],
    ) -> ReliablePayload {
        let mut inner = self.inner.borrow_mut();
        let state = inner.convos.entry(conversation_id.to_owned()).or_default();

        state.lamport_clock += 1;
        let lamport = state.lamport_clock;
        let message_id = derive_message_id(conversation_id, &sender.to_string(), lamport, content);
        let frontier = Frontier::new(sender.clone(), message_id.clone());

        let causal_history = state
            .frontiers
            .iter()
            .map(|f| HistoryEntry {
                message_id: f.message_id.clone(),
                sender_id: f.sender.to_string(),
                retrieval_hint: Bytes::new(),
            })
            .collect();

        // Our own message joins the seen-set so it appears in our future
        // causal history, and the own-set so a peer referencing it back is
        // recognised as acknowledging this send.
        state.own.insert(message_id.clone());
        state.record_seen(frontier);

        ReliablePayload {
            message_id,
            sender_id: sender.to_string(),
            channel_id: conversation_id.to_owned(),
            lamport_timestamp: lamport,
            causal_history,
            bloom_filter: Bytes::new(),
            content: Bytes::copy_from_slice(content),
        }
    }

    /// Process an inbound reliability envelope. Records the message as seen,
    /// merges the Lamport clock, and returns any referenced message IDs that
    /// were never delivered locally (newly detected gaps).
    ///
    /// Sender ids that are not a hex signer are ignored: a whole payload for
    /// its own id, a single entry for an entry's.
    pub fn on_receive(
        &self,
        conversation_id: &str,
        payload: &ReliablePayload,
    ) -> Vec<MissingMessage> {
        let Ok(payload_sender) = SignerKey::try_from(payload.sender_id.as_str()) else {
            tracing::warn!(convo = %conversation_id, "ignoring causal history with a malformed sender id");
            return Vec::new();
        };
        let mut inner = self.inner.borrow_mut();
        let Inner {
            convos,
            missing,
            acks,
        } = &mut *inner;
        let state = convos.entry(conversation_id.to_owned()).or_default();

        // Lamport merge: the next local send will be strictly greater than
        // anything we have observed.
        state.lamport_clock = state.lamport_clock.max(payload.lamport_timestamp);

        let mut detected = Vec::new();
        for entry in &payload.causal_history {
            let Ok(entry_sender) = SignerKey::try_from(entry.sender_id.as_str()) else {
                tracing::warn!(convo = %conversation_id, "ignoring a causal history entry with a malformed sender id");
                continue;
            };

            // The sender named one of ours, so it has it. Reported once per
            // peer per message, and never for the message's own author.
            if state.own.contains(&entry.message_id)
                && payload_sender != entry_sender
                && state
                    .acked_by
                    .entry(entry.message_id.clone())
                    .or_default()
                    .insert(payload_sender.clone())
            {
                acks.push(DeliveryAck {
                    conversation_id: conversation_id.to_owned(),
                    message_id: entry.message_id.clone(),
                    acked_by: payload_sender.clone(),
                });
            }

            let frontier = Frontier::new(entry_sender, entry.message_id.clone());
            if !state.seen.contains(&frontier) && state.reported_missing.insert(frontier.clone()) {
                let m = MissingMessage {
                    conversation_id: conversation_id.to_owned(),
                    frontier,
                };
                detected.push(m.clone());
                missing.push(m);
            }
        }

        state.record_seen(Frontier::new(payload_sender, payload.message_id.clone()));

        detected
    }

    /// Drain all gaps detected so far.
    ///
    /// This is the integration point for the client event system (issue
    /// #97); until that lands, callers poll here.
    pub fn take_missing(&self) -> Vec<MissingMessage> {
        std::mem::take(&mut self.inner.borrow_mut().missing)
    }

    /// Drain all acknowledgements of our own messages detected so far.
    pub fn take_acks(&self) -> Vec<DeliveryAck> {
        std::mem::take(&mut self.inner.borrow_mut().acks)
    }
}

/// Deterministic, collision-resistant message ID.
///
/// A single sender increments its Lamport clock on every send, so
/// `(sender, lamport)` is unique per message; `channel_id` and `content` are
/// folded in as well. Receivers store the field verbatim, so cross-peer
/// agreement does not depend on re-derivation.
fn derive_message_id(channel_id: &str, sender: &str, lamport: i32, content: &[u8]) -> String {
    let lamport_be = lamport.to_be_bytes();
    blake2b_hex::<hash_size::MessageId>(&[
        b"deterministic_frame_id|".as_slice(),
        channel_id.as_bytes(),
        b"|".as_slice(),
        sender.as_bytes(),
        b"|".as_slice(),
        lamport_be.as_slice(),
        b"|".as_slice(),
        content,
    ])
}

#[cfg(test)]
mod tests {
    use crypto::Ed25519SigningKey;

    use super::*;

    fn payload(
        store: &CausalHistoryStore,
        convo: &str,
        sender: &SignerKey,
        body: &[u8],
    ) -> ReliablePayload {
        store.on_send(convo, sender, body)
    }

    fn new_signer() -> SignerKey {
        SignerKey::from(Ed25519SigningKey::generate().verifying_key())
    }

    #[test]
    fn lamport_clock_increments_per_send() {
        let alice = new_signer();
        let s = CausalHistoryStore::new();
        let a = payload(&s, "c", &alice, b"1");
        let b = payload(&s, "c", &alice, b"2");
        assert_eq!(a.lamport_timestamp, 1);
        assert_eq!(b.lamport_timestamp, 2);
        // Second message's causal history references the first.
        assert_eq!(b.causal_history.len(), 1);
        assert_eq!(b.causal_history[0].message_id, a.message_id);
    }

    #[test]
    fn detects_a_gap_when_a_referenced_message_was_never_seen() {
        let alice = new_signer();
        let sender = CausalHistoryStore::new();
        let m1 = payload(&sender, "c", &alice, b"first");
        let m2 = payload(&sender, "c", &alice, b"second (dropped)");
        let m3 = payload(&sender, "c", &alice, b"third");

        let receiver = CausalHistoryStore::new();
        assert!(receiver.on_receive("c", &m1).is_empty());
        // m2 is never delivered to the receiver; m3 references it.
        let missing = receiver.on_receive("c", &m3);

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].frontier.message_id(), m2.message_id);
        assert_eq!(missing[0].frontier.sender().to_string(), m2.sender_id);
        assert_eq!(missing[0].conversation_id, "c");
    }

    #[test]
    fn no_gap_when_all_messages_are_delivered_in_order() {
        let alice = new_signer();
        let sender = CausalHistoryStore::new();
        let m1 = payload(&sender, "c", &alice, b"a");
        let m2 = payload(&sender, "c", &alice, b"b");

        let receiver = CausalHistoryStore::new();
        receiver.on_receive("c", &m1);
        receiver.on_receive("c", &m2);
        assert!(receiver.take_missing().is_empty());
    }

    #[test]
    fn missing_message_carries_sender_id_of_the_original_author() {
        let alice = new_signer();
        let alice_store = CausalHistoryStore::new();
        let m1 = payload(&alice_store, "c", &alice, b"first");
        let _m2 = payload(&alice_store, "c", &alice, b"second (dropped)");
        let m3 = payload(&alice_store, "c", &alice, b"third");

        let receiver = CausalHistoryStore::new();
        receiver.on_receive("c", &m1);
        let missing = receiver.on_receive("c", &m3);

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].frontier.sender(), &alice);
    }

    /// Bob replies after receiving Alice's message, so his causal history
    /// names it — that reference is the acknowledgement.
    #[test]
    fn a_peer_referencing_our_message_acknowledges_it() {
        let (alice, bob) = (new_signer(), new_signer());
        let alice_store = CausalHistoryStore::new();
        let bob_store = CausalHistoryStore::new();

        let a1 = payload(&alice_store, "c", &alice, b"hello");
        bob_store.on_receive("c", &a1);
        let b1 = payload(&bob_store, "c", &bob, b"hi back");
        alice_store.on_receive("c", &b1);

        assert_eq!(
            alice_store.take_acks(),
            vec![DeliveryAck {
                conversation_id: "c".to_owned(),
                message_id: a1.message_id.clone(),
                acked_by: bob.clone(),
            }]
        );
        // Draining clears the report.
        assert!(alice_store.take_acks().is_empty());
    }

    /// Every signer that replies acknowledges separately, which is what lets an
    /// application list the peers that hold a message.
    #[test]
    fn each_peer_acknowledges_separately() {
        let (alice, bob, carol) = (new_signer(), new_signer(), new_signer());
        let alice_store = CausalHistoryStore::new();
        let bob_store = CausalHistoryStore::new();
        let carol_store = CausalHistoryStore::new();

        let a1 = payload(&alice_store, "c", &alice, b"hello all");
        bob_store.on_receive("c", &a1);
        carol_store.on_receive("c", &a1);
        alice_store.on_receive("c", &payload(&bob_store, "c", &bob, b"bob here"));
        alice_store.on_receive("c", &payload(&carol_store, "c", &carol, b"carol here"));

        let holders: Vec<SignerKey> = alice_store
            .take_acks()
            .into_iter()
            .filter(|a| a.message_id == a1.message_id)
            .map(|a| a.acked_by)
            .collect();
        assert_eq!(holders, vec![bob, carol]);
    }

    /// Bob keeps naming the message in later sends; the application is told
    /// once.
    #[test]
    fn a_peer_acknowledges_a_message_only_once() {
        let (alice, bob) = (new_signer(), new_signer());
        let alice_store = CausalHistoryStore::new();
        let bob_store = CausalHistoryStore::new();

        let a1 = payload(&alice_store, "c", &alice, b"hello");
        bob_store.on_receive("c", &a1);
        alice_store.on_receive("c", &payload(&bob_store, "c", &bob, b"first reply"));
        alice_store.take_acks();
        alice_store.on_receive("c", &payload(&bob_store, "c", &bob, b"second reply"));

        assert!(
            alice_store.take_acks().is_empty(),
            "a peer's acknowledgement of one message is reported once"
        );
    }

    /// Carol's reply names Bob's message, not ours — nothing for us to report.
    #[test]
    fn a_reference_to_someone_elses_message_is_not_our_acknowledgement() {
        let (bob, carol) = (new_signer(), new_signer());
        let alice_store = CausalHistoryStore::new();
        let bob_store = CausalHistoryStore::new();
        let carol_store = CausalHistoryStore::new();

        let b1 = payload(&bob_store, "c", &bob, b"bob speaks");
        carol_store.on_receive("c", &b1);
        // Alice observes Carol's reply, which references Bob's message only.
        alice_store.on_receive("c", &payload(&carol_store, "c", &carol, b"carol replies"));

        assert!(alice_store.take_acks().is_empty());
    }

    /// A sender id that is not a hex signer carries no usable history.
    #[test]
    fn a_malformed_sender_id_is_ignored() {
        let alice = new_signer();
        let sender = CausalHistoryStore::new();
        let _m1 = payload(&sender, "c", &alice, b"first (dropped)");
        let mut m2 = payload(&sender, "c", &alice, b"second");
        m2.sender_id = "saro".to_owned();

        let receiver = CausalHistoryStore::new();
        assert!(receiver.on_receive("c", &m2).is_empty());
    }

    #[test]
    fn a_gap_is_reported_only_once() {
        let alice = new_signer();
        let sender = CausalHistoryStore::new();
        let m1 = payload(&sender, "c", &alice, b"a");
        let m2 = payload(&sender, "c", &alice, b"b");
        let m3 = payload(&sender, "c", &alice, b"c");

        let receiver = CausalHistoryStore::new();
        // Neither m1 nor m2 delivered; both m2 and m3 reference m1.
        receiver.on_receive("c", &m2);
        receiver.on_receive("c", &m3);
        let missing = receiver.take_missing();
        let m1_hits = missing
            .iter()
            .filter(|m| m.frontier.message_id() == m1.message_id)
            .count();
        assert_eq!(m1_hits, 1);
    }
}
