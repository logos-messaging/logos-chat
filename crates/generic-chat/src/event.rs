//! Application-facing chat events.
//!
//! Each variant of [`Event`] describes one observable thing the application
//! cares about: a new conversation has appeared, a message was decrypted on
//! an existing one, and so on. The enum is `#[non_exhaustive]` so new
//! variants can be added without breaking exhaustive matches in dependent
//! crates.

use std::sync::Arc;

use libchat::{ConversationClass, IdentId};

/// The sender of a received message, recovered from its credential.
///
/// `account` is present only when the sender associated an account *and* the
/// account → device directory confirmed this device belongs to it — spoofed or
/// unconfirmable claims never reach the application, so a `Some` account is
/// always verified. `local_identity` is the sending device (delegate key),
/// hex-encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSender {
    pub account: Option<IdentId>,
    pub local_identity: IdentId,
}

/// A discrete chat event.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Event {
    /// A new conversation has appeared.
    ConversationStarted {
        convo_id: Arc<str>,
        class: ConversationClass,
    },
    /// User content arrived on an existing conversation.
    MessageReceived {
        convo_id: Arc<str>,
        content: Vec<u8>,
        sender: MessageSender,
        /// Cross-peer id of this message, for referencing it (replies/reactions).
        message_id: String,
    },
    /// A peer acknowledged a message this client sent: it referenced that
    /// message in the causal history of a message of its own, so it held ours
    /// when it sent. `message_id` is the id the send returned.
    ///
    /// Evidence of delivery to the peer's client, not of a human reading it.
    /// The acknowledgement is passive — nothing is sent back on purpose — so a
    /// peer that never sends never acknowledges, and an application should
    /// treat the absence of one as "not confirmed" rather than "not delivered".
    ///
    /// `acked_by` is resolved from the peer's self-asserted `sender_id` and is
    /// **not authenticated**; see [`Self::MessageMissing`]'s `sender_hint`.
    /// `None` when it could not be resolved to a device.
    MessageAcked {
        convo_id: Arc<str>,
        message_id: String,
        acked_by: Option<MessageSender>,
    },
    /// A message this client never received, revealed by the causal history of
    /// one that did arrive. Detection only — nothing is fetched or replayed,
    /// and the gap is reported once.
    ///
    /// `sender_hint` is the author the *referencing* peer named, resolved the
    /// same way as [`Self::MessageReceived`]'s sender but **not authenticated**:
    /// nothing about a message we never saw can be verified, so treat it as a
    /// display hint. `None` when the hint could not be resolved to a device.
    MessageMissing {
        convo_id: Arc<str>,
        message_id: String,
        sender_hint: Option<MessageSender>,
    },
    /// A commit changed a conversation's membership.
    ConversationMembersChanged {
        convo_id: Arc<str>,
    },
    InboundError {
        message: String,
    },
}
