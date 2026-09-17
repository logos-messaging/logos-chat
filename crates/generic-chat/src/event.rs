//! Application-facing chat events.
//!
//! Each variant of [`Event`] describes one observable thing the application
//! cares about: a new conversation has appeared, a message was decrypted on
//! an existing one, and so on. The enum is `#[non_exhaustive]` so new
//! variants can be added without breaking exhaustive matches in dependent
//! crates.

use std::sync::Arc;

use libchat::{ConversationClass, SignerKey};

use crate::AuthenticatedMember;

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
        sender: AuthenticatedMember,
    },

    MessageAcked {
        convo_id: Arc<str>,
        message_id: String,
        acked_by: SignerKey,
    },
    /// A message this client never received, revealed by the causal history of
    /// one that did arrive. Detection only — nothing is fetched or replayed,
    /// and the gap is reported once.
    ///
    /// `sender_hint` is self-asserted, so it names a signer, not an
    /// [`AuthenticatedMember`].
    MessageMissing {
        convo_id: Arc<str>,
        message_id: String,
        sender_hint: SignerKey,
    },
    /// A commit changed a conversation's membership.
    ConversationMembersChanged {
        convo_id: Arc<str>,
    },
    InboundError {
        message: String,
    },
}
