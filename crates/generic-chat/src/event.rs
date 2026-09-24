//! Application-facing chat events.
//!
//! Each variant of [`Event`] describes one observable thing the application
//! cares about: a new conversation has appeared, a message was decrypted on
//! an existing one, and so on. The enum is `#[non_exhaustive]` so new
//! variants can be added without breaking exhaustive matches in dependent
//! crates.

use std::sync::Arc;

use libchat::{ConversationClass, SignerKey};

use crate::AuthenticatedSigner;

/// A discrete chat event.
///
/// `MessageReceived` is much the largest variant, nearly all of it the
/// `AccountAddr` inside its [`AuthenticatedSigner`]. Boxing the sender would
/// buy back the bytes at the cost of a heap hop and a `Box` in the public
/// match, on the one variant an application handles most; events are moved
/// once down a channel, so the copy is not worth that. Revisit here, not at
/// the call sites, if the enum grows another large variant.
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Event {
    /// A new conversation has appeared.
    ConversationStarted {
        convo_id: Arc<str>,
        class: ConversationClass,
    },
    /// User content arrived on an existing conversation.
    ///
    /// `content` is the body exactly as the sender produced it. Interpreting it
    /// is the application's concern — the `message-types` extension is one such
    /// format — so a consumer carrying its own is never forced through ours.
    #[non_exhaustive]
    MessageReceived {
        convo_id: Arc<str>,
        content: Vec<u8>,
        sender: AuthenticatedSigner,
        /// Cross-peer id of this message; reply to it by naming this id.
        message_id: String,
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
    /// [`AuthenticatedSigner`].
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
