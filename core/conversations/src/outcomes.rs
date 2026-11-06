//! Observations a single inbound payload produces.
//!
//! - [`ConvoOutcome`] — the [`Observation`]s on a single existing
//!   conversation, in order.
//! - [`InboxOutcome`] — a newly observed conversation, optionally with an
//!   initial [`ConvoOutcome`].
//! - [`PayloadOutcome`] — the union of the above, plus `Empty`.

use crate::storage::ConversationKind;
use serde::{Deserialize, Serialize};

use crate::conversation::ConversationId;
use crate::identity::AuthenticatedSigner;

#[derive(Debug, Clone)]
pub struct Content {
    pub bytes: Vec<u8>,
    pub sender: AuthenticatedSigner,
    /// Id of this content, as every peer that received it computes it — the
    /// same [`MessageId`](crate::MessageId) `send_content` returns to the
    /// sender. Lets a consumer reference the content, e.g. a reply.
    ///
    /// Opaque, defined by each conversation type, and valid between peers of
    /// one conversation.
    pub message_id: String,
}

/// One thing a conversation observed while handling a payload or a wakeup.
#[derive(Debug, Clone)]
pub enum Observation {
    Content(Content),
    /// A commit changed the group's signers.
    SignersChanged,
}

#[derive(Debug, Clone)]
pub struct ConvoOutcome {
    pub convo_id: ConversationId,
    /// In the order the conversation observed them.
    pub observations: Vec<Observation>,
}

impl ConvoOutcome {
    pub fn empty(convo_id: ConversationId) -> Self {
        Self {
            convo_id,
            observations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewConversation {
    pub convo_id: ConversationId,
    pub class: ConversationClass,
}

#[derive(Debug, Clone)]
pub struct InboxOutcome {
    pub new_conversation: NewConversation,
    pub initial: Option<ConvoOutcome>,
}

#[derive(Debug, Clone, Default)]
pub enum PayloadOutcome {
    #[default]
    Empty,
    Convo(ConvoOutcome),
    Inbox(InboxOutcome),
}

impl From<ConvoOutcome> for PayloadOutcome {
    fn from(c: ConvoOutcome) -> Self {
        Self::Convo(c)
    }
}

impl From<InboxOutcome> for PayloadOutcome {
    fn from(i: InboxOutcome) -> Self {
        Self::Inbox(i)
    }
}

/// Stable across protocol versions of the same conversation shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConversationClass {
    Dm,
    Group,
}

impl ConversationClass {
    /// `Unknown(_)` yields `None`.
    pub fn from_kind(kind: &ConversationKind) -> Option<Self> {
        match kind {
            ConversationKind::GroupV1 => Some(Self::Group),
            ConversationKind::Unknown(_) => None,
        }
    }
}
