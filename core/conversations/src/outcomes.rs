//! Observations a single inbound payload produces.
//!
//! - [`ConvoOutcome`] — an optional [`Content`] on a single existing
//!   conversation, plus whether a commit changed its membership.
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
    /// **Not canonical.** It is the reliability-envelope id, derived by the
    /// causal-history layer from SDS-internal values (channel, sender, Lamport
    /// timestamp) alongside the content bytes, so it exists only for
    /// conversations carrying that envelope and an application cannot
    /// recompute it from what it can see. A canonical content id over
    /// application-visible values is the intended replacement; until then,
    /// treat this as an opaque handle, valid between peers of one conversation.
    pub message_id: String,
}

#[derive(Debug, Clone)]
pub struct ConvoOutcome {
    pub convo_id: ConversationId,
    pub content: Option<Content>,
    pub members_changed: bool,
}

impl ConvoOutcome {
    pub fn empty(convo_id: ConversationId) -> Self {
        Self {
            convo_id,
            content: None,
            members_changed: false,
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
