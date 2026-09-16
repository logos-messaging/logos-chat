//! Observations a single inbound payload produces.
//!
//! - [`ConvoOutcome`] — an optional [`Content`] on a single existing
//!   conversation, plus whether a commit changed its membership.
//! - [`InboxOutcome`] — a newly observed conversation, optionally with an
//!   initial [`ConvoOutcome`].
//! - [`PayloadOutcome`] — the union of the above, plus `Empty`.

use serde::{Deserialize, Serialize};
use shared_traits::ExternalIdentifier;
use storage::ConversationKind;

use crate::conversation::ConversationId;

#[derive(Debug, Clone)]
pub struct AuthenticatedSender {
    pub signer: Vec<u8>,
    pub external_id: ExternalIdentifier,
}

impl AuthenticatedSender {
    pub fn with(signer: Vec<u8>, external_id: ExternalIdentifier) -> Self {
        Self {
            signer,
            external_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Content {
    pub bytes: Vec<u8>,
    pub sender: AuthenticatedSender,
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
