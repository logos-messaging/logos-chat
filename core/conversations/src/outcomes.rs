//! Observations a single inbound payload produces.
//!
//! - [`ConvoOutcome`] — the [`Observation`]s on a single existing
//!   conversation, in order.
//! - [`InboxOutcome`] — a newly observed conversation, optionally with an
//!   initial [`ConvoOutcome`].
//! - [`PayloadOutcome`] — the union of the above, plus `Empty`.

use crate::storage::ConversationKind;
use serde::{Deserialize, Serialize};

use crate::conversation::{ConversationId, MessageId, SyncState};
use crate::identity::{AuthenticatedSigner, SignerKey};
use crate::types::DeliveryMsgId;

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
    /// At least one other signer has received this message.
    Delivered(MessageId),
    Debug(DebugEvent),
    /// The group's [`SyncState`] changed, e.g. a fork was detected or cleared.
    SyncChanged(SyncState),
    /// A re-add we asked for landed: we hold the group again, on the branch
    /// that answered.
    Rejoined,
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

// -- Debug

/// A step a message took through SDS, for debugging. Only GroupV3 reports
/// these.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum DebugEvent {
    /// A message reached the conversation from delivery, before ordering.
    /// Each copy is reported, a duplicate included.
    ///
    /// Each is then ignored, released, or buffered until released or lost. A
    /// buffered message with neither yet is stuck.
    SdsReceived {
        message_id: MessageId,
        /// Self-asserted; `None` when it names no signer.
        sender_hint: Option<SignerKey>,
        delivery_msg_id: Option<DeliveryMsgId>,
    },
    /// A message received is neither buffered nor released.
    SdsIgnored {
        message_id: MessageId,
        reason: IgnoreReason,
    },
    /// A message waits for the messages it depends on.
    SdsBuffered {
        message_id: MessageId,
        /// Dependencies that never arrived.
        missing_dependencies: Vec<SdsDependency>,
        /// Dependencies that arrived but are buffered too.
        buffered_dependencies: Vec<SdsDependency>,
    },
    /// A message is in order and goes on to be decrypted, whatever happens to
    /// it next.
    SdsReleased {
        message_id: MessageId,
        /// What the message carries, as the conversation names it, such as
        /// `"commit"`.
        kind: String,
    },
    /// A buffered message was dropped unreleased.
    SdsLost {
        message_id: MessageId,
        reason: LossReason,
    },
    /// Delivery failed to fetch missing dependencies. They are asked for
    /// again only when a message buffered later names them.
    SdsFetchFailed {
        delivery_msg_ids: Vec<DeliveryMsgId>,
    },
    /// This member's message is published again, as no one has acknowledged
    /// it yet.
    SdsResent { message_id: MessageId },
    /// SDS stopped resending this member's message, no one having
    /// acknowledged it.
    SdsSendFailed { message_id: MessageId },
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    /// This member sent it.
    Own,
    /// This member already holds it.
    Duplicate,
    /// It is from at or before the point this member joined at, so it is kept
    /// as history.
    BeforeStart,
    /// It names another conversation's channel.
    WrongChannel,
    /// Its content is over the size SDS takes.
    TooLarge,
}

/// A message another one depends on.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SdsDependency {
    pub message_id: MessageId,
    /// The id to fetch it from delivery by. `None` when the message depending
    /// on it gives none, so it is never fetched.
    pub delivery_msg_id: Option<DeliveryMsgId>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossReason {
    /// Its dependencies did not arrive in time.
    Expired,
    /// It was the oldest buffered message when the buffer filled.
    BufferFull,
}
