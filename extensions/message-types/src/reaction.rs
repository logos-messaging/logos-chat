use serde::{Deserialize, Serialize};

use crate::{Content, MessageId};

/// A reaction to another message — an emoji keyed to the message it targets.
/// A namespaced semantic type (`logos/reaction`) rather than a media type,
/// since it has no natural IANA type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    /// The message this reaction is about.
    pub in_reply_to: MessageId,
    /// The reaction glyph, e.g. `"👍"`.
    pub emoji: String,
}

impl Reaction {
    pub fn new(in_reply_to: impl Into<MessageId>, emoji: impl Into<String>) -> Self {
        Self {
            in_reply_to: in_reply_to.into(),
            emoji: emoji.into(),
        }
    }
}

impl Content for Reaction {
    const CONTENT_TYPE: &'static str = "logos/reaction";

    fn fallback(&self) -> String {
        format!("reacted {}", self.emoji)
    }
}
