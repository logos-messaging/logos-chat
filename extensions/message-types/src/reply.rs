use serde::{Deserialize, Serialize};

use crate::{Content, MessageId};

/// A reply to another message. In this approach (Model B) the relationship is
/// carried **inside the payload** as its own content type — contrast Approach A,
/// where a reply is any message with a top-level `in_reply_to` field. Because the
/// envelope is ours, the referenced id is a plain string (no fixed-size id
/// constraint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    /// The message this one replies to.
    pub in_reply_to: MessageId,
    /// The reply body (plain text).
    pub body: String,
}

impl Reply {
    pub fn new(in_reply_to: impl Into<MessageId>, body: impl Into<String>) -> Self {
        Self {
            in_reply_to: in_reply_to.into(),
            body: body.into(),
        }
    }
}

impl Content for Reply {
    const CONTENT_TYPE: &'static str = "logos/reply";

    fn fallback(&self) -> String {
        // A client that doesn't render replies still sees the reply text.
        self.body.clone()
    }
}
