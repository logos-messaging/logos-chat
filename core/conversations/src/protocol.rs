use crate::storage::{ConversationMeta, Namespace};

use crate::ChatError;

/// The protocol that owns a piece of state; gains a variant when a protocol ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    GroupV1,
    DirectV1,
    GroupV2,
    InboxV2,
}

impl Protocol {
    /// The name the protocol files its state under, which is also what a record names it by.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Protocol::GroupV1 => "group_v1",
            Protocol::DirectV1 => "direct_v1",
            Protocol::GroupV2 => "group_v2",
            Protocol::InboxV2 => "inbox_v2",
        }
    }

    /// The protocol a stored name refers to; a name no protocol here answers to belongs to a
    /// conversation this core cannot rebuild.
    pub(crate) fn from_name(name: &str) -> Result<Self, ChatError> {
        match name {
            "group_v1" => Ok(Self::GroupV1),
            "direct_v1" => Ok(Self::DirectV1),
            "group_v2" => Ok(Self::GroupV2),
            "inbox_v2" => Ok(Self::InboxV2),
            other => Err(ChatError::UnsupportedConvoType(other.into())),
        }
    }

    /// The record listing a conversation under this protocol.
    pub(crate) fn record(self, convo_id: &str) -> ConversationMeta {
        ConversationMeta {
            local_convo_id: convo_id.to_string(),
            convo_type: self.name().to_string(),
        }
    }
}

impl From<Protocol> for Namespace {
    fn from(protocol: Protocol) -> Self {
        Namespace::new(protocol.name())
    }
}
