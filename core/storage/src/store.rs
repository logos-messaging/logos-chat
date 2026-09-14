use crate::StorageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationKind {
    Unknown(String),
    GroupV1,
}

impl ConversationKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unknown(value) => value.as_str(),
            Self::GroupV1 => "group_v1",
        }
    }
}

impl From<&str> for ConversationKind {
    fn from(value: &str) -> Self {
        match value {
            "group_v1" => Self::GroupV1,
            other => Self::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMeta {
    pub local_convo_id: String,
    pub kind: ConversationKind,
}

pub trait ConversationStore {
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError>;

    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<ConversationMeta>, StorageError>;

    fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError>;

    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError>;

    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError>;
}
