//! The contracts a store answers: the substrate every conversation type keeps its state in, byte
//! values addressed by scope and key inside transactions, and the client-level state kept as typed
//! records.

use thiserror::Error;

#[cfg(any(test, feature = "test-support"))]
mod in_memory_store;
#[cfg(any(test, feature = "test-support"))]
mod test_assertions;

#[cfg(any(test, feature = "test-support"))]
pub use in_memory_store::MemStore;
#[cfg(any(test, feature = "test-support"))]
pub use test_assertions::assert_kv_contract;

/// Common storage errors.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(String),

    #[error("invalid data: {0}")]
    InvalidData(String),
}

/// A key and the value stored under it.
pub type KvPair = (Vec<u8>, Vec<u8>);

/// The name an owner files its state under: a conversation kind such as GroupV1, or InboxV2 for
/// the key packages it mints. The substrate stores the name and never reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Namespace(&'static str);

impl Namespace {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Where a value lives: the namespace of its owner, and the instance of that owner the value
/// belongs to, the conversation for a conversation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope<'a> {
    pub ns: Namespace,
    pub instance: &'a str,
}

/// Byte values addressed by a scope and a key, reached through transactions alone.
pub trait KvStore {
    /// Opens a transaction; a second one while it is open is an error.
    fn begin(&self) -> Result<Box<dyn KvTx + '_>, StorageError>;
}

/// The substrate verbs inside one transaction.
///
/// Reads see its own writes. `commit` lands them; dropping it uncommitted discards them.
///
/// The verbs take `&self`: several scopes over one transaction are alive at once, and OpenMLS
/// writes through `&self`, so an implementation mutates through interior mutability.
pub trait KvTx {
    fn get(&self, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    fn put(&self, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    fn delete(&self, scope: &Scope, key: &[u8]) -> Result<(), StorageError>;

    /// Every pair under the prefix, in key order.
    fn scan_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError>;

    fn delete_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError>;

    fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError>;

    /// Drops every scope under a namespace, its conversations included.
    fn delete_namespace(&self, ns: Namespace) -> Result<(), StorageError>;

    fn commit(self: Box<Self>) -> Result<(), StorageError>;
}

/// A conversation's kind, which also names the namespace its state is filed under.
///
/// `#[non_exhaustive]` so a crate outside libchat matches with a fallback arm, and a kind added
/// here costs it no break.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationKind {
    GroupV1,
    DirectV1,
    GroupV2,
}

impl ConversationKind {
    /// Every kind, for reaching a conversation's state once no record names its kind.
    pub(crate) const ALL: [Self; 3] = [Self::GroupV1, Self::DirectV1, Self::GroupV2];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GroupV1 => "group_v1",
            Self::DirectV1 => "direct_v1",
            Self::GroupV2 => "group_v2",
        }
    }
}

impl TryFrom<&str> for ConversationKind {
    type Error = StorageError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "group_v1" => Ok(Self::GroupV1),
            "direct_v1" => Ok(Self::DirectV1),
            "group_v2" => Ok(Self::GroupV2),
            other => Err(StorageError::InvalidData(format!(
                "unknown conversation kind: {other}"
            ))),
        }
    }
}

impl From<ConversationKind> for Namespace {
    fn from(kind: ConversationKind) -> Self {
        Namespace::new(kind.as_str())
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
