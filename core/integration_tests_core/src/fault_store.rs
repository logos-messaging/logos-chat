//! A store that refuses a write on demand, so a test can see what an operation leaves behind
//! when the write it depends on does not land.

use std::cell::Cell;
use std::rc::Rc;

use libchat::test_support::MemStore;
use libchat::{
    ConversationMeta, ConversationStore, KvPair, KvStore, KvTx, Namespace, Scope, StorageError,
};

/// The refusals a [`FaultStore`] produces, switchable while it is in use.
#[derive(Clone, Default)]
pub struct Faults {
    commit: Rc<Cell<bool>>,
}

impl Faults {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh store producing these refusals.
    pub fn store(&self) -> FaultStore {
        FaultStore {
            inner: MemStore::new(),
            faults: self.clone(),
        }
    }

    /// While set, a transaction fails as it lands, with everything it wrote already staged.
    pub fn fail_commit(&self, fail: bool) {
        self.commit.set(fail);
    }
}

/// An in-memory store that refuses the writes its [`Faults`] name.
pub struct FaultStore {
    inner: MemStore,
    faults: Faults,
}

impl KvStore for FaultStore {
    fn begin(&self) -> Result<Box<dyn KvTx + '_>, StorageError> {
        Ok(Box::new(FaultTx {
            inner: self.inner.begin()?,
            faults: self.faults.clone(),
        }))
    }
}

impl ConversationStore for FaultStore {
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError> {
        self.inner.save_conversation(meta)
    }

    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<ConversationMeta>, StorageError> {
        self.inner.load_conversation(local_convo_id)
    }

    fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError> {
        self.inner.remove_conversation(local_convo_id)
    }

    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError> {
        self.inner.load_conversations()
    }

    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError> {
        self.inner.has_conversation(local_convo_id)
    }
}

struct FaultTx<'a> {
    inner: Box<dyn KvTx + 'a>,
    faults: Faults,
}

impl KvTx for FaultTx<'_> {
    fn get(&self, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(scope, key)
    }

    fn put(&self, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(scope, key, value)
    }

    fn delete(&self, scope: &Scope, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(scope, key)
    }

    fn scan_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError> {
        self.inner.scan_prefix(scope, prefix)
    }

    fn delete_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_prefix(scope, prefix)
    }

    fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError> {
        self.inner.delete_scope(scope)
    }

    fn delete_namespace(&self, ns: Namespace) -> Result<(), StorageError> {
        self.inner.delete_namespace(ns)
    }

    fn commit(self: Box<Self>) -> Result<(), StorageError> {
        if self.faults.commit.get() {
            return Err(StorageError::Database("commit refused".into()));
        }
        self.inner.commit()
    }
}
