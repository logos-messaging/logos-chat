//! The transaction over the substrate, and the handle to one scope inside it: `KvTransaction`
//! opens a transaction over a `KvStore`, and `ScopedKvStore` is the key verbs with one scope
//! already bound.

use crate::storage::{KvPair, KvStore, KvTx, Namespace, Scope, StorageError};

/// A transaction over the substrate.
pub struct KvTransaction<'a> {
    tx: Box<dyn KvTx + 'a>,
}

impl<'a> KvTransaction<'a> {
    pub fn begin<S: KvStore>(store: &'a S) -> Result<Self, StorageError> {
        Ok(Self { tx: store.begin()? })
    }

    /// Binds a scope to the key verbs for the length of the borrow.
    pub fn scope<'s>(&'s self, ns: impl Into<Namespace>, instance: &'s str) -> ScopedKvStore<'s> {
        ScopedKvStore {
            tx: self.tx.as_ref(),
            scope: Scope {
                ns: ns.into(),
                instance,
            },
        }
    }

    /// Empties one scope, named the way [`Self::scope`] names it.
    pub fn delete_scope(
        &self,
        ns: impl Into<Namespace>,
        instance: &str,
    ) -> Result<(), StorageError> {
        self.tx.delete_scope(&Scope {
            ns: ns.into(),
            instance,
        })
    }

    pub fn commit(self) -> Result<(), StorageError> {
        self.tx.commit()
    }
}

/// The key verbs with one scope bound.
#[derive(Clone, Copy)]
pub struct ScopedKvStore<'a> {
    tx: &'a dyn KvTx,
    scope: Scope<'a>,
}

impl ScopedKvStore<'_> {
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.tx.get(&self.scope, key)
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.tx.put(&self.scope, key, value)
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.tx.delete(&self.scope, key)
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError> {
        self.tx.scan_prefix(&self.scope, prefix)
    }

    pub fn delete_prefix(&self, prefix: &[u8]) -> Result<(), StorageError> {
        self.tx.delete_prefix(&self.scope, prefix)
    }
}
