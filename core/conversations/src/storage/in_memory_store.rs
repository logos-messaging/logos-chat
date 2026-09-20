use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, HashMap},
};

use super::{
    ConversationMeta, ConversationStore, KvPair, KvStore, KvTx, Namespace, Scope, StorageError,
};

/// A test-focused store which holds data in a hashmap.
pub struct MemStore {
    convos: HashMap<String, ConversationMeta>,
    kv: RefCell<Kv>,
    tx_open: Cell<bool>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            convos: HashMap::new(),
            kv: RefCell::new(Kv::new()),
            tx_open: Cell::new(false),
        }
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConversationStore for MemStore {
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError> {
        self.convos
            .insert(meta.local_convo_id.clone(), meta.clone());
        Ok(())
    }

    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<ConversationMeta>, StorageError> {
        let a = self.convos.get(local_convo_id).cloned();
        Ok(a)
    }

    fn remove_conversation(&mut self, _local_convo_id: &str) -> Result<(), StorageError> {
        todo!()
    }

    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError> {
        Ok(self.convos.values().cloned().collect())
    }

    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError> {
        Ok(self.convos.contains_key(local_convo_id))
    }
}

impl KvStore for MemStore {
    fn begin(&self) -> Result<Box<dyn KvTx + '_>, StorageError> {
        if self.tx_open.replace(true) {
            return Err(StorageError::Database(
                "a transaction is already open".into(),
            ));
        }
        Ok(Box::new(MemKvTx {
            store: self,
            staged: RefCell::new(self.kv.borrow().clone()),
        }))
    }
}

/// Every scope's keys, each scope kept apart from the rest.
type Kv = HashMap<(Namespace, String), BTreeMap<Vec<u8>, Vec<u8>>>;

/// One transaction, worked on a copy the store takes back only on commit.
struct MemKvTx<'a> {
    store: &'a MemStore,
    staged: RefCell<Kv>,
}

impl KvTx for MemKvTx<'_> {
    fn get(&self, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(get(&self.staged.borrow(), scope, key))
    }

    fn put(&self, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        put(&mut self.staged.borrow_mut(), scope, key, value);
        Ok(())
    }

    fn delete(&self, scope: &Scope, key: &[u8]) -> Result<(), StorageError> {
        delete(&mut self.staged.borrow_mut(), scope, key);
        Ok(())
    }

    fn scan_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError> {
        Ok(scan_prefix(&self.staged.borrow(), scope, prefix))
    }

    fn delete_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError> {
        delete_prefix(&mut self.staged.borrow_mut(), scope, prefix);
        Ok(())
    }

    fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError> {
        delete_scope(&mut self.staged.borrow_mut(), scope);
        Ok(())
    }

    fn delete_namespace(&self, ns: Namespace) -> Result<(), StorageError> {
        delete_namespace(&mut self.staged.borrow_mut(), ns);
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), StorageError> {
        *self.store.kv.borrow_mut() = self.staged.take();
        Ok(())
    }
}

impl Drop for MemKvTx<'_> {
    fn drop(&mut self) {
        self.store.tx_open.set(false);
    }
}

fn scope_key(scope: &Scope) -> (Namespace, String) {
    (scope.ns, scope.instance.to_owned())
}

fn get(kv: &Kv, scope: &Scope, key: &[u8]) -> Option<Vec<u8>> {
    kv.get(&scope_key(scope))?.get(key).cloned()
}

fn put(kv: &mut Kv, scope: &Scope, key: &[u8], value: &[u8]) {
    kv.entry(scope_key(scope))
        .or_default()
        .insert(key.to_vec(), value.to_vec());
}

fn delete(kv: &mut Kv, scope: &Scope, key: &[u8]) {
    if let Some(entries) = kv.get_mut(&scope_key(scope)) {
        entries.remove(key);
    }
}

fn scan_prefix(kv: &Kv, scope: &Scope, prefix: &[u8]) -> Vec<KvPair> {
    kv.get(&scope_key(scope))
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn delete_prefix(kv: &mut Kv, scope: &Scope, prefix: &[u8]) {
    if let Some(entries) = kv.get_mut(&scope_key(scope)) {
        entries.retain(|key, _| !key.starts_with(prefix));
    }
}

fn delete_scope(kv: &mut Kv, scope: &Scope) {
    kv.remove(&scope_key(scope));
}

fn delete_namespace(kv: &mut Kv, ns: Namespace) {
    kv.retain(|(scope_ns, _), _| *scope_ns != ns);
}

#[cfg(test)]
mod tests {
    use crate::storage::assert_kv_contract;

    use super::*;

    #[test]
    fn satisfies_the_substrate_contract() {
        assert_kv_contract(MemStore::new);
    }
}
