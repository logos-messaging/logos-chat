use std::collections::HashMap;

use storage::{
    // TODO: (P4) Importable crates need to be prefixed with a project name to avoid conflicts
    ConversationMeta,
    ConversationStore,
};

/// An Test focused StorageService which holds data in a hashmap
pub struct MemStore {
    convos: HashMap<String, ConversationMeta>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            convos: HashMap::new(),
        }
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConversationStore for MemStore {
    fn save_conversation(
        &mut self,
        meta: &storage::ConversationMeta,
    ) -> Result<(), storage::StorageError> {
        self.convos
            .insert(meta.local_convo_id.clone(), meta.clone());
        Ok(())
    }

    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<storage::ConversationMeta>, storage::StorageError> {
        let a = self.convos.get(local_convo_id).cloned();
        Ok(a)
    }

    fn remove_conversation(&mut self, _local_convo_id: &str) -> Result<(), storage::StorageError> {
        todo!()
    }

    fn load_conversations(&self) -> Result<Vec<storage::ConversationMeta>, storage::StorageError> {
        Ok(self.convos.values().cloned().collect())
    }

    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, storage::StorageError> {
        Ok(self.convos.contains_key(local_convo_id))
    }
}
