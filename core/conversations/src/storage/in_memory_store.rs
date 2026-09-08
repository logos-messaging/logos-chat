use std::collections::HashMap;

use super::{ConversationMeta, ConversationStore, StorageError};

/// A test-focused store which holds data in a hashmap.
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
