//! Chat-specific SQLite storage implementation.

mod common;
mod errors;
mod migrations;

use rusqlite::params;
use storage::{ConversationKind, ConversationMeta, ConversationStore, StorageError};

use crate::{
    common::SqliteDb,
    errors::{map_optional_row, map_rusqlite_error},
};

pub use common::StorageConfig;

/// Chat-specific storage operations.
///
/// This struct wraps a SqliteDb and provides domain-specific
/// storage operations for chat state (chat metadata).
pub struct ChatStorage {
    db: SqliteDb,
}

impl ChatStorage {
    /// Creates a new ChatStorage with the given configuration.
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        let db = SqliteDb::new(config)?;
        Self::run_migrations(db)
    }

    pub fn in_memory() -> Self {
        Self::new(StorageConfig::InMemory).unwrap()
    }

    /// Applies all migrations and returns the storage instance.
    fn run_migrations(mut db: SqliteDb) -> Result<Self, StorageError> {
        migrations::apply_migrations(db.connection_mut())?;
        Ok(Self { db })
    }
}

impl ConversationStore for ChatStorage {
    /// Saves conversation metadata.
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError> {
        self.db
            .connection()
            .execute(
                "INSERT OR REPLACE INTO conversations (local_convo_id, convo_type) VALUES (?1, ?2)",
                params![meta.local_convo_id, meta.kind.as_str()],
            )
            .map_err(map_rusqlite_error)?;
        Ok(())
    }

    /// Loads a single conversation record by its local ID.
    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<ConversationMeta>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT local_convo_id, convo_type FROM conversations WHERE local_convo_id = ?1",
            )
            .map_err(map_rusqlite_error)?;

        let result = stmt.query_row(params![local_convo_id], |row| {
            let local_convo_id: String = row.get(0)?;
            let convo_type: String = row.get(1)?;
            Ok(ConversationMeta {
                local_convo_id,
                kind: ConversationKind::from(convo_type.as_str()),
            })
        });

        map_optional_row(result)
    }

    /// Removes a conversation by its local ID.
    fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError> {
        self.db
            .connection()
            .execute(
                "DELETE FROM conversations WHERE local_convo_id = ?1",
                params![local_convo_id],
            )
            .map_err(map_rusqlite_error)?;
        Ok(())
    }

    /// Loads all conversation records.
    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT local_convo_id, convo_type FROM conversations")
            .map_err(map_rusqlite_error)?;

        let records = stmt
            .query_map([], |row| {
                let local_convo_id: String = row.get(0)?;
                let convo_type: String = row.get(1)?;
                Ok(ConversationMeta {
                    local_convo_id,
                    kind: ConversationKind::from(convo_type.as_str()),
                })
            })
            .map_err(map_rusqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_rusqlite_error)?;

        Ok(records)
    }

    /// Checks if a conversation exists by its local ID.
    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError> {
        let exists: bool = self
            .db
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM conversations WHERE local_convo_id = ?1)",
                params![local_convo_id],
                |row| row.get(0),
            )
            .map_err(map_rusqlite_error)?;
        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use storage::{ConversationKind, ConversationMeta, ConversationStore};

    use super::*;

    #[test]
    fn test_conversation_roundtrip() {
        let mut storage = ChatStorage::new(StorageConfig::InMemory).unwrap();

        // Initially empty
        let convos = storage.load_conversations().unwrap();
        assert!(convos.is_empty());

        // Save conversations
        storage
            .save_conversation(&ConversationMeta {
                local_convo_id: "local_1".into(),
                kind: ConversationKind::GroupV1,
            })
            .unwrap();
        storage
            .save_conversation(&ConversationMeta {
                local_convo_id: "local_2".into(),
                kind: ConversationKind::GroupV1,
            })
            .unwrap();

        let convos = storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 2);

        // Remove one
        storage.remove_conversation("local_1").unwrap();
        let convos = storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].local_convo_id, "local_2");
        assert_eq!(convos[0].kind.as_str(), "group_v1");
    }
}
