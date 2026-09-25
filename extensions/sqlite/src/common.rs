//! SQLite storage backend.

use std::time::Duration;

use libchat::StorageError;
use rusqlite::{Connection, TransactionBehavior};

use crate::errors::map_rusqlite_error;

/// Configuration for SQLite storage.
#[derive(Debug, Clone)]
pub enum StorageConfig {
    /// In-memory database (for testing).
    InMemory,
    /// File-based SQLite database.
    File(String),
    /// SQLCipher encrypted database.
    Encrypted { path: String, key: String },
}

/// SQLite database wrapper.
///
/// This provides the core database connection and can be shared
/// across different domain-specific storage implementations.
pub struct SqliteDb {
    conn: Connection,
}

impl SqliteDb {
    /// Creates a new SQLite database with the given configuration.
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        let mut conn = match config {
            StorageConfig::InMemory => Connection::open_in_memory().map_err(map_rusqlite_error)?,
            StorageConfig::File(ref path) => Connection::open(path).map_err(map_rusqlite_error)?,
            StorageConfig::Encrypted { ref path, ref key } => {
                let conn = Connection::open(path).map_err(map_rusqlite_error)?;
                conn.pragma_update(None, "key", key)
                    .map_err(map_rusqlite_error)?;
                conn
            }
        };

        // Pinned here: rusqlite documents its own default as subject to change.
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(map_rusqlite_error)?;

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(map_rusqlite_error)?;

        // WAL keeps -wal and -shm sidecars beside the database, so the database file alone is not
        // a copy of it, and it wants a local filesystem. SQLite answers with the mode it ends on
        // rather than failing when it cannot set the one asked for.
        conn.execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(map_rusqlite_error)?;

        // Under WAL this fsyncs at a checkpoint rather than at every commit: a process crash keeps
        // every committed transaction, a power cut can cost the most recent ones.
        conn.execute_batch("PRAGMA synchronous = NORMAL;")
            .map_err(map_rusqlite_error)?;

        // KvStore::begin holds &self and cannot pick a behaviour per transaction, so rusqlite takes
        // it from the connection. IMMEDIATE claims the write lock at BEGIN, so a transaction that
        // reads before it writes cannot fail to upgrade with its reads already staged.
        conn.set_transaction_behavior(TransactionBehavior::Immediate);

        Ok(Self { conn })
    }

    /// Returns a reference to the underlying connection.
    ///
    /// Use this for domain-specific storage operations.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Returns a mutable reference to the underlying connection.
    ///
    /// Use this for operations that require mutable access, such as transactions.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_database_runs_in_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db").to_string_lossy().into_owned();

        let db = SqliteDb::new(StorageConfig::File(path)).unwrap();

        let mode: String = db
            .connection()
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }
}
