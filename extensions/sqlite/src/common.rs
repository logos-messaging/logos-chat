//! SQLite storage backend.

use libchat::StorageError;
use rusqlite::Connection;

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
        let conn = match config {
            StorageConfig::InMemory => Connection::open_in_memory().map_err(map_rusqlite_error)?,
            StorageConfig::File(ref path) => Connection::open(path).map_err(map_rusqlite_error)?,
            StorageConfig::Encrypted { ref path, ref key } => {
                let conn = Connection::open(path).map_err(map_rusqlite_error)?;
                conn.pragma_update(None, "key", key)
                    .map_err(map_rusqlite_error)?;
                conn
            }
        };

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(map_rusqlite_error)?;

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
