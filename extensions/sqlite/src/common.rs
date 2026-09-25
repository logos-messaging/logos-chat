//! SQLite storage backend.

use libchat::StorageError;
use rusqlite::{Connection, ffi::ErrorCode};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::map_rusqlite_error;

/// The 32 bytes SQLCipher encrypts a database with.
///
/// Raw key material, not a passphrase: SQLCipher takes it as the key itself and runs no
/// derivation over it. Deriving these bytes from something a person can remember belongs where
/// the keychain or the password prompt is, not here.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DbKey([u8; 32]);

impl DbKey {
    /// The key as SQLCipher's raw-key pragma. Zeroizing, because the hex and the statement are
    /// two more heap copies of the key and outlive the borrow otherwise.
    fn pragma(&self) -> Zeroizing<String> {
        let mut hex = Zeroizing::new(String::with_capacity(64));
        for byte in self.0 {
            hex.push_str(&Zeroizing::new(format!("{byte:02x}")));
        }
        Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", *hex))
    }
}

impl From<[u8; 32]> for DbKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Never print key material.
impl std::fmt::Debug for DbKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DbKey").field(&"[redacted]").finish()
    }
}

/// Configuration for SQLite storage.
#[derive(Clone)]
pub enum StorageConfig {
    /// In-memory database (for testing).
    InMemory,
    /// File-based SQLite database.
    File(String),
    /// SQLCipher encrypted database, keyed by a passphrase SQLCipher derives from.
    ///
    /// On its way out in favour of [`StorageConfig::EncryptedWithKey`], which does not leave the
    /// derivation and its cost to SQLCipher. The two forms key different databases, so it stays
    /// until every caller has migrated deliberately.
    Encrypted { path: String, key: String },
    /// SQLCipher encrypted database, keyed by 32 raw bytes.
    EncryptedWithKey { path: String, key: DbKey },
}

/// Never print key material. `DbKey` redacts itself, but a derived `Debug` would print the
/// passphrase of [`StorageConfig::Encrypted`] in full.
impl std::fmt::Debug for StorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InMemory => f.write_str("InMemory"),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
            Self::Encrypted { path, .. } => f
                .debug_struct("Encrypted")
                .field("path", path)
                .field("key", &"[redacted]")
                .finish(),
            Self::EncryptedWithKey { path, key } => f
                .debug_struct("EncryptedWithKey")
                .field("path", path)
                .field("key", key)
                .finish(),
        }
    }
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
        let encrypted = !matches!(config, StorageConfig::InMemory | StorageConfig::File(_));
        let conn = match config {
            StorageConfig::InMemory => Connection::open_in_memory().map_err(map_rusqlite_error)?,
            StorageConfig::File(ref path) => Connection::open(path).map_err(map_rusqlite_error)?,
            StorageConfig::Encrypted { ref path, ref key } => {
                let conn = Connection::open(path).map_err(map_rusqlite_error)?;
                conn.pragma_update(None, "key", key)
                    .map_err(map_rusqlite_error)?;
                conn
            }
            StorageConfig::EncryptedWithKey { ref path, ref key } => {
                let conn = Connection::open(path).map_err(map_rusqlite_error)?;
                // `x'…'` is SQLCipher's raw-key form: these 32 bytes are the key, with no
                // derivation over them. A bare string would instead be run through SQLCipher's
                // own KDF, which is a different database for the same bytes.
                conn.execute_batch(&key.pragma())
                    .map_err(map_rusqlite_error)?;
                conn
            }
        };

        if encrypted {
            verify_key(&conn)?;
        }

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

/// Reads the schema so that a key which does not open the database says so here.
///
/// `PRAGMA key` decrypts nothing on its own; SQLCipher only notices a wrong key on the first
/// page read, which otherwise lands in the migration runner and reads as a malformed database —
/// the difference between "your password is wrong" and "your history is gone".
///
/// Only `NotADatabase` means the key did not open it. Everything else — a busy database, an I/O
/// error — is passed through as itself, so a lock held elsewhere is not reported as a bad key.
fn verify_key(conn: &Connection) -> Result<(), StorageError> {
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(_) => Ok(()),
        Err(err) if is_not_a_database(&err) => Err(StorageError::Database(
            "the database key is incorrect, the file is not a SQLCipher database, or it was \
             written in the other key form (a passphrase-keyed database does not open with a \
             raw key, and the reverse)"
                .into(),
        )),
        Err(err) => Err(map_rusqlite_error(err)),
    }
}

fn is_not_a_database(err: &rusqlite::Error) -> bool {
    matches!(
        err.sqlite_error(),
        Some(e) if e.code == ErrorCode::NotADatabase
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> DbKey {
        DbKey::from([byte; 32])
    }

    fn db_path(dir: &tempfile::TempDir) -> String {
        dir.path().join("chat.db").to_string_lossy().into_owned()
    }

    /// The point of the whole exercise: the same key opens the same database again.
    #[test]
    fn the_same_key_reopens_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = db_path(&dir);

        {
            let db = SqliteDb::new(StorageConfig::EncryptedWithKey {
                path: path.clone(),
                key: key(1),
            })
            .unwrap();
            db.connection()
                .execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('kept');")
                .unwrap();
        }

        let db = SqliteDb::new(StorageConfig::EncryptedWithKey { path, key: key(1) }).unwrap();
        let value: String = db
            .connection()
            .query_row("SELECT v FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "kept");
    }

    /// A wrong key fails at open, and says that is what happened.
    #[test]
    fn a_wrong_key_is_reported_as_a_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = db_path(&dir);

        {
            let db = SqliteDb::new(StorageConfig::EncryptedWithKey {
                path: path.clone(),
                key: key(1),
            })
            .unwrap();
            db.connection()
                .execute_batch("CREATE TABLE t (v TEXT);")
                .unwrap();
        }

        let Err(err) = SqliteDb::new(StorageConfig::EncryptedWithKey { path, key: key(2) }) else {
            panic!("a database must not open under a key that did not write it");
        };

        assert!(
            err.to_string().contains("key is incorrect"),
            "expected a wrong-key error, got: {err}"
        );
    }

    /// Only a key that does not open the file is a wrong key. A database another connection
    /// holds locked is busy, and saying "wrong key" would send someone looking for a lost
    /// password instead of the process holding the lock.
    #[test]
    fn a_busy_database_is_not_reported_as_a_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = db_path(&dir);

        let holder = SqliteDb::new(StorageConfig::EncryptedWithKey {
            path: path.clone(),
            key: key(1),
        })
        .unwrap();
        holder
            .connection()
            .execute_batch("CREATE TABLE t (v TEXT); BEGIN EXCLUSIVE; INSERT INTO t VALUES ('x');")
            .unwrap();

        let Err(err) = SqliteDb::new(StorageConfig::EncryptedWithKey { path, key: key(1) }) else {
            panic!("an exclusive lock is held, so the open cannot succeed");
        };
        assert!(
            !err.to_string().contains("key is incorrect"),
            "a busy database must not be reported as a wrong key, got: {err}"
        );
    }

    /// A passphrase-keyed database does not open with a raw key: the two forms are different
    /// keys for the same bytes, so an existing database needs deleting or rekeying.
    #[test]
    fn a_passphrase_database_does_not_open_with_a_raw_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = db_path(&dir);

        {
            let db = SqliteDb::new(StorageConfig::Encrypted {
                path: path.clone(),
                key: "chat-cli".into(),
            })
            .unwrap();
            db.connection()
                .execute_batch("CREATE TABLE t (v TEXT);")
                .unwrap();
        }

        let Err(err) = SqliteDb::new(StorageConfig::EncryptedWithKey { path, key: key(1) }) else {
            panic!("the two key forms must not open the same database");
        };
        assert!(err.to_string().contains("the other key form"), "got: {err}");
    }

    /// A config must not print the passphrase it carries.
    #[test]
    fn a_config_does_not_print_its_key() {
        let printed = format!(
            "{:?}",
            StorageConfig::Encrypted {
                path: "/tmp/chat.db".into(),
                key: "hunter2".into(),
            }
        );
        assert!(!printed.contains("hunter2"), "got: {printed}");
    }

    /// An unencrypted database is not asked to prove a key it does not have.
    #[test]
    fn a_plain_database_still_opens() {
        let dir = tempfile::tempdir().unwrap();
        SqliteDb::new(StorageConfig::File(db_path(&dir))).unwrap();
        SqliteDb::new(StorageConfig::InMemory).unwrap();
    }
}
