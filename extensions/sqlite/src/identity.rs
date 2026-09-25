//! The installation this database belongs to.

use libchat::{IdentityStore, StorageError, StoredInstallation};
use rusqlite::params;

use crate::{
    SqliteStore,
    errors::{map_optional_row, map_rusqlite_error},
};

impl IdentityStore for SqliteStore {
    fn load_installation(&self) -> Result<Option<StoredInstallation>, StorageError> {
        let record = self.db.connection().query_row(
            "SELECT record FROM installation WHERE id = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        );

        Ok(map_optional_row(record)?.map(StoredInstallation::new))
    }

    fn save_installation(&mut self, installation: &StoredInstallation) -> Result<(), StorageError> {
        self.db
            .connection()
            .execute(
                "INSERT OR REPLACE INTO installation (id, record) VALUES (1, ?1)",
                params![installation.as_bytes()],
            )
            .map_err(map_rusqlite_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use libchat::test_support::assert_identity_store_contract;

    use super::*;
    use crate::StorageConfig;

    /// The contract, against a fresh in-memory database per case.
    #[test]
    fn satisfies_the_identity_contract() {
        assert_identity_store_contract(SqliteStore::in_memory);
    }

    /// The reason the record is stored at all: it is still there in the next process.
    #[test]
    fn an_installation_outlives_the_store_that_wrote_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db").to_string_lossy().into_owned();
        let record = StoredInstallation::new(b"an installation".to_vec());

        {
            let mut store = SqliteStore::new(StorageConfig::File(path.clone())).unwrap();
            store.save_installation(&record).unwrap();
        }

        let reopened = SqliteStore::new(StorageConfig::File(path)).unwrap();
        assert_eq!(reopened.load_installation().unwrap().unwrap(), record);
    }
}
