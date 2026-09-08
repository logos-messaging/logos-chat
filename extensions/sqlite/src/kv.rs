//! Scoped key-value substrate over the `kv` table.

use libchat::{KvPair, KvStore, KvTx, Namespace, Scope, StorageError};
use rusqlite::{Connection, Transaction, params};

use crate::{
    SqliteStore,
    errors::{map_optional_row, map_rusqlite_error},
};

impl KvStore for SqliteStore {
    fn begin(&self) -> Result<Box<dyn KvTx + '_>, StorageError> {
        let tx = self
            .db
            .connection()
            .unchecked_transaction()
            .map_err(map_rusqlite_error)?;
        Ok(Box::new(SqliteKvTx { tx }))
    }
}

/// One transaction over the `kv` table, rolled back unless committed.
struct SqliteKvTx<'a> {
    tx: Transaction<'a>,
}

impl KvTx for SqliteKvTx<'_> {
    fn get(&self, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        get(&self.tx, scope, key)
    }

    fn put(&self, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        put(&self.tx, scope, key, value)
    }

    fn delete(&self, scope: &Scope, key: &[u8]) -> Result<(), StorageError> {
        delete(&self.tx, scope, key)
    }

    fn scan_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError> {
        scan_prefix(&self.tx, scope, prefix)
    }

    fn delete_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError> {
        delete_prefix(&self.tx, scope, prefix)
    }

    fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError> {
        delete_scope(&self.tx, scope)
    }

    fn delete_namespace(&self, ns: Namespace) -> Result<(), StorageError> {
        delete_namespace(&self.tx, ns)
    }

    fn commit(self: Box<Self>) -> Result<(), StorageError> {
        self.tx.commit().map_err(map_rusqlite_error)
    }
}

fn get(conn: &Connection, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
    let row = conn.query_row(
        "SELECT value FROM kv WHERE ns = ?1 AND instance = ?2 AND key = ?3",
        params![scope.ns.as_str(), scope.instance, key],
        |row| row.get(0),
    );
    map_optional_row(row)
}

fn put(conn: &Connection, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO kv (ns, instance, key, value) VALUES (?1, ?2, ?3, ?4)",
        params![scope.ns.as_str(), scope.instance, key, value],
    )
    .map_err(map_rusqlite_error)?;
    Ok(())
}

fn delete(conn: &Connection, scope: &Scope, key: &[u8]) -> Result<(), StorageError> {
    conn.execute(
        "DELETE FROM kv WHERE ns = ?1 AND instance = ?2 AND key = ?3",
        params![scope.ns.as_str(), scope.instance, key],
    )
    .map_err(map_rusqlite_error)?;
    Ok(())
}

/// The rows whose key starts with `?3`. Keys are arbitrary bytes, so the prefix matches bytewise;
/// LIKE would read % and _ in it as wildcards. substr of an empty key is NULL rather than an empty
/// blob, so the empty prefix is answered by length instead.
macro_rules! key_under_prefix {
    () => {
        "(length(?3) = 0 OR substr(key, 1, length(?3)) = ?3)"
    };
}

fn scan_prefix(
    conn: &Connection,
    scope: &Scope,
    prefix: &[u8],
) -> Result<Vec<KvPair>, StorageError> {
    let mut stmt = conn
        .prepare(concat!(
            "SELECT key, value FROM kv WHERE ns = ?1 AND instance = ?2 AND ",
            key_under_prefix!(),
            " ORDER BY key"
        ))
        .map_err(map_rusqlite_error)?;

    let pairs = stmt
        .query_map(params![scope.ns.as_str(), scope.instance, prefix], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(map_rusqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_rusqlite_error)?;

    Ok(pairs)
}

fn delete_prefix(conn: &Connection, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError> {
    conn.execute(
        concat!(
            "DELETE FROM kv WHERE ns = ?1 AND instance = ?2 AND ",
            key_under_prefix!()
        ),
        params![scope.ns.as_str(), scope.instance, prefix],
    )
    .map_err(map_rusqlite_error)?;
    Ok(())
}

fn delete_scope(conn: &Connection, scope: &Scope) -> Result<(), StorageError> {
    conn.execute(
        "DELETE FROM kv WHERE ns = ?1 AND instance = ?2",
        params![scope.ns.as_str(), scope.instance],
    )
    .map_err(map_rusqlite_error)?;
    Ok(())
}

fn delete_namespace(conn: &Connection, ns: Namespace) -> Result<(), StorageError> {
    conn.execute("DELETE FROM kv WHERE ns = ?1", params![ns.as_str()])
        .map_err(map_rusqlite_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use libchat::test_support::assert_kv_contract;

    use super::*;

    #[test]
    fn satisfies_the_substrate_contract() {
        assert_kv_contract(SqliteStore::in_memory);
    }
}
