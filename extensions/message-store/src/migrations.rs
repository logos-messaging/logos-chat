//! Schema migrations, recorded in a table of the store's own so the database can hold other
//! schemas.

use rusqlite::{Connection, TransactionBehavior};

const MIGRATIONS: &[(&str, &str)] =
    &[("001_messages", include_str!("migrations/001_messages.sql"))];

pub(crate) fn apply(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS message_store_migrations (
            name TEXT PRIMARY KEY,
            applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );",
    )?;

    for (name, sql) in MIGRATIONS {
        // IMMEDIATE takes the write lock before the check, so two connections cannot both apply it.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let applied: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM message_store_migrations WHERE name = ?1)",
            [name],
            |row| row.get(0),
        )?;
        if !applied {
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO message_store_migrations (name) VALUES (?1)",
                [name],
            )?;
        }
        tx.commit()?;
    }

    Ok(())
}
