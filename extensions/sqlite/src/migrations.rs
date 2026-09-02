//! Database migrations module.
//!
//! SQL migrations are embedded at compile time and applied in order.
//! Each migration is applied atomically within a transaction.

use libchat::StorageError;
use rusqlite::Connection;

use crate::errors::map_rusqlite_error;

/// Embeds and returns all migration SQL files in order.
pub fn get_migrations() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "001_initial_schema",
            include_str!("migrations/001_initial_schema.sql"),
        ),
        (
            "002_ratchet_state",
            include_str!("migrations/002_ratchet_state.sql"),
        ),
        (
            "003_drop_ratchet_state",
            include_str!("migrations/003_drop_ratchet_state.sql"),
        ),
        (
            "004_drop_ephemeral_keys",
            include_str!("migrations/004_drop_ephemeral_keys.sql"),
        ),
        (
            "005_drop_identity",
            include_str!("migrations/005_drop_identity.sql"),
        ),
        (
            "006_drop_remote_convo_id",
            include_str!("migrations/006_drop_remote_convo_id.sql"),
        ),
        ("007_kv", include_str!("migrations/007_kv.sql")),
        (
            "008_drop_conversations_without_state",
            include_str!("migrations/008_drop_conversations_without_state.sql"),
        ),
    ]
}

/// Applies all migrations to the database.
///
/// Uses a simple version tracking table to avoid re-running migrations.
pub fn apply_migrations(conn: &mut Connection) -> Result<(), StorageError> {
    // Create migrations tracking table if it doesn't exist
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (
            name TEXT PRIMARY KEY,
            applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );",
    )
    .map_err(map_rusqlite_error)?;

    for (name, sql) in get_migrations() {
        // Check if migration already applied
        let already_applied: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM _migrations WHERE name = ?1)",
                [name],
                |row| row.get(0),
            )
            .map_err(map_rusqlite_error)?;

        if !already_applied {
            // Apply migration and record it atomically in a transaction
            let tx = conn.transaction().map_err(map_rusqlite_error)?;
            tx.execute_batch(sql).map_err(map_rusqlite_error)?;
            tx.execute("INSERT INTO _migrations (name) VALUES (?1)", [name])
                .map_err(map_rusqlite_error)?;
            tx.commit().map_err(map_rusqlite_error)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;

    const SWEEP: &str = "008_drop_conversations_without_state";

    /// A migrated database with the sweep not yet applied, the state an upgrade meets.
    fn before_the_sweep() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn).unwrap();
        conn.execute("DELETE FROM _migrations WHERE name = ?1", [SWEEP])
            .unwrap();
        conn
    }

    fn record(conn: &Connection, local_convo_id: &str, convo_type: &str) {
        conn.execute(
            "INSERT INTO conversations (local_convo_id, convo_type) VALUES (?1, ?2)",
            params![local_convo_id, convo_type],
        )
        .unwrap();
    }

    fn state(conn: &Connection, ns: &str, instance: &str) {
        conn.execute(
            "INSERT INTO kv (ns, instance, key, value) VALUES (?1, ?2, ?3, ?4)",
            params![ns, instance, b"tree".as_slice(), b"state".as_slice()],
        )
        .unwrap();
    }

    fn listed(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT local_convo_id FROM conversations ORDER BY local_convo_id")
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn a_record_with_nothing_in_its_scope_is_dropped() {
        let mut conn = before_the_sweep();
        record(&conn, "empty", "group_v1");
        record(&conn, "misfiled", "group_v1");
        state(&conn, "direct_v1", "misfiled");
        record(&conn, "resumable", "direct_v1");
        state(&conn, "direct_v1", "resumable");

        apply_migrations(&mut conn).unwrap();

        assert_eq!(listed(&conn), ["resumable"]);
    }
}
