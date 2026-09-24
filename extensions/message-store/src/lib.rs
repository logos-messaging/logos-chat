#![doc = include_str!("../README.md")]

mod migrations;

pub use rusqlite;

use rusqlite::{Connection, Result, Row, params};

/// Whether the recording side sent the message or received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Received,
}

impl Direction {
    fn as_i64(self) -> i64 {
        match self {
            Direction::Sent => 0,
            Direction::Received => 1,
        }
    }
}

/// A chat message as the application records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The application's grouping of messages. One chat can span several conversations.
    pub chat_id: String,
    /// The conversation the message travelled over.
    pub convo_id: String,
    pub direction: Direction,
    pub sender_account: Option<String>,
    pub sender_installation: Option<String>,
    /// The protocol's id for the message, when it has one.
    pub message_id: Option<String>,
    /// Milliseconds since the Unix epoch, as the application stamps it. Messages are ordered by
    /// `seq`, not by this.
    pub timestamp_ms: i64,
    /// The encoded payload, stored as given.
    pub content: Vec<u8>,
}

/// A recorded message and the `seq` the store gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// Grows with every record and is never handed out twice, not even after a delete.
    pub seq: i64,
    pub message: Message,
}

/// Chat messages in a SQLite database the application opened.
///
/// The store creates only tables named `message_store_*` and sets no pragma, so the database can
/// hold other schemas, and a transaction the application started covers what the store writes
/// through it. [`MessageStore::migrate`] must have run on the database first.
pub struct MessageStore<'c> {
    conn: &'c Connection,
}

impl<'c> MessageStore<'c> {
    /// Creates or upgrades the store's tables. Idempotent, so it can run on every open.
    pub fn migrate(conn: &mut Connection) -> Result<()> {
        migrations::apply(conn)
    }

    /// Wraps a connection to a database [`MessageStore::migrate`] has run on.
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Records a message and returns its `seq`.
    pub fn record(&self, message: &Message) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO message_store_messages (
                chat_id, convo_id, direction, sender_account, sender_installation, message_id,
                timestamp_ms, content
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                message.chat_id,
                message.convo_id,
                message.direction.as_i64(),
                message.sender_account,
                message.sender_installation,
                message.message_id,
                message.timestamp_ms,
                message.content,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Up to `limit` messages of a chat, oldest first: the newest when `before` is `None`,
    /// otherwise those whose `seq` is below it. The `seq` of a page's first message reads the page
    /// before it, and a page shorter than `limit` has reached the chat's first message.
    pub fn messages(
        &self,
        chat_id: &str,
        before: Option<i64>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, chat_id, convo_id, direction, sender_account, sender_installation,
                    message_id, timestamp_ms, content
             FROM message_store_messages
             WHERE chat_id = ?1 AND seq < ?2
             ORDER BY seq DESC
             LIMIT ?3",
        )?;
        let mut page = stmt
            .query_map(
                params![chat_id, before.unwrap_or(i64::MAX), limit],
                stored_message,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        page.reverse();
        Ok(page)
    }

    /// How many messages a chat holds.
    pub fn count(&self, chat_id: &str) -> Result<usize> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM message_store_messages WHERE chat_id = ?1",
            [chat_id],
            |row| row.get(0),
        )
    }

    /// Deletes one message. `false` when no message has that `seq`.
    pub fn delete(&self, seq: i64) -> Result<bool> {
        let deleted = self
            .conn
            .execute("DELETE FROM message_store_messages WHERE seq = ?1", [seq])?;
        Ok(deleted > 0)
    }

    /// Deletes every message of a chat and returns how many there were.
    pub fn delete_chat(&self, chat_id: &str) -> Result<usize> {
        self.conn.execute(
            "DELETE FROM message_store_messages WHERE chat_id = ?1",
            [chat_id],
        )
    }
}

fn stored_message(row: &Row<'_>) -> Result<StoredMessage> {
    let direction = match row.get::<_, i64>(3)? {
        0 => Direction::Sent,
        1 => Direction::Received,
        other => return Err(rusqlite::Error::IntegralValueOutOfRange(3, other)),
    };
    Ok(StoredMessage {
        seq: row.get(0)?,
        message: Message {
            chat_id: row.get(1)?,
            convo_id: row.get(2)?,
            direction,
            sender_account: row.get(4)?,
            sender_installation: row.get(5)?,
            message_id: row.get(6)?,
            timestamp_ms: row.get(7)?,
            content: row.get(8)?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrated() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        MessageStore::migrate(&mut conn).unwrap();
        conn
    }

    fn message(chat_id: &str, content: &str) -> Message {
        Message {
            chat_id: chat_id.into(),
            convo_id: "convo-1".into(),
            direction: Direction::Received,
            sender_account: Some("raya".into()),
            sender_installation: Some("raya-phone".into()),
            message_id: None,
            timestamp_ms: 1_758_000_000_000,
            content: content.as_bytes().to_vec(),
        }
    }

    fn contents(page: &[StoredMessage]) -> Vec<String> {
        page.iter()
            .map(|stored| String::from_utf8(stored.message.content.clone()).unwrap())
            .collect()
    }

    #[test]
    fn messages_read_back_oldest_first_as_recorded() {
        let conn = migrated();
        let store = MessageStore::new(&conn);
        let sent = Message {
            direction: Direction::Sent,
            sender_account: None,
            sender_installation: None,
            message_id: Some("msg-1".into()),
            ..message("saro-raya", "hi raya")
        };
        let received = message("saro-raya", "hi saro");

        let first = store.record(&sent).unwrap();
        let second = store.record(&received).unwrap();

        assert_eq!(
            store.messages("saro-raya", None, 10).unwrap(),
            [
                StoredMessage {
                    seq: first,
                    message: sent
                },
                StoredMessage {
                    seq: second,
                    message: received
                },
            ]
        );
    }

    #[test]
    fn a_page_continues_below_its_cursor_while_messages_arrive() {
        let conn = migrated();
        let store = MessageStore::new(&conn);
        for i in 1..=10 {
            store
                .record(&message("saro-raya", &format!("m{i}")))
                .unwrap();
        }

        let newest = store.messages("saro-raya", None, 4).unwrap();
        store.record(&message("saro-raya", "m11")).unwrap();
        let older = store.messages("saro-raya", Some(newest[0].seq), 4).unwrap();
        let oldest = store.messages("saro-raya", Some(older[0].seq), 4).unwrap();

        assert_eq!(contents(&newest), ["m7", "m8", "m9", "m10"]);
        assert_eq!(contents(&older), ["m3", "m4", "m5", "m6"]);
        assert_eq!(contents(&oldest), ["m1", "m2"]);
    }

    #[test]
    fn a_chat_reads_as_one_list_across_its_conversations() {
        let conn = migrated();
        let store = MessageStore::new(&conn);
        for (convo_id, content) in [("convo-1", "a"), ("convo-2", "b"), ("convo-1", "c")] {
            let message = Message {
                convo_id: convo_id.into(),
                ..message("saro-raya", content)
            };
            store.record(&message).unwrap();
        }
        store.record(&message("saro-pax", "elsewhere")).unwrap();

        let page = store.messages("saro-raya", None, 10).unwrap();

        assert_eq!(contents(&page), ["a", "b", "c"]);
        let convo_ids: Vec<_> = page.iter().map(|m| m.message.convo_id.as_str()).collect();
        assert_eq!(convo_ids, ["convo-1", "convo-2", "convo-1"]);
    }

    #[test]
    fn count_is_every_message_of_a_chat_not_a_page() {
        let conn = migrated();
        let store = MessageStore::new(&conn);
        for i in 1..=5 {
            store
                .record(&message("saro-raya", &format!("m{i}")))
                .unwrap();
        }
        store.record(&message("saro-pax", "elsewhere")).unwrap();

        assert_eq!(store.messages("saro-raya", None, 2).unwrap().len(), 2);
        assert_eq!(store.count("saro-raya").unwrap(), 5);
        assert_eq!(store.count("saro-nobody").unwrap(), 0);
    }

    #[test]
    fn delete_removes_one_message() {
        let conn = migrated();
        let store = MessageStore::new(&conn);
        store.record(&message("saro-raya", "kept")).unwrap();
        let deleted = store.record(&message("saro-raya", "deleted")).unwrap();

        assert!(store.delete(deleted).unwrap());
        assert!(!store.delete(deleted).unwrap());
        assert_eq!(
            contents(&store.messages("saro-raya", None, 10).unwrap()),
            ["kept"]
        );
    }

    #[test]
    fn a_deleted_seq_is_never_handed_out_again() {
        let conn = migrated();
        let store = MessageStore::new(&conn);
        let deleted = store.record(&message("saro-raya", "deleted")).unwrap();
        store.delete(deleted).unwrap();

        let next = store.record(&message("saro-raya", "next")).unwrap();

        assert!(next > deleted);
    }

    #[test]
    fn delete_chat_leaves_other_chats() {
        let conn = migrated();
        let store = MessageStore::new(&conn);
        store.record(&message("saro-raya", "a")).unwrap();
        store.record(&message("saro-raya", "b")).unwrap();
        store.record(&message("saro-pax", "c")).unwrap();

        assert_eq!(store.delete_chat("saro-raya").unwrap(), 2);
        assert!(store.messages("saro-raya", None, 10).unwrap().is_empty());
        assert_eq!(
            contents(&store.messages("saro-pax", None, 10).unwrap()),
            ["c"]
        );
    }

    #[test]
    fn content_is_kept_as_bytes() {
        let conn = migrated();
        let store = MessageStore::new(&conn);
        let content = vec![0xff, 0x00, 0xfe];
        let message = Message {
            content: content.clone(),
            ..message("saro-raya", "")
        };

        store.record(&message).unwrap();

        let page = store.messages("saro-raya", None, 1).unwrap();
        assert_eq!(page[0].message.content, content);
    }

    #[test]
    fn messages_outlive_the_connection_that_recorded_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        {
            let mut conn = Connection::open(&path).unwrap();
            MessageStore::migrate(&mut conn).unwrap();
            MessageStore::new(&conn)
                .record(&message("saro-raya", "still here"))
                .unwrap();
        }

        let mut conn = Connection::open(&path).unwrap();
        MessageStore::migrate(&mut conn).unwrap();

        let page = MessageStore::new(&conn)
            .messages("saro-raya", None, 10)
            .unwrap();
        assert_eq!(contents(&page), ["still here"]);
    }

    #[test]
    fn migrate_leaves_the_databases_other_tables_alone() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (body TEXT);
             INSERT INTO messages VALUES ('the application''s own');
             CREATE TABLE _migrations (name TEXT PRIMARY KEY);
             INSERT INTO _migrations VALUES ('001_initial_schema');",
        )
        .unwrap();

        MessageStore::migrate(&mut conn).unwrap();
        MessageStore::new(&conn)
            .record(&message("saro-raya", "hi"))
            .unwrap();

        let own: String = conn
            .query_row("SELECT group_concat(body) FROM messages", [], |row| {
                row.get(0)
            })
            .unwrap();
        let migrations: String = conn
            .query_row("SELECT group_concat(name) FROM _migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(own, "the application's own");
        assert_eq!(migrations, "001_initial_schema");
    }

    #[test]
    fn a_record_rolls_back_with_the_applications_transaction() {
        let mut conn = migrated();

        let tx = conn.transaction().unwrap();
        MessageStore::new(&tx)
            .record(&message("saro-raya", "rolled back"))
            .unwrap();
        tx.rollback().unwrap();

        let tx = conn.transaction().unwrap();
        MessageStore::new(&tx)
            .record(&message("saro-raya", "committed"))
            .unwrap();
        tx.commit().unwrap();

        let page = MessageStore::new(&conn)
            .messages("saro-raya", None, 10)
            .unwrap();
        assert_eq!(contents(&page), ["committed"]);
    }
}
