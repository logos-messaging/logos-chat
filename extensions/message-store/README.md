# message-store

A default store for an application's chat messages: enough to keep a chat's history across restarts without
writing a store first. It is meant to get an application running, not to be a complete message database.

The application opens the SQLite connection, keys it when it uses SQLCipher, and sets its pragmas. The store
borrows that connection and creates only tables named `message_store_*`, so the same database can hold the
application's own tables, and a transaction the application opens covers what the store writes through it.

- A **chat** is the application's grouping of messages and can span several conversations. Each message also
  keeps the conversation it travelled over.
- Messages come back oldest first, a page at a time. The `seq` of a page's first message is the cursor for the
  page before it.
- Content is stored as the bytes it is given, whatever its type.

```rust
use message_store::rusqlite::Connection;
use message_store::{Direction, Message, MessageStore};

let mut conn = Connection::open_in_memory()?;
MessageStore::migrate(&mut conn)?;
let store = MessageStore::new(&conn);

store.record(&Message {
    chat_id: "saro-raya".into(),
    convo_id: "convo-1".into(),
    direction: Direction::Received,
    sender_account: Some("raya".into()),
    sender_installation: None,
    message_id: None,
    timestamp_ms: 1_758_000_000_000,
    content: b"hi saro".to_vec(),
})?;

let newest = store.messages("saro-raya", None, 50)?;
let before_them = store.messages("saro-raya", Some(newest[0].seq), 50)?;
assert!(before_them.is_empty());
Ok::<(), Box<dyn std::error::Error>>(())
```

`rusqlite` is re-exported, so the connection comes from the version the store takes. The store enables no
SQLite build of its own: the application's `rusqlite` features, or those of another crate in its build, choose
bundled SQLite, SQLCipher or the system library.
