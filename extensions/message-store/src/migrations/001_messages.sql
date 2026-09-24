CREATE TABLE message_store_messages (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id             TEXT NOT NULL,
    convo_id            TEXT NOT NULL,
    direction           INTEGER NOT NULL CHECK (direction IN (0, 1)),
    sender_account      TEXT,
    sender_installation TEXT,
    message_id          TEXT,
    timestamp_ms        INTEGER NOT NULL,
    content             BLOB NOT NULL
);

CREATE INDEX message_store_messages_by_chat ON message_store_messages (chat_id, seq);
