ALTER TABLE message_store_messages ADD COLUMN delivered INTEGER NOT NULL DEFAULT 0;

CREATE INDEX message_store_messages_by_message_id ON message_store_messages (convo_id, message_id);
