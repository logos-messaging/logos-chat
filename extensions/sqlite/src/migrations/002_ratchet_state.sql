-- Ratchet state tables
-- Migration: 002_ratchet_state

CREATE TABLE IF NOT EXISTS ratchet_state (
    conversation_id TEXT PRIMARY KEY,
    root_key BLOB NOT NULL,
    sending_chain BLOB,
    receiving_chain BLOB,
    dh_self_secret BLOB NOT NULL,
    dh_remote BLOB,
    msg_send INTEGER NOT NULL,
    msg_recv INTEGER NOT NULL,
    prev_chain_len INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS skipped_keys (
    conversation_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    msg_num INTEGER NOT NULL,
    message_key BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (conversation_id, public_key, msg_num),
    FOREIGN KEY (conversation_id) REFERENCES ratchet_state(conversation_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_skipped_keys_conversation
    ON skipped_keys(conversation_id);
