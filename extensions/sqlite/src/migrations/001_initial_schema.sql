-- Initial schema for chat storage
-- Migration: 001_initial_schema

-- Identity table (single row)
CREATE TABLE IF NOT EXISTS identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    secret_key BLOB NOT NULL
);

-- Ephemeral keys for inbox handshakes
CREATE TABLE IF NOT EXISTS ephemeral_keys (
    public_key_hex TEXT PRIMARY KEY,
    secret_key BLOB NOT NULL
);

-- Conversations metadata
CREATE TABLE IF NOT EXISTS conversations (
    local_convo_id TEXT PRIMARY KEY,
    remote_convo_id TEXT NOT NULL,
    convo_type TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
