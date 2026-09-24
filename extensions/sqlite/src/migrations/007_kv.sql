-- Scoped key-value substrate for the state libchat owns
-- Migration: 007_kv

CREATE TABLE IF NOT EXISTS kv (
    ns TEXT NOT NULL,
    instance TEXT NOT NULL,
    key BLOB NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (ns, instance, key)
);
