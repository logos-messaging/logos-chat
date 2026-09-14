-- Drops the remote conversation id column; a record is the local id and its kind
-- Migration: 006_drop_remote_convo_id

ALTER TABLE conversations DROP COLUMN remote_convo_id;
