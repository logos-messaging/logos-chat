-- Drops conversation records with no state behind them in kv
-- Migration: 008_drop_conversations_without_state

DELETE FROM conversations
WHERE NOT EXISTS (
    SELECT 1 FROM kv
    WHERE kv.ns = conversations.convo_type
      AND kv.instance = conversations.local_convo_id
);
