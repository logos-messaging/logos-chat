-- Ratchet state is no longer part of the store contract
-- Migration: 003_drop_ratchet_state

DROP TABLE IF EXISTS skipped_keys;
DROP TABLE IF EXISTS ratchet_state;
