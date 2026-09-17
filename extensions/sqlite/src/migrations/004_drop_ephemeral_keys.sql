-- Ephemeral keys are no longer part of the store contract
-- Migration: 004_drop_ephemeral_keys

DROP TABLE IF EXISTS ephemeral_keys;
