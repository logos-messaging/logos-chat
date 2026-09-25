-- The installation this database belongs to
-- Migration: 009_installation

-- One row: the conversations here were joined by one installation, and a second one reading
-- them would hold groups whose leaves it cannot sign for. `record` holds a signing key, so it
-- is only as protected as the surrounding database.
CREATE TABLE IF NOT EXISTS installation (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    record BLOB NOT NULL
);
