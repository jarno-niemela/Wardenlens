-- Migration 2 (ADR 0005 section 5, ADR 0006; ticket #50). Append-only: never edit a released
-- migration. No credential, host, display-name or other site-identifying column: those are vault
-- entries `cam:<id>:credential`, `cam:<id>:host` and `cam:<id>:name`. No foreign key from
-- `segments`: removing a camera never deletes recordings.
CREATE TABLE cameras (
  id            TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 32),
  model         TEXT    NOT NULL CHECK (length(model) BETWEEN 1 AND 64),
  rtsp_port     INTEGER NOT NULL CHECK (rtsp_port BETWEEN 1 AND 65535),
  main_path     TEXT    NOT NULL CHECK (length(main_path) BETWEEN 1 AND 512),
  sub_path      TEXT    CHECK (sub_path IS NULL OR length(sub_path) BETWEEN 1 AND 512),
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
) STRICT;
PRAGMA user_version = 2;
