-- Migration 1 (ADR 0005 section 5). Append-only: never edit a released migration.
CREATE TABLE segments (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  camera_id     TEXT    NOT NULL CHECK (length(camera_id) BETWEEN 1 AND 32),
  started_at_ms INTEGER NOT NULL CHECK (started_at_ms BETWEEN 946684800000 AND 4102444799999),
  duration_ms   INTEGER NOT NULL CHECK (duration_ms BETWEEN 1 AND 600000),
  ended_at_ms   INTEGER NOT NULL,
  bytes         INTEGER NOT NULL CHECK (bytes > 0),
  frame_count   INTEGER NOT NULL CHECK (frame_count > 0),
  tier          INTEGER NOT NULL CHECK (tier IN (0, 1)),
  CHECK (ended_at_ms = started_at_ms + duration_ms)
) STRICT;
CREATE UNIQUE INDEX segments_camera_start ON segments (camera_id, started_at_ms);
CREATE INDEX segments_tier_end ON segments (tier, ended_at_ms, id, bytes);
PRAGMA user_version = 1;
