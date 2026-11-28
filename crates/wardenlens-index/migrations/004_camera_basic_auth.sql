-- Migration 4 (ADR 0002 item 15; ticket #225). Append-only: never edit a released migration. The
-- per-camera opt-in to answer a Basic-only RTSP challenge with the password (which then crosses
-- the network in base64 cleartext). Off for every existing row. A flag, not a secret or a site
-- identifier, so it belongs in the registry rather than the vault.
ALTER TABLE cameras ADD COLUMN allow_basic_auth INTEGER NOT NULL DEFAULT 0
  CHECK (allow_basic_auth IN (0, 1));
PRAGMA user_version = 4;
