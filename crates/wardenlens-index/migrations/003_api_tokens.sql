-- Migration 3 (ADR 0005 section 5, ADR 0004 section 9; ticket #65). Append-only: never edit a
-- released migration. Hashes only: the secret of a token is never stored. The unique `id` is the
-- lookup key (its index is created by the constraint). Rows are never deleted: a revoked token
-- keeps its row so its id is never issued again.
CREATE TABLE api_tokens (
  id              TEXT    NOT NULL UNIQUE CHECK (length(id) = 8),
  digest          BLOB    NOT NULL CHECK (length(digest) = 32),
  name            TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  created_at_ms   INTEGER NOT NULL,
  last_used_at_ms INTEGER,
  revoked         INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
) STRICT;
PRAGMA user_version = 3;
