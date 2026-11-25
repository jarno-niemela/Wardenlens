-- Creation bootstrap (not a numbered migration): runs once, in rollback mode and in ONE
-- transaction, before WAL is switched on, so the main file itself carries the application id and
-- the instance id from the start. The `-wal` of this index is tied to its main file by that id.
PRAGMA application_id = 1464617304;
CREATE TABLE index_meta (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  instance_id BLOB NOT NULL CHECK (length(instance_id) = 16)
) STRICT;
-- SQLite's randomblob is seeded from the operating system (/dev/urandom); the id is for
-- uniqueness, not a secret.
INSERT INTO index_meta (id, instance_id) VALUES (1, randomblob(16));
