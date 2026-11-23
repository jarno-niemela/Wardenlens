# 0005. Recording format, SQLite index and tier-move protocol

- Status: proposed
- Date: 2026-11-23
- Ticket: #41 (epic #16)

Cameras are referred to by inventory id only (`reolink-1`, `reolink-2`, `xr`, `tapo`, `hdipc`, see ADR 0002); no
addresses or names appear here. Crate facts were observed on 2026-11-23 with `cargo info <crate>`, the crates.io API
(version, licence, `rust-version`, last release = `updated_at` of the crate, owners, downloads, features) and by reading
the downloaded sources. Nothing was written from memory. "Downloads" are the crates.io lifetime total and, in
brackets, the `recent_downloads` figure (about the last 90 days). Host numbers (`df -B1`, `stat -f`, `lsblk`) were
read on the NVR host on the same day. All probes (a box-writer prototype, `cargo deny`, a SQLite schema probe) were
built **outside the repository** and nothing was added to a `Cargo.toml`.

## Context

Phase 1 records the five main streams by passthrough (no decode, ADR 0003) into segment files on an SSD "hot" tier and
moves them to a slow 2 TB HDD (rotational) "archive" tier, keeping a minimum percentage of each volume free (default 25 %). A
SQLite index tells the API what exists and the storage loop what to move or evict. The format, the index schema and
the move protocol are shared by the recorder, storage, index, mp4 and api crates (ADR 0004 section 8), so they are
decided once here (DOC-5).

Facts this ADR builds on:

- ADR 0002: every camera sends H.264 (High profile); GOP 1-3.5 s; Reolink main is variable frame rate; Tapo and Dahua
  sub show non-monotonic DTS (8891 ffmpeg warnings in 30 min on Tapo main), so Wardenlens must stamp its own arrival
  clock and must not trust camera timestamps. Main stream bitrates: reolink-1 and reolink-2 2.9 Mbit/s each, xr 4.3,
  tapo 0.19 (static scene, VBR), hdipc 8.6.
- ADR 0003: main streams are not decoded, so the recorder handles H.264 access units and nothing else.
- ADR 0004: crate map (`index`, `mp4`, `recorder`, `storage`), tokio, core defines the store traits, the index
  implements `TokenStore` as plain SQL data access (`api_tokens`).
- ADR 0006 (proposed): the `cameras` table has **no** credential, host or display-name column; the vault is a separate
  SQLite file; the vault follows this ADR's SQLite crate choice.
- Host (2026-11-23): the hot directory `/srv/wardenlens/recordings` is **on the root filesystem** `/dev/sdb2` (SSD, non-rotational,
  982,240,026,624 B total, 302,966,685,696 B used, 629,302,824,960 B available), not on a volume of its own. The archive
  `/srv/wardenlens/archive` is a separate ext4 mount `/dev/sda1` (1,998,980,898,816 B total, 1,998,961,995,776 B
  available, mounted `rw,noatime`; fstab has `nofail`, so it can be absent at boot). I could not open the plan
  document from the sandbox, so the volume sizes are the measured ones, not the plan's nominal "2 TB".
  Consequence: the hot floor also protects the operating system, and an unmounted archive leaves an empty directory on
  the root filesystem (section 8).

## Options and decisions

### 1. fMP4 muxer

All three candidates are measured below. What Wardenlens needs is small: one video track, H.264, `ftyp` + `moov`
(with `mvex`/`trex`) once per file and `moof` + `mdat` per fragment (about 25 box types, see section 3). It does not
need to read MP4 files from untrusted sources (the recorder only writes; the reconciliation walk in section 9 reads
only box headers of its own files).

| | in-house box writer | `mp4-atom` 0.17.1 | `mp4` 0.14.0 |
|---|---|---|---|
| licence | ours | MIT OR Apache-2.0 | MIT |
| last release | n/a | 2026-11-04 (19 days ago); 28 versions since 2024-09-02 | **2023-08-01** (3.3 years ago); 26 versions since 2020-01-13 |
| owners | n/a | `kixelated` (1) | `alfg` (1) |
| downloads | n/a | 750,040 (477,126) | 16,218,849 (3,839,081) |
| `rust-version` | workspace 1.100 | 1.88 | none declared |
| features | none | `bytes`, `serde`, `strict`, `tokio` (all off for us; no default) | none |
| transitive crates (`cargo tree -e normal`, no default features) | 0 | 26 (+ itself): `derive_more`, `num` family (`num-bigint`, `num-complex`, `num-rational`, ...), `thiserror` 1.x, `tracing`, proc-macro crates `syn`/`quote`/`proc-macro2`/`pastey` | `byteorder`, `bytes`, `num-rational`, `serde`, `serde_json`, `thiserror` 1.x |
| fragment support | we write it | has `Moof`, `Mfhd`, `Traf`, `Tfhd`, `Tfdt`, `Trun` (`TrunSamples`), `Avcc`, `Moov`, `Mvex`; encodes into a buffer, no `Seek` | **no fragmented writer**: `Mp4Writer` needs `Write + Seek`, writes `mdat` first and the `moov` in `write_end` (read in `src/writer.rs`); a crash before `write_end` leaves a file without `moov`, which is unplayable. `MoofBox` has a `WriteBox` impl but nothing assembles fragments |
| `cargo deny` (repo `deny.toml`, scratch project) | n/a | ok | ok |

Other crates seen on crates.io and set aside (metadata only, not evaluated further): `muxide` 0.5.0 (MIT OR Apache-2.0,
created 2025-12-17, one owner, 45,450 downloads: too young for a storage-critical path), `shiguredo_mp4`
2026.6.0-canary.2 (Apache-2.0, a canary release), `re_mp4` 0.5.1 (MIT, a parser only).

**Evidence for the in-house writer.** A scratch prototype (136 lines, no dependencies, outside the repository) read a
synthetic H.264 Annex-B stream, split it into access units, removed SPS/PPS from the samples (they live in `avcC`),
converted start codes to 4-byte length prefixes and wrote `ftyp` + `moov` once and one `moof` + `mdat` per GOP, cutting
a new file at the first keyframe at or after 4 s. Input: `ffmpeg -f lavfi -i testsrc2=size=640x360:rate=25 -t 12 -c:v
libx264 -profile:v high -bf 0 -g 50 -keyint_min 50 -sc_threshold 0 -f h264` (1,126,436 bytes, 300 frames, no B-frames).
Result with the ffmpeg 8.0.1 and ffprobe 8.0.1 installed on the host:

- 3 files of 381,116, 378,453 and 372,799 bytes (the container adds **0.53 %** over the elementary stream).
- `ffprobe` for each: `h264`, `High`, 640x360, `time_base 1/90000`, `nb_read_frames=100`, `duration=4.000000`, 2 keyframes,
  first packet `pts=0 dts=0 K`, last packet `pts=dts=356400` (99 x 3600 ticks).
- `ffmpeg -xerror -i seg.mp4 -f null -` decodes every file without a warning.
- The `framemd5` of the 300 frames decoded from the three files is **identical** to the `framemd5` decoded from the
  source stream (`cmp` equal), so passthrough is lossless.
- Cutting a file at 200,000 bytes (inside the first fragment) makes ffmpeg report invalid NAL sizes for that fragment
  only: damage is confined to the last, incomplete fragment, which is the property we want from fMP4.

Box layout, flags and sizes below come from that prototype. `mp4-atom` was **not** prototyped end to end; I checked
only that its `Moof`/`Traf`/`Tfhd`/`Tfdt`/`Trun` types exist and encode into a buffer. `mp4` was rejected on the
source reading above, not on a test.

**Decision: in-house minimal box writer** in `crates/wardenlens-mp4` (ticket #54), no new dependency.
Reasons: the surface is about 25 boxes and the prototype shows the whole job fits in a few hundred lines; it adds no
crates (`mp4-atom` would add 26, including the `num` big-number family and `thiserror` 1.x next to the `thiserror` 2
that ADR 0004 pulled in, which `deny.toml`'s `multiple-versions = "warn"` will report); every length is ours to bound
(SEC-2, SEC-3); `mp4` cannot do crash-safe fragmented output at all. Cost: we own the byte layout, which is why #54
has golden-structure tests and an ffprobe/ffmpeg decode test. **Fallback:** the crate's public surface
(`init_segment`, `Fragment::write`) is small and independent of the implementation, so switching to `mp4-atom`
later is a local change if the in-house writer proves hard to keep correct.

### 2. Segment rule and timestamp policy

**Why fragmented, and why one fragment per GOP.** A fragment is written to the file as soon as its GOP is complete, so
the recorder holds at most one GOP in memory (hdipc: 3.5 s x 8.6 Mbit/s = 3.8 MB) instead of a whole segment
(60 s of hdipc is 64.8 MB), and a crash leaves a file that is playable up to the last complete fragment. v1 does not
salvage such a file (section 9) but the format allows it later.

**Rule** (pure logic in core, ticket #45; defaults are config values within the stated bounds):

1. **First segment** of a stream starts at the first keyframe. Frames before it are dropped (`Decision::Drop`).
2. **Target duration 60 s** (bounds 10-300 s). A segment is cut at the first keyframe whose media time since the segment
   start is at least the target: the keyframe becomes the first sample of the next segment.
3. **Hard maximum 120 s** (2x target). If no keyframe has arrived when the media time reaches the maximum, the
   segment is closed at that frame (a closed fMP4 does not need to end on a GOP boundary), and frames are dropped until
   the next keyframe starts a new segment. The loss is counted as a gap. Also forced: the byte cap `max_segment_bytes`
   (default 1 GiB; 120 s of the highest-bitrate camera is about 130 MB, so this is a sanity bound).
4. **Fragment** = one GOP. A fragment is also flushed early when it reaches 16 MiB, so no `mdat` approaches the u32
   size limit. A single frame larger than 8 MiB is treated as a stream error (a discontinuity, #57).
5. A discontinuity (reconnect), an SPS/PPS change (resolution, profile) or a write error closes the segment cleanly
   and the next one starts at the next keyframe (ticket #57).

**Why 60 s:** a crash or power cut loses at most one open segment per camera (at most 120 s, and 60 s normally); the
index stays small (5 cameras x 1,440 segments/day = 7,200 rows/day, section 6); a move or delete is a few MB to
65 MB; and an HTTP range request and a browser can seek inside one file. Shorter segments multiply rows and files;
longer ones raise crash loss and the unit of eviction.

**Timestamp policy.**

- *Index (wall clock):* `started_at_ms` is the **arrival** time of the segment's first frame (the frame that starts the
  segment), from the `Clock` trait (#46), as UTC Unix milliseconds. Camera clocks and RTP wall-clock mappings are never
  used. Per camera `started_at_ms` must be strictly increasing: `started_at_ms = max(arrival, previous + 1)`, which
  also makes the file name unique (section 3). `duration_ms` is the **media** duration (below) and
  `ended_at_ms = started_at_ms + duration_ms`. A gap between two segments is therefore visible as
  `started_next - ended_prev`, and "recorded coverage" (#70) is the sum of `duration_ms`.
- *File (monotonic media time):* timescale **90,000**; each file starts at `tfdt` base media time 0 (each file is
  independently playable and has its own `moov`). The `MediaClock` (#45) turns the RTP timestamp (unwrapped from 32
  bits with a signed wrapping difference, so a wrap every 13.25 h is handled) into
  `dts_i = max(rtp_i - rtp_0, dts_{i-1} + 1)`. It **clamps, it does not accumulate**: a non-monotonic or equal
  timestamp (Tapo, Dahua) becomes one tick after the previous one and the next normal frame is back on the RTP line,
  so the total media time does not drift from the camera's real pacing over thousands of jittery frames. A jump
  of more than **10 s** forward or backward is a re-base: the clock keeps the last good duration for that step and
  continues from the new RTP value (no gap in media time; the wall-clock gap shows in the index).
  `duration_i = dts_{i+1} - dts_i`; the last sample of a segment gets the previous duration (at least 1).
  Durations are clamped to 1..=900,000 ticks.
- *B-frames:* v1 writes no composition offsets (`trun` without `sample_composition_time_offset`, so PTS = DTS). That is
  correct only for streams without frame reordering. ADR 0002 did not record `has_b_frames` for the five cameras and I
  have no camera access here, so this is **an open risk** (see "Open risks"): #55 must verify it live before #57 is
  trusted.

### 3. On-disk layout, naming and the segment file

```
<root>/<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4          finished segment
<root>/<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4.part     being written (or an interrupted one)
<root>/quarantine/<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4   files reconciliation could not trust (section 9)
```

`<root>` is the hot root (`/srv/wardenlens/recordings`) or the archive root (`/srv/wardenlens/archive`). The relative
path `<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4` is **the same on both tiers**, so a move never changes it. Date and
time are **UTC** from `started_at_ms` (a local-time directory would change meaning at a DST step); `<mmm>` is the
milliseconds. A day directory holds at most about 1,440 files per camera (86,400 s / 60 s). The deepest file is at depth
4 below a root (`quarantine/<camera>/<day>/<file>`), which is the bound the reconciliation walk uses.

**Paths are derived, never stored, never taken from a camera (SEC-4).** There is **no `rel_path` column** (this overrides
#49 and #62): the path is a pure function `RelPath::new(&CameraId, started_at_ms)` in core. `CameraId` is the validated
slug of #43 (`[a-z0-9-]{1,32}`, starting with a letter), the time is an integer bounded to years 2000-2099, so the
result can contain no `..`, separator or other character than the pattern allows. A tampered or corrupt index row
therefore cannot name an arbitrary path: `camera_id` is re-parsed with `FromStr` when a row is read and a bad value is a
typed error. File names found on disk are accepted only if they match
`^[0-9]{6}-[0-9]{3}\.mp4(\.part)?$` under a directory `<camera_id>/<YYYY-MM-DD>` that parses, and the time must agree
with the directory date. Joining a root and a `RelPath` is followed by the containment check of #58/#62 (canonicalise,
must stay inside the canonical root; symlinks are never followed out of a root). Writers create files with
`O_CREAT|O_EXCL|O_NOFOLLOW` (so an existing name, including a planted symlink, is an error), mode `0600`, directories
`0700`. The walker uses `lstat`, never follows symlinks and ignores anything that is not a regular file.

**Segment file** (what `wardenlens-mp4` writes, from the prototype; all integers big-endian):

```
ftyp  major isom, minor 512, compatible isom iso5 iso6 avc1 mp41
moov  mvhd (timescale 90000, duration 0)
      trak: tkhd (flags 3, width/height from the SPS), mdia: mdhd (90000), hdlr "vide",
            minf: vmhd, dinf/dref/url (self-contained), stbl: stsd -> avc1 + avcC (SPS and PPS only here),
                  empty stts, stsc, stsz, stco
      mvex: trex (track 1, default sample description 1)
moof  mfhd (sequence 1, 2, ...)  traf: tfhd (flags 0x020000 default-base-is-moof), tfdt (version 1, 64-bit base time),
      trun (flags 0x000701: data offset, per-sample duration, size and flags; sync sample flags 0x02000000,
            non-sync 0x01010000)
mdat  4-byte length-prefixed (AVCC) NAL units, SEI and slices, no SPS/PPS
...   more moof + mdat pairs, one per GOP
```

Box sizes are `u32` through `u32::try_from` (a larger box is an error, never a wrap); SPS and PPS are bounded before
they are copied; the SPS is parsed defensively (#54, proptest). The file has no `mfra`/`sidx`: nothing needs random
access by index, a range request plus the player's own box walk suffices.

**Writing a segment (temp file, fsync, rename).** The recorder creates `<hot>/<camera_id>/<day>/<name>.mp4.part`, writes
`ftyp`+`moov`, then each fragment with plain `write(2)` (no fsync per fragment). On close: (1) write the last
fragment, (2) `fsync(file)`, (3) `rename` `.part` to `.mp4`, (4) `fsync` the directory, (5) only then
`Index::insert`. The order makes a visible `.mp4` always complete, and an indexed row always point at a complete,
durable file. When a day directory (or camera directory) is created, its parent is fsynced as well. A graceful stop
runs steps 1-5 for the open segment. ENOSPC aborts the segment: the `.part` is unlinked and the recorder waits for the
storage loop (#57).

### 4. SQLite crate

| | `rusqlite` 0.43.0 | `sqlx` 0.9.1 |
|---|---|---|
| licence | MIT | MIT OR Apache-2.0 |
| last release | 2026-11-15 (89 versions, created 2014-11-21) | 2026-11-18 (60 versions, created 2019-06-06) |
| owners | `thomcc`, `gwenn` | `abonander`, `mehcode` |
| downloads | 164,029,877 (66,904,608) | 197,027,928 (61,326,461) |
| `rust-version` | 1.89.0 | 1.94.0 |
| style | synchronous | asynchronous, compile-time checked queries, pools |
| crates with the features we would use (`cargo tree -e normal`, probe) | **6** (+ build-time `cc` and friends): `rusqlite`, `libsqlite3-sys` 0.40.0, `bitflags`, `fallible-iterator`, `fallible-streaming-iterator`, `smallvec` | **134** in the probe together with `mp4`; the same probe made `cargo deny` warn about duplicate `hashbrown`, `syn`, `thiserror` |
| `cargo deny` (repo `deny.toml`) | ok | ok |

`rusqlite` default features are `cache` and `ffi-sqlite-wasm-rs`; with `default-features = false, features =
["bundled"]` the resolved set is the 6 crates above (with the default features it is 9, adding `hashlink`,
`hashbrown`, `foldhash`). `bundled` compiles the SQLite amalgamation shipped in `libsqlite3-sys` 0.40.0
(**SQLite 3.54.1**, read from `sqlite3.h`); the licence check passes because the crates are MIT (SQLite itself is in the
public domain). It needs a C compiler at build time, which the Dockerfile (#69) must provide.

**Decision: `rusqlite` 0.43.0, `default-features = false`, `features = ["bundled"]`.** The index sees at most a few
writes per second (7,200 inserts a day plus moves); it needs no async driver and no query macros. A pinned, bundled
SQLite gives WAL and `STRICT` tables regardless of the host's library (the Docker image, #69). The API is
**synchronous**: async callers use `tokio::task::spawn_blocking` (ADR 0004 runtime), and the cli wraps the handle.
ADR 0006 follows this choice for the vault. The statement cache (`cache` feature) is not needed now; `prepare_cached`
can be enabled later at the cost of three more crates.

Scratch probe, 2026-11-23 (file DB, 72,000 rows = 5 cameras x 14,400): `PRAGMA journal_mode=WAL` returns `wal`;
a `PRAGMA user_version` set inside a transaction is rolled back with it (probe: 0 after rollback, 1 after commit);
`PRAGMA application_id` round-trips; the queries of section 5 use the planned indexes (plans below); the aggregate over
all rows took 20 ms.

### 5. SQLite configuration, migrations and schema

**File and open.** The index is `/var/lib/wardenlens/index.db` (a volume, on neither recordings volume; ticket #69), with
its `-wal` and `-shm` files, **separate from the vault file** (ADR 0006). It is created with mode `0600`, opened with
`SQLITE_OPEN_NOFOLLOW` and refused if it is a symlink. Pragmas on every connection: `journal_mode = WAL`,
`synchronous = FULL`, `foreign_keys = ON`, `busy_timeout = 5000`, `journal_size_limit = 67108864`. `synchronous = FULL`
(not `NORMAL`) is required by the tier protocol: step M8 must be durable before the hot file is unlinked
(section 7); the cost is irrelevant at this write rate. `application_id = 0x574C4958` (`WLIX`) is set at creation and
checked on open, so a foreign SQLite file is refused. One writer and the rest readers (WAL): the cli keeps one write
connection and a small number of read connections.

**Migration scheme: `PRAGMA user_version`, migrations written in-house** as an ordered array of SQL scripts compiled in
with `include_str!`. `Index::open` runs, under `BEGIN IMMEDIATE`, every script with a number above the stored
`user_version`, each followed by `PRAGMA user_version = <n>` **in the same transaction** (verified in the probe), then
commits; a failure rolls the whole step back. A stored version **higher** than the compiled-in latest is a typed
error (`SchemaTooNew`), never a downgrade. This **overrides** #49's "`schema_version` table": the version cannot drift
from the DDL it describes, and there is no extra table or crate. Considered: `rusqlite_migration` 2.7.0 (Apache-2.0,
last release 2026-11-10, one owner `cljoly`, 5,243,729 downloads, also based on `user_version`): fine, but it saves
about 40 lines, adds a crate and its release cadence to the supply chain; `refinery` 0.10.0 (MIT) is heavier and
table-based. Both can replace the in-house runner without a schema change. Each migration is append-only and tested
against the previous schema.

**Migration 1** (segments; cameras and `api_tokens` arrive with #50 and #65 as migrations 2 and 3, the DDL below is
the agreed shape):

```sql
CREATE TABLE segments (
  id            INTEGER PRIMARY KEY,                 -- the id the API exposes
  camera_id     TEXT    NOT NULL CHECK (length(camera_id) BETWEEN 1 AND 32),
  started_at_ms INTEGER NOT NULL CHECK (started_at_ms BETWEEN 946684800000 AND 4102444799999),  -- 2000..2099 UTC
  duration_ms   INTEGER NOT NULL CHECK (duration_ms BETWEEN 1 AND 600000),
  ended_at_ms   INTEGER NOT NULL,
  bytes         INTEGER NOT NULL CHECK (bytes > 0),
  frame_count   INTEGER NOT NULL CHECK (frame_count > 0),
  tier          INTEGER NOT NULL CHECK (tier IN (0, 1)),   -- 0 hot, 1 archive (core's Tier maps to it)
  CHECK (ended_at_ms = started_at_ms + duration_ms)
) STRICT;
CREATE UNIQUE INDEX segments_camera_start ON segments (camera_id, started_at_ms);     -- also the path's uniqueness
CREATE INDEX segments_tier_end ON segments (tier, ended_at_ms, id, bytes);            -- eviction order and totals
```

`camera_id` is plain text with **no foreign key** to `cameras`: removing a camera never deletes recordings (#50);
a segment whose camera is gone is an orphan found with a `LEFT JOIN`, not a column.

Queries (every one parameterised, no SQL built from data; `EXPLAIN QUERY PLAN` observed in the probe):

- `list(camera, from, to, limit <= 1000, cursor)`:
  `WHERE camera_id = ?1 AND started_at_ms >= ?2 - 600000 AND started_at_ms < ?3 AND ended_at_ms > ?2 AND (started_at_ms,
  id) > (?4, ?5) ORDER BY started_at_ms, id LIMIT ?6`. Plan: `SEARCH segments USING INDEX segments_camera_start
  (camera_id=? AND started_at_ms>? AND started_at_ms<?)`, no sort. The 600,000 ms look-back is the column's
  `CHECK` bound on duration (the real maximum is 120 s), so the overlap test is exact. The cursor is the last row's
  `(started_at_ms, id)`, stable under inserts and deletes. A listing across cameras would need a second index
  `(started_at_ms, id)`, added when the API needs it.
- `oldest(tier, n)`: `WHERE tier = ?1 ORDER BY ended_at_ms, id LIMIT ?2`. Plan: `SEARCH ... USING INDEX
  segments_tier_end (tier=?)`, no temporary sort.
- `bytes_by_tier()`: `SELECT tier, SUM(bytes), COUNT(*) FROM segments GROUP BY tier`. Plan: `SCAN ... USING COVERING
  INDEX segments_tier_end`. Rows stay bounded by disk size (about 56,000 for the 7.8 days in section 10).
- `set_tier(id, tier)`: `UPDATE segments SET tier = ?2 WHERE id = ?1 AND tier = ?3`, which must change exactly one row.
  It takes **no path** (this overrides #49's `set_tier(id, tier, rel_path)`).
- `insert(SegmentRecord, tier)` takes no path either; `delete(id)`.

**`cameras`** (ADR 0006 is authoritative; migration 2, ticket #50): `id TEXT PRIMARY KEY` (a `CameraId`, length
check), `model TEXT NOT NULL` (catalogue reference), `rtsp_port INTEGER NOT NULL CHECK (rtsp_port BETWEEN 1 AND 65535)`,
`main_path TEXT NOT NULL`, `sub_path TEXT`, `created_at_ms INTEGER NOT NULL`, `updated_at_ms INTEGER NOT NULL`, `STRICT`.
**No** credential, host, display-name or other site-identifying column; those are vault entries `cam:<id>:...`.

**`api_tokens`** (ADR 0004 section 9; migration 3, ticket #65): `id TEXT NOT NULL UNIQUE CHECK (length(id) = 8)` (8
characters of lowercase base32), `digest BLOB NOT NULL CHECK (length(digest) = 32)` (SHA-256 of the decoded secret),
`name TEXT NOT NULL`, `created_at_ms INTEGER NOT NULL`, `last_used_at_ms INTEGER` (nullable; written at most once a
minute per token), `revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))`, `STRICT`. The `id` is the primary
lookup key, so the unique constraint creates its index. Rows are never deleted (revoked ids are never reused).
No roles in v1. The table holds hashes only, so it needs no ADR 0006 encryption.

The index holds nothing that cannot be rebuilt except `cameras` (re-importable) and `api_tokens`; `segments` can be
rebuilt from the files by the adoption rule of section 9.

### 6. When to move, what to evict (policy; the pure planner is #44)

Terms: for a volume, `total = f_blocks * f_frsize` and `free = f_bavail * f_frsize` (what an unprivileged writer can
use; `statvfs` through the `rustix` safe wrapper, #58, checked arithmetic), `free_percent = free * 100 / total`. The
**floor** is `min_free_percent` (0-90, default 25) per volume. The **headroom** is a fixed 1 percentage point of
`total`: a volume that dips below its floor is brought back to `floor + headroom`, not just to the floor, so the loop
does not move one segment per tick. 1 % of the hot volume (9.8 GB) is about 70 minutes of all five cameras, against
71 MB written per 30 s tick.

**Hot to archive happens when either holds:**

1. *Hot floor:* `hot.free < hot.total * floor`. Move the oldest hot segments (by `ended_at_ms`, then `id`, across all
   cameras) until `hot.free >= hot.total * (floor + 1 pp)`, **regardless of age**.
2. *Hot max age:* any hot segment with `ended_at_ms < now - hot_max_age` (default **12 h**, config
   `storage.hot_max_age`) is moved, oldest first, also without pressure. It keeps the SSD as a recent-video cache and
   lets the HDD spin up in bounded work rather than in bursts. `hot_max_age` never deletes anything.

**Archive eviction (frees the HDD) happens when** `archive.free < archive.total * floor`, **or** when a planned move
would leave `archive.free - move_bytes < archive.total * floor`. Before such a move the planner deletes the oldest
archive segments until `archive.free - move_bytes >= archive.total * (floor + 1 pp)`; deletions are planned
**before** the move that needs the room (#44).

**Eviction order**, always oldest first by `ended_at_ms`, ties by `id`, across cameras (every camera keeps the same
depth of history; Phase 2 adds retention by event and age):

1. Quarantined files of that volume (section 9), oldest first by the time in the name. They are not in the index and
   not in the pure plan: the executor deletes them first whenever a volume is below its floor.
2. Archive segments.
3. Hot segments, **only** as a last resort (below).

**Both volumes full or the archive missing (order of precedence):**

1. Hot below floor, archive can absorb after evicting: evict archive (oldest), then move. Net archive space is
   conserved: every moved byte displaces an older archived byte.
2. Archive **unavailable** (not mounted, probe error, or `st_dev` equal to the hot volume's, which also catches an
   unmounted archive whose empty mount-point directory would otherwise fill the SSD: #58's probe error): the plan
   becomes `Delete` of the oldest hot segments until the hot floor plus headroom holds. **The floor wins over keeping
   video**, because the hot directory is on the root filesystem and an NVR that fills `/` takes the host down. The
   state `archive_unavailable` is exposed and `floor_breaches_total` is increased (#63), the log names the volume by tier
   only.
3. A move that is **impossible** because a single segment is larger than the archive's capacity above its floor
   (`archive.total * (1 - floor) < segment.bytes`): `PlanError`, never a panic; hot segments are then deleted as in 2.
4. Even deleting every segment cannot restore a floor (something else fills the volume): `PlanError::Unsatisfiable`;
   the recorder keeps retrying on ENOSPC (#57) and the storage endpoint reports `below_floor`. Recording does not stop
   by itself for a floor breach; it stops only when the OS refuses the write.

Bounds: one tick executes at most `max_actions_per_tick` (default **64**) actions; it re-probes after each one. The
tick interval is 30 s (#68). Catch-up after downtime takes several ticks (see the example), which is acceptable
because writing continues meanwhile.

### 7. Crash-safe tier move

Only the storage loop moves or deletes segments and changes `tier` (a single task, enforced by one process holding an
exclusive lock on `/var/lib/wardenlens/wardenlens.lock`, #68); the recorder only adds hot files and rows.

**Move of segment S (row `id`, path `R`) from hot to archive**; `A` is the archive root, `H` the hot root:

| step | action | durable effect |
|---|---|---|
| M1 | `lstat(H/R)`: regular file, size equals the row's `bytes`; otherwise stop (reconciliation will deal with it) | none |
| M2 | create the archive directory chain; fsync each parent of a directory this step created | directories |
| M3 | unlink a stale `A/R.part` if one exists (only the mover writes archive `.part` files), then create `A/R.part` with `O_CREAT|O_EXCL|O_NOFOLLOW` | an empty `.part` |
| M4 | copy `H/R` to `A/R.part` in 1 MiB chunks; the copied length must equal `bytes` | a `.part` |
| M5 | `fsync(A/R.part)` | the data is durable |
| M6 | `rename(A/R.part, A/R)` (atomic, one filesystem) | `A/R` appears complete, because M5 came first |
| M7 | fsync the archive directory that contains `R` | the rename is durable |
| M8 | `UPDATE segments SET tier = 1 WHERE id = ? AND tier = 0`, exactly one row (WAL, `synchronous = FULL`: committed and durable on return) | **the commit point** |
| M9 | `unlink(H/R)` (`ENOENT` is fine), then fsync `H`'s directory (best effort: correctness does not depend on it) | the hot copy is gone |

**Crash points** (state = what exists after the power cut or `kill -9`; "recovers" = what the reconciliation of
section 9 does, in the order the rules are listed there):

| crash after | files | row | recovery |
|---|---|---|---|
| before M3 / M3 | hot file | hot | nothing to do |
| during M4 / after M4, before M5 | hot + partial `A/R.part` | hot | rule 1 deletes the `.part`; the hot copy is authoritative; the next tick moves again |
| after M5, before M6 | hot + complete `A/R.part` | hot | same (the `.part` is deleted and copied again; correct, merely wasteful) |
| after M6, before M7 | hot + `A/R` (it may or may not survive a power cut, but if present it is complete) | hot | present: rule 5 (both tiers, row hot, archive size equals `bytes`) rolls **forward**: set `tier = 1`, delete the hot file. Absent: nothing |
| after M7, before M8 | hot + `A/R` | hot | rule 5, roll forward |
| during M8 | WAL commit is atomic: either the row is still hot (as above) or archive (next line) | either | as the matching line |
| after M8, before M9 | hot + `A/R` | archive | rule 6 (both tiers, row archive): keep the archive copy, delete the hot file |
| after M9 | `A/R` | archive | nothing to do |

At every crash point at least one complete copy exists and the row points at a tier where a complete copy exists:
before M8 the row says hot and the hot file is untouched; after M8 the row says archive and `A/R` was made durable at
M7, which came first. Unlinking the hot file is the **last** step, so no crash can lose the only copy.

**Delete (eviction) of segment S:** unlink the file(s) first (a second copy on the other tier too, if present), then
`DELETE FROM segments WHERE id = ?`. Crash in between leaves a row without a file, which rule 3 deletes and counts. The
opposite order would leave a file without a row, and rule 4 would adopt it again: an evicted segment would come back.
(This **overrides** #58's "runs `Index::delete` and unlinks".)

**Readers during a move** (#62): the API looks up the row, joins the path for the row's tier and opens the file. A
download that already has the file open keeps it through the unlink (POSIX semantics, #62 tests it). A request that
read `tier = hot` but opens after M9 gets `ENOENT`: it re-reads the row once and, if the tier changed, opens the
archive copy; otherwise it returns 404.

### 8. Volume safety

The probe refuses to start the storage loop or the recorder when the hot or archive root is missing, when both are
on the same filesystem (same `st_dev`; allowed only by an explicit test switch, #58), or when the archive root is a
plain directory on the root filesystem (this is the same `st_dev` check, because the archive is a separate mount
point). With `nofail` in fstab, a missing HDD is therefore a reported degraded state (section 6, case 2), not a silent
fill of the SSD. Index and vault live under `/var/lib/wardenlens`, not on a recordings volume.

### 9. Reconciliation after a crash or restart

Runs at start-up **before** any recorder or storage loop starts (#68), holding the process lock. It walks both
roots to depth 4, never follows symlinks (`lstat`; anything that is not a regular file or directory is reported and
left), and treats only paths that match the section 3 patterns as ours. **Anything else is left in place and reported**
(it may be the owner's). A walk is also bounded in entries (default 5,000,000) and fails with a typed error beyond
that (SEC-2). Rules, applied in this order; "size" is the file size compared with the row's `bytes`, which is the
ground truth because rows are written after the final file size is known:

1. `*.mp4.part` in either root: **delete** (hot: an interrupted segment, at most one per camera per crash, at most
   about 120 s each; archive: an interrupted move). v1 does not salvage a hot `.part` (the fMP4 structure would allow
   truncating to the last complete `moof`+`mdat` pair; see follow-ups).
2. A `.mp4` with a row **on the same tier** and equal size: consistent, nothing to do. A different size: untrusted file,
   **quarantine** it (rename into `<root>/quarantine/...`, same relative path), delete the row, count `size_mismatch`.
3. A row with **no file on either tier**: delete the row, log, count `missing`.
4. A `.mp4` with **no row** (a crash between the recorder's rename and `Index::insert`, or a file put there by hand
   with a valid name): **adopt it**. `started_at_ms` comes from directory date and file name, `camera_id` from the
   directory (both validated, section 3); `bytes` from the file size; `duration_ms` and `frame_count` from a bounded
   walk of its `moof` boxes (sum of `trun` sample durations and counts, a limit of 100,000 fragments and 1 GiB). The file
   must have `ftyp`, `moov` and at least one complete `moof`+`mdat` pair and no trailing partial box; then the row
   is inserted. Otherwise **quarantine**. Adoption is the choice over deleting: the file was fully synced before its
   rename (section 3), so it is real video that only lacks a row. (This settles the "indexed or quarantined" choice of #59.)
5. Both tiers have the file, row says **hot**: if the archive size equals `bytes`, **roll forward**: set `tier = 1`,
   delete the hot file. Otherwise (archive copy wrong): delete the archive file, keep hot.
6. Both tiers have the file, row says **archive**: if the archive size equals `bytes`, delete the hot file. Otherwise
   if the hot size equals `bytes`, roll **back**: set `tier = 0`, delete the archive file. Neither equal: quarantine both,
   delete the row.
7. File on only one tier and the row names the **other** tier: if the size equals `bytes`, set the row to the tier
   where the file is (the file is the truth); otherwise quarantine and delete the row.

The result is a report with counts per category (`part_deleted`, `rolled_forward`, `rolled_back`, `missing`, `adopted`,
`quarantined`, `size_mismatch`, `unknown_left`), logged by tier only, and the post-condition "every row has exactly one
file on its tier and every `.mp4` has a row". Quarantined files stay out of the index, count against the floor and are
the first eviction candidates (section 6). Periodic scrubbing and bit-rot checks are out of scope.

### 10. Worked example with real numbers

Inputs: 5 main streams at the ADR 0002 bitrates (`reolink-1` 2.9, `reolink-2` 2.9, `xr` 4.3, `tapo` 0.19, `hdipc`
8.6 Mbit/s); container overhead 0.53 % (measured above); hot volume 982,240,026,624 B; archive volume
1,998,980,898,816 B (the host values above); min free 25 % on both; headroom 1 pp; `hot_max_age` 12 h; one
segment per camera per minute. Decimal GB (10^9).

**Recording rate.**

| camera | Mbit/s | one 60 s segment | per day |
|---|---|---|---|
| reolink-1 | 2.9 | 21.86 MB | 31.48 GB |
| reolink-2 | 2.9 | 21.86 MB | 31.48 GB |
| xr | 4.3 | 32.42 MB | 46.68 GB |
| tapo | 0.19 | 1.43 MB | 2.06 GB |
| hdipc | 8.6 | 64.84 MB | 93.37 GB |
| **total** | **18.89** | **142.42 MB per minute (5 segments, average 28.48 MB)** | **205.09 GB (191.0 GiB)** |

The tapo figure was measured on a static scene and will rise with motion; hdipc alone is 46 % of the volume.

**Capacity.** Floors: hot `982,240,026,624 x 25 % = 245,560,006,656` B; archive `1,998,980,898,816 x 25 % =
499,745,224,704` B. With the hot volume as measured (629,302,824,960 B available) the headroom above the floor is
383,742,818,304 B, which is 1.87 days of recording; the archive's usable space above its floor is 1,499,235,674,112 B,
**7.31 days**. With `hot_max_age` 12 h the hot tier holds about 102.5 GB (12 h) and never reaches its floor at this
rate, so steady state is: 12 h hot, then archive, and the oldest archive video is deleted once the archive reaches
its floor. The retention a user gets today is therefore about **7.3 days + 12 h, roughly 7.8 days**. If the same
five cameras recorded at twice the rate, the same disks hold about 3.9 days (the planner needs no change, only the
numbers do).

**A floor-driven tick (both volumes at their floors).** Suppose `hot_max_age` is set high, so the hot tier fills
until the floor, and the archive has been at its floor for a while. State at a tick:

- hot: free 245,400,000,000 B = 24.98 % (below 25 % by 160,006,656 B);
- archive: free 499,800,000,000 B = 25.003 % (just above the floor).

1. Hot target = floor + 1 pp = 245,560,006,656 + 9,822,400,266 = **255,382,406,922** B free. Bytes to move out of hot:
   255,382,406,922 - 245,400,000,000 = **9,982,406,922** B, which is about 70 minutes of the 142.42 MB-per-minute
   stream, i.e. about 350 oldest segments (9,982,406,922 / 28.48 MB).
2. Archive after absorbing them: 499,800,000,000 - 9,982,406,922 = 489,817,593,078 B, **below** its floor of
   499,745,224,704. The archive target is floor + 1 pp = 499,745,224,704 + 19,989,808,988 = **519,735,033,692** B, so
   the planner must delete 519,735,033,692 - 489,817,593,078 = **29,917,440,614** B first, which is 0.146 days (3.5 h)
   of the oldest archived video, about 1,050 oldest segments.
3. Plan order: all `Delete` actions for the oldest archive segments, then `MoveToArchive` for the oldest hot segments,
   each move following M1-M9.
4. Execution: at 64 actions per tick and 30 s ticks, this catch-up takes about 22 ticks (1,050 + 350 actions), roughly
   11 minutes. In steady state the loop only handles what was recorded since the last tick: 30 s of recording is 2.5
   segments (71 MB), so one tick is a handful of actions.
5. Copy volume: 9.98 GB moved to the HDD; at the average input of 2.37 MB/s the HDD is idle most of the time. I did not
   measure the HDD's write speed, so the catch-up time above is bounded by the action count, not by the disk.

**Archive missing:** the same hot state with the archive unmounted gives `Delete` of the oldest hot segments totalling
9,982,406,922 B (about 70 minutes of video) and the state `archive_unavailable`; the SSD keeps its floor and
`floor_breaches_total` increases once.

**Segment-rule example (hdipc, GOP 3.5 s):** keyframes fall at multiples of 3.5 s (59.5 s, 63 s), so the first keyframe at or after the
60 s target is at 63 s: the segment closes with 63 s of media time (one file of about 68.1 MB) and the next file starts at
that keyframe. If hdipc
sent no keyframe for 120 s the segment would be closed at 120 s on a delta frame and the frames up to the next keyframe
dropped and counted as a gap.

## Decision

| question | decision |
|---|---|
| muxer | in-house minimal fMP4 box writer in `wardenlens-mp4`, no dependency; `mp4-atom` 0.17.1 is the documented fallback; `mp4` 0.14.0 rejected (no fragmented writer, last release 2023-08-01) |
| segment | target 60 s, cut only at a keyframe, hard maximum 120 s (closed on the frame, resume at next keyframe), first segment at the first keyframe, fragment = one GOP, caps 16 MiB per fragment, 1 GiB per segment, 8 MiB per frame |
| timestamps | index: arrival wall clock UTC ms, `started_at_ms` strictly increasing per camera, `duration_ms` = media duration; file: 90 kHz media time from 0 per file, `dts = max(rtp - rtp0, prev + 1)`, 10 s re-base |
| layout | `<root>/<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4`, UTC, identical relative path on both tiers, `.part` while writing, quarantine under `<root>/quarantine/`; paths derived from validated id and time, **not stored** |
| segment close | write, `fsync(file)`, `rename`, `fsync(dir)`, then `Index::insert` |
| SQLite | `rusqlite` 0.43.0, `default-features = false`, `bundled` (SQLite 3.54.1); WAL, `synchronous = FULL`, `foreign_keys = ON`, `application_id`; synchronous API with `spawn_blocking` callers |
| migrations | in-house ordered scripts, `PRAGMA user_version` in the same transaction; newer version is an error |
| tables | `segments`, `cameras` (no credential, host or name columns, ADR 0006), `api_tokens` (ADR 0004); indexes as in section 5 |
| tier policy | move on hot floor (to floor + 1 pp) or hot age (12 h); evict archive oldest first before a move that would breach its floor; floor wins over video when the archive is unavailable; defaults 25 %, 12 h, 64 actions per tick |
| move protocol | copy to `.part`, fsync, rename, fsync dir, `UPDATE tier` (durable), then unlink hot; delete = unlink then `DELETE` row |
| reconciliation | rules 1-7 of section 9: delete `.part`, adopt orphan files, delete rows without files, roll forward or back by size, quarantine the untrusted, leave unknown files |

## Downstream tickets

This ADR **overrides** ticket text written before it. Where a ticket and this ADR disagree, this ADR wins. I did **not**
edit any ticket; the controller adds an "Amended by ADR 0005" section to each ticket below. Checked against the ticket
bodies read on 2026-11-23.

| ticket | what it must do, and what it overrides |
|---|---|
| #43 (core camera model) | `CameraId` is also the path component (SEC-4) and the `segments.camera_id` value; no change to the type |
| #44 (core planner) | `Policy { hot_min_free, archive_min_free, hot_max_age }` and a fixed 1 pp headroom; actions are moves and deletes in the order of section 6 (archive deletions first, then moves), `now` is an input; hot deletes only when the archive is unavailable (an input `ArchiveState`) or a move is impossible; `PlanError` for the unsatisfiable cases; the unit test reproduces the worked example of section 10 to the byte, plus the proptest |
| #45 (core segmenter, media clock) | the rules of section 2: target 60 s (10-300), hard maximum 2x target closed on the frame, byte and fragment caps, `dts = max(rtp - rtp0, prev + 1)` (clamp, not accumulate), 32-bit unwrap, 10 s re-base; `SegmentRecord { camera, started_at_ms, duration_ms, bytes, frame_count }` (`ended_at_ms` derived); also the pure `RelPath` (`new(&CameraId, started_at_ms)` and a strict `FromStr`) shared by recorder, storage, index and api; tests from the ADR 0002 jitter patterns |
| #46 (Clock) | returns UTC Unix milliseconds (a newtype); the recorder uses it for `started_at_ms` |
| #47 (service config) | keys `storage.hot_root`, `storage.archive_root`, `storage.hot_min_free_percent`, `storage.archive_min_free_percent` (0-90, default 25), `storage.hot_max_age` (default 12 h), `recording.segment_target_secs` (10-300, default 60), `storage.max_actions_per_tick` (default 64); roots must be absolute |
| #49 (index) | **overrides:** no `schema_version` table: `PRAGMA user_version` with in-house scripts; **no `rel_path` column**: `insert(SegmentRecord, tier)` and `set_tier(id, tier)` carry no path; `synchronous = FULL`, `application_id`, `SQLITE_OPEN_NOFOLLOW`; schema and indexes as in section 5; `rusqlite` 0.43.0 `default-features = false`, `bundled`; the `EXPLAIN QUERY PLAN` test asserts the plans of section 5; sync API |
| #50 (cameras table) | columns exactly as in section 5 (ADR 0006 authoritative); no foreign key from `segments`; `remove` leaves segments (orphans by `LEFT JOIN`) |
| #54 (mp4 crate) | in-house writer, no new dependency; the layout of section 3 (`default-base-is-moof`, `tfdt` v1, `trun` flags `0x000701`, sample flags `0x02000000`/`0x01010000`, SPS/PPS only in `avcC`, no composition offsets), fragment per GOP, checked `u32` sizes; golden-structure tests and the `#[ignore]` ffprobe/ffmpeg decode test (frame hashes equal to the source, as in this ADR's prototype); a documented fallback to `mp4-atom` |
| #55, #56 (ingest) | deliver the RTP timestamp, the arrival time from `Clock`, SPS/PPS and a discontinuity flag per frame; #55 verifies on the five main streams that there is no frame reordering (`has_b_frames`/`pic_order_cnt_type`), see open risk 1 |
| #57 (recorder) | layout and close sequence of sections 2 and 3 (`.part` -> fsync -> rename -> fsync dir -> `Index::insert`); `started_at_ms` strictly increasing per camera; a crash leaves at most one `.part` **per camera**; the path is `RelPath`, containment asserted; files `0600`, directories `0700` |
| #58 (storage) | the move sequence M1-M9 of section 7 (hot `unlink` last; `set_tier(id, tier)`); delete = unlink **then** `Index::delete` (overrides "Index::delete and unlinks"); `rustix` for `statvfs`; same-filesystem refusal; archive-unavailable handling; quarantine files evicted first; fault-injection tests at every crash point of the table |
| #59 (reconciliation) | rules 1-7 of section 9 (overrides "indexed with duration read from moof headers or quarantined": **adopt, else quarantine**; `.part` deleted in both roots; roll-forward/back by size); walk depth 4 and an entry cap; report categories as listed; one test per crash row |
| #62 (recordings API) | the path comes from `RelPath::new(camera_id, started_at_ms)` of the row, **not from a stored path** (overrides "root + relative path from the index"); one re-read of the row after `ENOENT`; containment check; range requests |
| #63 (storage endpoint) | adds `archive_unavailable` to the state; `free_percent` is `f_bavail * 100 / f_blocks`; quarantine count |
| #65 (token CLI) | the `api_tokens` DDL of section 5 (migration 3); `last_used_at_ms` nullable; rows never deleted |
| #68 (serve) | order at start-up: take the process lock, open and migrate the index, **run reconciliation**, then start the storage loop and recorders; refuse a second instance |
| #69 (Docker) | volumes for the hot root, the archive root and `/var/lib/wardenlens` (index and vault, which are not on a recordings volume); a C compiler in the build stage for `rusqlite` `bundled`; the archive mount must be a separate filesystem |
| #70 (48 h gate) | the restart and hard-kill checks use the reconciliation report counts of section 9 and expect `quarantined = 0`, `size_mismatch = 0` |
| ADR 0006 / #74 | unchanged: follows `rusqlite` `bundled` (this ADR agrees) and keeps its own file |

## Consequences

- Easier: a crash loses at most the open segment of each camera (up to 120 s) and never the only copy of a finished one;
  recovery is deterministic and rule-based; the index is small, rebuildable from the files and queried with planned
  indexes; no muxer or ORM dependency, only 6 new crates (`rusqlite` set) plus a C compiler in the build.
- Harder / accepted:
  - We own the MP4 box layout (golden tests and ffprobe tests are mandatory) and the migration runner.
  - A hot `.part` is discarded after a crash (up to 120 s per camera); salvage is a follow-up.
  - With the hot directory on the root filesystem, the 25 % hot floor shares the disk with the OS and the index; the
    floor-wins rule (delete oldest hot when the archive is unavailable) can discard unarchived video on purpose.
  - `synchronous = FULL` costs an fsync per commit; at a few commits a second this is negligible.
  - The tier move copies data and waits for an `fsync` on a slow HDD; the 64-action cap and the 30 s tick bound the
    work, but a long copy of a 65 MB segment ties up the loop for its duration.
  - UTC directory names mean a local "day" spans two directories; the API works in timestamps so this is invisible.

## Open risks and follow-ups

1. **B-frames not verified.** v1 writes PTS = DTS. If any main stream has frame reordering, durations and playback
   order are wrong. Check `has_b_frames` (or `pic_order_cnt_type`) on the five main streams while implementing #55.
   If a camera does reorder, switch `trun` to version 1 with composition offsets (a muxer-only change) and teach the
   `MediaClock` the reorder depth. Proposed ticket: "spike: confirm no B-frames on the five main streams" (small,
   needs the owner's LAN).
2. **Tapo and hdipc bitrate in the example** are static-scene or single-sample figures (ADR 0002); real retention
   will vary with motion. The example is arithmetic on measured inputs, not a forecast.
3. **HDD write speed unmeasured**; the 22-tick catch-up bound comes from the action cap. Measure during the 48 h gate (#70).
4. **Salvage of hot `.part` files** (truncate to the last complete fragment, then adopt) would cut crash loss from up to
   120 s to one GOP. Proposed follow-up ticket for Phase 2.
5. **Silent corruption (bit rot) on the HDD** is not detected; a checksum per segment at move time and a scrub are out of
   scope here and are a later ticket.
6. **`mp4-atom` was not prototyped end to end**; the fallback decision rests on its type list and metadata only.
7. **The plan document could not be read**; the volume sizes are the measured ones. If the plan states other sizes or a
   dedicated SSD volume, only the worked example's numbers change.
8. **Clock steps** (NTP) can make `started_at_ms` jump; the strictly-increasing rule keeps names unique, but the index
   may show an overlap or a gap that did not occur in media time.
