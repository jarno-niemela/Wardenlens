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
the move protocol are shared by the recorder, storage, index and mp4 crates and, through core ports only, the api (ADR 0004 section 8, amended in section 11), so they are
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
  982,240,026,624 B total, 629,582,364,672 B available at the time of the final read; `f_bfree` is larger than `f_bavail`
  because ext4 reserves 5 % of the blocks), not on a volume of its own. The archive
  `/srv/wardenlens/archive` is a separate ext4 mount `/dev/sda1` (1,998,980,898,816 B total, 1,998,961,995,776 B
  available, mounted `rw,noatime`; fstab has `nofail`, so it can be absent at boot). I could not open the plan
  document from the sandbox, so the volume sizes are the measured ones, not the plan's nominal "2 TB".
  Consequence: the hot floor also protects the operating system, and an unmounted archive leaves an empty directory on
  the root filesystem (sections 8 and 9).

## Options and decisions

### 1. fMP4 muxer

All three candidates are measured below. What Wardenlens needs is small: one video track, H.264, `ftyp` + `moov`
(with `mvex`/`trex`) once per file and `moof` + `mdat` per fragment (about 25 box types, see section 3). It does not
need a general MP4 reader: the recorder only writes, and the one place that reads a file without a row (the adoption
parser of section 9) is a small, bounded box-header walk that treats the file as **untrusted**, because a file with a
valid name may have been planted or damaged.

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
2. **Target duration 60 s** (bounds 10-290 s, so that twice the target, 580 s, stays below the 600 s `CHECK` on `duration_ms`). A segment is cut at the first keyframe whose media time since the segment
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
  used. `started_at_ms = arrival`, plus 1 ms **repeated until neither a row in the index nor a known file
  (the walk's keys, section 9) has that key** (an exact key collision), which keeps the file name unique (section 3); a forward clock step therefore
  does not compress the index. A health warning is raised when `arrival < previous` (the clock stepped back). At
  start-up the recorder seeds `previous` per camera from `SELECT MAX(started_at_ms) FROM segments WHERE camera_id = ?`
  **and** from the maximum key found by the reconciliation walk (orphan files that were quarantined or left are not in
  the index), so a clock that stepped back across a restart cannot collide with an existing name. A wall clock
  earlier than the year 2000 (946,684,800,000 ms) **or later than the year 2099 (4,102,444,799,999 ms)**, the bounds of
  the column's `CHECK`, **holds off recording** for that camera and raises a health warning, instead of failing inserts. `duration_ms` is the **media** duration (below), converted from 90 kHz ticks
  to milliseconds **rounding up**, minimum 1, and
  `ended_at_ms = started_at_ms + duration_ms`. A gap between two segments is therefore visible as
  `started_next - ended_prev`, and "recorded coverage" (#70) is the sum of `duration_ms`.
- *File (monotonic media time):* timescale **90,000**; each file starts at `tfdt` base media time 0 (each file is
  independently playable and has its own `moov`). The `MediaClock` (#45) turns the RTP timestamp (unwrapped from 32
  bits with a signed wrapping difference, so a wrap every 13.25 h is handled) into
  `dts_i = max(rtp_i - rtp_0, dts_{i-1} + 1)`. It **clamps, it does not accumulate**: a non-monotonic or equal
  timestamp (Tapo, Dahua) becomes one tick after the previous one and the next normal frame is back on the RTP line,
  so the total media time does not drift from the camera's real pacing over thousands of jittery frames. A jump
  of more than **10 s forward** or a step **backward of more than about 1 s** is a re-base: the clock keeps the last
  good duration for that step and continues from the new RTP value (no gap in media time; the wall-clock gap shows in
  the index). A smaller backward step is jitter and is clamped as above.
  `duration_i = dts_{i+1} - dts_i`; the last sample of a segment gets the previous duration (at least 1).
  Durations are clamped to 1..=900,000 ticks.
- *B-frames:* v1 writes no composition offsets (`trun` without `sample_composition_time_offset`, so PTS = DTS). That is
  correct only for streams without frame reordering. ADR 0002 did not record `has_b_frames` for the five cameras and I
  have no camera access here. Its soak measured about 1 non-monotonic DTS warning per 3 frames on Tapo main (8,891
  lines for 26,991 frames), which is what RTP timestamps in decode order look like when frames are reordered, and also
  what plain timestamp jitter looks like; the two cannot be told apart from that data. This is **an open risk** (see
  "Open risks"): the #55 reordering check (`has_b_frames` / `pic_order_cnt_type` on the five main streams) **blocks
  both the #45 `MediaClock` and #57**; neither is trusted before it passes.

### 3. On-disk layout, naming and the segment file

```
<root>/<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4          finished segment
<root>/<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4.part     being written (or an interrupted one)
<root>/_quarantine/<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4   files reconciliation could not trust (section 9)
```

`<root>` is the hot root (`/srv/wardenlens/recordings`) or the archive root (`/srv/wardenlens/archive`). The relative
path `<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4` is **the same on both tiers**, so a move never changes it. Date and
time are **UTC** from `started_at_ms` (a local-time directory would change meaning at a DST step); `<mmm>` is the
milliseconds. A day directory holds at most about 1,440 files per camera (86,400 s / 60 s). The deepest file is at depth
4 below a root (`_quarantine/<camera>/<day>/<file>`), which is the bound the reconciliation walk uses. The name `_quarantine`
begins with an underscore, so no `CameraId` (it must start with a letter) can ever produce it.

**Paths are derived, never stored, never taken from a camera (SEC-4).** There is **no `rel_path` column** (this overrides
#49 and #62): the path is a pure function `RelPath::new(&CameraId, started_at_ms)` in core. `CameraId` is the validated
slug of #43 (`[a-z0-9-]{1,32}`, starting with a letter), the time is an integer bounded to years 2000-2099, so the
result can contain no `..`, separator or other character than the pattern allows. A tampered or corrupt index row
therefore cannot name an arbitrary path: `camera_id` is re-parsed with `FromStr` when a row is read and a bad value is a
typed error. File names found on disk are accepted only if they match
`^[0-9]{6}-[0-9]{3}\.mp4(\.part)?$` under a directory `<camera_id>/<YYYY-MM-DD>` that parses, and the time must agree
with the directory date. The match is **canonical**: the name is parsed (HH at most 23, MM and SS at most 59, a real
calendar date) and must **round-trip**, `RelPath::new(parse(name)) == name`; a name that matches the pattern but is not
canonical (`996099-000.mp4`) is `unknown_left`, never adopted or deleted. **Opening a file (SEC-4):** the **hot** root
is opened once as a directory handle at start-up; the **archive** handle always comes from the **latest probe**
(section 8), never from start-up. Every file is opened **relative to its root handle** with `openat2` and
`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` (rustix, safe Rust), so `..`, absolute paths and any symlink component are
refused by the kernel; **every open of a file that may be planted by someone else (M1, adoption, the `SegmentFiles`
open) adds `O_NONBLOCK`** (or `O_PATH` followed by `fstat` and a re-open of a regular file), so a FIFO or device node
planted at a segment name cannot block the storage loop or a request; the open handle is then `fstat`ed (regular file
only; its size is what the caller uses). This replaces "canonicalise and check containment" of #58/#62 (a
check-then-open race). Writers create files the same way with `O_CREAT|O_EXCL|O_NOFOLLOW` (an existing name, including
a planted symlink, is an error), mode `0600`, directories `0700`. The walker uses `lstat`, never follows symlinks and
treats anything that is not a regular file or directory as `unknown_left`.

**Segment file** (what `wardenlens-mp4` writes, from the prototype; all integers big-endian):

```
ftyp  major isom, minor 512, compatible isom iso5 iso6 avc1 mp41
moov  mvhd (timescale 90000, duration 0)
      trak: tkhd (flags 3, width/height from the SPS), mdia: mdhd (90000), hdlr "vide",
            minf: vmhd, dinf/dref/url (self-contained), stbl: stsd -> avc1 + avcC (SPS and PPS only here),
                  empty stts, stsc, stsz, stco
      mvex: mehd (version 1, fragment duration), trex (track 1, default sample description 1)
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
`ftyp`+`moov` (with `mvhd.duration` and `mehd.fragment_duration` still 0), then each fragment with plain `write(2)` (no
fsync per fragment). On close: (1) write the last fragment, (2) **patch the total duration** into `mvhd` and `mehd` with
`pwrite` at their known offsets, so that a browser or player that reads only `moov` can show a length and seek (the
durations are in 90 kHz ticks and fit the 32-bit `mvhd` field: 13.25 h is far above 580 s), (3) `fsync(file)`, (4) `renameat2`
`.part` to `.mp4` (`RENAME_NOREPLACE`), (5) `fsync` the directory, (6) only then `Index::insert`. If the insert fails for
any reason, the recorder first **retries transient errors** (`SQLITE_BUSY`, I/O errors) a bounded number of times
(default 5, with a short back-off) and **quarantines** the file (section 9) only on a constraint violation or a
permanent error, never in an unbounded loop. The order makes a visible
`.mp4` always complete, and an indexed row always point at a complete, durable file. A crash before step 2 leaves a
`.part` with duration 0, which is deleted anyway. When a day directory (or camera directory) is created, its parent is fsynced as well. A graceful stop
runs steps 1-6 for the open segment. ENOSPC aborts the segment: the `.part` is unlinked and the recorder waits for the
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
its `-wal` and `-shm` files, **separate from the vault file** (ADR 0006). It is created and opened with the **secure open helper of `wardenlens-fsutil`**, the one ADR 0006 section 4 describes and that the vault also uses (section 11): mode `0600` created before
SQLite opens it, our own `O_NOFOLLOW` descriptor with `fstat`, SQLite opened by path with `SQLITE_OPEN_NOFOLLOW`, and
the device and inode compared; a symlink or a wrong owner is refused. Pragmas on every connection: `journal_mode = WAL`,
`synchronous = FULL`, `foreign_keys = ON`, `busy_timeout = 5000`, `journal_size_limit = 67108864`. `synchronous = FULL`
(not `NORMAL`) is required by the tier protocol: step M8 must be durable before the hot file is unlinked
(section 7); the cost is irrelevant at this write rate. `application_id = 0x574C4958` (`WLIX`) is set at creation and
checked on open, so a foreign SQLite file is refused. One writer and the rest readers (WAL): the cli keeps one write
connection and a small number of read connections.

**Sidecars and identity (#49 round 2, defect pattern P3).** SQLite replays a hot `-journal` and a `-wal` on the first
read and checkpoints when the last connection closes, so **no read-write connection is opened on `index.db` until its
identity and every sidecar are proven by means no sidecar can influence**: the parent directory is ours and not group- or
world-writable (`fsutil::check_parent`, shared with the vault); each `-wal`, `-shm` and `-journal` is `lstat`ed and must
be a regular file owned by the service user with no group or other bit; the 100-byte header is read through our own
descriptor (magic, `application_id`, journal mode); the settled state (`application_id`, `user_version`, exactly the
`sqlite_master` objects of that version, `quick_check`) is judged read-only, by an `immutable=1` open when there is no
`-wal`, and otherwise on a **private copy** of the main file and the `-wal` in a `0700` scratch directory (the vault's
rolled-back-copy technique, helpers in `fsutil`). Rules by sidecar: a `-journal` is refused in every state, because an
index in WAL mode never writes one and a rollback-mode index exists only during creation, before any row (a non-empty one
is `PendingJournal`, an empty one `StraySidecar`; **deleting it is safe**, and the index is recreated or adopted again);
a `-wal` or `-shm` next to a rollback-mode or empty file is refused; a `-wal` must have a WAL header of the main file's page
size and must replay, on the copy, to a database that is still ours (`ForeignWal` otherwise). A `-wal` copied from another
copy of this index by the same user is accepted: that needs the privileges to edit the index itself. A too-new
`user_version` is refused from the same read-only view, so the file and its sidecars stay byte-identical. The creation-window
`-journal` is **not** identified on a private copy: refusing it with a remedy that loses nothing is simpler and safe.

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
  id            INTEGER PRIMARY KEY AUTOINCREMENT,   -- the id the API exposes; never reused after a delete
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
a segment whose camera is gone is an orphan found with a `LEFT JOIN`, not a column. `AUTOINCREMENT` makes an id
unique over the life of the file (a plain rowid could be reused after the newest row is deleted, and a client holding
an old id would then download another segment).

Queries (every one parameterised, no SQL built from data; `EXPLAIN QUERY PLAN` observed in the probe):

- `list(camera, from, to, limit <= 1000, cursor)`:
  `WHERE camera_id = ?1 AND started_at_ms >= ?2 - 600000 AND started_at_ms < ?3 AND ended_at_ms > ?2 AND (started_at_ms,
  id) > (?4, ?5) ORDER BY started_at_ms, id LIMIT ?6`. Plan: `SEARCH segments USING INDEX segments_camera_start
  (camera_id=? AND started_at_ms>? AND started_at_ms<?)`, no sort. The 600,000 ms look-back is the column's
  `CHECK` bound on duration (the real maximum is 120 s), so the overlap test is exact. The cursor is the last row's
  `(started_at_ms, id)`, stable under inserts and deletes. A listing across cameras would need a second index
  `(started_at_ms, id)`, added when the API needs it.
- `oldest(tier, after, n)`: `WHERE tier = ?1 AND (ended_at_ms, id) > (?2, ?3) ORDER BY ended_at_ms, id LIMIT ?4`: a keyset
  continuation (`after` is the `(ended_at, id)` of the last row of the previous page), so a caller pages through a whole
  tier. `n` is bounded by a memory limit (`MAX_OLDEST` = 10,000 rows), not by a number of cameras. Plan: `SEARCH ... USING
  INDEX segments_tier_end (tier=? AND ended_at_ms>?)`, no temporary sort.
- `bytes_by_tier()`: `SELECT tier, SUM(bytes), COUNT(*), MIN(bytes), MAX(bytes) FROM segments GROUP BY tier` (each `bytes` is 1 to
  `MAX_SEGMENT_BYTES` = 64 GiB, checked on insert and on read, so the sum cannot overflow below 2^27 rows). Plan: `SCAN ... USING COVERING
  INDEX segments_tier_end`. Rows stay bounded by disk size (about 56,000 for the 7.8 days in section 10).
- `set_tier(id, tier)`: `UPDATE segments SET tier = ?2 WHERE id = ?1 AND tier = ?3`, which must change exactly one row.
  It takes **no path** (this overrides #49's `set_tier(id, tier, rel_path)`).
- `insert(SegmentRecord, tier)` takes no path either; `delete(id)`.

**`cameras`** (ADR 0006 is authoritative; migration 2, ticket #50): `id TEXT PRIMARY KEY` (a `CameraId`, length
check), `model TEXT NOT NULL CHECK (length(model) BETWEEN 1 AND 64)` (catalogue reference), `rtsp_port INTEGER NOT NULL CHECK (rtsp_port BETWEEN 1 AND 65535)`,
`main_path TEXT NOT NULL CHECK (length(main_path) BETWEEN 1 AND 512)`, `sub_path TEXT CHECK (sub_path IS NULL OR length(sub_path) BETWEEN 1 AND 512)`, `created_at_ms INTEGER NOT NULL`, `updated_at_ms INTEGER NOT NULL`, `STRICT`.
**No** credential, host, display-name or other site-identifying column; those are vault entries `cam:<id>:...`. Because a
vendor RTSP path can carry credentials in the query string, #50 **rejects** a `main_path` or `sub_path` that contains `@`, or
whose query string has a parameter named (case-insensitive) `pass`, `password`, `pwd`, `user`, `usr`, `token`, `auth`,
`key` or `secret`, **or any query string at all that the catalogue does not allow for that camera model** (an
allow-list, so a vendor parameter such as a channel or stream number passes only if the catalogue entry lists it), at
the parse step and again as a typed error when a row is read.

**`api_tokens`** (ADR 0004 section 9; migration 3, ticket #65): `id TEXT NOT NULL UNIQUE CHECK (length(id) = 8)` (8
characters of lowercase base32), `digest BLOB NOT NULL CHECK (length(digest) = 32)` (SHA-256 of the decoded secret),
`name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64)`, `created_at_ms INTEGER NOT NULL`, `last_used_at_ms INTEGER` (nullable; written at most once a
minute per token), `revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))`, `STRICT`. The `id` is the primary
lookup key, so the unique constraint creates its index. Rows are never deleted (revoked ids are never reused).
No roles in v1. The table holds hashes only, so it needs no ADR 0006 encryption.

The index holds nothing that cannot be rebuilt except `cameras` (re-importable) and `api_tokens`; `segments` can be
rebuilt from the files by the adoption rule of section 9.

### 6. When to move, what to evict (policy; the pure planner is #44)

Terms. For a volume, `statvfs` (through the `rustix` safe wrapper, #58, checked arithmetic) gives `f_blocks`, `f_bfree`,
`f_bavail`, `f_frsize`. The floor arithmetic uses **available space**, not the raw total: ext4 reserves 5 % of blocks
for root, which an unprivileged writer can never use, so `free = f_bavail * f_frsize` and
`capacity = (f_blocks - f_bfree + f_bavail) * f_frsize` (used space plus available space, the space the service can
ever occupy). `free_percent = free * 100 / capacity`. The **floor** is `min_free_percent` (0-90, default 25) per volume,
a free amount of `capacity * floor`. The **headroom** is a fixed 1 percentage point of `capacity`: a volume that dips
below its floor is brought back to `floor + headroom`, not just to the floor, so the loop does not move one segment per
tick. On the hot volume 1 % is 9.3 GB, about 65 minutes of all five cameras, against 71 MB written per 30 s tick.

**A volume with `capacity == 0`, or whose arithmetic overflows (checked arithmetic, SEC-3), is *unusable*, never a
division:** an unusable archive is unavailable (section 8, with the cause `unusable`); an unusable hot root refuses to
start.

**Hot to archive happens when either holds** (and the archive is available, section 8):

1. *Hot floor:* `hot.free < hot.capacity * floor`. Move the oldest hot segments (by `ended_at_ms`, then `id`, across all
   cameras) until `hot.free >= hot.capacity * (floor + 1 pp)`, **regardless of age**.
2. *Hot max age:* any hot segment with `ended_at_ms < now - hot_max_age` (default **12 h**, config
   `storage.hot_max_age`) is moved, oldest first, also without pressure. It keeps the SSD as a recent-video cache and
   lets the HDD spin up in bounded work rather than in bursts. `hot_max_age` never deletes anything.

**Archive eviction (frees the HDD) happens when** `archive.free < archive.capacity * floor`, **or** when a planned move
would leave `archive.free - move_bytes < archive.capacity * floor`. Before such a move the planner deletes the oldest
archive segments until `archive.free - move_bytes >= archive.capacity * (floor + 1 pp)`; deletions are planned
**before** the move that needs the room (#44).

**Eviction order**, always oldest first by `ended_at_ms`, ties by `id`, across cameras (every camera keeps the same
depth of history; Phase 2 adds retention by event and age):

1. Quarantined files of that volume (section 9), oldest first by the time in the name. They are not in the index and
   not in the pure plan: the executor deletes them first whenever a volume is below its floor.
2. Archive segments.
3. Hot segments, **only** as a last resort (below).

**Both volumes full or the archive unavailable (order of precedence):**

1. Hot below floor, archive available and can absorb after evicting: evict archive (oldest), then move. Net archive
   space is conserved: every moved byte displaces an older archived byte.
2. Archive **unavailable** (the definition is in section 8: missing, same filesystem, read-only, unmarked or failing):
   the plan becomes `Delete` of the oldest hot segments until the hot floor plus headroom holds. **The floor wins over
   keeping video**, because the hot directory is on the root filesystem and an NVR that fills `/` takes the host down.
   The state `archive_unavailable` is exposed and `floor_breaches_total` is increased (#63); the log names the volume
   by tier only. Archive rows and files are **not touched** while the archive is unavailable.
3. The archive is **available but cannot absorb the moves even after evicting all of its segments** (for example
   `archive.capacity * (1 - floor) < segment.bytes`, or the needed bytes exceed everything the archive could free):
   the planner behaves as in case 2 (`Delete` of the oldest hot segments to hold the hot floor), never plans an
   impossible move, never panics, and reports the state **`archive_full`** (exposed with `archive_unavailable`, #63).
4. Even deleting every segment cannot restore a floor (something else fills the volume): `PlanError::Unsatisfiable`,
   and the planner **returns it without planning any hot deletion**: deleting video that cannot restore the floor
   only loses recordings. It first checks whether `hot.free + sum(deletable hot bytes) >= target`; if not, it plans
   nothing. The recorder keeps retrying on ENOSPC (#57) and the storage endpoint reports `below_floor`. Recording does not stop
   by itself for a floor breach; it stops only when the OS refuses the write.

Bounds: one tick executes at most `max_actions_per_tick` (default **64**) actions; it re-probes after each one. The
tick interval is 30 s (#68). Catch-up after downtime takes several ticks (see the example), which is acceptable
because writing continues meanwhile.

### 7. Crash-safe tier move

Only the storage loop moves or deletes segments and changes `tier` (a single task, enforced by one process holding an
exclusive lock on `/var/lib/wardenlens/wardenlens.lock`, #68); the recorder only adds hot files and rows. All paths are
opened relative to a root directory handle with `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` (rustix, section 3).
**Directory operations** (`renameat2`, `unlinkat`, `mkdirat`) act on a **parent directory descriptor** that was itself
opened with `openat2` (`O_DIRECTORY`, `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) and take a **single-component** name
(no `/`), so no path is ever re-resolved between a check and the operation. The archive handle is the one from the
latest successful probe (section 8), never one cached from start-up.

**Move of segment S (row `id`, path `R`) from hot to archive**; `A` is the archive root, `H` the hot root:

| step | action | durable effect |
|---|---|---|
| M1 | open `H/R` **once** with `openat2` (read-only, `BENEATH`, `NO_SYMLINKS`) and `fstat` the **handle**: regular file, size equals the row's `bytes`. M4 copies from this same descriptor, so the file checked is the file copied. A non-ENOENT open error (EIO, EACCES, ...) skips the segment and marks it `unverified` (no conclusion).  **In both bad-hot branches** (a **missing** hot file, ENOENT only, or a **wrong-size** or non-regular one) the mover evaluates `A/R` (with the same `O_NONBLOCK` open) and acts **exactly as the section 9 cell** for row = hot and that H, A: (hot, none, none) delete the row (`missing`); (hot, none, valid) fsync `A/R` and its directory, then `set_tier(archive)`; (hot, none, invalid) quarantine A and delete the row; (hot, invalid, none) quarantine H and delete the row (`size_mismatch`); (hot, invalid, valid) fsync A, `set_tier(archive)`, quarantine H; (hot, invalid, invalid) quarantine both and delete the row. A **non-ENOENT error** on `A/R` makes S `unverified` and **never drops the row**. Either way the mover skips S and goes on with the next segment, so one bad segment never stalls the loop | none |
| M2 | create the archive directory chain; fsync each parent of a directory this step created | directories |
| M3 | unlink a stale `A/R.part` if one exists (only the mover writes archive `.part` files), then create `A/R.part` with `O_CREAT`, `O_EXCL`, `O_NOFOLLOW` | an empty `.part` |
| M4 | copy from the M1 descriptor to `A/R.part` in 1 MiB chunks; the copied length must equal `bytes` | a `.part` |
| M5 | `fsync(A/R.part)` | the data is durable |
| M6 | `renameat2(A/R.part, A/R, RENAME_NOREPLACE)` (rustix; atomic, one filesystem; an existing `A/R` is an error, never silently replaced) | `A/R` appears complete, because M5 came first |
| M7 | fsync the archive directory that contains `R` | the rename is durable |
| M8 | `UPDATE segments SET tier = 1 WHERE id = ? AND tier = 0`, exactly one row (WAL, `synchronous = FULL`: committed and durable on return) | **the commit point** |
| M9 | `unlink(H/R)` (`ENOENT` is fine), then fsync `H`'s directory (best effort: correctness does not depend on it) | the hot copy is gone |

**Which errors blame the archive.** Only **archive-side** errors count as a **move failure**: M2 (directory creation on
`A`), M3 (creating `A/R.part`), the **write half** of M4 (a `write`, `ENOSPC` or `EIO` on the archive file), and M5-M7
(`fsync`, `renameat2`, directory fsync on `A`). Three consecutive move failures make the archive unavailable (section 8);
a successful move resets the count. Everything else is **not** the archive's fault and must not flap its availability
(which would delete hot video needlessly):

- a **read error on the source** (EIO reading `H/R` in M4): quarantine that hot segment (and drop its row, as in M1)
  and continue;
- an **index error** (M8, or reading the row): skip the segment for this tick; after 3 consecutive ticks with index
  errors raise a health error (the index is the problem, not the archive);
- **`EEXIST` at M6** (`RENAME_NOREPLACE` found an `A/R`): if `A/R` has the row's size, **roll forward** (it is a
  stale complete copy from an earlier attempt: fsync it and its directory, delete `A/R.part`, continue with M8);
  otherwise quarantine the stale `A/R` and retry M6 once.

The mover **never retries the same failed segment within a tick** and runs the rest of the plan. Required #58 tests:
an M4 **read** failure leaves the archive available and deletes no hot video; a stale complete `A/R` at M6 is rolled
forward.

**Durability before the only copy.** Before any index write that makes one copy the only one, the surviving copy and
its directory are fsynced: the roll-forward cells of section 9 (fsync `A` and its directory, then `set_tier`, then
delete `H`), the M1 runtime rule (a valid `A/R` becomes the row's tier only after `A/R` and its directory are fsynced),
and adoption (the adopted file and its directory are fsynced before the row is inserted and any twin is deleted).

**Crash points** (state = what exists after the power cut or `kill -9`; "recovers" = the cell of the section 9 decision
table that matches, `H`, `A` = hot and archive file, `R` = row; a `.part` is handled first by the `.part` rule):

| crash after | files | row | recovery |
|---|---|---|---|
| before M3 | hot file | hot | consistent (H valid, A none, R hot) |
| during M3 / M4, before M5 | hot, plus an absent, empty or partial `A/R.part` | hot | the `.part` rule deletes it; consistent as above; the next tick moves again |
| after M5, before M6 | hot + complete `A/R.part` | hot | same (the `.part` is deleted and copied again; correct, merely wasteful) |
| after M6, before M7 | hot + `A/R` (it may or may not survive a power cut, but if present it is complete) | hot | present: H valid, A valid, R hot: roll **forward** (set `tier = 1`, delete hot). Absent: consistent |
| after M7, before M8 | hot + `A/R` | hot | H valid, A valid, R hot: roll forward |
| during M8 | WAL commit is atomic: either the row is still hot (as above) or archive (next line) | either | as the matching line |
| after M8, before M9 | hot + `A/R` | archive | H valid, A valid, R archive: delete the hot file |
| after M9 | `A/R` | archive | consistent (H none, A valid, R archive) |

At every crash point at least one complete copy exists and the row points at a tier where a complete copy exists:
before M8 the row says hot and the hot file is untouched; after M8 the row says archive and `A/R` was made durable at
M7, which came first. Unlinking the hot file is the **last** step, so no crash can lose the only copy.

**Delete (eviction) of segment S:** unlink the hot copy, then the archive copy (when each exists and, for the archive,
when it is available), **fsync each parent directory after its unlink and before the `DELETE`** (so a power cut cannot
bring the file back after the row is gone), then `DELETE FROM segments WHERE id = ?`. A crash in between leaves a row without a file or a
row whose other copy still exists, which the decision table handles (H none, A none, R present: delete the row; H none,
A valid, R archive: consistent, evicted again later). The opposite order would leave a file without a row, and the table
would adopt it again: an evicted segment would come back. (This **overrides** #58's "runs `Index::delete` and unlinks".)

**Readers during a move** are the behaviour of **storage's `SegmentFiles` implementation** (section 11), which the API
reaches only through the core port (#62). `open_segment(id)` reads the row, derives the path from it, and opens the file
for the row's tier through `RootDir` (the hot handle, or the archive handle of the latest successful probe), with
`O_NONBLOCK` and `fstat` (section 3). If the open returns `ENOENT` (the move finished between the row read and the
open) it **re-reads the row once** and, if the tier changed, opens the other tier; otherwise it fails. It returns
**typed errors**: not found (no row, or no file on the tier the row names after the re-read), archive unavailable
(the row says archive and the state is unavailable), and I/O. A download that already holds the file open keeps it
through the unlink (POSIX semantics; #62 tests it).

### 8. Volume safety and the archive state

**Hot root.** A missing, non-directory, unwritable or otherwise unusable **hot** root (or an index that cannot be
opened) is the only volume problem that makes `wardenlens serve` refuse to start.

**Archive state (`ArchiveState`) has one definition, used at boot and at every tick.** The archive is **unavailable**
when any of these holds, and **available** otherwise:

1. the archive root is missing or not a directory (the fresh `O_DIRECTORY | O_NOFOLLOW` open below fails);
2. it is on the same filesystem as the hot root (same `st_dev`; this also catches an unmounted HDD: with `nofail` in
   fstab the mount point is then a plain, empty directory on the root filesystem, and writing to it would fill the
   SSD). An explicit test switch allows it in tests (#58);
3. `statvfs` reports `ST_RDONLY` (ext4 `errors=remount-ro` after an I/O error, a read-only mount);
4. the marker file `<archive>/.wardenlens-archive` is missing. The operator creates it once on the mounted archive
   (`wardenlens storage mark-archive`, #64/#68). It is what tells our archive from an empty replacement disk or a stale
   mount point;
5. three consecutive **archive-side** move failures (section 7; source read errors, index errors and an `EEXIST` at M6
   do not count), cleared by the next probe that can create, fsync and remove a small `<archive>/.wl-probe` file; a
   stale `.wl-probe` left by a crash is unlinked first (`ENOENT` accepted).

**Every probe opens a fresh handle.** A directory handle opened at start-up keeps pointing at the empty directory that
a later mount **covers**, so a path probe would say "available" while every `fstat` through the old handle still sees
the root filesystem and moves would land on the SSD. Therefore each probe opens the archive root again with
`O_DIRECTORY | O_NOFOLLOW` and runs **all** checks on that new handle: `fstat` for `st_dev` (check 2), `fstatvfs` for
`ST_RDONLY` (check 3) and the marker through `openat` (check 4). The mover, the reconciliation pass and storage's `SegmentFiles` implementation (the API
never holds a handle) use **only the handle from the latest successful probe**, swapped (the old one closed) when the pair `(st_dev, st_ino)`
changes; an operation holds its handle for its own duration, so a swap never changes the target in the middle of
one. A failed probe leaves the state unavailable and keeps no handle. In the container (#69) the archive bind mount
uses `rslave` propagation so a later host mount becomes visible, or the container is started after the archive is
mounted (documented). Required test (#58/#59): start with the archive unmounted, mount it while the service runs;
every archive row is kept and moves land on the HDD, not on the covered directory.

Checks 1-4 cost an `open`, an `fstat`, an `fstatvfs` and an `openat` and are **re-probed every tick**, so the state
recovers by itself when the disk comes back. **One boot behaviour for every unavailable case:** the service starts, the recorder and the
storage loop run in `archive_unavailable` mode (section 6, case 2: delete the oldest hot segments to hold the floor),
the state is reported (`/api/v1/storage`, #63) and logged by tier only. It does not refuse to start and it does not
stop recording. When the state changes from unavailable to available, the storage loop first runs the
"archive returned" pass (section 9, which has a strictly limited scope) and only then plans moves. Index and vault live
under `/var/lib/wardenlens`, not on a recordings volume.

### 9. Reconciliation after a crash or restart

**Order at start-up (#68):** take the process lock, open and migrate the index, **probe both volumes (section 8)**, run
this reconciliation, then start the storage loop and the recorders. The probe comes first because reconciliation must
know whether the archive can be seen at all: an unmounted HDD looks exactly like an archive with no files, and
concluding "the file is gone" from it would delete about 7 days of index. **When the archive is unavailable,
reconciliation never concludes anything from an absent archive file**: it keeps every archive row and every archive
file untouched, evaluates only what the hot root shows, and reports `archive_unavailable` plus the number of
`unverified` rows.

**Walk.** It walks both roots to depth 4, never follows symlinks (`lstat`; anything that is not a regular file or
directory is reported as `unknown_left` and left, and the key it would belong to is skipped), and treats only paths that
match the section 3 patterns as ours. **Anything else is left in place and reported** (it may be the owner's). The
walk is bounded in entries (default 5,000,000); **when the cap is exceeded at start-up the service starts anyway**: it stops walking, reports the affected tier as
`unverified`, raises a health error and concludes nothing from the part it did not see (SEC-2). Reports contain
**counts and the tier only, never a file name or a path** (the names carry camera ids and times).

**`.part` files first.** `*.mp4.part` in the hot root: **delete** (an interrupted segment, at most one per camera per
crash, at most about 120 s each). In the archive root: delete (an interrupted move), only when the archive is
available. (`.part` files are incomplete temporary files, not invalid segments, which is why they are deleted and
invalid `.mp4` files are quarantined.) v1 does not salvage a hot `.part` (the fMP4 structure would allow truncating to the last complete
`moof`+`mdat` pair; see follow-ups).

**Then per key.** A **key** is `(camera_id, started_at_ms)`: the path of a file and the unique columns of a row. For each
key the reconciliation looks at the hot file `H`, the archive file `A` and the row `R` **together** and applies exactly
one cell of the table. This replaces a rule list: no combination is undefined and a rule cannot be unreachable behind
another. Definitions:

- *none*: the lookup failed with **ENOENT and nothing else**. Any other error (EIO, EACCES, ELOOP, ENOTDIR, ...) makes
  the key, or the whole directory if the listing failed, **unverified**: no conclusion is drawn, the row and the
  files stay as they are, and it is counted as `unverified`. *valid*: a regular file; if a row exists its size equals the row's `bytes`; if there is
  no row, it passes the adoption parser below. *invalid*: a regular file that is not valid.
  **An invalid file is never deleted**: it is always quarantined, even when a valid twin exists, so nothing that
  could be evidence of corruption or a real recording is destroyed silently. Only a *valid* duplicate (a copy whose
  twin is valid and whose row says the file lives elsewhere) and `.part` files are deleted.
- *keep row* means the row, **and therefore its `id`, is unchanged**. An id is never reassigned while a row exists, and
  a deleted row's id is never reused (`AUTOINCREMENT`, section 5).
- *quarantine X*: `renameat2` with `RENAME_NOREPLACE` into `<its root>/_quarantine/<camera>/<day>/<name>` (the same
  relative path, same filesystem). If the target exists (`EEXIST`), the name gets a numeric suffix, `<name>.1`,
  `<name>.2`, and so on, up to a bound of 1,000; **when the bound is exhausted the file is left in place and counted `unverified`: nothing is
  overwritten and nothing loops**; the quarantine evictor (section 6) accepts these names, and the walk
  treats `_quarantine` contents as ours only when they match `<name>(\.[0-9]+)?`. The `_quarantine` directory name can never equal a `CameraId` (a camera id must start with a letter), so
  it cannot collide with a camera directory.
- *adopt X as tier T*: insert a row from the file (below) with `tier = T`.

(Every roll-forward, adoption and "file is the truth" cell follows the durability rule of section 7: fsync the surviving file and its directory **before** the row changes or a twin is deleted.)

**Archive available.** 26 cells are listed; the 27th, (none, none, none), is the implicit "no key, nothing to do".
(`-` = nothing to do.)

| row | H | A | action |
|---|---|---|---|
| none | none | valid | adopt A as archive |
| none | none | invalid | quarantine A |
| none | valid | none | adopt H as hot (a crash between the recorder's rename and `Index::insert`) |
| none | valid | valid | adopt A as archive; delete H **only when H and A have equal sizes**, otherwise quarantine H |
| none | valid | invalid | adopt H as hot, quarantine A |
| none | invalid | none | quarantine H |
| none | invalid | valid | adopt A as archive, quarantine H |
| none | invalid | invalid | quarantine H and A |
| hot | none | none | delete the row, count `missing` |
| hot | none | valid | set `tier = archive` (the file is the truth) |
| hot | none | invalid | quarantine A, delete the row |
| hot | valid | none | - (consistent) |
| hot | valid | valid | roll **forward**: set `tier = archive`, delete H (crash after M6, M7 or before M8) |
| hot | valid | invalid | quarantine A, keep H |
| hot | invalid | none | quarantine H, delete the row |
| hot | invalid | valid | set `tier = archive`, quarantine H |
| hot | invalid | invalid | quarantine H and A, delete the row |
| archive | none | none | delete the row, count `missing` |
| archive | none | valid | - (consistent) |
| archive | none | invalid | quarantine A, delete the row |
| archive | valid | none | set `tier = hot` (the file is the truth) |
| archive | valid | valid | delete H (crash after M8, before M9) |
| archive | valid | invalid | roll **back**: set `tier = hot`, quarantine A |
| archive | invalid | none | quarantine H, delete the row |
| archive | invalid | valid | quarantine H, keep the row |
| archive | invalid | invalid | quarantine H and A, delete the row |

**Archive unavailable.** The archive is not observable, so `A` is *unknown*, not *none*, and nothing is concluded from
it. Every archive row is kept; archive files are not touched.

| row | H | action |
|---|---|---|
| none | none | - (no key) |
| none | valid | adopt H as hot (if an archive twin exists, the "archive returned" pass resolves it by the table above) |
| none | invalid | quarantine H |
| hot | none | keep the row, count `unverified` (the archive may hold the file; the "archive returned" pass decides) |
| hot | valid | - (consistent) |
| hot | invalid | quarantine H, keep the row, count `unverified` |
| archive | none | keep the row, count `unverified` |
| archive | valid | keep the row and H (the archive copy is unverified, so H is not deleted) |
| archive | invalid | quarantine H, keep the row, count `unverified` |

**The "archive returned" pass** (runtime, after the archive changes from unavailable to available, with a fresh handle,
section 8). The recorders are running, so this pass has a **strictly limited scope**: it evaluates only keys that have
an archive file, a `tier = archive` row, or a `tier = hot` row **whose hot file is missing**, using the "archive
available" table. It applies only the **archive** `.part` rule. For a key **without a row** it adopts the archive file and **never touches H** (a hot file there may be in the recorder's rename-to-insert window; the equal-size delete and the quarantine of H in the (none, valid, valid) cell apply at start-up only). It **never** touches a hot `.part` file (it may be a
segment the recorder is writing right now), and it **never adopts a hot-only key** (a hot `.mp4` without a row may be
in the recorder's rename-to-insert window); those two rules run only at start-up, before the recorders start. It runs
**on the storage-loop task, serialised with the mover**, so no move is in flight. Required test (#58/#59): the pass
runs while a recorder is mid-segment and mid-rename, and no hot file or hot row is affected.

**Checked against the move crash table (section 7):** every crash row maps to one cell: before M3 and the `.part`
rows to (hot, valid, none); after M6 and M7 to (hot, valid, valid) or (hot, valid, none); after M8 to (archive, valid,
valid); after M9 to (archive, none, valid). The delete protocol's crash leaves (hot or archive, none, none), (archive,
none, valid) or the same with the archive unknown. The recorder's crash between rename and insert is (none, valid,
none). A move that was interrupted while the archive was unmounted is only ever (hot, valid, none) in the unavailable
table. Invalid files never appear in the crash table (every crash row leaves a valid file or none), so the
"always quarantine" rule changes no crash recovery; it only governs corruption found by the walk.

**Adoption parser (untrusted input).** A file without a row is not trusted: it may be a tampered or foreign file with
a valid name. `started_at_ms` comes from the directory date and file name and `camera_id` from the directory (both
validated, section 3); `bytes` from the file size; `duration_ms` and `frame_count` from a bounded walk of the boxes
(`core::mp4box`, section 11): a **header-at-a-time** walk, never a whole-file slice. **Storage does the reads** (it owns
the `Read + Seek` over the file opened as in section 3); the walk reads one box header at a time, **skips `mdat`
payloads by seeking**, and reads a `moov` or `moof` payload only if it is at most **1 MiB** (larger is rejected). It
must reject, with typed errors and no panic: a box size of 0 or below 8; a `largesize` (size field 1) beyond the
file or the parent (or reject `largesize` altogether: our writer never produces it); a child that does not lie inside
its parent; a trailing partial box; `sample_count * entry_size` greater than the box payload (checked before any
allocation and before iterating); more than 100,000 fragments or more than 1 GiB; and every sum is a checked `u64`.
The file must have `ftyp`, `moov` and at least one complete `moof`+`mdat` pair. The duration is the sum of `trun`
sample durations in ticks, converted to ms **rounding up**, minimum 1, and must be within the column's `CHECK`; if it
violates a constraint, or the index insert fails with a constraint or permanent error (transient `SQLITE_BUSY` or I/O
errors are retried a bounded number of times first, as in section 3), the file is quarantined, never retried in an unbounded loop. The same rule
applies to the recorder's own insert after the rename (section 3). Adoption rather than deletion is chosen because
the file was fully synced before its rename (section 3), so it is real video that only lacks a row; this settles
the "indexed or quarantined" choice of #59.

**Result.** A report with counts per category (`part_deleted`, `rolled_forward`, `rolled_back`, `missing`, `adopted`,
`quarantined`, `size_mismatch`, `unverified`, `unknown_left`, `archive_unavailable`), logged by tier only, and the
post-condition (archive available) "every row has exactly one file, on its tier, and every `.mp4` has a row". Quarantined
files stay out of the index, count against the floor and are the first eviction candidates (section 6). Periodic
scrubbing and bit-rot checks are out of scope.

### 10. Worked example with real numbers

Inputs: 5 main streams at the ADR 0002 bitrates (`reolink-1` 2.9, `reolink-2` 2.9, `xr` 4.3, `tapo` 0.19, `hdipc`
8.6 Mbit/s); container overhead 0.53 % (measured above); min free 25 % on both; headroom 1 pp; `hot_max_age` 12 h; one
segment per camera per minute. Decimal GB (10^9). Volumes (`stat -f`, 4,096-byte blocks, read 2026-11-23):

| volume | `f_blocks` | `f_bfree` | `f_bavail` | capacity = (blocks - bfree + bavail) x 4,096 | available |
|---|---|---|---|---|---|
| hot (SSD, root fs) | 239,804,694 | 165,906,465 | 153,706,632 | **932,269,510,656 B** | 629,582,364,672 B |
| archive (HDD) | 488,032,446 | 488,031,927 | 488,027,831 | **1,998,964,121,600 B** | 1,998,961,995,776 B |

The hot volume's raw size is 982,240,026,624 B; 49,970,515,968 B of it is the ext4 reserve and is excluded.

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

**Capacity.** Floors (25 % of capacity): hot `932,269,510,656 x 25 % = 233,067,377,664` B; archive
`1,998,964,121,600 x 25 % = 499,741,030,400` B. With the hot volume as measured (629,582,364,672 B available) the room
above the floor is 396,514,987,008 B, which is 1.93 days of recording; the archive's usable space above its floor is
1,499,223,091,200 B, **7.31 days**. With `hot_max_age` 12 h the hot tier holds about 102.5 GB (12 h) and never
reaches its floor at this rate, so steady state is: 12 h hot, then archive, and the oldest archive video is deleted
once the archive reaches its floor. The retention a user gets today is therefore about **7.3 days + 12 h, roughly
7.8 days**. If the same five cameras recorded at twice the rate, the archive would hold about 3.7 days (1,499,223,091,200 B /
(2 x 205.09 GB)) and the hot tier, which is **time-based** (12 h), still its 12 h, so retention is about **4.15 days**,
not half of 7.8 (the planner needs no change, only the numbers do).

**A floor-driven tick (both volumes at their floors).** Suppose `hot_max_age` is set high, so the hot tier fills
until the floor, and the archive has been at its floor for a while. State at a tick (available space):

- hot: available 232,907,377,664 B = 24.98 % of capacity (below the floor by 160,000,000 B);
- archive: available 499,796,030,400 B = 25.003 % of capacity (just above the floor).

1. Hot target = floor + 1 pp = 233,067,377,664 + 9,322,695,106 = **242,390,072,770** B available. Bytes to move out of
   hot: 242,390,072,770 - 232,907,377,664 = **9,482,695,106** B, which is about 67 minutes of the 142.42 MB-per-minute
   stream, i.e. about 333 oldest segments (9,482,695,106 / 28.48 MB).
2. Archive after absorbing them: 499,796,030,400 - 9,482,695,106 = 490,313,335,294 B, **below** its floor of
   499,741,030,400. The archive target is floor + 1 pp = 499,741,030,400 + 19,989,641,216 = **519,730,671,616** B, so
   the planner must delete 519,730,671,616 - 490,313,335,294 = **29,417,336,322** B first, which is 3.4 h of the oldest
   archived video, about 1,033 oldest segments.
3. Plan order: all `Delete` actions for the oldest archive segments, then `MoveToArchive` for the oldest hot segments,
   each move following M1-M9.
4. Execution: at 64 actions per tick and 30 s ticks, this catch-up takes about 22 ticks (1,033 + 333 actions), roughly
   11 minutes. In steady state the loop only handles what was recorded since the last tick: 30 s of recording is 2.5
   segments (71 MB), so one tick is a handful of actions.
5. Copy volume: 9.48 GB moved to the HDD; at the average input of 2.37 MB/s the HDD is idle most of the time. I did not
   measure the HDD's write speed, so the catch-up time above is bounded by the action count, not by the disk.

**Archive missing (at boot or later):** the same hot state with the archive unmounted gives `Delete` of the oldest hot
segments totalling 9,482,695,106 B (about 67 minutes of video) and the state `archive_unavailable`; the SSD keeps its
floor, `floor_breaches_total` increases once, and the roughly 7 days of archive rows (about 50,000 rows) stay in the
index untouched until the disk returns, when the "archive returned" pass reconciles them.

**Segment-rule example (hdipc, GOP 3.5 s):** keyframes fall at multiples of 3.5 s (59.5 s, 63 s), so the first keyframe at or after the
60 s target is at 63 s: the segment closes with 63 s of media time (one file of about 68.1 MB) and the next file starts at
that keyframe. If hdipc
sent no keyframe for 120 s the segment would be closed at 120 s on a delta frame and the frames up to the next keyframe
dropped and counted as a gap.

### 11. Code placement and the one new dependency (amends ADR 0004 section 8 and ADR 0006 section 4 by reference)

ADR 0004's crate map has no home for three things this ADR needs: a secure file-open helper that both the vault and
the index use (ADR 0004: `index` never depends on `vault` or `secrets`), a root-directory handle that storage and the
recorder share while `api` depends on neither, and the fMP4 box walk used by the `mp4` tests and by the adoption
parser. **This ADR amends ADR 0004 section 8 (crate map) and ADR 0006 section 4 (the open helper) by reference; those
documents are not edited here.**

- **New crate `wardenlens-fsutil`** (depends on `core` and `rustix` only; no SQLite, no async). It owns:
  1. the **secure SQLite-file open helper** of ADR 0006 section 4 (create with mode `0600` before SQLite opens it, our
     own `O_NOFOLLOW` descriptor and `fstat`, owner and mode checks, and the device and inode comparison after SQLite
     has opened the path). It performs the file checks; the `rusqlite` open call with `SQLITE_OPEN_NOFOLLOW` stays in
     `index` and `vault`. **The vault and the index both use it**, so neither depends on the other;
  2. **`RootDir`**: a root directory handle opened with `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), parent
     descriptors opened the same way, and **single-component** `renameat2`, `unlinkat` and `mkdirat` on them (sections 3
     and 7), plus `fstat`/`fstatvfs` helpers for the probe (section 8);
  3. the **quarantine rename** (`RENAME_NOREPLACE`, numeric suffix, bound of 1,000, section 9).
  `index`, `vault`, `storage` and `recorder` may depend on `fsutil`; it is a leaf, so the rule "adapters do not depend on
  each other except `recorder` to `mp4`" gains one allowed edge target, not a cycle.
- **The API reaches segment files only through a core port**, `SegmentFiles` (open a segment for reading **by id**,
  returning a read-only handle, its length and its tier). `storage` implements it with the archive handle of the latest
  successful probe (section 8) and `fsutil`; `cli` wires it in as a generic. `api` therefore still depends on `core`
  only (ADR 0004 section 8), and #62 holds no path and no root.
- **The fMP4 box *parser* is pure byte parsing in `core::mp4box`** (a bounded box-header walk over `&[u8]`/a reader:
  size 0 or below 8, `largesize`, children inside parents, checked sums, `sample_count * entry_size <= payload`),
  shared by the `mp4` writer's tests (replacing a private test-only parser) and by the `storage` adoption walk. The
  **writer** stays in `wardenlens-mp4`.

Resulting edges: `index -> core, fsutil`; `vault -> core, secrets, fsutil`; `storage -> core, fsutil`; `recorder -> core,
mp4, fsutil`; `mp4 -> core`; `api -> core`; `fsutil -> core`; `cli -> all`.

**`rustix`** (the only new external crate of this section; #58 and #68 already name it for `statvfs` and `RLIMIT_NOFILE`).
Observed 2026-11-23 with `cargo info` and the crates.io API:

| crate | version | licence | `rust-version` | last release | owner | downloads (recent) | features used |
|---|---|---|---|---|---|---|---|
| `rustix` | 1.1.6 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 1.65 | 2026-10-27 | `sunfishcode` | 1,454,053,218 (388,521,252) | `std`, `fs` (default features off) |

A scratch project with `default-features = false, features = ["std", "fs"]` resolves to **3 crates** (`rustix`,
`bitflags` 2.13.2, which `rusqlite` already needs, and `linux-raw-sys` 0.12.1), passes `cargo deny check` against the
repository's `deny.toml`, and **compiles calls** to `openat2` (with `ResolveFlags::BENEATH | NO_SYMLINKS`),
`renameat_with` (`RenameFlags::NOREPLACE`), `unlinkat`, `mkdirat`, `fstat` and `fstatvfs` (`StatVfsMountFlags::RDONLY`);
it was not run against a mount. **Platform requirements:** `openat2` needs **Linux 5.6 or later** (the host runs 7.0), and
the container's **seccomp profile must allow `openat2` and `renameat2`**; `RENAME_NOREPLACE` also needs filesystem
support (ext4 has it; `EINVAL` from a filesystem without it makes that volume unavailable). #69 tests both inside the
image.

## Decision

| question | decision |
|---|---|
| muxer | in-house minimal fMP4 box writer in `wardenlens-mp4`, no dependency; `mp4-atom` 0.17.1 is the documented fallback; `mp4` 0.14.0 rejected (no fragmented writer, last release 2023-08-01) |
| segment | target 60 s, cut only at a keyframe, hard maximum 120 s (closed on the frame, resume at next keyframe; `segment_target_secs` 10-290), first segment at the first keyframe, fragment = one GOP, caps 16 MiB per fragment, 1 GiB per segment, 8 MiB per frame; `mvhd`/`mehd` duration patched before the fsync |
| timestamps | index: arrival wall clock UTC ms, `started_at_ms` = arrival, +1 ms repeated until neither a row nor a known file has the key, so a backward clock step gives overlapping times and a health warning (forward steps do not compress the index); recording is held off for a wall clock before 2000 or after 2099; seeded per camera from the index `MAX` and from the reconciliation walk; `duration_ms` = media duration (ticks to ms rounded up, min 1); file: 90 kHz media time from 0 per file, `dts = max(rtp - rtp0, prev + 1)`, re-base on a jump above 10 s forward or a step back of about 1 s |
| layout | `<root>/<camera_id>/<YYYY-MM-DD>/<HHMMSS>-<mmm>.mp4`, UTC, identical relative path on both tiers, `.part` while writing, quarantine under `<root>/_quarantine/` (cannot be a `CameraId`); paths derived from validated id and time, **not stored**; opened with `openat2` `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` through the hot root handle (opened once) or the archive handle of the latest probe; `O_NONBLOCK` on opens of planted-able files; file names must round-trip `RelPath` |
| segment close | write, patch durations, `fsync(file)`, `renameat2(RENAME_NOREPLACE)`, `fsync(dir)`, then `Index::insert`; an insert failure quarantines the file |
| SQLite | `rusqlite` 0.43.0, `default-features = false`, `bundled` (SQLite 3.54.1); WAL, `synchronous = FULL`, `foreign_keys = ON`, `application_id`; the file is opened with the `wardenlens-fsutil` secure open helper (section 11); synchronous API with `spawn_blocking` callers |
| migrations | in-house ordered scripts, `PRAGMA user_version` in the same transaction; newer version is an error |
| tables | `segments` (`AUTOINCREMENT` id), `cameras` (no credential, host or name columns, ADR 0006; length checks), `api_tokens` (ADR 0004; length checks); indexes as in section 5 |
| tier policy | floor arithmetic on available space (`capacity = (blocks - bfree + bavail) x frsize`); move on hot floor (to floor + 1 pp) or hot age (12 h); evict archive oldest first before a move that would breach its floor; floor wins over video when the archive is unavailable; defaults 25 %, 12 h, 64 actions per tick |
| move protocol | copy to `.part`, fsync, `renameat2(RENAME_NOREPLACE)`, fsync dir, `UPDATE tier` (durable), then unlink hot; delete = unlink then `DELETE` row; a bad hot file is handled at run time per the section 9 cells so the mover never stalls; fsync each parent directory after an unlink and before the `DELETE` |
| code placement | new crate `wardenlens-fsutil` (core + `rustix` `fs`): secure SQLite-file open helper (vault and index), `RootDir` (`openat2` handles, single-component `*at` ops), quarantine rename; core port `SegmentFiles` for the API; `core::mp4box` pure box parser shared by `mp4` tests and the storage adoption walk; amends ADR 0004 section 8 and ADR 0006 section 4 by reference |
| archive state | one definition at boot and every tick: unavailable when missing, same filesystem, `ST_RDONLY`, marker `.wardenlens-archive` missing, or 3 consecutive **archive-side** move failures (or unusable: `capacity == 0` or overflow); when it is available but cannot absorb moves even after evicting everything it reports `archive_full` and behaves the same; then the service **still starts and records**, deleting the oldest hot to hold the floor; only a bad **hot** root refuses to start |
| reconciliation | volumes probed **first**; a per-key `(camera_id, started_at_ms)` decision table over hot file, archive file and row (27 cells with the archive available, 26 listed plus the implicit none/none/none, and 9 without); with the archive unavailable nothing is concluded from an absent archive file and archive rows are kept; counts and tier only in reports |

## Downstream tickets

This ADR **overrides** ticket text written before it. Where a ticket and this ADR disagree, this ADR wins. I did **not**
edit any ticket; the controller adds an "Amended by ADR 0005" section to each ticket below. Checked against the ticket
bodies read on 2026-11-23.

| ticket | what it must do, and what it overrides |
|---|---|
| new crate `wardenlens-fsutil` (a new ticket, before #49/#58) | depends on `core` and `rustix` 1.1.6 (`std`, `fs`) only; `RootDir`, the secure SQLite-file open helper (used by #49 `index` and #74 `vault`; ADR 0006 section 4 is amended by reference), the NOREPLACE quarantine rename with numeric suffixes; tests of `openat2` refusal of `..`, absolute paths and symlinks, and of single-component operations |
| `SegmentFiles` core port (in #44/#45's recording module or its own small ticket) | `open_segment(id)` for reading, returning a read-only handle, length and tier; implemented by `storage` (#58) with the latest probe handle, wired in `cli` (#68); **#62 uses only this port**, never a path or a root |
| `core::mp4box` (a new small ticket, with #54) | pure bounded box-header parser (rejections listed in section 9); used by #54's golden tests and by #59's adoption walk; the writer stays in `wardenlens-mp4` |
| #43 (core camera model) | `CameraId` is also the path component (SEC-4) and the `segments.camera_id` value; no change to the type |
| #44 (core planner) | `Policy { hot_min_free, archive_min_free, hot_max_age }` and a fixed 1 pp headroom; actions are moves and deletes in the order of section 6 (archive deletions first, then moves), `now` is an input; hot deletes only when the archive is unavailable (an input `ArchiveState`) or a move is impossible; `PlanError` for the unsatisfiable cases, and `Unsatisfiable` is returned **without planning hot deletions** that cannot restore the floor (check `free + deletable bytes >= target` first); the unit test reproduces the worked example of section 10 to the byte, plus the proptest |
| #45 (core segmenter, media clock) | the rules of section 2: target 60 s (10-**290**, so the hard maximum stays under the 600 s `CHECK`), hard maximum 2x target closed on the frame, ticks to ms rounded **up** (min 1), byte and fragment caps, `dts = max(rtp - rtp0, prev + 1)` (clamp, not accumulate), 32-bit unwrap, re-base on more than 10 s forward or about 1 s backward; `SegmentRecord { camera, started_at_ms, duration_ms, bytes, frame_count }` (`ended_at_ms` derived); also the pure `RelPath` (`new(&CameraId, started_at_ms)` and a strict `FromStr`) shared by recorder, storage and index (the API gets no path, section 11); tests from the ADR 0002 jitter patterns; the `MediaClock` is not trusted before the #55 reordering check passes |
| #46 (Clock) | returns UTC Unix milliseconds (a newtype); the recorder uses it for `started_at_ms`; a value before the year 2000 (946,684,800,000 ms) is reported as an error the recorder holds off on, as is a value after 4,102,444,799,999 ms (year 2099); `arrival < previous` is a health warning |
| #47 (service config) | keys `storage.hot_root`, `storage.archive_root`, `storage.hot_min_free_percent`, `storage.archive_min_free_percent` (0-90, default 25), `storage.hot_max_age` (default 12 h), `recording.segment_target_secs` (10-**290**, default 60), `storage.max_actions_per_tick` (default 64); roots must be absolute |
| #49 (index) | **overrides:** no `schema_version` table: `PRAGMA user_version` with in-house scripts; **no `rel_path` column**: `insert(SegmentRecord, tier)` and `set_tier(id, tier)` carry no path; `synchronous = FULL`, `application_id`; the file open uses the **secure open helper of `wardenlens-fsutil`** (`O_NOFOLLOW` + `fstat` + device/inode compare; the `rusqlite` open with `SQLITE_OPEN_NOFOLLOW` stays in `index`); `index` depends on `core` and `fsutil` only; `segments.id` is `INTEGER PRIMARY KEY AUTOINCREMENT`; schema and indexes as in section 5; `MAX(started_at_ms)` per camera is available for the recorder's seed; `rusqlite` 0.43.0 `default-features = false`, `bundled`; the `EXPLAIN QUERY PLAN` test asserts the plans of section 5; sync API |
| #50 (cameras table) | columns exactly as in section 5 (ADR 0006 authoritative) with the length `CHECK`s on `model` (64), `main_path` and `sub_path` (512); **rejects** a camera path containing `@`, or a query parameter named (case-insensitive) `pass`, `password`, `pwd`, `user`, `usr`, `token`, `auth`, `key` or `secret`, or any query string the catalogue does not allow for that model, at parse and on read; no foreign key from `segments`; `remove` leaves segments (orphans by `LEFT JOIN`) |
| #54 (mp4 crate) | in-house writer, no new external dependency; the golden tests use `core::mp4box` instead of a private test-only parser; the layout of section 3 (`default-base-is-moof`, `tfdt` v1, `trun` flags `0x000701`, sample flags `0x02000000`/`0x01010000`, SPS/PPS only in `avcC`, no composition offsets), fragment per GOP, checked `u32` sizes; golden-structure tests and the `#[ignore]` ffprobe/ffmpeg decode test (frame hashes equal to the source, as in this ADR's prototype); a documented fallback to `mp4-atom` |
| #55, #56 (ingest) | deliver the RTP timestamp, the arrival time from `Clock`, SPS/PPS and a discontinuity flag per frame; #55 verifies on the five main streams that there is no frame reordering (`has_b_frames`/`pic_order_cnt_type`), see open risk 1; that check **blocks both the #45 `MediaClock` and #57** |
| #57 (recorder) | layout and close sequence of sections 2 and 3 (`.part`, patch `mvhd`/`mehd` duration with `pwrite`, fsync, `renameat2(RENAME_NOREPLACE)`, fsync dir, `Index::insert`); **an insert failure retries transient errors (BUSY, I/O) a bounded number of times and quarantines the file only on a constraint or permanent error**; `started_at_ms = arrival` plus 1 ms repeated until neither a row nor a known file has the key (forward clock steps do not compress the index), a health warning when `arrival < previous`, **seeded from `MAX(started_at_ms)` and from the reconciliation walk's maximum key** at start-up; a clock before 2000 or after 2099 holds recording off with a health warning; a crash leaves at most one `.part` **per camera**; the path is `RelPath` opened through `wardenlens-fsutil`'s `RootDir` (hot root handle opened once at start-up) with `openat2` `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` (overrides "containment asserted") then `fstat`; files `0600`, directories `0700`; blocked by the #55 reordering check |
| #58 (storage) | the move sequence M1-M9 of section 7 (hot `unlink` last; `set_tier(id, tier)`; M6 is `renameat2(RENAME_NOREPLACE)` via rustix); **M1: for a missing or a wrong-size hot file it evaluates `A/R` and acts exactly as the section 9 cell (row = hot); a non-ENOENT error on `A/R` makes the segment `unverified` and never drops the row; it continues with the next segment**, so the mover never stalls; delete = unlink, **fsync each parent directory**, **then** `Index::delete` (overrides "Index::delete and unlinks"); floor arithmetic on `capacity` and `f_bavail` (section 6); **every probe opens a fresh `O_DIRECTORY` + `O_NOFOLLOW` handle on the archive root and runs `fstat` (`st_dev`), `fstatvfs` (`ST_RDONLY`) and the marker `openat` on it; the mover, the reconciliation pass and the `SegmentFiles` implementation use only the handle from the latest successful probe, swapped when `(st_dev, st_ino)` changes** (a start-up handle goes stale when a mount later covers the directory); `renameat2`, `unlinkat` and `mkdirat` act on an `openat2`-opened parent descriptor with a single-component name; quarantine renames use `RENAME_NOREPLACE` with `.1`, `.2` suffixes on `EEXIST` and, when the 1,000 bound is used up, leave the file in place as `unverified`; **only archive-side errors (M2, M3, the write half of M4, M5-M7) count toward the 3 failures**: a source read error quarantines that hot segment and continues, an index error skips the segment this tick (a health error after 3 ticks), `EEXIST` at M6 rolls forward if `A/R` has the row's size, otherwise quarantines it; the mover never retries a failed segment within a tick and runs the rest of the plan; **M1 opens `H/R` once with `openat2`, `fstat`s the handle and M4 copies from that descriptor**, a non-ENOENT error marks the segment `unverified`; a stale `.wl-probe` is unlinked first; fsync of the surviving file and its directory before any index write that makes it the only copy; tests: an M4 **read** failure leaves the archive available and deletes no hot video, a stale complete `A/R` at M6 is rolled forward; "none" means ENOENT only, any other error is `unverified`; `ArchiveState` of section 8: unavailable on missing root, same `st_dev`, `ST_RDONLY`, missing `.wardenlens-archive` marker or 3 consecutive archive-side move failures, re-probed every tick, **replaces "errors if hot and archive resolve to the same filesystem"** (unavailable mode, not an error); the "archive returned" pass runs on the storage-loop task, serialised with the mover, with the limited scope of section 9 (for keys without a row it never touches H); test: start unmounted, mount while running (every archive row kept, moves land on the HDD); `openat2` `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` through root handles, with `O_NONBLOCK` on opens of files others may plant (overrides "canonicalize"); `capacity == 0` or overflow makes a volume unusable, never a division; the archive-full case (available but unable to absorb moves even after evicting everything) behaves like unavailable and reports `archive_full`; implements the core `SegmentFiles` port (re-read the row once after `ENOENT`, open the other tier, typed errors not found / archive unavailable / I/O); reads for the `core::mp4box` walk (`Read + Seek`, skip `mdat`, 1 MiB cap on `moov`/`moof`); quarantine files evicted first; fault-injection tests at every crash point of the table |
| #59 (reconciliation) | runs **after the volume probe**; the per-key decision table of section 9 (27 cells with the archive available, 26 listed plus the implicit none/none/none, and 9 without), one test per cell and per crash-table row; **required tests: archive unmounted, every archive row is kept; archive mounted *while running* (start unmounted), every archive row kept; the "archive returned" pass runs while a recorder is mid-segment and mid-rename and touches no hot file** (and no archive file touched); an **invalid file is never deleted** (always quarantined), and for "both tiers, no row" the archive copy is adopted when it is valid and H is deleted only when the two sizes are equal, otherwise H is quarantined; ids never reassigned while a row exists; a pattern-matching but non-canonical file name (`RelPath` round trip, HH at most 23, MM and SS at most 59) is `unknown_left`; opens use `O_NONBLOCK`; the M1 runtime rule follows the same cells; the (none, valid, valid) cell deletes H only when the sizes are equal, otherwise quarantines H; fsync before any index write that makes a copy the only one; **the walk cap (default 5,000,000 entries), when exceeded at start-up, does not stop the service: it reports `unverified` and raises a health error**; an **invalid file is always quarantined, never deleted** (every "delete A" or "delete H" cell for an invalid copy is now a quarantine; only valid duplicates and `.part` files are deleted); quarantine uses `RENAME_NOREPLACE` with numeric suffixes; "none" means ENOENT only, any other error leaves the key `unverified`; the "archive returned" pass evaluates only keys with an archive file, a `tier = archive` row or a `tier = hot` row whose hot file is missing, applies only the archive `.part` rule, never touches hot `.part` files and never adopts hot-only keys (those run only at start-up, before the recorders); quarantine into `_quarantine/` (not `quarantine/`); overrides "indexed with duration read from moof headers or quarantined" (**adopt, else quarantine**) and "`.part` files in either root are deleted" (archive `.part` only when the archive is available); **the adoption parser treats files as untrusted** (reject box size 0 or below 8, `largesize` handled or rejected, each box inside its parent, `sample_count * entry_size <= payload`, checked `u64` sums, caps of 100,000 fragments and 1 GiB), ticks to ms rounded up (min 1), any index-insert failure quarantines; walk depth 4 and an entry cap; the adoption box walk is `core::mp4box` (header at a time, storage reads, `mdat` skipped, `moov`/`moof` capped at 1 MiB, never a whole-file slice); reports hold **counts and tier only, never file names**; also the "archive returned" pass used by #58 |
| #62 (recordings API) | calls `SegmentFiles::open_segment(id)` **only** and maps its typed errors (not found to 404, archive unavailable to 503, I/O to 500) plus single-range requests; it holds **no path, root, handle or `openat2`** and does not derive a path (overrides "root + relative path from the index" and "canonicalised"); the re-read after `ENOENT` and the tier choice live in storage's implementation (section 7) |
| #63 (storage endpoint) | adds `archive_unavailable` (and its cause class) and `archive_full` to the state; `free_percent` is `f_bavail * 100 / capacity` with `capacity = (f_blocks - f_bfree + f_bavail) * f_frsize`; `unverified` and quarantine counts |
| #65 (token CLI) | the `api_tokens` DDL of section 5 (migration 3) with the `CHECK (length(name) BETWEEN 1 AND 64)`; `last_used_at_ms` nullable; rows never deleted |
| #68 (serve) | order at start-up: take the process lock, open and migrate the index, **probe both volumes**, run reconciliation, then start the storage loop and recorders; refuse a second instance; **one boot behaviour:** a missing, same-filesystem, read-only or unmarked archive starts in `archive_unavailable` mode (recording continues, oldest hot is deleted to hold the floor); only a missing or unusable **hot** root or an unopenable index refuses to start (overrides "refuses to start if hot or archive is missing or both are on one filesystem") |
| #69 (Docker) | volumes for the hot root, the archive root and `/var/lib/wardenlens` (index and vault, which are not on a recordings volume); a C compiler in the build stage for `rusqlite` `bundled`; the container seccomp profile allows `openat2` and `renameat2`, the kernel is 5.6 or later, and both are **tested inside the image** (`RootDir` refuses `..` and symlinks, `RENAME_NOREPLACE` works on the archive filesystem); the archive bind mount uses `rslave` propagation (so a mount made after the container started becomes visible) **or** the container is started after the archive is mounted, documented in `docs/deploy.md`; the archive mount must be a separate filesystem and carries the `.wardenlens-archive` marker file (created once with `wardenlens storage mark-archive`, a small subcommand for #64/#68) |
| #70 (48 h gate) | the restart and hard-kill checks use the reconciliation report counts of section 9 and expect `quarantined = 0`, `size_mismatch = 0`; the restart test includes an archive-unmounted restart that keeps every archive row |
| ADR 0006 / #74 | unchanged: follows `rusqlite` `bundled` (this ADR agrees) and keeps its own file |

## Consequences

- Easier: a crash loses at most the open segment of each camera (up to 120 s) and never the only copy of a finished one;
  recovery is deterministic and rule-based; the index is small, rebuildable from the files and queried with planned
  indexes; no muxer or ORM dependency, only **8 new crates** (the 6 of the `rusqlite` set plus `rustix` and `linux-raw-sys`; `bitflags` is shared) and a C compiler
  in the build.
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
   `MediaClock` the reorder depth. Until the check passes, neither the #45 `MediaClock` nor #57 is trusted. Proposed ticket: "spike: confirm no B-frames on the five main streams" (small,
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
8. **Clock steps** (NTP) can make `started_at_ms` jump. Names stay unique because the +1 ms rule repeats until neither a
   row nor a known file has the key, but a **backward** step gives overlapping `started_at_ms`/`ended_at_ms` ranges
   (reported with a health warning) and a forward step a gap that did not occur in media time. Recording is held off
   below 2000 and above 2099; the seed comes from the index `MAX` and the walk.
9. **Known limit: archive orphans are invisible to the seed while the archive is unavailable at start-up.** The
   per-camera `started_at_ms` seed (index `MAX` and the walk) cannot see an archive file that has no row until the archive
   returns, so the recorder can pick a key that an orphan on the unavailable archive already has (an exact-millisecond
   collision with an old file, which needs the same camera and the same millisecond). When the archive returns, the
   "archive returned" pass **adopts the orphan under that key** and the recorder's own insert for the live segment then
   fails on the unique constraint, so **the live segment is quarantined** (kept, but out of the index). Accepted as a
   **negligible known limit**: the probability is about one in 10^9 per segment against any existing orphan.
10. **Known limit: a hot file whose row says archive is invisible to eviction while the archive is unavailable** (the row
    is kept and the file is not counted as a hot candidate). Bounded to about one such segment per crash.
11. **Known limit: retention can be lost to a line-rate camera.** One camera sending at a very high bitrate shortens
    every camera's retention, because eviction is global oldest-first. Phase 2: a per-camera bitrate or quota alarm.
12. **Follow-up (after merge, not part of this ADR):** change `docs/CODING_GUIDELINES.md` SEC-4 to prefer handle-relative
    `openat2` (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) over canonicalise-and-check.
