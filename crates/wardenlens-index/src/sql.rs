//! Every SQL statement of the crate, as a `&'static str` with `?N` placeholders.
//!
//! This is the whole enforcement of "no SQL is built from data": nothing in the crate formats or
//! concatenates SQL, values only ever travel as bound parameters, and the `hygiene` test greps the
//! production sources to keep it that way.

// The column list of a full row is repeated in `GET` and `LIST` on purpose, in the order
// `rows::decode_segment` reads it: a `concat!` would be one more way to build SQL.
pub(crate) const INSERT: &str = "INSERT INTO segments \
    (camera_id, started_at_ms, duration_ms, ended_at_ms, bytes, frame_count, tier) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

pub(crate) const GET: &str = "SELECT id, camera_id, started_at_ms, duration_ms, ended_at_ms, \
    bytes, frame_count, tier FROM segments WHERE id = ?1";

/// ?1 camera, ?2 `from` minus the longest duration, ?3 `to`, ?4 `from`, ?5 and ?6 the cursor
/// position `(started_at_ms, id)`, ?7 the row count to fetch.
pub(crate) const LIST: &str = "SELECT id, camera_id, started_at_ms, duration_ms, ended_at_ms, \
    bytes, frame_count, tier FROM segments \
    WHERE camera_id = ?1 AND started_at_ms >= ?2 AND started_at_ms < ?3 AND ended_at_ms > ?4 \
    AND (started_at_ms, id) > (?5, ?6) \
    ORDER BY started_at_ms, id LIMIT ?7";

/// ?1 id, ?2 the new tier, ?3 the tier it must be on now.
pub(crate) const SET_TIER: &str = "UPDATE segments SET tier = ?2 WHERE id = ?1 AND tier = ?3";

pub(crate) const TIER_OF: &str = "SELECT tier FROM segments WHERE id = ?1";

pub(crate) const DELETE: &str = "DELETE FROM segments WHERE id = ?1";

pub(crate) const OLDEST: &str = "SELECT id, tier, bytes, ended_at_ms FROM segments \
    WHERE tier = ?1 ORDER BY ended_at_ms, id LIMIT ?2";

pub(crate) const BYTES_BY_TIER: &str =
    "SELECT tier, SUM(bytes), COUNT(*) FROM segments GROUP BY tier";

pub(crate) const LATEST_START: &str =
    "SELECT MAX(started_at_ms) FROM segments WHERE camera_id = ?1";

// Open and migration statements.
pub(crate) const GET_APP_ID: &str = "PRAGMA application_id";
pub(crate) const USER_VERSION: &str = "PRAGMA user_version";
pub(crate) const OBJECT_COUNT: &str = "SELECT count(*) FROM sqlite_master";
/// Must equal `open::APPLICATION_ID` (a test checks).
pub(crate) const SET_APP_ID: &str = "PRAGMA application_id = 1464617304";
pub(crate) const SET_WAL: &str = "PRAGMA journal_mode = WAL";
pub(crate) const SET_SYNC: &str = "PRAGMA synchronous = FULL";
pub(crate) const SET_FK: &str = "PRAGMA foreign_keys = ON";
/// Must equal `open::JOURNAL_SIZE_LIMIT` (a test checks).
pub(crate) const SET_JOURNAL_LIMIT: &str = "PRAGMA journal_size_limit = 67108864";
pub(crate) const GET_SYNC: &str = "PRAGMA synchronous";
pub(crate) const GET_FK: &str = "PRAGMA foreign_keys";
pub(crate) const GET_JOURNAL_LIMIT: &str = "PRAGMA journal_size_limit";
pub(crate) const GET_BUSY: &str = "PRAGMA busy_timeout";
