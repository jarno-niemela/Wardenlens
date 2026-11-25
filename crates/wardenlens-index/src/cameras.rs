//! The camera registry (ADR 0005 section 5, ADR 0006; ticket #50).
//!
//! The `cameras` table holds what the recorder needs to open a stream and nothing that identifies
//! a site: the id, the catalogue model, the RTSP port and the stream paths. The host, the display
//! name and the credential are vault entries (`cam:<id>:host`, `cam:<id>:name`,
//! `cam:<id>:credential`). **The API shape enforces that**: [`CameraRecord`] has no field for them
//! and no function here takes a `Host`, a `DisplayName` or a `Credential`; the one place that
//! sees a core `Camera` ([`CameraRecord::from_camera`]) copies its id, model, port and streams
//! and nothing else. A test checks the source for the three types.
//!
//! Paths are vetted at one choke point, [`vet_path`] (SEC-10), on the way in ([`Index::upsert_camera`])
//! and on the way out (every row read): core's `RtspPath` rules (no `@`, no credential parameter,
//! the character set), then the catalogue's query allow-list for the camera's model
//! ([`wardenlens_core::catalogue::query_allowed`]). A row that fails on read is a typed error, not
//! a panic. `remove` deletes the registry row only; segments keep their `camera_id` and are
//! orphans, found with a `LEFT JOIN` ([`Index::orphan_camera_ids`]).

use std::num::NonZeroU16;

use rusqlite::params;
use rusqlite::types::ValueRef;
use wardenlens_core::camera::{Camera, CameraId, ModelRef, RtspPath, StreamSet};
use wardenlens_core::catalogue::{CatalogueEntry, query_allowed};
use wardenlens_core::time::UnixMs;

use crate::error::IndexError;
use crate::{Index, sql};

/// The most cameras the registry holds. A bound on `list_cameras`, not a product limit.
pub const MAX_CAMERAS: usize = 1024;

/// The most orphaned camera ids `orphan_camera_ids` returns.
const MAX_ORPHANS: usize = 1024;

/// The longest `model` text the schema allows (`vendor/model`).
const MAX_MODEL_TEXT: usize = 64;

/// What the registry stores of a camera. No host, name or credential: see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraRecord {
    id: CameraId,
    model: ModelRef,
    port: NonZeroU16,
    streams: StreamSet,
}

impl CameraRecord {
    /// A record from validated parts.
    #[must_use]
    pub fn new(id: CameraId, model: ModelRef, port: NonZeroU16, streams: StreamSet) -> Self {
        Self {
            id,
            model,
            port,
            streams,
        }
    }

    /// The registry's share of `camera`; its host and display name are not read.
    #[must_use]
    pub fn from_camera(camera: &Camera) -> Self {
        Self::new(
            camera.id().clone(),
            camera.model().clone(),
            camera.port(),
            camera.streams().clone(),
        )
    }

    /// The camera id.
    #[must_use]
    pub fn id(&self) -> &CameraId {
        &self.id
    }

    /// The catalogue model.
    #[must_use]
    pub fn model(&self) -> &ModelRef {
        &self.model
    }

    /// The RTSP port.
    #[must_use]
    pub fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// The stream paths (redacting `Debug`).
    #[must_use]
    pub fn streams(&self) -> &StreamSet {
        &self.streams
    }
}

/// A registry row read back: the record and its two timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCamera {
    record: CameraRecord,
    created_at: UnixMs,
    updated_at: UnixMs,
}

impl StoredCamera {
    /// The stored fields.
    #[must_use]
    pub fn record(&self) -> &CameraRecord {
        &self.record
    }

    /// When the camera was first registered (kept by later upserts).
    #[must_use]
    pub fn created_at(&self) -> UnixMs {
        self.created_at
    }

    /// When the row was last written.
    #[must_use]
    pub fn updated_at(&self) -> UnixMs {
        self.updated_at
    }
}

/// The single choke point for camera paths (SEC-10): used by `upsert_camera` for each path it
/// stores and by `decode` for each path it reads. Core's `RtspPath` rules first (`@`, credential
/// parameter names, characters, length), then the catalogue's query allow-list for `model`.
pub(crate) fn vet_path(
    field: &'static str,
    model: &ModelRef,
    catalogue: &[CatalogueEntry],
    text: &str,
) -> Result<RtspPath, IndexError> {
    let path =
        RtspPath::new(text).map_err(|source| IndexError::CameraPathInvalid { field, source })?;
    if !query_allowed(catalogue, model, &path) {
        return Err(IndexError::CameraQueryNotAllowed { field });
    }
    Ok(path)
}

/// The `model` column text: `vendor/model`, at most 64 bytes (the schema's `CHECK`).
fn model_text(model: &ModelRef) -> Result<String, IndexError> {
    let text = [model.vendor(), "/", model.model()].concat();
    if text.len() > MAX_MODEL_TEXT {
        return Err(IndexError::InvalidRecord { field: "model" });
    }
    Ok(text)
}

fn corrupt(field: &'static str) -> IndexError {
    IndexError::CorruptCameraRow { field }
}

fn text_col<'r>(
    row: &'r rusqlite::Row<'_>,
    idx: usize,
    field: &'static str,
) -> Result<&'r str, IndexError> {
    match row.get_ref(idx) {
        Ok(ValueRef::Text(t)) => std::str::from_utf8(t).map_err(|_| corrupt(field)),
        Ok(_) => Err(corrupt(field)),
        Err(e) => Err(IndexError::sqlite("read camera")(e)),
    }
}

fn int_col(row: &rusqlite::Row<'_>, idx: usize, field: &'static str) -> Result<i64, IndexError> {
    match row.get_ref(idx) {
        Ok(ValueRef::Integer(i)) => Ok(i),
        Ok(_) => Err(corrupt(field)),
        Err(e) => Err(IndexError::sqlite("read camera")(e)),
    }
}

fn time_col(
    row: &rusqlite::Row<'_>,
    idx: usize,
    field: &'static str,
) -> Result<UnixMs, IndexError> {
    UnixMs::new(int_col(row, idx, field)?).map_err(|_| corrupt(field))
}

/// A stored path column: 1 to `MAX_PATH_LEN` bytes of text (the `CHECK`), then [`vet_path`].
fn path_col(
    row: &rusqlite::Row<'_>,
    idx: usize,
    field: &'static str,
    model: &ModelRef,
    catalogue: &[CatalogueEntry],
) -> Result<RtspPath, IndexError> {
    let text = text_col(row, idx, field)?;
    if text.is_empty() {
        return Err(corrupt(field));
    }
    vet_path(field, model, catalogue, text)
}

/// Decodes the column list of `sql::GET_CAMERA` and `sql::LIST_CAMERAS`.
fn decode(
    row: &rusqlite::Row<'_>,
    catalogue: &[CatalogueEntry],
) -> Result<StoredCamera, IndexError> {
    let id = CameraId::new(text_col(row, 0, "id")?).map_err(|_| corrupt("id"))?;
    let model = text_col(row, 1, "model")?
        .split_once('/')
        .and_then(|(v, m)| ModelRef::new(v, m).ok())
        .ok_or(corrupt("model"))?;
    let port = u16::try_from(int_col(row, 2, "rtsp_port")?)
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or(corrupt("rtsp_port"))?;
    let main = path_col(row, 3, "main_path", &model, catalogue)?;
    let sub = match row.get_ref(4) {
        Ok(ValueRef::Null) => None,
        Ok(_) => Some(path_col(row, 4, "sub_path", &model, catalogue)?),
        Err(e) => return Err(IndexError::sqlite("read camera")(e)),
    };
    let created_at = time_col(row, 5, "created_at_ms")?;
    let updated_at = time_col(row, 6, "updated_at_ms")?;
    Ok(StoredCamera {
        record: CameraRecord::new(id, model, port, StreamSet::new(main, sub)),
        created_at,
        updated_at,
    })
}

fn count(db: &sql::Db, stmt: sql::ReadSql, id: Option<&str>) -> Result<i64, IndexError> {
    let r = match id {
        Some(id) => sql::query_row(db, stmt, [id], |r| r.get(0)),
        None => sql::query_row(db, stmt, [], |r| r.get(0)),
    };
    r.map_err(IndexError::sqlite("count cameras"))
}

impl Index {
    /// Registers `record`, or replaces the row of the same id (its `created_at` is kept, its
    /// `updated_at` becomes `now`). One write transaction.
    ///
    /// `catalogue` is the loaded camera catalogue: a path with a query string is stored only when
    /// the catalogue lists that query for the record's model.
    ///
    /// # Errors
    /// - [`IndexError::CameraPathInvalid`]: a path has an `@`, a credential parameter or another
    ///   rule of core's `RtspPath` is broken.
    /// - [`IndexError::CameraQueryNotAllowed`]: a query string the catalogue does not list.
    /// - [`IndexError::InvalidRecord`]: `vendor/model` is over 64 bytes.
    /// - [`IndexError::TooManyCameras`]: a new camera, and [`MAX_CAMERAS`] are registered.
    /// - [`IndexError::Busy`], [`IndexError::Sqlite`]: SQLite failures.
    pub fn upsert_camera(
        &mut self,
        record: &CameraRecord,
        catalogue: &[CatalogueEntry],
        now: UnixMs,
    ) -> Result<(), IndexError> {
        let model = model_text(&record.model)?;
        let main = vet_path(
            "main_path",
            &record.model,
            catalogue,
            record.streams.main.as_str(),
        )?;
        let sub = record
            .streams
            .sub
            .as_ref()
            .map(|p| vet_path("sub_path", &record.model, catalogue, p.as_str()))
            .transpose()?;
        let id = record.id.as_str();
        sql::write_tx(&mut self.conn, "upsert camera", |w| {
            if count(w.read_conn(), sql::CAMERA_EXISTS, Some(id))? == 0
                && usize::try_from(count(w.read_conn(), sql::CAMERA_COUNT, None)?)
                    .map_or(true, |n| n >= MAX_CAMERAS)
            {
                return Err(IndexError::TooManyCameras { max: MAX_CAMERAS });
            }
            w.write(
                sql::UPSERT_CAMERA,
                params![
                    id,
                    model,
                    record.port.get(),
                    main.as_str(),
                    sub.as_ref().map(RtspPath::as_str),
                    now.as_i64()
                ],
            )
            .map_err(|e| match e.sqlite_error_code() {
                Some(rusqlite::ErrorCode::ConstraintViolation) => IndexError::Constraint {
                    op: "upsert camera",
                },
                _ => IndexError::sqlite("upsert camera")(e),
            })?;
            Ok(())
        })
    }

    /// The camera with `id`, or `None`. The stored paths are vetted again (see the module docs).
    ///
    /// # Errors
    /// [`IndexError::CorruptCameraRow`] (a column is out of bounds, naming the column),
    /// [`IndexError::CameraPathInvalid`] and [`IndexError::CameraQueryNotAllowed`] (the stored
    /// path fails today's rules), [`IndexError::Busy`], [`IndexError::Sqlite`].
    pub fn get_camera(
        &self,
        id: &CameraId,
        catalogue: &[CatalogueEntry],
    ) -> Result<Option<StoredCamera>, IndexError> {
        let mut stmt =
            sql::prepare(&self.conn, sql::GET_CAMERA).map_err(IndexError::sqlite("get camera"))?;
        let mut rows = stmt
            .query([id.as_str()])
            .map_err(IndexError::sqlite("get camera"))?;
        match rows.next().map_err(IndexError::sqlite("get camera"))? {
            Some(row) => decode(row, catalogue).map(Some),
            None => Ok(None),
        }
    }

    /// Every camera, ordered by id (at most [`MAX_CAMERAS`] rows). One bad row fails the call.
    ///
    /// # Errors
    /// The errors of [`Index::get_camera`].
    pub fn list_cameras(
        &self,
        catalogue: &[CatalogueEntry],
    ) -> Result<Vec<StoredCamera>, IndexError> {
        let limit = i64::try_from(MAX_CAMERAS).unwrap_or(i64::MAX);
        let mut stmt = sql::prepare(&self.conn, sql::LIST_CAMERAS)
            .map_err(IndexError::sqlite("list cameras"))?;
        let mut rows = stmt
            .query([limit])
            .map_err(IndexError::sqlite("list cameras"))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(IndexError::sqlite("list cameras"))? {
            out.push(decode(row, catalogue)?);
        }
        Ok(out)
    }

    /// Removes the registry row of `id`; `true` when there was one. **Segments are not touched**:
    /// they stay, and [`Index::orphan_camera_ids`] lists their camera. A missing id writes
    /// nothing.
    ///
    /// # Errors
    /// [`IndexError::Busy`], [`IndexError::Sqlite`].
    pub fn remove_camera(&mut self, id: &CameraId) -> Result<bool, IndexError> {
        let removed = sql::write_tx_opt(&mut self.conn, "remove camera", |w| {
            let n = w
                .write(sql::DELETE_CAMERA, [id.as_str()])
                .map_err(IndexError::sqlite("remove camera"))?;
            Ok((n > 0).then_some(()))
        })?;
        Ok(removed.is_some())
    }

    /// The camera ids that have segments and no registry row (at most 1,024, in id order): what
    /// is left after [`Index::remove_camera`]. A stored id that is not a camera id is
    /// [`IndexError::CorruptCameraRow`].
    ///
    /// # Errors
    /// [`IndexError::CorruptCameraRow`], [`IndexError::Busy`], [`IndexError::Sqlite`].
    pub fn orphan_camera_ids(&self) -> Result<Vec<CameraId>, IndexError> {
        let limit = i64::try_from(MAX_ORPHANS).unwrap_or(i64::MAX);
        let mut stmt = sql::prepare(&self.conn, sql::ORPHAN_CAMERAS)
            .map_err(IndexError::sqlite("orphan cameras"))?;
        let mut rows = stmt
            .query([limit])
            .map_err(IndexError::sqlite("orphan cameras"))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(IndexError::sqlite("orphan cameras"))? {
            out.push(
                CameraId::new(text_col(row, 0, "camera_id")?).map_err(|_| corrupt("camera_id"))?,
            );
        }
        Ok(out)
    }
}
