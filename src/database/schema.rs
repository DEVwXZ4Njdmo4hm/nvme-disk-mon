use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::{DbWriteError, DeviceRegistration, RecoveredSmartBaseline};

pub(super) const SUPPORTED_SCHEMA_VERSION: i64 = 1;
const MINIMUM_SQLITE_VERSION: &str = "3.37.0";
const RESERVED_WORKLOAD_ID: i64 = 0;
pub(super) const RESERVED_WORKLOAD_NAME: &str = "ndm:_bucket_complete";
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const LOWERCASE_HEX: &[u8; 16] = b"0123456789abcdef";

const GLOBAL_SCHEMA_SQL: &str = r"
CREATE TABLE devs (
    hash_id  TEXT NOT NULL PRIMARY KEY
        CHECK (
            length(hash_id) = 64
            AND hash_id NOT GLOB '*[^0-9a-f]*'
        ),
    label  TEXT NOT NULL,
    serial  TEXT NOT NULL,
    linux_by_disk_path  TEXT NOT NULL UNIQUE
) STRICT, WITHOUT ROWID;

CREATE TABLE workloads (
    workload_id  INTEGER PRIMARY KEY
        CHECK (workload_id >= 0),
    name  TEXT NOT NULL UNIQUE
        CHECK (length(name) > 0)
) STRICT;

INSERT INTO workloads (workload_id, name)
VALUES (0, 'ndm:_bucket_complete');

PRAGMA user_version = 1;
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceTableNames {
    pub(crate) hash_id: String,
    pub(crate) data_identifier: String,
    pub(crate) writer_history_identifier: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LatestSmartSample {
    pub(crate) timestamp: i64,
    pub(crate) data_units_written: u128,
}

struct SmartStatsRow {
    timestamp: i64,
    previous_timestamp: Option<i64>,
    data_units_written: u128,
    write_amount_bytes: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SmartDeviceStats {
    pub(crate) latest_sample: Option<LatestSmartSample>,
    pub(crate) last_threshold_timestamp: Option<i64>,
}

impl SmartDeviceStats {
    const fn empty() -> Self {
        Self {
            latest_sample: None,
            last_threshold_timestamp: None,
        }
    }

    fn observe_threshold(
        &mut self,
        timestamp: i64,
        previous_timestamp: Option<i64>,
        write_amount_bytes: i64,
        expected_span_ms: i64,
        threshold_gib: f64,
    ) -> bool {
        if self.last_threshold_timestamp.is_none()
            && let Some(previous_timestamp) = previous_timestamp
            && let Some(actual_span_ms) = timestamp.checked_sub(previous_timestamp)
            && actual_span_ms.abs_diff(expected_span_ms) <= 60_000
            && bytes_strictly_exceed_gib(write_amount_bytes, threshold_gib)
        {
            self.last_threshold_timestamp = Some(timestamp);
        }
        self.last_threshold_timestamp.is_some()
    }
}

pub(crate) fn device_hash_id(serial: &str, configured_by_id_path: &Path) -> Option<String> {
    let path = configured_by_id_path.to_str()?;
    let mut hasher = Sha256::new();
    hasher.update(serial.as_bytes());
    hasher.update([0]);
    hasher.update(path.as_bytes());
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(LOWERCASE_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWERCASE_HEX[usize::from(byte & 0x0f)]));
    }
    Some(encoded)
}

pub(crate) fn is_valid_hash_id(hash_id: &str) -> bool {
    hash_id.len() == 64
        && hash_id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

pub(crate) fn device_table_names(hash_id: &str) -> Result<DeviceTableNames, DbWriteError> {
    if !is_valid_hash_id(hash_id) {
        return Err(DbWriteError::InvalidDeviceTableIdentifier);
    }
    Ok(DeviceTableNames {
        hash_id: hash_id.to_owned(),
        data_identifier: format!("\"d_{hash_id}_data\""),
        writer_history_identifier: format!("\"d_{hash_id}_writer_history\""),
    })
}

pub(crate) fn open_writer_connection(path: &Path) -> Result<Connection, DbWriteError> {
    let connection = Connection::open(path).map_err(|source| DbWriteError::Open {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    verify_sqlite_version(&connection)?;
    configure_writer_connection(&connection)?;
    Ok(connection)
}

pub(crate) fn open_query_connection(path: &Path) -> Result<Connection, DbWriteError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection =
        Connection::open_with_flags(path, flags).map_err(|source| DbWriteError::Open {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
    verify_sqlite_version(&connection)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .map_err(|source| DbWriteError::Configure {
            pragma: "journal_mode",
            source: Box::new(source),
        })?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(DbWriteError::WalModeUnavailable {
            actual: journal_mode,
        });
    }
    configure_foreign_keys(&connection)?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|source| DbWriteError::Configure {
            pragma: "busy_timeout",
            source: Box::new(source),
        })?;
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout;", [], |row| row.get(0))
        .map_err(|source| DbWriteError::Configure {
            pragma: "busy_timeout",
            source: Box::new(source),
        })?;
    if busy_timeout != 5_000 {
        return Err(DbWriteError::Configure {
            pragma: "busy_timeout",
            source: Box::new(std::io::Error::other(
                "SQLite did not apply the requested busy timeout",
            )),
        });
    }
    connection
        .execute_batch("PRAGMA query_only = ON;")
        .map_err(|source| DbWriteError::Configure {
            pragma: "query_only",
            source: Box::new(source),
        })?;
    let query_only: i64 = connection
        .query_row("PRAGMA query_only;", [], |row| row.get(0))
        .map_err(|source| DbWriteError::Configure {
            pragma: "query_only",
            source: Box::new(source),
        })?;
    if query_only != 1 {
        return Err(DbWriteError::Configure {
            pragma: "query_only",
            source: Box::new(std::io::Error::other(
                "SQLite did not enable query-only mode",
            )),
        });
    }
    Ok(connection)
}

pub(crate) fn read_smart_device_stats(
    path: &Path,
    serial: &str,
    configured_by_id_path: &Path,
    detect_window_hr: u64,
    threshold_gib: f64,
) -> Result<SmartDeviceStats, DbWriteError> {
    let mut connection = open_query_connection(path)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|source| startup_transaction_error("begin_stats_query", source))?;
    validate_existing_v1_read_only(&transaction)?;

    let mut stats = SmartDeviceStats::empty();

    let hash_id = device_hash_id(serial, configured_by_id_path)
        .ok_or(DbWriteError::InvalidDeviceTableIdentifier)?;
    let tables = validated_device_tables(&transaction)?;
    let Some(table) = tables.get(&hash_id) else {
        transaction
            .commit()
            .map_err(|source| startup_transaction_error("commit_stats_query", source))?;
        return Ok(stats);
    };
    let expected_span_ms = detect_window_hr
        .checked_mul(3_600_000)
        .and_then(|value| i64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(DbWriteError::InvalidBatch {
            request_id: 0,
            reason: super::BatchInvariant::ValueOutOfSqliteRange,
        })?;
    if !threshold_gib.is_finite() || threshold_gib < 0.0 {
        return Err(DbWriteError::InvalidBatch {
            request_id: 0,
            reason: super::BatchInvariant::ValueOutOfSqliteRange,
        });
    }

    let sql = format!(
        "SELECT timestamp, previous_timestamp, data_units_written_be, write_amount_bytes \
         FROM ( \
             SELECT timestamp, \
                    LAG(timestamp) OVER (ORDER BY timestamp) AS previous_timestamp, \
                    data_units_written_be, \
                    write_amount_bytes \
             FROM {} \
         ) \
         ORDER BY timestamp DESC;",
        table.data_identifier
    );
    {
        let mut statement = transaction
            .prepare(&sql)
            .map_err(|source| stats_load_error(&hash_id, source))?;
        let mut rows = statement
            .query([])
            .map_err(|source| stats_load_error(&hash_id, source))?;
        while let Some(row) = rows
            .next()
            .map_err(|source| stats_load_error(&hash_id, source))?
        {
            let row = read_smart_stats_row(row, &hash_id)?;
            if stats.latest_sample.is_none() {
                stats.latest_sample = Some(LatestSmartSample {
                    timestamp: row.timestamp,
                    data_units_written: row.data_units_written,
                });
            }
            let Some(write_amount_bytes) = row.write_amount_bytes else {
                continue;
            };
            if stats.observe_threshold(
                row.timestamp,
                row.previous_timestamp,
                write_amount_bytes,
                expected_span_ms,
                threshold_gib,
            ) {
                break;
            }
        }
    }
    transaction
        .commit()
        .map_err(|source| startup_transaction_error("commit_stats_query", source))?;
    Ok(stats)
}

fn read_smart_stats_row(
    row: &rusqlite::Row<'_>,
    hash_id: &str,
) -> Result<SmartStatsRow, DbWriteError> {
    let timestamp = row
        .get::<_, i64>(0)
        .map_err(|source| stats_load_error(hash_id, source))?;
    let previous_timestamp = row
        .get::<_, Option<i64>>(1)
        .map_err(|source| stats_load_error(hash_id, source))?;
    let bytes = row
        .get::<_, Vec<u8>>(2)
        .map_err(|source| stats_load_error(hash_id, source))?;
    let write_amount_bytes = row
        .get::<_, Option<i64>>(3)
        .map_err(|source| stats_load_error(hash_id, source))?;
    Ok(SmartStatsRow {
        timestamp,
        previous_timestamp,
        data_units_written: decode_data_units_written(hash_id, timestamp, bytes)?,
        write_amount_bytes,
    })
}

fn stats_load_error(hash_id: &str, source: rusqlite::Error) -> DbWriteError {
    DbWriteError::LoadRecoveryState {
        hash_id: hash_id.to_owned(),
        source: Box::new(source),
    }
}

fn validate_existing_v1_read_only(connection: &Connection) -> Result<(), DbWriteError> {
    let user_version: i64 = connection
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|source| startup_transaction_error("read_user_version", source))?;
    match user_version {
        SUPPORTED_SCHEMA_VERSION => validate_v1_layout(connection),
        0 if !ndm_application_table_names(connection)?.is_empty() => {
            Err(DbWriteError::UnversionedNdmLayoutPresent)
        }
        found => Err(DbWriteError::UnsupportedSchemaVersion {
            found,
            supported: SUPPORTED_SCHEMA_VERSION,
        }),
    }
}

fn bytes_strictly_exceed_gib(write_amount_bytes: i64, threshold_gib: f64) -> bool {
    let Ok(write_amount_bytes) = u64::try_from(write_amount_bytes) else {
        return false;
    };
    let Some(threshold_floor_bytes) = gib_floor_bytes(threshold_gib) else {
        return false;
    };
    u128::from(write_amount_bytes) > threshold_floor_bytes
}

fn gib_floor_bytes(value: f64) -> Option<u128> {
    const FRACTION_BITS: i32 = 52;
    const EXPONENT_BIAS: i32 = 1023;
    const GIB_POWER: i32 = 30;
    const EXPONENT_MASK: u64 = 0x7ff;
    const FRACTION_MASK: u64 = (1_u64 << 52) - 1;

    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let bits = value.to_bits();
    let encoded_exponent = (bits >> 52) & EXPONENT_MASK;
    if encoded_exponent == 0 {
        return Some(0);
    }

    let exponent = i32::from(u16::try_from(encoded_exponent).ok()?) - EXPONENT_BIAS;
    let significand = (1_u64 << 52) | (bits & FRACTION_MASK);
    let byte_shift = exponent - FRACTION_BITS + GIB_POWER;
    if byte_shift >= 0 {
        if byte_shift >= 12 {
            return Some(u128::from(u64::MAX) + 1);
        }
        u128::from(significand).checked_shl(u32::try_from(byte_shift).ok()?)
    } else {
        let right_shift = byte_shift.unsigned_abs();
        if right_shift >= u128::BITS {
            Some(0)
        } else {
            Some(u128::from(significand) >> right_shift)
        }
    }
}

fn verify_sqlite_version(connection: &Connection) -> Result<(), DbWriteError> {
    let found: String = connection
        .query_row("SELECT sqlite_version();", [], |row| row.get(0))
        .map_err(|source| DbWriteError::Configure {
            pragma: "sqlite_version",
            source: Box::new(source),
        })?;
    let parsed = parse_version(&found).ok_or_else(|| DbWriteError::SqliteVersionTooOld {
        found: found.clone(),
        minimum: MINIMUM_SQLITE_VERSION,
    })?;
    if parsed < (3, 37, 0) {
        return Err(DbWriteError::SqliteVersionTooOld {
            found,
            minimum: MINIMUM_SQLITE_VERSION,
        });
    }
    Ok(())
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn configure_writer_connection(connection: &Connection) -> Result<(), DbWriteError> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
        .map_err(|source| DbWriteError::Configure {
            pragma: "journal_mode",
            source: Box::new(source),
        })?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(DbWriteError::WalModeUnavailable {
            actual: journal_mode,
        });
    }

    connection
        .execute_batch("PRAGMA synchronous = FULL;")
        .map_err(|source| DbWriteError::Configure {
            pragma: "synchronous",
            source: Box::new(source),
        })?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous;", [], |row| row.get(0))
        .map_err(|source| DbWriteError::Configure {
            pragma: "synchronous",
            source: Box::new(source),
        })?;
    if synchronous != 2 {
        return Err(DbWriteError::Configure {
            pragma: "synchronous",
            source: Box::new(std::io::Error::other(
                "SQLite did not enable FULL synchronous mode",
            )),
        });
    }

    configure_foreign_keys(connection)?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|source| DbWriteError::Configure {
            pragma: "busy_timeout",
            source: Box::new(source),
        })?;
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout;", [], |row| row.get(0))
        .map_err(|source| DbWriteError::Configure {
            pragma: "busy_timeout",
            source: Box::new(source),
        })?;
    if busy_timeout != 5_000 {
        return Err(DbWriteError::Configure {
            pragma: "busy_timeout",
            source: Box::new(std::io::Error::other(
                "SQLite did not apply the requested busy timeout",
            )),
        });
    }
    Ok(())
}

fn configure_foreign_keys(connection: &Connection) -> Result<(), DbWriteError> {
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(|source| DbWriteError::Configure {
            pragma: "foreign_keys",
            source: Box::new(source),
        })?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .map_err(|source| DbWriteError::Configure {
            pragma: "foreign_keys",
            source: Box::new(source),
        })?;
    if foreign_keys != 1 {
        return Err(DbWriteError::ForeignKeysUnavailable);
    }
    Ok(())
}

pub(crate) fn initialize_or_validate_v1(connection: &mut Connection) -> Result<(), DbWriteError> {
    let user_version: i64 = connection
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|source| startup_transaction_error("read_user_version", source))?;

    match user_version {
        0 => {
            if !ndm_application_table_names(connection)?.is_empty() {
                return Err(DbWriteError::UnversionedNdmLayoutPresent);
            }
            connection
                .execute_batch("BEGIN IMMEDIATE;")
                .map_err(|source| startup_transaction_error("begin", source))?;
            if let Err(error) = connection.execute_batch(GLOBAL_SCHEMA_SQL) {
                return rollback_startup(connection, "initialize_schema", error);
            }
            connection.execute_batch("COMMIT;").map_err(|source| {
                DbWriteError::CommitOutcomeUnknown {
                    request_id: 0,
                    source: Some(Box::new(source)),
                }
            })?;
        }
        SUPPORTED_SCHEMA_VERSION => {}
        found => {
            return Err(DbWriteError::UnsupportedSchemaVersion {
                found,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
    }

    validate_v1_layout(connection)
}

pub(crate) fn register_devices_startup(
    connection: &mut Connection,
    devices: &[DeviceRegistration],
) -> Result<(), DbWriteError> {
    validate_device_registrations(devices, 0)?;
    connection
        .execute_batch("BEGIN IMMEDIATE;")
        .map_err(|source| startup_transaction_error("begin", source))?;
    if let Err(error) = apply_device_registrations(connection, devices, 0) {
        let rollback = connection.execute_batch("ROLLBACK;");
        return match rollback {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(DbWriteError::RollbackFailed {
                request_id: 0,
                transaction_error: Box::new(error),
                rollback_error: Box::new(rollback_error),
            }),
        };
    }
    connection
        .execute_batch("COMMIT;")
        .map_err(|source| DbWriteError::CommitOutcomeUnknown {
            request_id: 0,
            source: Some(Box::new(source)),
        })?;
    validate_v1_layout(connection)
}

pub(super) fn validate_device_registrations(
    devices: &[DeviceRegistration],
    request_id: u64,
) -> Result<(), DbWriteError> {
    let mut hashes = HashSet::with_capacity(devices.len());
    let mut paths = HashSet::with_capacity(devices.len());
    for device in devices {
        let expected_hash = device_hash_id(&device.serial, &device.by_id_path).ok_or(
            DbWriteError::InvalidBatch {
                request_id,
                reason: super::BatchInvariant::UnsafeDeviceIdentifier,
            },
        )?;
        if !is_valid_hash_id(&device.hash_id) || expected_hash != device.hash_id {
            return Err(DbWriteError::InvalidBatch {
                request_id,
                reason: super::BatchInvariant::UnsafeDeviceIdentifier,
            });
        }
        if !hashes.insert(device.hash_id.as_str()) || !paths.insert(device.by_id_path.as_path()) {
            return Err(DbWriteError::InvalidBatch {
                request_id,
                reason: super::BatchInvariant::DuplicateWriterRecord,
            });
        }
    }
    Ok(())
}

pub(super) fn apply_device_registrations(
    connection: &Connection,
    devices: &[DeviceRegistration],
    request_id: u64,
) -> Result<(), DbWriteError> {
    for device in devices {
        let path = device
            .by_id_path
            .to_str()
            .ok_or(DbWriteError::InvalidBatch {
                request_id,
                reason: super::BatchInvariant::UnsafeDeviceIdentifier,
            })?;
        let existing = connection
            .query_row(
                "SELECT label, serial, linux_by_disk_path FROM devs WHERE hash_id = ?1;",
                [&device.hash_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| transaction_error(request_id, "register_device", source))?;

        if let Some((label, serial, stored_path)) = existing {
            if serial != device.serial || stored_path != path {
                return Err(DbWriteError::SchemaMismatch {
                    object: format!("devs:{}", device.hash_id),
                });
            }
            if label != device.label {
                connection
                    .execute(
                        "UPDATE devs SET label = ?1 WHERE hash_id = ?2;",
                        params![device.label, device.hash_id],
                    )
                    .map_err(|source| transaction_error(request_id, "register_device", source))?;
            }
        } else {
            let conflicting_hash: Option<String> = connection
                .query_row(
                    "SELECT hash_id FROM devs WHERE linux_by_disk_path = ?1;",
                    [path],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|source| transaction_error(request_id, "register_device", source))?;
            if conflicting_hash.is_some() {
                return Err(DbWriteError::SchemaMismatch {
                    object: "devs.linux_by_disk_path".to_owned(),
                });
            }
            connection
                .execute(
                    "INSERT INTO devs (hash_id, label, serial, linux_by_disk_path) VALUES (?1, ?2, ?3, ?4);",
                    params![device.hash_id, device.label, device.serial, path],
                )
                .map_err(|source| transaction_error(request_id, "register_device", source))?;
        }

        let tables = device_table_names(&device.hash_id)?;
        create_device_table_if_absent(
            connection,
            &tables.data_identifier,
            &canonical_data_table_sql(&device.hash_id),
            request_id,
        )?;
        create_device_table_if_absent(
            connection,
            &tables.writer_history_identifier,
            &canonical_writer_history_sql(&device.hash_id),
            request_id,
        )?;
    }
    Ok(())
}

fn create_device_table_if_absent(
    connection: &Connection,
    quoted_identifier: &str,
    create_sql: &str,
    request_id: u64,
) -> Result<(), DbWriteError> {
    let raw_name = quoted_identifier.trim_matches('"');
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1);",
            [raw_name],
            |row| row.get(0),
        )
        .map_err(|source| transaction_error(request_id, "register_device", source))?;
    if !exists {
        connection
            .execute_batch(create_sql)
            .map_err(|source| transaction_error(request_id, "register_device", source))?;
    }
    Ok(())
}

pub(crate) fn validated_device_tables(
    connection: &Connection,
) -> Result<HashMap<String, DeviceTableNames>, DbWriteError> {
    let mut statement = connection
        .prepare("SELECT hash_id, serial, linux_by_disk_path FROM devs ORDER BY hash_id;")
        .map_err(|source| startup_transaction_error("validate_schema", source))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|source| startup_transaction_error("validate_schema", source))?;

    let mut mappings = HashMap::new();
    for row in rows {
        let (hash_id, serial, path) =
            row.map_err(|source| startup_transaction_error("validate_schema", source))?;
        let expected = device_hash_id(&serial, Path::new(&path))
            .ok_or(DbWriteError::InvalidDeviceTableIdentifier)?;
        if expected != hash_id {
            return Err(DbWriteError::SchemaMismatch {
                object: format!("devs:{hash_id}"),
            });
        }
        let tables = device_table_names(&hash_id)?;
        mappings.insert(hash_id, tables);
    }
    Ok(mappings)
}

pub(super) fn load_recovery_state(
    connection: &Connection,
    tables: &HashMap<String, DeviceTableNames>,
) -> Result<HashMap<String, RecoveredSmartBaseline>, DbWriteError> {
    let mut recovery = HashMap::new();
    for (hash_id, names) in tables {
        let sql = format!(
            "SELECT timestamp, data_units_written_be FROM {} ORDER BY timestamp DESC LIMIT 1;",
            names.data_identifier
        );
        let stored = connection
            .query_row(&sql, [], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .optional()
            .map_err(|source| DbWriteError::LoadRecoveryState {
                hash_id: hash_id.clone(),
                source: Box::new(source),
            })?;
        let Some((timestamp, bytes)) = stored else {
            continue;
        };
        recovery.insert(
            hash_id.clone(),
            RecoveredSmartBaseline {
                timestamp,
                data_units_written: decode_data_units_written(hash_id, timestamp, bytes)?,
            },
        );
    }
    Ok(recovery)
}

fn decode_data_units_written(
    hash_id: &str,
    timestamp: i64,
    bytes: Vec<u8>,
) -> Result<u128, DbWriteError> {
    let actual_length = bytes.len();
    let bytes: [u8; 16] =
        bytes
            .try_into()
            .map_err(|_| DbWriteError::InvalidStoredSmartCounter {
                hash_id: hash_id.to_owned(),
                timestamp,
                actual_length,
            })?;
    Ok(u128::from_be_bytes(bytes))
}

pub(super) fn validate_v1_layout(connection: &Connection) -> Result<(), DbWriteError> {
    validate_schema_sql(connection, "devs", canonical_devs_sql())?;
    validate_schema_sql(connection, "workloads", canonical_workloads_sql())?;
    validate_reserved_workload(connection)?;

    let mappings = validated_device_tables(connection)?;
    let mut expected_names = HashSet::from(["devs".to_owned(), "workloads".to_owned()]);
    for names in mappings.values() {
        let data_name = names.data_identifier.trim_matches('"');
        let history_name = names.writer_history_identifier.trim_matches('"');
        validate_schema_sql(
            connection,
            data_name,
            &canonical_data_table_sql(&names.hash_id),
        )?;
        validate_schema_sql(
            connection,
            history_name,
            &canonical_writer_history_sql(&names.hash_id),
        )?;
        expected_names.insert(data_name.to_owned());
        expected_names.insert(history_name.to_owned());
    }

    let actual_names: HashSet<String> = ndm_application_table_names(connection)?
        .into_iter()
        .collect();
    if actual_names != expected_names {
        return Err(DbWriteError::SchemaMismatch {
            object: "application table set".to_owned(),
        });
    }

    let foreign_key_problem: Option<String> = connection
        .query_row("PRAGMA foreign_key_check;", [], |row| row.get(0))
        .optional()
        .map_err(|source| startup_transaction_error("validate_schema", source))?;
    if let Some(table) = foreign_key_problem {
        return Err(DbWriteError::SchemaMismatch {
            object: format!("foreign key:{table}"),
        });
    }
    Ok(())
}

fn validate_schema_sql(
    connection: &Connection,
    name: &str,
    expected_sql: &str,
) -> Result<(), DbWriteError> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1;",
            [name],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| startup_transaction_error("validate_schema", source))?;
    let Some(actual) = actual else {
        return Err(DbWriteError::SchemaMismatch {
            object: name.to_owned(),
        });
    };
    if normalize_schema_sql(&actual) != normalize_schema_sql(expected_sql) {
        return Err(DbWriteError::SchemaMismatch {
            object: name.to_owned(),
        });
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    let mut in_string_literal = false;

    while let Some(character) = characters.next() {
        if character == '\'' {
            normalized.push(character);
            if in_string_literal && characters.peek() == Some(&'\'') {
                normalized.push(characters.next().unwrap_or('\''));
            } else {
                in_string_literal = !in_string_literal;
            }
        } else if in_string_literal {
            normalized.push(character);
        } else if !character.is_ascii_whitespace() && character != ';' {
            normalized.extend(character.to_lowercase());
        }
    }

    normalized
}

fn validate_reserved_workload(connection: &Connection) -> Result<(), DbWriteError> {
    let by_id: Option<String> = connection
        .query_row(
            "SELECT name FROM workloads WHERE workload_id = ?1;",
            [RESERVED_WORKLOAD_ID],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| startup_transaction_error("validate_reserved_workload", source))?;
    let by_name: Option<i64> = connection
        .query_row(
            "SELECT workload_id FROM workloads WHERE name = ?1;",
            [RESERVED_WORKLOAD_NAME],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| startup_transaction_error("validate_reserved_workload", source))?;
    if by_id.as_deref() != Some(RESERVED_WORKLOAD_NAME) || by_name != Some(RESERVED_WORKLOAD_ID) {
        return Err(DbWriteError::ReservedWorkloadInvalid);
    }
    Ok(())
}

fn ndm_application_table_names(connection: &Connection) -> Result<Vec<String>, DbWriteError> {
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name;")
        .map_err(|source| startup_transaction_error("inspect_schema", source))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|source| startup_transaction_error("inspect_schema", source))?;
    let mut names = Vec::new();
    for row in rows {
        let name = row.map_err(|source| startup_transaction_error("inspect_schema", source))?;
        if is_ndm_application_table_name(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

fn is_ndm_application_table_name(name: &str) -> bool {
    name == "devs"
        || name == "workloads"
        || (name.starts_with("d_")
            && (name.ends_with("_data") || name.ends_with("_writer_history")))
}

fn canonical_devs_sql() -> &'static str {
    r"CREATE TABLE devs (
        hash_id TEXT NOT NULL PRIMARY KEY
            CHECK (length(hash_id) = 64 AND hash_id NOT GLOB '*[^0-9a-f]*'),
        label TEXT NOT NULL,
        serial TEXT NOT NULL,
        linux_by_disk_path TEXT NOT NULL UNIQUE
    ) STRICT, WITHOUT ROWID;"
}

fn canonical_workloads_sql() -> &'static str {
    r"CREATE TABLE workloads (
        workload_id INTEGER PRIMARY KEY CHECK (workload_id >= 0),
        name TEXT NOT NULL UNIQUE CHECK (length(name) > 0)
    ) STRICT;"
}

fn canonical_data_table_sql(hash_id: &str) -> String {
    format!(
        r#"CREATE TABLE "d_{hash_id}_data" (
            hash_id TEXT NOT NULL DEFAULT '{hash_id}'
                REFERENCES devs(hash_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
            timestamp INTEGER NOT NULL PRIMARY KEY CHECK (timestamp >= 0),
            data_units_written_be BLOB NOT NULL CHECK (length(data_units_written_be) = 16),
            write_amount_bytes INTEGER
                CHECK (write_amount_bytes IS NULL OR write_amount_bytes >= 0),
            write_amount_gib REAL GENERATED ALWAYS AS
                (write_amount_bytes / 1073741824.0) VIRTUAL,
            CHECK (hash_id = '{hash_id}')
        ) STRICT, WITHOUT ROWID;"#
    )
}

fn canonical_writer_history_sql(hash_id: &str) -> String {
    format!(
        r#"CREATE TABLE "d_{hash_id}_writer_history" (
            hash_id TEXT NOT NULL DEFAULT '{hash_id}'
                REFERENCES devs(hash_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
            timestamp INTEGER NOT NULL
                CHECK (timestamp >= 0 AND timestamp % 60000 = 0),
            workload_id INTEGER NOT NULL
                REFERENCES workloads(workload_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
            write_amount_bytes INTEGER NOT NULL CHECK (write_amount_bytes >= 0),
            PRIMARY KEY (timestamp, workload_id),
            CHECK (
                (workload_id = 0 AND write_amount_bytes = 0)
                OR (workload_id > 0 AND write_amount_bytes > 0)
            ),
            CHECK (hash_id = '{hash_id}')
        ) STRICT, WITHOUT ROWID;"#
    )
}

fn transaction_error(
    request_id: u64,
    stage: &'static str,
    source: rusqlite::Error,
) -> DbWriteError {
    DbWriteError::Transaction {
        request_id,
        stage,
        source: Box::new(source),
    }
}

fn startup_transaction_error(stage: &'static str, source: rusqlite::Error) -> DbWriteError {
    transaction_error(0, stage, source)
}

fn rollback_startup<T>(
    connection: &Connection,
    stage: &'static str,
    transaction_error: rusqlite::Error,
) -> Result<T, DbWriteError> {
    match connection.execute_batch("ROLLBACK;") {
        Ok(()) => Err(startup_transaction_error(stage, transaction_error)),
        Err(rollback_error) => Err(DbWriteError::RollbackFailed {
            request_id: 0,
            transaction_error: Box::new(transaction_error),
            rollback_error: Box::new(rollback_error),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn registration(serial: &str, suffix: &str) -> DeviceRegistration {
        let path = PathBuf::from(format!("/dev/disk/by-id/{suffix}"));
        DeviceRegistration {
            hash_id: device_hash_id(serial, &path).expect("test path is UTF-8"),
            label: suffix.to_owned(),
            serial: serial.to_owned(),
            by_id_path: path,
            major: 259,
            minor: 0,
        }
    }

    #[test]
    fn hash_id_has_stable_framing_and_validation() {
        let path = Path::new("/dev/disk/by-id/nvme-test");
        let hash = device_hash_id("SERIAL", path).expect("UTF-8 path");
        assert_eq!(
            hash,
            "68d073128688e22e68645aee9d9b53a934e1df107892cd90581855bc6c30aa44"
        );
        assert!(is_valid_hash_id(&hash));
        assert!(!is_valid_hash_id(&hash.to_uppercase()));
        assert!(!is_valid_hash_id("abc"));
    }

    #[test]
    fn schema_normalization_preserves_string_literal_case() {
        assert_eq!(
            normalize_schema_sql("CREATE TABLE T (value TEXT DEFAULT 'Ab''Cd');"),
            "createtablet(valuetextdefault'Ab''Cd')"
        );
    }

    #[test]
    fn initializes_file_database_and_reopens_version_one_layout() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("stats.db");
        let device = registration("SERIAL-0", "nvme-test-0");

        {
            let mut connection = open_writer_connection(&path).expect("open writer");
            initialize_or_validate_v1(&mut connection).expect("initialize schema");
            register_devices_startup(&mut connection, std::slice::from_ref(&device))
                .expect("register device");
            let version: i64 = connection
                .query_row("PRAGMA user_version;", [], |row| row.get(0))
                .expect("user version");
            let journal: String = connection
                .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
                .expect("journal mode");
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%';",
                    [],
                    |row| row.get(0),
                )
                .expect("table count");
            assert_eq!(version, 1);
            assert_eq!(journal, "wal");
            assert_eq!(count, 4);
        }

        let mut reopened = open_writer_connection(&path).expect("reopen writer");
        initialize_or_validate_v1(&mut reopened).expect("validate existing schema");
        register_devices_startup(&mut reopened, &[device]).expect("verify device");
    }

    #[test]
    fn rejects_future_schema_and_mismatched_layout() {
        let directory = tempdir().expect("temp directory");
        let future_path = directory.path().join("future.db");
        let mut future = open_writer_connection(&future_path).expect("open future DB");
        future
            .execute_batch("PRAGMA user_version = 2;")
            .expect("set future version");
        assert!(matches!(
            initialize_or_validate_v1(&mut future),
            Err(DbWriteError::UnsupportedSchemaVersion { found: 2, .. })
        ));

        let mismatch_path = directory.path().join("mismatch.db");
        let mut mismatch = open_writer_connection(&mismatch_path).expect("open mismatch DB");
        initialize_or_validate_v1(&mut mismatch).expect("initialize mismatch DB");
        mismatch
            .execute_batch("ALTER TABLE devs ADD COLUMN unexpected TEXT;")
            .expect("alter schema");
        assert!(matches!(
            initialize_or_validate_v1(&mut mismatch),
            Err(DbWriteError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn rejects_unversioned_ndm_layout() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("unversioned.db");
        let mut connection = open_writer_connection(&path).expect("open DB");
        connection
            .execute_batch("CREATE TABLE devs (hash_id TEXT);")
            .expect("create conflicting table");
        assert!(matches!(
            initialize_or_validate_v1(&mut connection),
            Err(DbWriteError::UnversionedNdmLayoutPresent)
        ));
    }

    #[test]
    fn recovery_decodes_last_committed_counter() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("recovery.db");
        let device = registration("SERIAL-1", "nvme-test-1");
        let mut connection = open_writer_connection(&path).expect("open DB");
        initialize_or_validate_v1(&mut connection).expect("initialize DB");
        register_devices_startup(&mut connection, std::slice::from_ref(&device))
            .expect("register device");
        let names = device_table_names(&device.hash_id).expect("table names");
        let sql = format!(
            "INSERT INTO {} (hash_id, timestamp, data_units_written_be, write_amount_bytes) VALUES (?1, ?2, ?3, NULL);",
            names.data_identifier
        );
        connection
            .execute(
                &sql,
                params![device.hash_id, 123_i64, 42_u128.to_be_bytes()],
            )
            .expect("insert counter");
        let mappings = validated_device_tables(&connection).expect("mappings");
        let recovery = load_recovery_state(&connection, &mappings).expect("recovery");
        assert_eq!(
            recovery.get(&device.hash_id),
            Some(&RecoveredSmartBaseline {
                timestamp: 123,
                data_units_written: 42,
            })
        );
    }

    #[test]
    fn read_only_stats_returns_latest_sample_and_strict_threshold_breach() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("stats.db");
        let device = registration("SERIAL-STATS", "nvme-test-stats");
        let mut connection = open_writer_connection(&path).expect("open DB");
        initialize_or_validate_v1(&mut connection).expect("initialize DB");
        register_devices_startup(&mut connection, std::slice::from_ref(&device))
            .expect("register device");
        assert_eq!(
            read_smart_device_stats(&path, &device.serial, &device.by_id_path, 1, 1.0)
                .expect("query empty stats"),
            SmartDeviceStats {
                latest_sample: None,
                last_threshold_timestamp: None,
            }
        );
        let names = device_table_names(&device.hash_id).expect("table names");
        let insert = format!(
            "INSERT INTO {} (hash_id, timestamp, data_units_written_be, write_amount_bytes) \
             VALUES (?1, ?2, ?3, ?4);",
            names.data_identifier
        );
        for (timestamp, counter, amount) in [
            (0_i64, 1_u128, None),
            (3_600_000, 2, Some(1_073_741_824_i64)),
            (7_200_000, 3, Some(1_073_741_825_i64)),
            (10_860_001, 9_564_528, Some(2_147_483_648_i64)),
        ] {
            connection
                .execute(
                    &insert,
                    params![device.hash_id, timestamp, counter.to_be_bytes(), amount],
                )
                .expect("insert SMART row");
        }
        drop(connection);

        let stats = read_smart_device_stats(&path, &device.serial, &device.by_id_path, 1, 1.0)
            .expect("query stats");
        assert_eq!(
            stats.latest_sample,
            Some(LatestSmartSample {
                timestamp: 10_860_001,
                data_units_written: 9_564_528,
            })
        );
        assert_eq!(stats.last_threshold_timestamp, Some(7_200_000));

        let without_breach =
            read_smart_device_stats(&path, &device.serial, &device.by_id_path, 1, 3.0)
                .expect("query stats without match");
        assert_eq!(without_breach.latest_sample, stats.latest_sample);
        assert_eq!(without_breach.last_threshold_timestamp, None);
    }

    #[test]
    fn read_only_stats_does_not_create_a_missing_database() {
        let directory = tempdir().expect("temp directory");
        let path = directory.path().join("missing.db");
        assert!(matches!(
            read_smart_device_stats(
                &path,
                "SERIAL",
                Path::new("/dev/disk/by-id/missing"),
                1,
                1.0,
            ),
            Err(DbWriteError::Open { .. })
        ));
        assert!(!path.exists());
    }
}
