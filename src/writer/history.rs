use std::{
    collections::HashMap,
    error::Error,
    fmt,
    num::{NonZeroU32, NonZeroUsize},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, ErrorCode, TransactionBehavior};

use crate::{
    ErrorSource,
    database::{DbWriteError, DeviceRegistration, DeviceTableNames, open_query_connection},
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WriterRank {
    pub(crate) name: String,
    pub(crate) w_amount_mib: f64,
}

pub(crate) enum RankError {
    DeviceNotMonitored {
        path: PathBuf,
    },
    DeviceResolution {
        path: PathBuf,
        source: std::io::Error,
    },
    InvalidDeviceIdentity {
        path: PathBuf,
    },
    IncompleteHistory {
        start_timestamp: i64,
        end_timestamp: i64,
        expected_buckets: u32,
        complete_buckets: u32,
    },
    ClockBeforeUnixEpoch(std::time::SystemTimeError),
    QueryParameterOutOfRange {
        parameter: &'static str,
    },
    AmountOutOfRange,
    DatabaseBusy {
        operation: &'static str,
        source: ErrorSource,
    },
    DatabaseQuery {
        operation: &'static str,
        source: ErrorSource,
    },
}

impl fmt::Display for RankError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceNotMonitored { path } => write!(
                formatter,
                "device is not monitored: {}",
                log_safe_path(path)
            ),
            Self::DeviceResolution { path, .. } => write!(
                formatter,
                "cannot resolve monitored device {}",
                log_safe_path(path)
            ),
            Self::InvalidDeviceIdentity { path } => write!(
                formatter,
                "monitored device identity changed: {}",
                log_safe_path(path)
            ),
            Self::IncompleteHistory {
                start_timestamp,
                end_timestamp,
                expected_buckets,
                complete_buckets,
            } => write!(
                formatter,
                "writer history [{start_timestamp}, {end_timestamp}) is incomplete: expected {expected_buckets} bucket(s), found {complete_buckets}"
            ),
            Self::ClockBeforeUnixEpoch(_) => {
                formatter.write_str("system clock is before the Unix epoch")
            }
            Self::QueryParameterOutOfRange { parameter } => {
                write!(
                    formatter,
                    "writer ranking parameter is out of range: {parameter}"
                )
            }
            Self::AmountOutOfRange => {
                formatter.write_str("writer ranking amount is outside the supported range")
            }
            Self::DatabaseBusy { operation, .. } => {
                write!(
                    formatter,
                    "state database is busy during writer ranking {operation}"
                )
            }
            Self::DatabaseQuery { operation, .. } => {
                write!(formatter, "state database query failed during {operation}")
            }
        }
    }
}

impl fmt::Debug for RankError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for RankError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DeviceResolution { source, .. } => Some(source),
            Self::ClockBeforeUnixEpoch(source) => Some(source),
            Self::DatabaseBusy { source, .. } | Self::DatabaseQuery { source, .. } => {
                Some(source.as_ref())
            }
            Self::DeviceNotMonitored { .. }
            | Self::InvalidDeviceIdentity { .. }
            | Self::IncompleteHistory { .. }
            | Self::QueryParameterOutOfRange { .. }
            | Self::AmountOutOfRange => None,
        }
    }
}

impl From<std::time::SystemTimeError> for RankError {
    fn from(source: std::time::SystemTimeError) -> Self {
        Self::ClockBeforeUnixEpoch(source)
    }
}

#[derive(Debug, Clone)]
struct QueryDevice {
    writer_history_identifier: String,
    major: u32,
    minor: u32,
}

pub(crate) struct WriterHistory {
    connection: Mutex<Connection>,
    devices: HashMap<PathBuf, QueryDevice>,
}

impl WriterHistory {
    pub(crate) fn open(
        path: &Path,
        devices: &[DeviceRegistration],
        tables: &HashMap<String, DeviceTableNames>,
    ) -> Result<Self, DbWriteError> {
        let connection = open_query_connection(path)?;
        let mut query_devices = HashMap::with_capacity(devices.len());
        for device in devices {
            let table =
                tables
                    .get(&device.hash_id)
                    .ok_or_else(|| DbWriteError::SchemaMismatch {
                        object: format!("device mapping:{}", device.hash_id),
                    })?;
            query_devices.insert(
                device.by_id_path.clone(),
                QueryDevice {
                    writer_history_identifier: table.writer_history_identifier.clone(),
                    major: device.major,
                    minor: device.minor,
                },
            );
        }
        Ok(Self {
            connection: Mutex::new(connection),
            devices: query_devices,
        })
    }

    // This is the clock-based public query contract from the design brief.
    // Alert delivery uses the event-bound variant below so delayed work cannot
    // silently move the requested UTC window.
    #[allow(dead_code)]
    pub(crate) fn top_writers(
        &self,
        device_by_id: &Path,
        limit: NonZeroUsize,
        lookback_minutes: NonZeroU32,
    ) -> Result<Vec<WriterRank>, RankError> {
        let device =
            self.devices
                .get(device_by_id)
                .ok_or_else(|| RankError::DeviceNotMonitored {
                    path: device_by_id.to_path_buf(),
                })?;
        verify_device_identity(device_by_id, device)?;
        let duration = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let now_ms = i64::try_from(duration.as_millis()).map_err(|_| {
            RankError::QueryParameterOutOfRange {
                parameter: "current_time",
            }
        })?;
        let end_timestamp = minute_floor(now_ms).ok_or(RankError::QueryParameterOutOfRange {
            parameter: "current_time",
        })?;
        self.query_top_writers(device, limit, lookback_minutes, end_timestamp)
    }

    pub(crate) fn top_writers_ending_at(
        &self,
        device_by_id: &Path,
        limit: NonZeroUsize,
        lookback_minutes: NonZeroU32,
        end_timestamp: i64,
    ) -> Result<Vec<WriterRank>, RankError> {
        let device =
            self.devices
                .get(device_by_id)
                .ok_or_else(|| RankError::DeviceNotMonitored {
                    path: device_by_id.to_path_buf(),
                })?;
        verify_device_identity(device_by_id, device)?;
        if end_timestamp < 0 || end_timestamp.rem_euclid(60_000) != 0 {
            return Err(RankError::QueryParameterOutOfRange {
                parameter: "end_timestamp",
            });
        }
        self.query_top_writers(device, limit, lookback_minutes, end_timestamp)
    }

    fn query_top_writers(
        &self,
        device: &QueryDevice,
        limit: NonZeroUsize,
        lookback_minutes: NonZeroU32,
        end_timestamp: i64,
    ) -> Result<Vec<WriterRank>, RankError> {
        let lookback_ms = i64::from(lookback_minutes.get())
            .checked_mul(60_000)
            .ok_or(RankError::QueryParameterOutOfRange {
                parameter: "lookback_minutes",
            })?;
        let start_timestamp =
            end_timestamp
                .checked_sub(lookback_ms)
                .ok_or(RankError::QueryParameterOutOfRange {
                    parameter: "lookback_minutes",
                })?;
        if start_timestamp < 0 {
            return Err(RankError::QueryParameterOutOfRange {
                parameter: "lookback_minutes",
            });
        }
        let sqlite_limit = i64::try_from(limit.get())
            .map_err(|_| RankError::QueryParameterOutOfRange { parameter: "limit" })?;

        let mut connection = self
            .connection
            .lock()
            .map_err(|_| RankError::DatabaseQuery {
                operation: "lock_query_connection",
                source: Box::new(std::io::Error::other(
                    "writer history query connection lock is poisoned",
                )),
            })?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|source| map_query_error("begin_read_transaction", source))?;

        let coverage_sql = format!(
            "SELECT COUNT(*) \
             FROM {} AS h \
             JOIN workloads AS w ON w.workload_id = h.workload_id \
             WHERE h.timestamp >= ?1 AND h.timestamp < ?2 \
             AND w.name = 'ndm:_bucket_complete';",
            device.writer_history_identifier
        );
        let complete_count: i64 = transaction
            .query_row(&coverage_sql, [start_timestamp, end_timestamp], |row| {
                row.get(0)
            })
            .map_err(|source| map_query_error("check_history_coverage", source))?;
        let complete_buckets =
            u32::try_from(complete_count).map_err(|_| RankError::AmountOutOfRange)?;
        let expected_buckets = lookback_minutes.get();
        if complete_buckets != expected_buckets {
            transaction
                .rollback()
                .map_err(|source| map_query_error("rollback_incomplete_query", source))?;
            return Err(RankError::IncompleteHistory {
                start_timestamp,
                end_timestamp,
                expected_buckets,
                complete_buckets,
            });
        }

        let ranking_sql = format!(
            "SELECT w.name, SUM(h.write_amount_bytes) / 1048576.0 AS w_amount_mib \
             FROM {} AS h \
             JOIN workloads AS w ON w.workload_id = h.workload_id \
             WHERE h.timestamp >= ?1 AND h.timestamp < ?2 AND w.workload_id <> 0 \
             GROUP BY h.workload_id, w.name \
             HAVING SUM(h.write_amount_bytes) > 0 \
             ORDER BY SUM(h.write_amount_bytes) DESC, w.name ASC \
             LIMIT ?3;",
            device.writer_history_identifier
        );
        let ranks = {
            let mut statement = transaction
                .prepare(&ranking_sql)
                .map_err(|source| map_query_error("prepare_ranking", source))?;
            let mut rows = statement
                .query([start_timestamp, end_timestamp, sqlite_limit])
                .map_err(map_amount_or_query_error)?;
            let mut ranks = Vec::new();
            while let Some(row) = rows.next().map_err(map_amount_or_query_error)? {
                let name = row.get::<_, String>(0).map_err(map_amount_or_query_error)?;
                let w_amount_mib = row.get::<_, f64>(1).map_err(map_amount_or_query_error)?;
                if !w_amount_mib.is_finite() || w_amount_mib < 0.0 {
                    return Err(RankError::AmountOutOfRange);
                }
                ranks.push(WriterRank { name, w_amount_mib });
            }
            ranks
        };
        transaction
            .commit()
            .map_err(|source| map_query_error("commit_read_transaction", source))?;
        Ok(ranks)
    }
}

#[allow(dead_code)]
fn minute_floor(timestamp: i64) -> Option<i64> {
    timestamp
        .checked_div(60_000)
        .and_then(|minutes| minutes.checked_mul(60_000))
}

fn verify_device_identity(path: &Path, expected: &QueryDevice) -> Result<(), RankError> {
    let metadata = std::fs::metadata(path).map_err(|source| RankError::DeviceResolution {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_block_device() {
        return Err(RankError::InvalidDeviceIdentity {
            path: path.to_path_buf(),
        });
    }
    let Some((major, minor)) = linux_device_number(metadata.rdev()) else {
        return Err(RankError::InvalidDeviceIdentity {
            path: path.to_path_buf(),
        });
    };
    if major != expected.major || minor != expected.minor {
        return Err(RankError::InvalidDeviceIdentity {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn linux_device_number(device: u64) -> Option<(u32, u32)> {
    let major = ((device >> 8) & 0x0fff) | ((device >> 32) & 0xffff_f000);
    let minor = (device & 0x00ff) | ((device >> 12) & 0xffff_ff00);
    Some((u32::try_from(major).ok()?, u32::try_from(minor).ok()?))
}

fn map_query_error(operation: &'static str, source: rusqlite::Error) -> RankError {
    if matches!(
        source.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    ) {
        RankError::DatabaseBusy {
            operation,
            source: Box::new(source),
        }
    } else {
        RankError::DatabaseQuery {
            operation,
            source: Box::new(source),
        }
    }
}

fn map_amount_or_query_error(source: rusqlite::Error) -> RankError {
    if matches!(
        &source,
        rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("integer overflow")
    ) {
        RankError::AmountOutOfRange
    } else {
        map_query_error("read_ranking", source)
    }
}

fn log_safe_path(path: &Path) -> String {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut escaped = String::new();
    for byte in bytes.iter().take(256) {
        escaped.extend(std::ascii::escape_default(*byte).map(char::from));
    }
    if bytes.len() > 256 {
        escaped.push_str("...");
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{
        DeviceRegistration,
        schema::{
            device_hash_id, device_table_names, initialize_or_validate_v1, open_writer_connection,
            register_devices_startup, validated_device_tables,
        },
    };
    use rusqlite::params;
    use tempfile::tempdir;

    fn registration() -> DeviceRegistration {
        let path = PathBuf::from("/dev/disk/by-id/history-test");
        DeviceRegistration {
            hash_id: device_hash_id("HISTORY-SERIAL", &path).expect("UTF-8 path"),
            label: "history test".to_owned(),
            serial: "HISTORY-SERIAL".to_owned(),
            by_id_path: path,
            major: 259,
            minor: 3,
        }
    }

    fn setup_history() -> (
        tempfile::TempDir,
        DeviceRegistration,
        WriterHistory,
        QueryDevice,
    ) {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("stats.db");
        let device = registration();
        let mut writer = open_writer_connection(&path).expect("open writer");
        initialize_or_validate_v1(&mut writer).expect("initialize DB");
        register_devices_startup(&mut writer, std::slice::from_ref(&device))
            .expect("register device");
        drop(writer);
        let tables = {
            let writer = open_writer_connection(&path).expect("reopen writer");
            validated_device_tables(&writer).expect("table mappings")
        };
        let history = WriterHistory::open(&path, std::slice::from_ref(&device), &tables)
            .expect("open history");
        let table = tables.get(&device.hash_id).expect("device table");
        let query_device = QueryDevice {
            writer_history_identifier: table.writer_history_identifier.clone(),
            major: device.major,
            minor: device.minor,
        };
        (directory, device, history, query_device)
    }

    fn insert_bucket(
        path: &Path,
        device: &DeviceRegistration,
        timestamp: i64,
        amounts: &[(&str, i64)],
    ) {
        let connection = open_writer_connection(path).expect("open writer");
        let table = device_table_names(&device.hash_id).expect("table name");
        for (name, amount) in amounts {
            connection
                .execute(
                    "INSERT INTO workloads(name) VALUES (?1) ON CONFLICT(name) DO NOTHING;",
                    [name],
                )
                .expect("insert workload");
            let workload_id: i64 = connection
                .query_row(
                    "SELECT workload_id FROM workloads WHERE name = ?1;",
                    [name],
                    |row| row.get(0),
                )
                .expect("workload ID");
            connection
                .execute(
                    &format!(
                        "INSERT INTO {} (hash_id, timestamp, workload_id, write_amount_bytes) VALUES (?1, ?2, ?3, ?4);",
                        table.writer_history_identifier
                    ),
                    params![device.hash_id, timestamp, workload_id, amount],
                )
                .expect("insert amount");
        }
        connection
            .execute(
                &format!(
                    "INSERT INTO {} (hash_id, timestamp, workload_id, write_amount_bytes) VALUES (?1, ?2, 0, 0);",
                    table.writer_history_identifier
                ),
                params![device.hash_id, timestamp],
            )
            .expect("insert completion marker");
    }

    #[test]
    fn ranks_complete_window_with_stable_ties_and_limit() {
        let (directory, device, history, query_device) = setup_history();
        let path = directory.path().join("stats.db");
        insert_bucket(
            &path,
            &device,
            0,
            &[("systemd:system:z.service", 1_048_576)],
        );
        insert_bucket(
            &path,
            &device,
            60_000,
            &[
                ("systemd:system:a.service", 1_048_576),
                ("systemd:system:z.service", 1_048_576),
            ],
        );
        let ranks = history
            .query_top_writers(
                &query_device,
                NonZeroUsize::new(2).expect("nonzero"),
                NonZeroU32::new(2).expect("nonzero"),
                120_000,
            )
            .expect("ranking");
        assert_eq!(ranks.len(), 2);
        assert_eq!(ranks[0].name, "systemd:system:z.service");
        assert!((ranks[0].w_amount_mib - 2.0).abs() < f64::EPSILON);
        assert_eq!(ranks[1].name, "systemd:system:a.service");
        assert!((ranks[1].w_amount_mib - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn equal_amounts_are_sorted_by_name() {
        let (directory, device, history, query_device) = setup_history();
        let path = directory.path().join("stats.db");
        insert_bucket(
            &path,
            &device,
            0,
            &[
                ("systemd:system:z.service", 512),
                ("systemd:system:a.service", 512),
            ],
        );
        let ranks = history
            .query_top_writers(
                &query_device,
                NonZeroUsize::new(1).expect("nonzero"),
                NonZeroU32::new(1).expect("nonzero"),
                60_000,
            )
            .expect("ranking");
        assert_eq!(ranks[0].name, "systemd:system:a.service");
    }

    #[test]
    fn complete_empty_window_returns_empty_vector() {
        let (directory, device, history, query_device) = setup_history();
        insert_bucket(&directory.path().join("stats.db"), &device, 0, &[]);
        let ranks = history
            .query_top_writers(
                &query_device,
                NonZeroUsize::new(10).expect("nonzero"),
                NonZeroU32::new(1).expect("nonzero"),
                60_000,
            )
            .expect("empty ranking");
        assert!(ranks.is_empty());
    }

    #[test]
    fn incomplete_window_is_not_shortened() {
        let (directory, device, history, query_device) = setup_history();
        insert_bucket(&directory.path().join("stats.db"), &device, 60_000, &[]);
        let error = history
            .query_top_writers(
                &query_device,
                NonZeroUsize::new(10).expect("nonzero"),
                NonZeroU32::new(2).expect("nonzero"),
                120_000,
            )
            .expect_err("history must be incomplete");
        assert!(matches!(
            error,
            RankError::IncompleteHistory {
                start_timestamp: 0,
                end_timestamp: 120_000,
                expected_buckets: 2,
                complete_buckets: 1,
            }
        ));
    }

    #[test]
    fn unknown_device_is_rejected_before_resolution() {
        let (_directory, _device, history, _query_device) = setup_history();
        let error = history
            .top_writers(
                Path::new("/dev/disk/by-id/not-monitored"),
                NonZeroUsize::new(1).expect("nonzero"),
                NonZeroU32::new(1).expect("nonzero"),
            )
            .expect_err("unknown device must fail");
        assert!(matches!(error, RankError::DeviceNotMonitored { .. }));
    }

    #[test]
    fn dynamic_path_is_escaped_in_error_display() {
        let error = RankError::DeviceNotMonitored {
            path: PathBuf::from("/dev/test\n\x1b[31m"),
        };
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains('\n'));
            assert!(!rendered.contains('\u{1b}'));
            assert!(rendered.contains("\\n"));
        }
    }
}
