use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize},
        mpsc::{Receiver, channel, sync_channel},
    },
    thread,
    time::Duration,
};

use rusqlite::{Connection, ErrorCode, params};

use super::{
    BatchInvariant, CommitAck, CompleteDeviceBucket, DATABASE_QUEUE_CAPACITY, DatabaseBatch,
    DatabaseHandle, DatabaseRuntime, DbRequest, DbWriteError, DeviceRegistration,
    REQUEST_EXECUTING, RecoveredSmartBaseline, SmartSampleBatch, WriterBucketBatch,
    schema::{
        self, DeviceTableNames, apply_device_registrations, initialize_or_validate_v1,
        load_recovery_state, open_writer_connection, register_devices_startup,
        validate_device_registrations, validated_device_tables,
    },
};
use crate::writer::history::WriterHistory;

const MAX_BATCH_ATTEMPTS: usize = 3;
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(50);

type WriterInitialization = (
    Connection,
    HashMap<String, DeviceTableNames>,
    HashMap<String, RecoveredSmartBaseline>,
);

enum StartupMessage {
    Ready {
        recovery: HashMap<String, RecoveredSmartBaseline>,
        tables: HashMap<String, DeviceTableNames>,
    },
    Failed,
}

pub(crate) fn start_database(
    path: &Path,
    devices: &[DeviceRegistration],
) -> Result<DatabaseRuntime, DbWriteError> {
    let path = path.to_path_buf();
    let devices = devices.to_vec();
    let (request_sender, request_receiver) = sync_channel(DATABASE_QUEUE_CAPACITY);
    let (startup_sender, startup_receiver) = channel();
    let writer_path = path.clone();
    let writer_devices = devices.clone();

    let task = thread::Builder::new()
        .name("ndm-database-writer".to_owned())
        .spawn(move || {
            let startup = initialize_writer(&writer_path, &writer_devices);
            let (connection, tables, recovery) = match startup {
                Ok(values) => values,
                Err(error) => {
                    let _ = startup_sender.send(StartupMessage::Failed);
                    return Err(error);
                }
            };
            if startup_sender
                .send(StartupMessage::Ready {
                    recovery,
                    tables: tables.clone(),
                })
                .is_err()
            {
                return Err(DbWriteError::QueueClosed);
            }
            run_writer(connection, &writer_path, tables, &request_receiver)
        })
        .map_err(|source| DbWriteError::Open {
            path: path.clone(),
            source: Box::new(source),
        })?;

    let startup = startup_receiver.recv();
    let (recovery, tables) = match startup {
        Ok(StartupMessage::Ready { recovery, tables }) => (recovery, tables),
        Ok(StartupMessage::Failed) | Err(_) => {
            let writer_result = task.join().map_err(|_| writer_panicked_error())?;
            return match writer_result {
                Err(error) => Err(error),
                Ok(()) => Err(DbWriteError::Open {
                    path,
                    source: Box::new(std::io::Error::other(
                        "database writer exited during startup",
                    )),
                }),
            };
        }
    };

    let history = match WriterHistory::open(&path, &devices, &tables) {
        Ok(history) => history,
        Err(error) => {
            drop(request_sender);
            let _ = task.join();
            return Err(error);
        }
    };

    let unconfirmed_requests = Arc::new(AtomicUsize::new(0));
    let handle = DatabaseHandle {
        sender: request_sender,
        next_request_id: Arc::new(AtomicU64::new(1)),
        pending_smart: Arc::new(Mutex::new(HashSet::new())),
        unconfirmed_requests: Arc::clone(&unconfirmed_requests),
    };
    Ok(DatabaseRuntime {
        handle,
        history: Some(history),
        recovery,
        task,
        unconfirmed_requests,
    })
}

fn initialize_writer(
    path: &Path,
    devices: &[DeviceRegistration],
) -> Result<WriterInitialization, DbWriteError> {
    let mut connection = open_writer_connection(path)?;
    initialize_or_validate_v1(&mut connection)?;
    register_devices_startup(&mut connection, devices)?;
    let tables = validated_device_tables(&connection)?;
    let recovery = load_recovery_state(&connection, &tables)?;
    Ok((connection, tables, recovery))
}

fn run_writer(
    connection: Connection,
    path: &Path,
    mut tables: HashMap<String, DeviceTableNames>,
    receiver: &Receiver<DbRequest>,
) -> Result<(), DbWriteError> {
    let mut connection = Some(connection);
    while let Ok(request) = receiver.recv() {
        request
            .progress
            .store(REQUEST_EXECUTING, std::sync::atomic::Ordering::Release);
        let request_id = request.request_id;
        let result = if request.replay_requires_reopen {
            reopen_writer_connection(&mut connection, path, &mut tables)
                .and_then(|()| process_request(&mut connection, path, &mut tables, &request))
        } else {
            process_request(&mut connection, path, &mut tables, &request)
        };
        let fatal_connection = result.as_ref().err().is_some_and(is_connection_fatal);
        let acknowledgement = result.map(|()| CommitAck { request_id });
        // A closed per-request receiver must not close the global writer FIFO.
        let _ = request.commit_ack.send(acknowledgement);
        if fatal_connection {
            return Err(DbWriteError::QueueClosed);
        }
    }
    Ok(())
}

fn process_request(
    connection: &mut Option<Connection>,
    path: &Path,
    tables: &mut HashMap<String, DeviceTableNames>,
    request: &DbRequest,
) -> Result<(), DbWriteError> {
    validate_batch(request.request_id, request.batch.as_ref(), tables)?;
    let mut delay = INITIAL_RETRY_DELAY;
    let mut attempts_remaining = MAX_BATCH_ATTEMPTS;

    loop {
        let active_connection = connection.as_ref().ok_or(DbWriteError::QueueClosed)?;
        match execute_transaction(
            active_connection,
            request.request_id,
            request.batch.as_ref(),
            tables,
        ) {
            Ok(()) => {
                if matches!(request.batch.as_ref(), DatabaseBatch::RegisterDevices(_)) {
                    *tables = validated_device_tables(active_connection)?;
                }
                return Ok(());
            }
            Err(error @ DbWriteError::Busy { .. }) => {
                attempts_remaining -= 1;
                if attempts_remaining == 0 {
                    return Err(error);
                }
                tracing::warn!(
                    request_id = request.request_id,
                    batch_kind = request.batch.kind(),
                    attempts_remaining,
                    retry_delay_ms = ?delay.as_millis(),
                    error = %error,
                    "database transaction is busy; retrying the unchanged batch"
                );
            }
            Err(error @ DbWriteError::Transaction { .. }) if is_recoverable_transaction(&error) => {
                attempts_remaining -= 1;
                if attempts_remaining == 0 {
                    return Err(error);
                }
                tracing::warn!(
                    request_id = request.request_id,
                    batch_kind = request.batch.kind(),
                    attempts_remaining,
                    retry_delay_ms = ?delay.as_millis(),
                    error = %error,
                    "recoverable database transaction failure; reopening and retrying the unchanged batch"
                );
                reopen_writer_connection(connection, path, tables)?;
            }
            Err(error @ DbWriteError::CommitOutcomeUnknown { .. }) => {
                attempts_remaining -= 1;
                if attempts_remaining == 0 {
                    return Err(error);
                }
                tracing::warn!(
                    request_id = request.request_id,
                    batch_kind = request.batch.kind(),
                    attempts_remaining,
                    retry_delay_ms = ?delay.as_millis(),
                    error = %error,
                    "database commit outcome is unknown; reopening and replaying the unchanged batch"
                );
                reopen_writer_connection(connection, path, tables)?;
            }
            Err(error) => return Err(error),
        }

        thread::sleep(delay);
        delay = delay.saturating_mul(2);
    }
}

fn reopen_writer_connection(
    connection: &mut Option<Connection>,
    path: &Path,
    tables: &mut HashMap<String, DeviceTableNames>,
) -> Result<(), DbWriteError> {
    drop(connection.take());
    let mut reopened = open_writer_connection(path)?;
    initialize_or_validate_v1(&mut reopened)?;
    let reopened_tables = validated_device_tables(&reopened)?;
    *tables = reopened_tables;
    *connection = Some(reopened);
    Ok(())
}

fn validate_batch(
    request_id: u64,
    batch: &DatabaseBatch,
    tables: &HashMap<String, DeviceTableNames>,
) -> Result<(), DbWriteError> {
    match batch {
        DatabaseBatch::RegisterDevices(devices) => {
            validate_device_registrations(devices, request_id)
        }
        DatabaseBatch::SmartSample(sample) => validate_smart_sample(request_id, sample, tables),
        DatabaseBatch::WriterBucket(bucket) => validate_writer_bucket(request_id, bucket, tables),
    }
}

fn validate_smart_sample(
    request_id: u64,
    sample: &SmartSampleBatch,
    tables: &HashMap<String, DeviceTableNames>,
) -> Result<(), DbWriteError> {
    if !schema::is_valid_hash_id(&sample.device_hash_id) {
        return invalid_batch(request_id, BatchInvariant::UnsafeDeviceIdentifier);
    }
    if !tables.contains_key(&sample.device_hash_id) {
        return invalid_batch(request_id, BatchInvariant::UnknownDevice);
    }
    if sample.timestamp < 0
        || sample
            .write_amount_bytes
            .is_some_and(|write_amount| write_amount < 0)
    {
        return invalid_batch(request_id, BatchInvariant::ValueOutOfSqliteRange);
    }
    Ok(())
}

fn validate_writer_bucket(
    request_id: u64,
    bucket: &WriterBucketBatch,
    tables: &HashMap<String, DeviceTableNames>,
) -> Result<(), DbWriteError> {
    if bucket.timestamp < 0 || bucket.timestamp % 60_000 != 0 {
        return invalid_batch(request_id, BatchInvariant::UnalignedWriterBucketTimestamp);
    }

    let mut devices = HashSet::with_capacity(bucket.devices.len());
    for device in &bucket.devices {
        if !schema::is_valid_hash_id(&device.device_hash_id) {
            return invalid_batch(request_id, BatchInvariant::UnsafeDeviceIdentifier);
        }
        if !tables.contains_key(&device.device_hash_id) {
            return invalid_batch(request_id, BatchInvariant::UnknownDevice);
        }
        if !devices.insert(device.device_hash_id.as_str()) {
            return invalid_batch(request_id, BatchInvariant::DuplicateWriterRecord);
        }

        let mut workloads = HashSet::with_capacity(device.amounts.len());
        for amount in &device.amounts {
            if amount.workload_name.starts_with("ndm:") {
                return invalid_batch(request_id, BatchInvariant::UnexpectedReservedWorkload);
            }
            if !is_valid_workload_name(&amount.workload_name) {
                return invalid_batch(request_id, BatchInvariant::InvalidWorkloadName);
            }
            if amount.write_amount_bytes <= 0 {
                return invalid_batch(request_id, BatchInvariant::InvalidWriterAmount);
            }
            if !workloads.insert(amount.workload_name.as_str()) {
                return invalid_batch(request_id, BatchInvariant::DuplicateWriterRecord);
            }
        }
    }
    Ok(())
}

fn is_valid_workload_name(name: &str) -> bool {
    if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    if let Some(unit) = name.strip_prefix("systemd:system:") {
        return !unit.is_empty();
    }
    if let Some(rest) = name.strip_prefix("systemd:user:") {
        let Some((uid, unit)) = rest.split_once(':') else {
            return false;
        };
        return !unit.is_empty() && uid.parse::<u32>().is_ok();
    }
    name.strip_prefix("cgroup:")
        .is_some_and(|path| path.starts_with('/'))
}

fn invalid_batch<T>(request_id: u64, reason: BatchInvariant) -> Result<T, DbWriteError> {
    Err(DbWriteError::InvalidBatch { request_id, reason })
}

fn execute_transaction(
    connection: &Connection,
    request_id: u64,
    batch: &DatabaseBatch,
    tables: &HashMap<String, DeviceTableNames>,
) -> Result<(), DbWriteError> {
    connection
        .execute_batch("BEGIN IMMEDIATE;")
        .map_err(|source| map_sqlite_error(request_id, "begin", source))?;

    let body_result = match batch {
        DatabaseBatch::RegisterDevices(devices) => {
            apply_device_registrations(connection, devices, request_id)
        }
        DatabaseBatch::SmartSample(sample) => {
            write_smart_sample(connection, request_id, sample, tables)
        }
        DatabaseBatch::WriterBucket(bucket) => {
            write_writer_bucket(connection, request_id, bucket, tables)
        }
    };
    if let Err(error) = body_result {
        return rollback_after_error(connection, request_id, error);
    }

    match connection.execute_batch("COMMIT;") {
        Ok(()) => Ok(()),
        Err(source) if is_busy_or_locked(&source) => {
            let transaction_error = map_sqlite_error(request_id, "commit", source);
            rollback_after_error(connection, request_id, transaction_error)
        }
        Err(source) if commit_outcome_may_be_unknown(&source) => {
            Err(DbWriteError::CommitOutcomeUnknown {
                request_id,
                source: Some(Box::new(source)),
            })
        }
        Err(source) => rollback_after_error(
            connection,
            request_id,
            map_sqlite_error(request_id, "commit", source),
        ),
    }
}

fn write_smart_sample(
    connection: &Connection,
    request_id: u64,
    sample: &SmartSampleBatch,
    tables: &HashMap<String, DeviceTableNames>,
) -> Result<(), DbWriteError> {
    let table = tables
        .get(&sample.device_hash_id)
        .ok_or(DbWriteError::InvalidBatch {
            request_id,
            reason: BatchInvariant::UnknownDevice,
        })?;
    let sql = format!(
        "INSERT INTO {} (hash_id, timestamp, data_units_written_be, write_amount_bytes) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(timestamp) DO UPDATE SET \
         hash_id = excluded.hash_id, \
         data_units_written_be = excluded.data_units_written_be, \
         write_amount_bytes = excluded.write_amount_bytes;",
        table.data_identifier
    );
    connection
        .execute(
            &sql,
            params![
                sample.device_hash_id,
                sample.timestamp,
                sample.data_units_written_be,
                sample.write_amount_bytes
            ],
        )
        .map_err(|source| map_sqlite_error(request_id, "write_smart_sample", source))?;
    Ok(())
}

fn write_writer_bucket(
    connection: &Connection,
    request_id: u64,
    bucket: &WriterBucketBatch,
    tables: &HashMap<String, DeviceTableNames>,
) -> Result<(), DbWriteError> {
    for device in &bucket.devices {
        write_complete_device_bucket(connection, request_id, bucket.timestamp, device, tables)?;
    }
    Ok(())
}

fn write_complete_device_bucket(
    connection: &Connection,
    request_id: u64,
    timestamp: i64,
    device: &CompleteDeviceBucket,
    tables: &HashMap<String, DeviceTableNames>,
) -> Result<(), DbWriteError> {
    let table = tables
        .get(&device.device_hash_id)
        .ok_or(DbWriteError::InvalidBatch {
            request_id,
            reason: BatchInvariant::UnknownDevice,
        })?;
    let upsert_sql = format!(
        "INSERT INTO {} (hash_id, timestamp, workload_id, write_amount_bytes) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(timestamp, workload_id) DO UPDATE SET \
         hash_id = excluded.hash_id, \
         write_amount_bytes = excluded.write_amount_bytes;",
        table.writer_history_identifier
    );

    for amount in &device.amounts {
        connection
            .execute(
                "INSERT INTO workloads(name) VALUES (?1) ON CONFLICT(name) DO NOTHING;",
                [&amount.workload_name],
            )
            .map_err(|source| map_sqlite_error(request_id, "resolve_workload", source))?;
        let workload_id: i64 = connection
            .query_row(
                "SELECT workload_id FROM workloads WHERE name = ?1;",
                [&amount.workload_name],
                |row| row.get(0),
            )
            .map_err(|source| map_sqlite_error(request_id, "resolve_workload", source))?;
        connection
            .execute(
                &upsert_sql,
                params![
                    device.device_hash_id,
                    timestamp,
                    workload_id,
                    amount.write_amount_bytes
                ],
            )
            .map_err(|source| map_sqlite_error(request_id, "write_writer_amount", source))?;
    }

    connection
        .execute(
            &upsert_sql,
            params![device.device_hash_id, timestamp, 0_i64, 0_i64],
        )
        .map_err(|source| map_sqlite_error(request_id, "write_bucket_complete", source))?;
    Ok(())
}

fn rollback_after_error<T>(
    connection: &Connection,
    request_id: u64,
    transaction_error: DbWriteError,
) -> Result<T, DbWriteError> {
    match connection.execute_batch("ROLLBACK;") {
        Ok(()) => Err(transaction_error),
        Err(rollback_error) => Err(DbWriteError::RollbackFailed {
            request_id,
            transaction_error: Box::new(transaction_error),
            rollback_error: Box::new(rollback_error),
        }),
    }
}

fn map_sqlite_error(request_id: u64, stage: &'static str, source: rusqlite::Error) -> DbWriteError {
    if is_busy_or_locked(&source) {
        DbWriteError::Busy {
            request_id,
            stage,
            source: Box::new(source),
        }
    } else {
        DbWriteError::Transaction {
            request_id,
            stage,
            source: Box::new(source),
        }
    }
}

fn is_busy_or_locked(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn commit_outcome_may_be_unknown(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(
            ErrorCode::OperationInterrupted
                | ErrorCode::SystemIoFailure
                | ErrorCode::CannotOpen
                | ErrorCode::FileLockingProtocolFailed
        )
    )
}

fn is_recoverable_transaction(error: &DbWriteError) -> bool {
    let DbWriteError::Transaction { source, .. } = error else {
        return false;
    };
    let Some(source) = source.downcast_ref::<rusqlite::Error>() else {
        return false;
    };
    matches!(
        source.sqlite_error_code(),
        Some(
            ErrorCode::OperationInterrupted
                | ErrorCode::SystemIoFailure
                | ErrorCode::CannotOpen
                | ErrorCode::FileLockingProtocolFailed
                | ErrorCode::SchemaChanged
        )
    )
}

fn is_connection_fatal(error: &DbWriteError) -> bool {
    matches!(
        error,
        DbWriteError::RollbackFailed { .. }
            | DbWriteError::Transaction { .. }
            | DbWriteError::CommitOutcomeUnknown { .. }
            | DbWriteError::QueueClosed
            | DbWriteError::InvalidBatch { .. }
            | DbWriteError::Open { .. }
            | DbWriteError::SqliteVersionTooOld { .. }
            | DbWriteError::Configure { .. }
            | DbWriteError::ForeignKeysUnavailable
            | DbWriteError::WalModeUnavailable { .. }
            | DbWriteError::UnsupportedSchemaVersion { .. }
            | DbWriteError::UnversionedNdmLayoutPresent
            | DbWriteError::SchemaMismatch { .. }
            | DbWriteError::InvalidDeviceTableIdentifier
            | DbWriteError::ReservedWorkloadInvalid
    )
}

fn writer_panicked_error() -> DbWriteError {
    DbWriteError::Transaction {
        request_id: 0,
        stage: "start_writer",
        source: Box::new(std::io::Error::other("database writer task panicked")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{
        WriterAmount,
        schema::{device_hash_id, device_table_names},
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU8, Ordering},
    };
    use tempfile::tempdir;

    fn registration() -> DeviceRegistration {
        let path = PathBuf::from("/dev/disk/by-id/ndm-task-test");
        DeviceRegistration {
            hash_id: device_hash_id("TASK-SERIAL", &path).expect("UTF-8 path"),
            label: "test disk".to_owned(),
            serial: "TASK-SERIAL".to_owned(),
            by_id_path: path,
            major: 259,
            minor: 7,
        }
    }

    fn transaction_error(code: ErrorCode) -> DbWriteError {
        DbWriteError::Transaction {
            request_id: 42,
            stage: "test",
            source: Box::new(sqlite_error(code)),
        }
    }

    fn sqlite_error(code: ErrorCode) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code,
                extended_code: 0,
            },
            None,
        )
    }

    fn request(
        request_id: u64,
        batch: DatabaseBatch,
        replay_requires_reopen: bool,
    ) -> (
        DbRequest,
        Receiver<Result<CommitAck, DbWriteError>>,
        Arc<AtomicU8>,
    ) {
        let (ack_sender, ack_receiver) = sync_channel(1);
        let progress = Arc::new(AtomicU8::new(super::super::REQUEST_QUEUED));
        (
            DbRequest {
                request_id,
                batch: Arc::new(batch),
                commit_ack: ack_sender,
                progress: Arc::clone(&progress),
                replay_requires_reopen,
            },
            ack_receiver,
            progress,
        )
    }

    #[test]
    fn transaction_retry_classification_excludes_explicit_fatal_codes() {
        for code in [
            ErrorCode::DiskFull,
            ErrorCode::ReadOnly,
            ErrorCode::DatabaseCorrupt,
            ErrorCode::NotADatabase,
        ] {
            assert!(!is_recoverable_transaction(&transaction_error(code)));
        }
        for code in [ErrorCode::SystemIoFailure, ErrorCode::SchemaChanged] {
            assert!(is_recoverable_transaction(&transaction_error(code)));
        }
    }

    #[test]
    fn commit_error_classification_replays_only_uncertain_outcomes() {
        for code in [
            ErrorCode::OperationInterrupted,
            ErrorCode::SystemIoFailure,
            ErrorCode::CannotOpen,
            ErrorCode::FileLockingProtocolFailed,
        ] {
            assert!(commit_outcome_may_be_unknown(&sqlite_error(code)));
        }
        for code in [
            ErrorCode::DiskFull,
            ErrorCode::ReadOnly,
            ErrorCode::DatabaseCorrupt,
            ErrorCode::NotADatabase,
            ErrorCode::ConstraintViolation,
        ] {
            assert!(!commit_outcome_may_be_unknown(&sqlite_error(code)));
        }
    }

    #[test]
    fn busy_retry_is_bounded_and_keeps_the_connection_usable() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("stats.db");
        let device = registration();
        let (connection, mut tables, _) =
            initialize_writer(&path, std::slice::from_ref(&device)).expect("initialize DB");
        connection
            .busy_timeout(Duration::ZERO)
            .expect("disable SQLite busy wait for the test");
        let locker = Connection::open(&path).expect("open competing connection");
        locker
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("hold the write lock");
        let (request, _ack_receiver, _) = request(
            7,
            DatabaseBatch::WriterBucket(WriterBucketBatch {
                timestamp: 0,
                devices: Vec::new(),
            }),
            false,
        );
        let mut connection = Some(connection);

        let error = process_request(&mut connection, &path, &mut tables, &request)
            .expect_err("bounded retries must eventually report BUSY");
        assert!(matches!(
            error,
            DbWriteError::Busy {
                request_id: 7,
                stage: "begin",
                ..
            }
        ));
        assert!(connection.is_some());
        assert!(!is_connection_fatal(&error));

        locker
            .execute_batch("ROLLBACK;")
            .expect("release write lock");
        process_request(&mut connection, &path, &mut tables, &request)
            .expect("the same connection remains usable after BUSY");
    }

    #[test]
    fn lost_acknowledgement_keeps_writer_available_for_exact_replay() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("stats.db");
        let device = registration();
        let (connection, tables, _) =
            initialize_writer(&path, std::slice::from_ref(&device)).expect("initialize DB");
        let (request_sender, request_receiver) = sync_channel(DATABASE_QUEUE_CAPACITY);
        let batch = Arc::new(DatabaseBatch::SmartSample(SmartSampleBatch {
            device_hash_id: device.hash_id.clone(),
            timestamp: 60_000,
            data_units_written_be: 3_u128.to_be_bytes(),
            write_amount_bytes: None,
        }));
        let (discarded_ack_sender, discarded_ack_receiver) = sync_channel(1);
        drop(discarded_ack_receiver);
        request_sender
            .send(DbRequest {
                request_id: 17,
                batch: Arc::clone(&batch),
                commit_ack: discarded_ack_sender,
                progress: Arc::new(AtomicU8::new(super::super::REQUEST_QUEUED)),
                replay_requires_reopen: false,
            })
            .expect("queue request with lost acknowledgement");
        let (replay_acknowledgement, replay_receiver) = sync_channel(1);
        request_sender
            .send(DbRequest {
                request_id: 17,
                batch,
                commit_ack: replay_acknowledgement,
                progress: Arc::new(AtomicU8::new(super::super::REQUEST_QUEUED)),
                replay_requires_reopen: true,
            })
            .expect("queue exact replay");
        drop(request_sender);

        run_writer(connection, &path, tables, &request_receiver).expect("execute replay");
        assert_eq!(
            replay_receiver
                .recv()
                .expect("writer acknowledgement")
                .expect("replay result")
                .request_id,
            17
        );
        let query = schema::open_query_connection(&path).expect("query replayed row");
        let tables = device_table_names(&device.hash_id).expect("table names");
        let count: i64 = query
            .query_row(
                &format!("SELECT COUNT(*) FROM {};", tables.data_identifier),
                [],
                |row| row.get(0),
            )
            .expect("SMART row count");
        assert_eq!(count, 1);
    }

    #[test]
    fn fatal_writer_result_rejects_queued_requests_as_queue_closed() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("stats.db");
        let device = registration();
        let (connection, tables, _) =
            initialize_writer(&path, std::slice::from_ref(&device)).expect("initialize DB");
        let (request_sender, request_receiver) = sync_channel(DATABASE_QUEUE_CAPACITY);
        let (fatal_request, fatal_ack, _) = request(
            21,
            DatabaseBatch::WriterBucket(WriterBucketBatch {
                timestamp: 1,
                devices: Vec::new(),
            }),
            false,
        );
        let (queued_request, queued_ack, queued_progress) = request(
            22,
            DatabaseBatch::WriterBucket(WriterBucketBatch {
                timestamp: 60_000,
                devices: Vec::new(),
            }),
            false,
        );
        request_sender
            .send(fatal_request)
            .expect("queue fatal request");
        request_sender
            .send(queued_request)
            .expect("queue following request");
        drop(request_sender);

        assert!(matches!(
            run_writer(connection, &path, tables, &request_receiver),
            Err(DbWriteError::QueueClosed)
        ));
        assert!(matches!(
            fatal_ack.recv().expect("fatal acknowledgement"),
            Err(DbWriteError::InvalidBatch {
                request_id: 21,
                reason: BatchInvariant::UnalignedWriterBucketTimestamp
            })
        ));
        assert_eq!(
            queued_progress.load(Ordering::Acquire),
            super::super::REQUEST_QUEUED
        );
        drop(request_receiver);
        assert!(queued_ack.recv().is_err());
        assert!(matches!(
            super::super::closed_acknowledgement_error(
                22,
                queued_progress.load(Ordering::Acquire),
                false
            ),
            DbWriteError::QueueClosed
        ));
    }

    #[test]
    fn smart_and_writer_batches_are_idempotent() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("stats.db");
        let device = registration();
        let runtime = start_database(&path, std::slice::from_ref(&device)).expect("start DB");
        let handle = runtime.handle.clone();

        let smart = DatabaseBatch::SmartSample(SmartSampleBatch {
            device_hash_id: device.hash_id.clone(),
            timestamp: 120_000,
            data_units_written_be: 100_u128.to_be_bytes(),
            write_amount_bytes: Some(512_000),
        });
        handle.submit(smart.clone()).expect("write SMART");
        handle.submit(smart).expect("replay SMART");

        let writer = DatabaseBatch::WriterBucket(WriterBucketBatch {
            timestamp: 60_000,
            devices: vec![CompleteDeviceBucket {
                device_hash_id: device.hash_id.clone(),
                amounts: vec![WriterAmount {
                    workload_name: "systemd:system:postgresql.service".to_owned(),
                    write_amount_bytes: 4_096,
                }],
            }],
        });
        handle.submit(writer.clone()).expect("write bucket");
        handle.submit(writer).expect("replay bucket");

        let connection = schema::open_query_connection(&path).expect("query connection");
        let tables = device_table_names(&device.hash_id).expect("table names");
        let smart_count: i64 = connection
            .query_row(
                &format!("SELECT COUNT(*) FROM {};", tables.data_identifier),
                [],
                |row| row.get(0),
            )
            .expect("SMART count");
        let rows: i64 = connection
            .query_row(
                &format!("SELECT COUNT(*) FROM {};", tables.writer_history_identifier),
                [],
                |row| row.get(0),
            )
            .expect("writer row count");
        let amount: i64 = connection
            .query_row(
                &format!(
                    "SELECT write_amount_bytes FROM {} WHERE workload_id <> 0;",
                    tables.writer_history_identifier
                ),
                [],
                |row| row.get(0),
            )
            .expect("writer amount");
        assert_eq!(smart_count, 1);
        assert_eq!(rows, 2);
        assert_eq!(amount, 4_096);

        drop(connection);
        drop(handle);
        runtime.shutdown().expect("shutdown DB");
    }

    #[test]
    fn restart_recovers_last_smart_baseline() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("stats.db");
        let device = registration();
        let first = start_database(&path, std::slice::from_ref(&device)).expect("start DB");
        first
            .handle
            .submit(DatabaseBatch::SmartSample(SmartSampleBatch {
                device_hash_id: device.hash_id.clone(),
                timestamp: 180_000,
                data_units_written_be: 77_u128.to_be_bytes(),
                write_amount_bytes: None,
            }))
            .expect("write SMART");
        first.shutdown().expect("first shutdown");

        let second = start_database(&path, std::slice::from_ref(&device)).expect("restart DB");
        assert_eq!(
            second.recovery.get(&device.hash_id),
            Some(&RecoveredSmartBaseline {
                timestamp: 180_000,
                data_units_written: 77,
            })
        );
        second.shutdown().expect("second shutdown");
    }

    #[test]
    fn rejects_invalid_writer_batch_without_rows() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("stats.db");
        let device = registration();
        let runtime = start_database(&path, std::slice::from_ref(&device)).expect("start DB");
        let error = runtime
            .handle
            .submit(DatabaseBatch::WriterBucket(WriterBucketBatch {
                timestamp: 1,
                devices: Vec::new(),
            }))
            .expect_err("unaligned bucket must fail");
        assert!(matches!(
            error,
            DbWriteError::InvalidBatch {
                reason: BatchInvariant::UnalignedWriterBucketTimestamp,
                ..
            }
        ));
        assert!(matches!(runtime.shutdown(), Err(DbWriteError::QueueClosed)));
    }

    #[test]
    fn shutdown_drains_requests_waiting_on_the_bounded_fifo() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("stats.db");
        let device = registration();
        let runtime = start_database(&path, std::slice::from_ref(&device)).expect("start DB");
        let mut producers = Vec::new();

        for minute in 0_i64..40 {
            let handle = runtime.handle.clone();
            let device_hash_id = device.hash_id.clone();
            producers.push(thread::spawn(move || {
                handle.submit(DatabaseBatch::WriterBucket(WriterBucketBatch {
                    timestamp: minute * 60_000,
                    devices: vec![CompleteDeviceBucket {
                        device_hash_id,
                        amounts: Vec::new(),
                    }],
                }))
            }));
        }

        runtime.shutdown().expect("drain and shut down DB");
        for producer in producers {
            producer
                .join()
                .expect("producer did not panic")
                .expect("writer bucket was acknowledged");
        }

        let connection = open_writer_connection(&path).expect("open drained DB");
        let tables = device_table_names(&device.hash_id).expect("table names");
        let completion_count: i64 = connection
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE workload_id = 0;",
                    tables.writer_history_identifier
                ),
                [],
                |row| row.get(0),
            )
            .expect("completion count");
        assert_eq!(completion_count, 40);
    }
}
