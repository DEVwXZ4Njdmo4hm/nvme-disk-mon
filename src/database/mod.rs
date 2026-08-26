pub(crate) mod schema;
mod task;

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    thread::JoinHandle,
    time::Duration,
};

use crate::{ErrorSource, writer::history::WriterHistory};

pub(crate) use schema::{DeviceTableNames, open_query_connection, read_smart_device_stats};
pub(crate) use task::start_database;

const DATABASE_QUEUE_CAPACITY: usize = 32;
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const ADMISSION_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_ACK_REPLAY_ATTEMPTS: usize = 3;
const REQUEST_QUEUED: u8 = 0;
const REQUEST_EXECUTING: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchInvariant {
    UnknownDevice,
    UnsafeDeviceIdentifier,
    InvalidWorkloadName,
    // The public batch contract reserves this invariant even though the current
    // representation carries one shared timestamp for the whole batch.
    #[allow(dead_code)]
    MixedWriterBucketTimestamp,
    UnalignedWriterBucketTimestamp,
    DuplicateWriterRecord,
    InvalidWriterAmount,
    UnexpectedReservedWorkload,
    ValueOutOfSqliteRange,
    SmartBatchAlreadyPending,
}

impl fmt::Display for BatchInvariant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownDevice => "unknown device",
            Self::UnsafeDeviceIdentifier => "unsafe device identifier",
            Self::InvalidWorkloadName => "invalid workload name",
            Self::MixedWriterBucketTimestamp => "mixed writer bucket timestamps",
            Self::UnalignedWriterBucketTimestamp => "unaligned writer bucket timestamp",
            Self::DuplicateWriterRecord => "duplicate writer record",
            Self::InvalidWriterAmount => "invalid writer amount",
            Self::UnexpectedReservedWorkload => "unexpected reserved workload",
            Self::ValueOutOfSqliteRange => "value outside the SQLite integer range",
            Self::SmartBatchAlreadyPending => "SMART batch already pending for this device",
        })
    }
}

pub(crate) enum DbWriteError {
    Open {
        path: PathBuf,
        source: ErrorSource,
    },
    SqliteVersionTooOld {
        found: String,
        minimum: &'static str,
    },
    Configure {
        pragma: &'static str,
        source: ErrorSource,
    },
    ForeignKeysUnavailable,
    WalModeUnavailable {
        actual: String,
    },
    UnsupportedSchemaVersion {
        found: i64,
        supported: i64,
    },
    UnversionedNdmLayoutPresent,
    SchemaMismatch {
        object: String,
    },
    InvalidDeviceTableIdentifier,
    ReservedWorkloadInvalid,
    LoadRecoveryState {
        hash_id: String,
        source: ErrorSource,
    },
    InvalidStoredSmartCounter {
        hash_id: String,
        timestamp: i64,
        actual_length: usize,
    },
    QueueClosed,
    InvalidBatch {
        request_id: u64,
        reason: BatchInvariant,
    },
    Busy {
        request_id: u64,
        stage: &'static str,
        source: ErrorSource,
    },
    Transaction {
        request_id: u64,
        stage: &'static str,
        source: ErrorSource,
    },
    RollbackFailed {
        request_id: u64,
        transaction_error: ErrorSource,
        // Retained alongside the primary transaction error for diagnostics.
        #[allow(dead_code)]
        rollback_error: ErrorSource,
    },
    CommitOutcomeUnknown {
        request_id: u64,
        source: Option<ErrorSource>,
    },
    CommitAcknowledgementLost {
        request_id: u64,
    },
    // Reserved for an explicit shutdown or maintenance checkpoint operation.
    #[allow(dead_code)]
    Checkpoint {
        source: ErrorSource,
    },
    ShutdownTimeout {
        unconfirmed_requests: usize,
    },
}

impl fmt::Display for DbWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, .. } => {
                write!(
                    formatter,
                    "cannot open state database {}",
                    log_safe_path(path)
                )
            }
            Self::SqliteVersionTooOld { found, minimum } => write!(
                formatter,
                "SQLite version {} is older than required {minimum}",
                log_safe_text(found, 64)
            ),
            Self::Configure { pragma, .. } => {
                write!(formatter, "cannot configure SQLite pragma {pragma}")
            }
            Self::ForeignKeysUnavailable => {
                formatter.write_str("SQLite foreign-key enforcement is unavailable")
            }
            Self::WalModeUnavailable { actual } => write!(
                formatter,
                "SQLite WAL mode is unavailable (actual={})",
                log_safe_text(actual, 32)
            ),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                formatter,
                "unsupported state database schema version {found}; supported version is {supported}"
            ),
            Self::UnversionedNdmLayoutPresent => formatter
                .write_str("unversioned NDM application tables are present in the state database"),
            Self::SchemaMismatch { object } => write!(
                formatter,
                "state database schema does not match version 1 at {}",
                log_safe_text(object, 160)
            ),
            Self::InvalidDeviceTableIdentifier => {
                formatter.write_str("device table identifier is invalid")
            }
            Self::ReservedWorkloadInvalid => {
                formatter.write_str("reserved workload identity is missing or invalid")
            }
            Self::LoadRecoveryState { hash_id, .. } => write!(
                formatter,
                "cannot load SMART recovery state for device {}",
                log_safe_text(hash_id, 64)
            ),
            Self::InvalidStoredSmartCounter {
                hash_id,
                timestamp,
                actual_length,
            } => write!(
                formatter,
                "stored SMART counter for device {} at {timestamp} has length {actual_length}, expected 16",
                log_safe_text(hash_id, 64)
            ),
            Self::QueueClosed => formatter.write_str("database writer queue is closed"),
            Self::InvalidBatch { request_id, reason } => {
                write!(
                    formatter,
                    "database request {request_id} violates a batch invariant: {reason}"
                )
            }
            Self::Busy {
                request_id, stage, ..
            } => write!(
                formatter,
                "database request {request_id} is busy or locked during {stage}"
            ),
            Self::Transaction {
                request_id, stage, ..
            } => write!(
                formatter,
                "database request {request_id} failed during {stage}"
            ),
            Self::RollbackFailed { request_id, .. } => {
                write!(
                    formatter,
                    "database request {request_id} failed and could not be rolled back"
                )
            }
            Self::CommitOutcomeUnknown { request_id, .. } => write!(
                formatter,
                "database request {request_id} has an unknown commit outcome"
            ),
            Self::CommitAcknowledgementLost { request_id } => write!(
                formatter,
                "database request {request_id} may be committed but its acknowledgement was lost"
            ),
            Self::Checkpoint { .. } => formatter.write_str("SQLite WAL checkpoint failed"),
            Self::ShutdownTimeout {
                unconfirmed_requests,
            } => write!(
                formatter,
                "database writer shutdown timed out with {unconfirmed_requests} unconfirmed request(s)"
            ),
        }
    }
}

impl fmt::Debug for DbWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for DbWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. }
            | Self::Configure { source, .. }
            | Self::LoadRecoveryState { source, .. }
            | Self::Busy { source, .. }
            | Self::Transaction { source, .. }
            | Self::Checkpoint { source }
            | Self::CommitOutcomeUnknown {
                source: Some(source),
                ..
            } => Some(source.as_ref()),
            Self::RollbackFailed {
                transaction_error, ..
            } => Some(transaction_error.as_ref()),
            Self::SqliteVersionTooOld { .. }
            | Self::ForeignKeysUnavailable
            | Self::WalModeUnavailable { .. }
            | Self::UnsupportedSchemaVersion { .. }
            | Self::UnversionedNdmLayoutPresent
            | Self::SchemaMismatch { .. }
            | Self::InvalidDeviceTableIdentifier
            | Self::ReservedWorkloadInvalid
            | Self::InvalidStoredSmartCounter { .. }
            | Self::QueueClosed
            | Self::InvalidBatch { .. }
            | Self::CommitOutcomeUnknown { source: None, .. }
            | Self::CommitAcknowledgementLost { .. }
            | Self::ShutdownTimeout { .. } => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DeviceRegistration {
    pub(crate) hash_id: String,
    pub(crate) label: String,
    pub(crate) serial: String,
    pub(crate) by_id_path: PathBuf,
    pub(crate) major: u32,
    pub(crate) minor: u32,
}

impl fmt::Debug for DeviceRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceRegistration")
            .field("hash_id", &self.hash_id)
            .field("label", &self.label)
            .field("serial", &"[REDACTED]")
            .field("by_id_path", &log_safe_path(&self.by_id_path))
            .field("major", &self.major)
            .field("minor", &self.minor)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SmartSampleBatch {
    pub(crate) device_hash_id: String,
    pub(crate) timestamp: i64,
    pub(crate) data_units_written_be: [u8; 16],
    pub(crate) write_amount_bytes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriterAmount {
    pub(crate) workload_name: String,
    pub(crate) write_amount_bytes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompleteDeviceBucket {
    pub(crate) device_hash_id: String,
    pub(crate) amounts: Vec<WriterAmount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriterBucketBatch {
    pub(crate) timestamp: i64,
    pub(crate) devices: Vec<CompleteDeviceBucket>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DatabaseBatch {
    // Runtime device changes use the same writer FIFO; startup registration is
    // currently the only producer in the daemon binary.
    #[allow(dead_code)]
    RegisterDevices(Vec<DeviceRegistration>),
    SmartSample(SmartSampleBatch),
    WriterBucket(WriterBucketBatch),
}

impl DatabaseBatch {
    const fn kind(&self) -> &'static str {
        match self {
            Self::RegisterDevices(_) => "register_devices",
            Self::SmartSample(_) => "smart_sample",
            Self::WriterBucket(_) => "writer_bucket",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommitAck {
    pub(crate) request_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveredSmartBaseline {
    pub(crate) timestamp: i64,
    pub(crate) data_units_written: u128,
}

struct DbRequest {
    request_id: u64,
    batch: Arc<DatabaseBatch>,
    commit_ack: SyncSender<Result<CommitAck, DbWriteError>>,
    progress: Arc<AtomicU8>,
    replay_requires_reopen: bool,
}

#[derive(Clone)]
pub(crate) struct DatabaseHandle {
    sender: SyncSender<DbRequest>,
    next_request_id: Arc<AtomicU64>,
    pending_smart: Arc<Mutex<HashSet<String>>>,
    unconfirmed_requests: Arc<AtomicUsize>,
}

impl DatabaseHandle {
    #[allow(dead_code)]
    pub(crate) fn submit(&self, batch: DatabaseBatch) -> Result<CommitAck, DbWriteError> {
        self.submit_inner(batch, None)?
            .ok_or(DbWriteError::QueueClosed)
    }

    pub(crate) fn submit_until_stopped(
        &self,
        batch: DatabaseBatch,
        stop: &AtomicBool,
    ) -> Result<Option<CommitAck>, DbWriteError> {
        self.submit_inner(batch, Some(stop))
    }

    fn submit_inner(
        &self,
        batch: DatabaseBatch,
        stop: Option<&AtomicBool>,
    ) -> Result<Option<CommitAck>, DbWriteError> {
        let request_id =
            self.next_request_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                });
        let request_id = request_id.map_err(|_| DbWriteError::InvalidBatch {
            request_id: u64::MAX,
            reason: BatchInvariant::ValueOutOfSqliteRange,
        })?;

        let batch = Arc::new(batch);
        let pending_device = match batch.as_ref() {
            DatabaseBatch::SmartSample(sample) => {
                let mut pending =
                    self.pending_smart
                        .lock()
                        .map_err(|_| DbWriteError::InvalidBatch {
                            request_id,
                            reason: BatchInvariant::SmartBatchAlreadyPending,
                        })?;
                if !pending.insert(sample.device_hash_id.clone()) {
                    return Err(DbWriteError::InvalidBatch {
                        request_id,
                        reason: BatchInvariant::SmartBatchAlreadyPending,
                    });
                }
                Some(sample.device_hash_id.clone())
            }
            DatabaseBatch::RegisterDevices(_) | DatabaseBatch::WriterBucket(_) => None,
        };

        self.unconfirmed_requests.fetch_add(1, Ordering::Relaxed);
        let submission = PendingSubmission {
            device_hash_id: pending_device,
            _batch: Arc::clone(&batch),
            pending_smart: Arc::clone(&self.pending_smart),
            unconfirmed_requests: Arc::clone(&self.unconfirmed_requests),
        };
        let mut outcome_was_uncertain = false;

        for attempt in 0..MAX_ACK_REPLAY_ATTEMPTS {
            let (ack_sender, ack_receiver) = sync_channel(1);
            let progress = Arc::new(AtomicU8::new(REQUEST_QUEUED));
            let mut request = DbRequest {
                request_id,
                batch: Arc::clone(&batch),
                commit_ack: ack_sender,
                progress: Arc::clone(&progress),
                replay_requires_reopen: attempt > 0,
            };

            if attempt == 0 {
                if let Some(stop) = stop {
                    loop {
                        // signal-hook stores this flag with SeqCst ordering.
                        // This load is the admission linearization point: a
                        // false value admits exactly the following try_send;
                        // a full queue releases the attempt and checks again.
                        if stop.load(Ordering::SeqCst) {
                            return Ok(None);
                        }
                        match self.sender.try_send(request) {
                            Ok(()) => break,
                            Err(TrySendError::Full(returned)) => {
                                request = returned;
                                std::thread::sleep(ADMISSION_POLL_INTERVAL);
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                return Err(DbWriteError::QueueClosed);
                            }
                        }
                    }
                } else if self.sender.send(request).is_err() {
                    return Err(DbWriteError::QueueClosed);
                }
            } else if self.sender.send(request).is_err() {
                return Err(DbWriteError::CommitAcknowledgementLost { request_id });
            }

            match ack_receiver.recv() {
                Ok(result) => return result.map(Some),
                Err(_) if progress.load(Ordering::Acquire) == REQUEST_QUEUED => {
                    return Err(closed_acknowledgement_error(
                        request_id,
                        REQUEST_QUEUED,
                        outcome_was_uncertain,
                    ));
                }
                Err(_) => {
                    outcome_was_uncertain = true;
                    if attempt + 1 < MAX_ACK_REPLAY_ATTEMPTS {
                        tracing::warn!(
                            request_id,
                            batch_kind = batch.kind(),
                            next_attempt = attempt + 2,
                            maximum_attempts = MAX_ACK_REPLAY_ATTEMPTS,
                            "database commit acknowledgement was lost; replaying the unchanged batch"
                        );
                    }
                }
            }
        }

        drop(submission);
        Err(DbWriteError::CommitAcknowledgementLost { request_id })
    }
}

fn closed_acknowledgement_error(
    request_id: u64,
    progress: u8,
    earlier_outcome_was_uncertain: bool,
) -> DbWriteError {
    if progress == REQUEST_QUEUED && !earlier_outcome_was_uncertain {
        DbWriteError::QueueClosed
    } else {
        DbWriteError::CommitAcknowledgementLost { request_id }
    }
}

struct PendingSubmission {
    device_hash_id: Option<String>,
    _batch: Arc<DatabaseBatch>,
    pending_smart: Arc<Mutex<HashSet<String>>>,
    unconfirmed_requests: Arc<AtomicUsize>,
}

impl Drop for PendingSubmission {
    fn drop(&mut self) {
        if let Some(device_hash_id) = &self.device_hash_id
            && let Ok(mut pending) = self.pending_smart.lock()
        {
            pending.remove(device_hash_id);
        }
        self.unconfirmed_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct DatabaseRuntime {
    pub(crate) handle: DatabaseHandle,
    history: Option<WriterHistory>,
    pub(crate) recovery: HashMap<String, RecoveredSmartBaseline>,
    task: JoinHandle<Result<(), DbWriteError>>,
    unconfirmed_requests: Arc<AtomicUsize>,
}

impl DatabaseRuntime {
    pub(crate) fn writer_is_finished(&self) -> bool {
        self.task.is_finished()
    }

    pub(crate) fn take_history(&mut self) -> Option<WriterHistory> {
        self.history.take()
    }

    pub(crate) fn shutdown(self) -> Result<(), DbWriteError> {
        self.shutdown_with_timeout(DEFAULT_SHUTDOWN_TIMEOUT)
    }

    pub(crate) fn shutdown_with_timeout(self, timeout: Duration) -> Result<(), DbWriteError> {
        let Self {
            handle,
            history,
            recovery: _,
            task,
            unconfirmed_requests,
        } = self;
        drop(history);
        drop(handle);

        let started = std::time::Instant::now();
        while !task.is_finished() {
            if started.elapsed() >= timeout {
                return Err(DbWriteError::ShutdownTimeout {
                    unconfirmed_requests: unconfirmed_requests.load(Ordering::Relaxed),
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        task.join().map_err(|_| DbWriteError::Transaction {
            request_id: 0,
            stage: "join_writer",
            source: Box::new(std::io::Error::other("database writer task panicked")),
        })?
    }
}

fn log_safe_path(path: &Path) -> String {
    log_safe_bytes(path.as_os_str().as_encoded_bytes(), 256)
}

fn log_safe_text(value: &str, limit: usize) -> String {
    log_safe_bytes(value.as_bytes(), limit)
}

fn log_safe_bytes(bytes: &[u8], limit: usize) -> String {
    let mut escaped = String::new();
    for byte in bytes.iter().take(limit) {
        escaped.extend(std::ascii::escape_default(*byte).map(char::from));
    }
    if bytes.len() > limit {
        escaped.push_str("...");
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_handle(sender: SyncSender<DbRequest>) -> DatabaseHandle {
        DatabaseHandle {
            sender,
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending_smart: Arc::new(Mutex::new(HashSet::new())),
            unconfirmed_requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn empty_writer_batch(timestamp: i64) -> DatabaseBatch {
        DatabaseBatch::WriterBucket(WriterBucketBatch {
            timestamp,
            devices: Vec::new(),
        })
    }

    #[test]
    fn batch_invariants_have_stable_messages() {
        let values = [
            BatchInvariant::UnknownDevice,
            BatchInvariant::UnsafeDeviceIdentifier,
            BatchInvariant::InvalidWorkloadName,
            BatchInvariant::MixedWriterBucketTimestamp,
            BatchInvariant::UnalignedWriterBucketTimestamp,
            BatchInvariant::DuplicateWriterRecord,
            BatchInvariant::InvalidWriterAmount,
            BatchInvariant::UnexpectedReservedWorkload,
            BatchInvariant::ValueOutOfSqliteRange,
            BatchInvariant::SmartBatchAlreadyPending,
        ];
        for value in values {
            assert!(!value.to_string().is_empty());
        }
    }

    #[test]
    fn database_error_display_escapes_dynamic_control_characters() {
        let error = DbWriteError::Open {
            path: PathBuf::from("/tmp/state\n\x1b[31m.db"),
            source: Box::new(std::io::Error::other("safe source")),
        };
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains('\n'));
            assert!(!rendered.contains('\u{1b}'));
            assert!(rendered.contains("\\n"));
        }
        assert!(error.source().is_some());
    }

    #[test]
    fn source_less_error_reports_no_source() {
        let error = DbWriteError::InvalidBatch {
            request_id: 7,
            reason: BatchInvariant::UnknownDevice,
        };
        assert!(error.source().is_none());
        assert!(error.to_string().contains('7'));
    }

    #[test]
    fn closed_ack_channel_distinguishes_unstarted_and_uncertain_requests() {
        assert!(matches!(
            closed_acknowledgement_error(11, REQUEST_QUEUED, false),
            DbWriteError::QueueClosed
        ));
        assert!(matches!(
            closed_acknowledgement_error(12, REQUEST_EXECUTING, false),
            DbWriteError::CommitAcknowledgementLost { request_id: 12 }
        ));
        assert!(matches!(
            closed_acknowledgement_error(13, REQUEST_QUEUED, true),
            DbWriteError::CommitAcknowledgementLost { request_id: 13 }
        ));
    }

    #[test]
    fn acknowledgement_loss_replays_same_request_id_and_batch() {
        let (sender, receiver) = sync_channel(1);
        let handle = test_handle(sender);
        let writer = std::thread::spawn(move || {
            let first = receiver.recv().expect("first request");
            assert!(!first.replay_requires_reopen);
            first.progress.store(REQUEST_EXECUTING, Ordering::Release);
            let request_id = first.request_id;
            let batch = Arc::clone(&first.batch);
            drop(first);

            let second = receiver.recv().expect("replayed request");
            assert_eq!(second.request_id, request_id);
            assert!(Arc::ptr_eq(&second.batch, &batch));
            assert!(second.replay_requires_reopen);
            second.progress.store(REQUEST_EXECUTING, Ordering::Release);
            second
                .commit_ack
                .send(Ok(CommitAck { request_id }))
                .expect("send replay acknowledgement");
        });

        let acknowledgement = handle
            .submit(empty_writer_batch(0))
            .expect("same logical request is replayed");
        assert_eq!(acknowledgement.request_id, 1);
        writer.join().expect("fake writer");
    }

    #[test]
    fn acknowledgement_closed_before_execution_is_queue_closed_without_replay() {
        let (sender, receiver) = sync_channel(1);
        let handle = test_handle(sender);
        let writer = std::thread::spawn(move || {
            let request = receiver.recv().expect("queued request");
            assert_eq!(request.progress.load(Ordering::Acquire), REQUEST_QUEUED);
            drop(request);
            assert!(matches!(
                receiver.recv_timeout(Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
        });

        let error = handle
            .submit(empty_writer_batch(0))
            .expect_err("an unexecuted request has a known uncommitted outcome");
        assert!(matches!(error, DbWriteError::QueueClosed));
        writer.join().expect("fake writer");
    }

    #[test]
    fn accepted_request_waits_for_acknowledgement_after_stop() {
        let (sender, receiver) = sync_channel(1);
        let handle = test_handle(sender);
        let stop = Arc::new(AtomicBool::new(false));
        let (accepted_sender, accepted_receiver) = sync_channel(0);
        let (release_sender, release_receiver) = sync_channel(0);
        let writer = std::thread::spawn(move || {
            let request = receiver.recv().expect("accepted request");
            request.progress.store(REQUEST_EXECUTING, Ordering::Release);
            accepted_sender.send(()).expect("report admission");
            release_receiver.recv().expect("release acknowledgement");
            request
                .commit_ack
                .send(Ok(CommitAck {
                    request_id: request.request_id,
                }))
                .expect("send acknowledgement");
        });

        let producer_stop = Arc::clone(&stop);
        let producer = std::thread::spawn(move || {
            handle.submit_until_stopped(empty_writer_batch(0), &producer_stop)
        });
        accepted_receiver.recv().expect("request entered FIFO");
        stop.store(true, Ordering::Release);
        release_sender.send(()).expect("release writer");

        let acknowledgement = producer
            .join()
            .expect("producer")
            .expect("acknowledgement result")
            .expect("accepted request remains pending during stop");
        assert_eq!(acknowledgement.request_id, 1);
        writer.join().expect("fake writer");
    }

    #[test]
    fn stopped_producer_does_not_enter_a_full_fifo() {
        let (sender, receiver) = sync_channel(1);
        let handle = test_handle(sender.clone());
        let (dummy_ack, _dummy_receiver) = sync_channel(1);
        sender
            .send(DbRequest {
                request_id: 99,
                batch: Arc::new(empty_writer_batch(0)),
                commit_ack: dummy_ack,
                progress: Arc::new(AtomicU8::new(REQUEST_QUEUED)),
                replay_requires_reopen: false,
            })
            .expect("fill request queue");

        let stop = Arc::new(AtomicBool::new(false));
        let producer_stop = Arc::clone(&stop);
        let producer_handle = handle.clone();
        let producer = std::thread::spawn(move || {
            producer_handle.submit_until_stopped(empty_writer_batch(60_000), &producer_stop)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while handle.unconfirmed_requests.load(Ordering::Acquire) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "producer did not wait"
            );
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Release);

        assert!(
            producer
                .join()
                .expect("producer")
                .expect("stop result")
                .is_none()
        );
        assert_eq!(
            receiver.recv().expect("original queued request").request_id,
            99
        );
        assert!(receiver.try_recv().is_err());
    }
}
