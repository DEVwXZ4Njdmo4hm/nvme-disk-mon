pub(crate) mod smart;

use std::{
    fmt::Write as _,
    io,
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    ErrorSource,
    config::{DiskConfig, MailConfig},
    database::{DatabaseBatch, DatabaseHandle, RecoveredSmartBaseline, SmartSampleBatch},
    mail::{MailError, PreparedMessage, SmtpReceipt},
    writer::{
        collector::WriterBoundaryTracker,
        history::{RankError, WriterHistory, WriterRank},
    },
};

pub(crate) use smart::{
    NvmeTarget, SmartReadError, VerifiedNvmeDevice, device_hash_id, is_valid_hash_id,
    read_verified_smart,
};

const NVME_DATA_UNIT_BYTES: u128 = 512_000;
#[cfg(test)]
const GIB_BYTES: f64 = 1_073_741_824.0;
const WINDOW_TOLERANCE_MS: u64 = 60_000;
const UTC_MINUTE_MS: i64 = 60_000;
const MAX_SMART_READ_RETRIES: u32 = 3;
const SMART_READ_RETRY_BASE: Duration = Duration::from_secs(1);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SmartDeltaState {
    ValidWindow {
        write_amount_bytes: i64,
    },
    OutsideDetectionWindow {
        write_amount_bytes: i64,
        expected_span_ms: i64,
        actual_span_ms: i64,
    },
    FirstBaseline,
    CounterRegressed,
    ContinuityUncertain,
    AmountOutOfSqliteRange,
}

impl SmartDeltaState {
    const fn persisted_amount(self) -> Option<i64> {
        match self {
            Self::ValidWindow { write_amount_bytes }
            | Self::OutsideDetectionWindow {
                write_amount_bytes, ..
            } => Some(write_amount_bytes),
            Self::FirstBaseline
            | Self::CounterRegressed
            | Self::ContinuityUncertain
            | Self::AmountOutOfSqliteRange => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SmartThresholdEvent {
    pub(crate) device_hash_id: String,
    pub(crate) label: String,
    pub(crate) configured_path: PathBuf,
    pub(crate) previous_timestamp: i64,
    pub(crate) current_timestamp: i64,
    pub(crate) write_amount_bytes: i64,
    pub(crate) threshold_gib: f64,
    pub(crate) lookback_minutes: NonZeroU32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SmartBaseline {
    timestamp: i64,
    data_units_written: u128,
}

impl From<RecoveredSmartBaseline> for SmartBaseline {
    fn from(recovered: RecoveredSmartBaseline) -> Self {
        Self {
            timestamp: recovered.timestamp,
            data_units_written: recovered.data_units_written,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingSmartSample {
    timestamp: i64,
    data_units_written: u128,
    previous_timestamp: Option<i64>,
    delta_state: SmartDeltaState,
}

impl PendingSmartSample {
    fn to_batch(self, device_hash_id: &str) -> SmartSampleBatch {
        SmartSampleBatch {
            device_hash_id: device_hash_id.to_owned(),
            timestamp: self.timestamp,
            data_units_written_be: self.data_units_written.to_be_bytes(),
            write_amount_bytes: self.delta_state.persisted_amount(),
        }
    }
}

pub(crate) struct SmartMonitorDevice {
    label: String,
    target: NvmeTarget,
    verified: VerifiedNvmeDevice,
    expected_span_ms: i64,
    lookback_minutes: NonZeroU32,
    threshold_gib: f64,
    baseline: Option<SmartBaseline>,
    pending: Option<PendingSmartSample>,
    next_due_timestamp: i64,
    read_failures: u32,
    active: bool,
}

impl SmartMonitorDevice {
    pub(crate) fn new(
        config: &DiskConfig,
        verified: VerifiedNvmeDevice,
        recovered: Option<RecoveredSmartBaseline>,
    ) -> Result<Self, ErrorSource> {
        let expected_span_ms = config
            .detect_window_hr
            .checked_mul(3_600_000)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SMART detection window is outside the supported range",
                )) as ErrorSource
            })?;
        let lookback_minutes = config
            .detect_window_hr
            .checked_mul(60)
            .and_then(|value| u32::try_from(value).ok())
            .and_then(NonZeroU32::new)
            .ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SMART detection window does not fit the ranking lookback range",
                )) as ErrorSource
            })?;
        let expected_hash = device_hash_id(&config.serial, &config.path);
        if verified.configured_path != config.path
            || !is_valid_hash_id(&verified.hash_id)
            || verified.hash_id != expected_hash
        {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "verified NVMe device identity is inconsistent",
            )));
        }

        Ok(Self {
            label: config.label.clone(),
            target: NvmeTarget {
                configured_path: config.path.clone(),
                expected_serial: config.serial.clone(),
            },
            verified,
            expected_span_ms,
            lookback_minutes,
            threshold_gib: config.w_delta_threshold_gib,
            baseline: recovered.map(SmartBaseline::from),
            pending: None,
            next_due_timestamp: 0,
            read_failures: 0,
            active: true,
        })
    }

    pub(crate) fn hash_id(&self) -> &str {
        &self.verified.hash_id
    }

    fn identity_matches(&self, observed: &VerifiedNvmeDevice) -> bool {
        observed == &self.verified
    }

    fn prepare_current(&mut self, timestamp: i64, data_units_written: u128) -> SmartDeltaState {
        if let Some(pending) = self.pending {
            return pending.delta_state;
        }

        let delta_state = classify_smart_delta(
            self.baseline,
            timestamp,
            data_units_written,
            self.expected_span_ms,
        );
        self.pending = Some(PendingSmartSample {
            timestamp,
            data_units_written,
            previous_timestamp: self.baseline.map(|baseline| baseline.timestamp),
            delta_state,
        });
        delta_state
    }

    fn pending_batch(&self) -> Option<SmartSampleBatch> {
        self.pending
            .map(|pending| pending.to_batch(&self.verified.hash_id))
    }

    fn acknowledge_pending(&mut self) -> Option<SmartThresholdEvent> {
        let pending = self.pending.take()?;
        self.baseline = Some(SmartBaseline {
            timestamp: pending.timestamp,
            data_units_written: pending.data_units_written,
        });

        let SmartDeltaState::ValidWindow { write_amount_bytes } = pending.delta_state else {
            return None;
        };
        if !bytes_strictly_exceed_gib(write_amount_bytes, self.threshold_gib) {
            return None;
        }
        let previous_timestamp = pending.previous_timestamp?;
        Some(SmartThresholdEvent {
            device_hash_id: self.verified.hash_id.clone(),
            label: self.label.clone(),
            configured_path: self.verified.configured_path.clone(),
            previous_timestamp,
            current_timestamp: pending.timestamp,
            write_amount_bytes,
            threshold_gib: self.threshold_gib,
            lookback_minutes: self.lookback_minutes,
        })
    }

    fn schedule_after_success(&mut self, sampled_timestamp: i64) -> Result<(), ErrorSource> {
        self.next_due_timestamp =
            utc_minute_nearest_window(sampled_timestamp, self.expected_span_ms).ok_or_else(
                || {
                    Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SMART schedule timestamp is outside the supported range",
                    )) as ErrorSource
                },
            )?;
        self.read_failures = 0;
        Ok(())
    }

    fn schedule_after_read_failure(&mut self, now_ms: i64) -> Result<(), ErrorSource> {
        self.read_failures += 1;
        if self.read_failures <= MAX_SMART_READ_RETRIES {
            let shift = self.read_failures - 1;
            let factor = 1_u32 << shift;
            let retry_ms = SMART_READ_RETRY_BASE
                .checked_mul(factor)
                .and_then(|duration| i64::try_from(duration.as_millis()).ok())
                .ok_or_else(|| {
                    Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SMART retry schedule is outside the supported range",
                    )) as ErrorSource
                })?;
            self.next_due_timestamp = now_ms.checked_add(retry_ms).ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SMART retry timestamp is outside the supported range",
                )) as ErrorSource
            })?;
        } else {
            self.read_failures = 0;
            self.next_due_timestamp = utc_minute_nearest_window(now_ms, self.expected_span_ms)
                .ok_or_else(|| {
                    Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SMART schedule timestamp is outside the supported range",
                    )) as ErrorSource
                })?;
        }
        Ok(())
    }
}

pub(crate) struct SmartAlertFacility {
    inner: Arc<SmartAlertInner>,
    runtime: tokio::runtime::Handle,
}

struct SmartAlertInner {
    history: WriterHistory,
    boundary_tracker: WriterBoundaryTracker,
    mail_config: MailConfig,
    host: String,
    stop: Arc<AtomicBool>,
    rank_limit: NonZeroUsize,
    mail_gate: Mutex<()>,
}

impl SmartAlertFacility {
    pub(crate) fn new(
        history: WriterHistory,
        boundary_tracker: WriterBoundaryTracker,
        mail_config: MailConfig,
        host: String,
        stop: Arc<AtomicBool>,
        runtime: tokio::runtime::Handle,
        rank_limit: NonZeroUsize,
    ) -> Self {
        Self {
            inner: Arc::new(SmartAlertInner {
                history,
                boundary_tracker,
                mail_config,
                host,
                stop,
                rank_limit,
                mail_gate: Mutex::new(()),
            }),
            runtime,
        }
    }

    fn handle_threshold(&self, event: &SmartThresholdEvent) {
        let inner = Arc::clone(&self.inner);
        let event = event.clone();
        let runtime = self.runtime.clone();
        let task_runtime = runtime.clone();
        drop(runtime.spawn_blocking(move || {
            inner.handle_threshold_blocking(&event, &task_runtime);
        }));
    }
}

impl SmartAlertInner {
    fn handle_threshold_blocking(
        &self,
        event: &SmartThresholdEvent,
        runtime: &tokio::runtime::Handle,
    ) {
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        let end_timestamp =
            event.current_timestamp - event.current_timestamp.rem_euclid(UTC_MINUTE_MS);
        match self.boundary_tracker.wait_until_processed(
            end_timestamp,
            &event.device_hash_id,
            self.stop.as_ref(),
        ) {
            Ok(Some(true)) => {}
            Ok(Some(false)) => tracing::warn!(
                device_hash_id = event.device_hash_id.as_str(),
                bucket_end_unix_ms = end_timestamp,
                "writer bucket is incomplete for a SMART alert"
            ),
            Ok(None) => tracing::warn!(
                device_hash_id = event.device_hash_id.as_str(),
                bucket_end_unix_ms = end_timestamp,
                "writer boundary result is no longer available for a SMART alert"
            ),
            Err(_) if self.stop.load(Ordering::Acquire) => return,
            Err(error) => tracing::warn!(
                device_hash_id = event.device_hash_id.as_str(),
                bucket_end_unix_ms = end_timestamp,
                error = %error,
                "writer boundary wait failed for a SMART alert"
            ),
        }

        let ranking = self.history.top_writers_ending_at(
            &event.configured_path,
            self.rank_limit,
            event.lookback_minutes,
            end_timestamp,
        );
        let message = match prepare_threshold_message(&self.mail_config, &self.host, event, ranking)
        {
            Ok(message) => message,
            Err(error) => {
                tracing::error!(
                    device_hash_id = event.device_hash_id.as_str(),
                    error = %error,
                    "could not construct a SMART alert message"
                );
                return;
            }
        };
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        let Ok(_mail_guard) = self.mail_gate.lock() else {
            tracing::error!(
                device_hash_id = event.device_hash_id.as_str(),
                "mail serialization state is unavailable for a SMART alert"
            );
            return;
        };
        if self.stop.load(Ordering::Acquire) {
            return;
        }
        run_alert_mail_attempt(event.device_hash_id.as_str(), || {
            runtime.block_on(crate::mail::send_mail(&self.mail_config, &message))
        });
    }
}

fn run_alert_mail_attempt(
    device_hash_id: &str,
    send: impl FnOnce() -> Result<SmtpReceipt, MailError>,
) {
    match send() {
        Ok(receipt) => tracing::info!(
            device_hash_id,
            smtp_status = receipt.code,
            "SMART alert mail was accepted by the SMTP server"
        ),
        Err(error) => tracing::error!(
            device_hash_id,
            error = %error,
            "SMART alert mail was not accepted"
        ),
    }
}

fn prepare_threshold_message(
    mail_config: &MailConfig,
    host: &str,
    event: &SmartThresholdEvent,
    ranking: Result<Vec<WriterRank>, RankError>,
) -> Result<PreparedMessage, MailError> {
    let body = threshold_body(host, event, ranking)?;
    PreparedMessage::text(
        &mail_config.send_as,
        &mail_config.send_to,
        "NVMe-Disk-Mon write alert",
        &body,
    )
}

fn threshold_body(
    host: &str,
    event: &SmartThresholdEvent,
    ranking: Result<Vec<WriterRank>, RankError>,
) -> Result<String, MailError> {
    let write_amount_gib =
        format_bytes_as_gib(event.write_amount_bytes).ok_or(MailError::InvalidMessage {
            field: "write_amount_bytes",
        })?;
    let mut body = format!(
        "NVMe host-write threshold exceeded.\r\n\r\nHost: {}\r\nDevice: {}\r\nPath: {}\r\nWindow: {} minute(s)\r\nWrite amount: {write_amount_gib} GiB\r\nThreshold: {:.3} GiB\r\n",
        log_safe_text(host),
        log_safe_text(&event.label),
        log_safe_path(&event.configured_path),
        event.lookback_minutes,
        event.threshold_gib,
    );
    match ranking {
        Ok(ranks) if ranks.is_empty() => {
            body.push_str("\r\nTop writers: no attributed writes in the complete window.\r\n");
        }
        Ok(ranks) => {
            body.push_str("\r\nTop writers:\r\n");
            for rank in ranks {
                write!(
                    body,
                    "- {}: {:.3} MiB\r\n",
                    log_safe_text(&rank.name),
                    rank.w_amount_mib
                )
                .map_err(|_| MailError::InvalidMessage {
                    field: "alert body",
                })?;
            }
        }
        Err(error) => {
            write!(
                body,
                "\r\nWriter attribution unavailable for the requested window: {}\r\n",
                log_safe_text(&error.to_string())
            )
            .map_err(|_| MailError::InvalidMessage {
                field: "alert body",
            })?;
        }
    }
    Ok(body)
}

fn format_bytes_as_gib(write_amount_bytes: i64) -> Option<String> {
    const GIB_BYTES: u128 = 1_073_741_824;

    let write_amount_bytes = u128::from(u64::try_from(write_amount_bytes).ok()?);
    let rounded_thousandths = (write_amount_bytes * 1_000 + GIB_BYTES / 2) / GIB_BYTES;
    let whole = rounded_thousandths / 1_000;
    let fraction = rounded_thousandths % 1_000;
    Some(format!("{whole}.{fraction:03}"))
}

fn log_safe_text(value: &str) -> String {
    log_safe_bytes(value.as_bytes(), 256)
}

fn log_safe_path(path: &Path) -> String {
    log_safe_bytes(path.as_os_str().as_encoded_bytes(), 512)
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

pub(crate) struct SmartMonitorTask {
    devices: Vec<SmartMonitorDevice>,
    database: DatabaseHandle,
    stop: Arc<AtomicBool>,
    alerts: SmartAlertFacility,
}

impl SmartMonitorTask {
    pub(crate) fn new(
        devices: Vec<SmartMonitorDevice>,
        database: DatabaseHandle,
        stop: Arc<AtomicBool>,
        alerts: SmartAlertFacility,
    ) -> Self {
        Self {
            devices,
            database,
            stop,
            alerts,
        }
    }

    pub(crate) fn run(mut self) -> Result<(), ErrorSource> {
        if self.devices.is_empty() {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SMART monitor has no devices",
            )));
        }

        log_smart_monitor_start(&self.devices);

        while !self.stop.load(Ordering::Acquire) {
            let now_ms = unix_milliseconds()?;
            let mut sampled_any = false;

            for device in &mut self.devices {
                if self.stop.load(Ordering::Acquire) {
                    break;
                }
                if !device.active || device.next_due_timestamp > now_ms {
                    continue;
                }
                sampled_any = true;

                let health = match read_verified_smart(&device.target) {
                    Ok((observed, health)) if device.identity_matches(&observed) => health,
                    Ok(_) => {
                        tracing::error!(
                            device_hash_id = device.hash_id(),
                            device_label = %log_safe_text(&device.label),
                            configured_path = %log_safe_path(&device.verified.configured_path),
                            "stopping SMART collection for a device after identity change"
                        );
                        device.active = false;
                        continue;
                    }
                    Err(error @ SmartReadError::SerialMismatch { .. }) => {
                        tracing::error!(
                            device_hash_id = device.hash_id(),
                            device_label = %log_safe_text(&device.label),
                            configured_path = %log_safe_path(&device.verified.configured_path),
                            error = %error,
                            "stopping SMART collection for a device after identity mismatch"
                        );
                        device.active = false;
                        continue;
                    }
                    Err(error) => {
                        device.schedule_after_read_failure(now_ms)?;
                        tracing::warn!(
                            device_hash_id = device.hash_id(),
                            device_label = %log_safe_text(&device.label),
                            configured_path = %log_safe_path(&device.verified.configured_path),
                            next_due_unix_ms = device.next_due_timestamp,
                            error = %error,
                            "SMART sample failed; keeping the committed baseline"
                        );
                        continue;
                    }
                };

                let sampled_timestamp = system_time_milliseconds(health.sampled_at)?;
                let delta_state = match prepare_health_sample(
                    device,
                    sampled_timestamp,
                    health.data_units_written,
                ) {
                    Ok(delta_state) => delta_state,
                    Err(error) => {
                        device.schedule_after_read_failure(now_ms)?;
                        tracing::warn!(
                            device_hash_id = device.hash_id(),
                            device_label = %log_safe_text(&device.label),
                            configured_path = %log_safe_path(&device.verified.configured_path),
                            next_due_unix_ms = device.next_due_timestamp,
                            error = %error,
                            "SMART sample lacks the required counter; keeping the committed baseline"
                        );
                        continue;
                    }
                };

                if self.stop.load(Ordering::Acquire) {
                    break;
                }
                if !submit_pending(&self.database, device, self.stop.as_ref())? {
                    break;
                }
                let event = device.acknowledge_pending();
                device.schedule_after_success(sampled_timestamp)?;
                log_committed_smart_sample(device, sampled_timestamp, delta_state);
                if let Some(event) = event {
                    log_smart_threshold_event(&event);
                    self.alerts.handle_threshold(&event);
                }
            }

            if !self.devices.iter().any(|device| device.active) {
                return Err(Box::new(io::Error::other(
                    "SMART collection stopped for every configured device",
                )));
            }
            if !sampled_any {
                sleep_until_due_or_stopped(&self.devices, &self.stop)?;
            }
        }
        tracing::info!("SMART monitor stopped");
        Ok(())
    }
}

fn log_smart_monitor_start(devices: &[SmartMonitorDevice]) {
    tracing::info!(device_count = devices.len(), "SMART monitor started");
    for device in devices {
        tracing::info!(
            device_hash_id = device.hash_id(),
            device_label = %log_safe_text(&device.label),
            configured_path = %log_safe_path(&device.verified.configured_path),
            detect_window_hours = device.expected_span_ms / 3_600_000,
            threshold_gib = device.threshold_gib,
            recovered_baseline = device.baseline.is_some(),
            "SMART monitoring is enabled for device"
        );
    }
}

fn log_smart_threshold_event(event: &SmartThresholdEvent) {
    tracing::warn!(
        device_hash_id = event.device_hash_id.as_str(),
        device_label = %log_safe_text(&event.label),
        configured_path = %log_safe_path(&event.configured_path),
        write_amount_bytes = event.write_amount_bytes,
        threshold_gib = event.threshold_gib,
        window_minutes = event.lookback_minutes.get(),
        "SMART host-write threshold exceeded; preparing alert"
    );
}

fn log_committed_smart_sample(
    device: &SmartMonitorDevice,
    sampled_timestamp: i64,
    delta_state: SmartDeltaState,
) {
    match delta_state {
        SmartDeltaState::ValidWindow { write_amount_bytes } => tracing::info!(
            device_hash_id = device.hash_id(),
            device_label = %log_safe_text(&device.label),
            configured_path = %log_safe_path(&device.verified.configured_path),
            sampled_at_unix_ms = sampled_timestamp,
            write_amount_bytes,
            next_due_unix_ms = device.next_due_timestamp,
            "SMART sample committed"
        ),
        SmartDeltaState::OutsideDetectionWindow {
            write_amount_bytes,
            expected_span_ms,
            actual_span_ms,
        } => tracing::warn!(
            device_hash_id = device.hash_id(),
            device_label = %log_safe_text(&device.label),
            configured_path = %log_safe_path(&device.verified.configured_path),
            sampled_at_unix_ms = sampled_timestamp,
            write_amount_bytes,
            expected_span_ms,
            actual_span_ms,
            next_due_unix_ms = device.next_due_timestamp,
            "SMART sample committed outside the detection window; threshold evaluation skipped"
        ),
        SmartDeltaState::FirstBaseline => tracing::info!(
            device_hash_id = device.hash_id(),
            device_label = %log_safe_text(&device.label),
            configured_path = %log_safe_path(&device.verified.configured_path),
            sampled_at_unix_ms = sampled_timestamp,
            next_due_unix_ms = device.next_due_timestamp,
            "initial SMART baseline committed"
        ),
        SmartDeltaState::CounterRegressed => tracing::warn!(
            device_hash_id = device.hash_id(),
            device_label = %log_safe_text(&device.label),
            configured_path = %log_safe_path(&device.verified.configured_path),
            sampled_at_unix_ms = sampled_timestamp,
            next_due_unix_ms = device.next_due_timestamp,
            "SMART counter regressed; new baseline committed without a write delta"
        ),
        SmartDeltaState::ContinuityUncertain => tracing::warn!(
            device_hash_id = device.hash_id(),
            device_label = %log_safe_text(&device.label),
            configured_path = %log_safe_path(&device.verified.configured_path),
            sampled_at_unix_ms = sampled_timestamp,
            next_due_unix_ms = device.next_due_timestamp,
            "SMART sample continuity is uncertain; new baseline committed without a write delta"
        ),
        SmartDeltaState::AmountOutOfSqliteRange => tracing::warn!(
            device_hash_id = device.hash_id(),
            device_label = %log_safe_text(&device.label),
            configured_path = %log_safe_path(&device.verified.configured_path),
            sampled_at_unix_ms = sampled_timestamp,
            next_due_unix_ms = device.next_due_timestamp,
            "SMART write delta is outside the database range; new baseline committed without a write delta"
        ),
    }
}

fn classify_smart_delta(
    previous: Option<SmartBaseline>,
    current_timestamp: i64,
    current_data_units_written: u128,
    expected_span_ms: i64,
) -> SmartDeltaState {
    let Some(previous) = previous else {
        return SmartDeltaState::FirstBaseline;
    };
    let Some(delta_units) = current_data_units_written.checked_sub(previous.data_units_written)
    else {
        return SmartDeltaState::CounterRegressed;
    };
    let Some(actual_span_ms) = current_timestamp.checked_sub(previous.timestamp) else {
        return SmartDeltaState::ContinuityUncertain;
    };
    if actual_span_ms < 0 {
        return SmartDeltaState::ContinuityUncertain;
    }
    let Some(write_amount_bytes) = delta_units
        .checked_mul(NVME_DATA_UNIT_BYTES)
        .and_then(|amount| i64::try_from(amount).ok())
    else {
        return SmartDeltaState::AmountOutOfSqliteRange;
    };

    if actual_span_ms.abs_diff(expected_span_ms) <= WINDOW_TOLERANCE_MS {
        SmartDeltaState::ValidWindow { write_amount_bytes }
    } else {
        SmartDeltaState::OutsideDetectionWindow {
            write_amount_bytes,
            expected_span_ms,
            actual_span_ms,
        }
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
        // Zero and every subnormal GiB value are smaller than one byte.
        return Some(0);
    }

    let exponent = i32::from(u16::try_from(encoded_exponent).ok()?) - EXPONENT_BIAS;
    let significand = (1_u64 << 52) | (bits & FRACTION_MASK);
    let byte_shift = exponent - FRACTION_BITS + GIB_POWER;
    if byte_shift >= 0 {
        if byte_shift >= 12 {
            // The minimum normal significand is 2^52, so this threshold is at
            // least 2^64 bytes and no non-negative SQLite INTEGER can exceed it.
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

fn submit_pending(
    database: &DatabaseHandle,
    device: &SmartMonitorDevice,
    stop: &AtomicBool,
) -> Result<bool, ErrorSource> {
    let batch = device.pending_batch().ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SMART database submission has no pending sample",
        )) as ErrorSource
    })?;

    database
        .submit_until_stopped(DatabaseBatch::SmartSample(batch), stop)
        .map(|acknowledgement| acknowledgement.is_some())
        .map_err(|error| Box::new(error) as ErrorSource)
}

pub(crate) fn required_data_units_written(counter: Option<u128>) -> Result<u128, SmartReadError> {
    counter.ok_or(SmartReadError::RequiredCounterUnavailable {
        field: "data_units_written",
    })
}

fn prepare_health_sample(
    device: &mut SmartMonitorDevice,
    sampled_timestamp: i64,
    data_units_written: Option<u128>,
) -> Result<SmartDeltaState, SmartReadError> {
    let data_units_written = required_data_units_written(data_units_written)?;
    Ok(device.prepare_current(sampled_timestamp, data_units_written))
}

fn utc_minute_nearest_window(sampled_timestamp: i64, window_ms: i64) -> Option<i64> {
    let target = sampled_timestamp.checked_add(window_ms)?;
    let remainder = target.rem_euclid(UTC_MINUTE_MS);
    if remainder < UTC_MINUTE_MS / 2 {
        target.checked_sub(remainder)
    } else {
        target.checked_add(UTC_MINUTE_MS - remainder)
    }
}

fn sleep_until_due_or_stopped(
    devices: &[SmartMonitorDevice],
    stop: &AtomicBool,
) -> Result<(), ErrorSource> {
    let Some(next_due) = devices
        .iter()
        .filter(|device| device.active)
        .map(|device| device.next_due_timestamp)
        .min()
    else {
        return Ok(());
    };

    while !stop.load(Ordering::Acquire) {
        let now_ms = unix_milliseconds()?;
        if now_ms >= next_due {
            break;
        }
        let remaining = u64::try_from(next_due - now_ms).map(Duration::from_millis)?;
        thread::sleep(remaining.min(STOP_POLL_INTERVAL));
    }
    Ok(())
}

fn unix_milliseconds() -> Result<i64, ErrorSource> {
    system_time_milliseconds(SystemTime::now())
}

fn system_time_milliseconds(time: SystemTime) -> Result<i64, ErrorSource> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Box::new(error) as ErrorSource)?;
    i64::try_from(duration.as_millis()).map_err(|_| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "system time is outside the supported range",
        )) as ErrorSource
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn baseline(timestamp: i64, data_units_written: u128) -> SmartBaseline {
        SmartBaseline {
            timestamp,
            data_units_written,
        }
    }

    fn test_device(
        threshold_gib: f64,
        recovered: Option<RecoveredSmartBaseline>,
    ) -> SmartMonitorDevice {
        let config = DiskConfig {
            label: "test-disk".to_owned(),
            serial: "SERIAL0".to_owned(),
            path: PathBuf::from("/dev/disk/by-id/nvme-test"),
            detect_window_hr: 1,
            w_delta_threshold_gib: threshold_gib,
        };
        let verified = VerifiedNvmeDevice {
            configured_path: config.path.clone(),
            namespace_major: 259,
            namespace_minor: 3,
            controller_path: PathBuf::from("/dev/nvme0"),
            hash_id: device_hash_id(&config.serial, &config.path),
        };
        SmartMonitorDevice::new(&config, verified, recovered).expect("valid test device")
    }

    #[test]
    fn delta_states_cover_baselines_counter_order_and_window_tolerance() {
        let expected = 3_600_000;
        let cases = [
            (
                "first baseline",
                None,
                expected,
                10,
                SmartDeltaState::FirstBaseline,
            ),
            (
                "exact window",
                Some(baseline(0, 10)),
                expected,
                12,
                SmartDeltaState::ValidWindow {
                    write_amount_bytes: 1_024_000,
                },
            ),
            (
                "lower tolerance edge",
                Some(baseline(0, 10)),
                expected - 60_000,
                11,
                SmartDeltaState::ValidWindow {
                    write_amount_bytes: 512_000,
                },
            ),
            (
                "upper tolerance edge",
                Some(baseline(0, 10)),
                expected + 60_000,
                11,
                SmartDeltaState::ValidWindow {
                    write_amount_bytes: 512_000,
                },
            ),
            (
                "outside tolerance",
                Some(baseline(0, 10)),
                expected + 60_001,
                11,
                SmartDeltaState::OutsideDetectionWindow {
                    write_amount_bytes: 512_000,
                    expected_span_ms: expected,
                    actual_span_ms: expected + 60_001,
                },
            ),
            (
                "counter regressed",
                Some(baseline(0, 10)),
                expected,
                9,
                SmartDeltaState::CounterRegressed,
            ),
            (
                "clock regressed",
                Some(baseline(1, 10)),
                0,
                11,
                SmartDeltaState::ContinuityUncertain,
            ),
        ];

        for (name, previous, timestamp, counter, expected_state) in cases {
            assert_eq!(
                classify_smart_delta(previous, timestamp, counter, expected),
                expected_state,
                "{name}"
            );
        }
    }

    #[test]
    fn delta_conversion_is_checked_at_the_sqlite_boundary() {
        let maximum_units = u128::try_from(i64::MAX).expect("positive") / NVME_DATA_UNIT_BYTES;
        assert_eq!(
            classify_smart_delta(
                Some(baseline(0, 5)),
                3_600_000,
                5 + maximum_units,
                3_600_000,
            ),
            SmartDeltaState::ValidWindow {
                write_amount_bytes: i64::try_from(maximum_units * NVME_DATA_UNIT_BYTES)
                    .expect("within SQLite range"),
            }
        );
        assert_eq!(
            classify_smart_delta(
                Some(baseline(0, 5)),
                3_600_000,
                5 + maximum_units + 1,
                3_600_000,
            ),
            SmartDeltaState::AmountOutOfSqliteRange
        );
        assert_eq!(
            classify_smart_delta(Some(baseline(0, 0)), 3_600_000, u128::MAX, 3_600_000,),
            SmartDeltaState::AmountOutOfSqliteRange
        );
    }

    #[test]
    fn pending_batch_is_immutable_until_acknowledged() {
        let recovered = RecoveredSmartBaseline {
            timestamp: 0,
            data_units_written: 10,
        };
        let mut device = test_device(100.0, Some(recovered));
        device.prepare_current(3_600_000, 12);

        let first = device.pending_batch().expect("pending batch");
        assert_eq!(first.timestamp, 3_600_000);
        assert_eq!(first.data_units_written_be, 12_u128.to_be_bytes());
        assert_eq!(first.write_amount_bytes, Some(1_024_000));
        assert_eq!(device.baseline, Some(recovered.into()));

        let second = device.pending_batch().expect("same pending batch");
        assert_eq!(second, first);
        assert!(device.acknowledge_pending().is_none());
        assert_eq!(
            device.baseline,
            Some(baseline(3_600_000, 12)),
            "only acknowledgement advances the baseline"
        );
        assert!(device.pending_batch().is_none());
    }

    #[test]
    fn threshold_is_strict_and_only_valid_windows_participate() {
        let amount_gib = 512_000.0 / GIB_BYTES;
        let recovered = RecoveredSmartBaseline {
            timestamp: 0,
            data_units_written: 10,
        };

        let mut equal = test_device(amount_gib, Some(recovered));
        equal.prepare_current(3_600_000, 11);
        assert!(equal.acknowledge_pending().is_none());

        let mut exceeded = test_device(amount_gib / 2.0, Some(recovered));
        exceeded.prepare_current(3_600_000, 11);
        let event = exceeded.acknowledge_pending().expect("strictly exceeded");
        assert_eq!(event.previous_timestamp, 0);
        assert_eq!(event.current_timestamp, 3_600_000);
        assert_eq!(event.write_amount_bytes, 512_000);
        assert_eq!(event.lookback_minutes.get(), 60);

        let two_to_53_bytes = 1_i64 << 53;
        assert!(!bytes_strictly_exceed_gib(two_to_53_bytes, 8_388_608.0));
        assert!(bytes_strictly_exceed_gib(two_to_53_bytes + 1, 8_388_608.0));

        let mut outside = test_device(0.0, Some(recovered));
        outside.prepare_current(3_660_001, 11);
        assert!(outside.acknowledge_pending().is_none());
    }

    #[test]
    fn first_or_unavailable_counter_does_not_construct_an_amount() {
        let mut device = test_device(0.0, None);
        assert!(prepare_health_sample(&mut device, 50, None).is_err());
        assert!(
            device.pending_batch().is_none(),
            "a missing counter must not create a database batch"
        );
        assert_eq!(
            device.prepare_current(100, 50),
            SmartDeltaState::FirstBaseline
        );
        let batch = device.pending_batch().expect("raw baseline batch");
        assert_eq!(batch.write_amount_bytes, None);

        assert!(required_data_units_written(None).is_err());
        assert_eq!(
            device.pending_batch().expect("unchanged batch"),
            batch,
            "a missing required counter cannot replace or create a SMART batch"
        );
    }

    #[test]
    fn schedule_uses_the_nearest_utc_minute_to_preserve_tolerance_margin() {
        assert_eq!(
            utc_minute_nearest_window(123_456, 3_600_000),
            Some(3_720_000)
        );
        assert_eq!(
            utc_minute_nearest_window(120_000, 3_600_000),
            Some(3_720_000)
        );
        assert_eq!(utc_minute_nearest_window(i64::MAX, 1), None);
    }

    #[test]
    fn restored_identity_exposes_registration_device_number() {
        let device = test_device(1.0, None);
        assert!(is_valid_hash_id(device.hash_id()));
        assert_eq!(device.verified.namespace_major, 259);
        assert_eq!(device.verified.namespace_minor, 3);
        assert_eq!(
            device.verified.configured_path,
            Path::new("/dev/disk/by-id/nvme-test")
        );
    }

    #[test]
    fn runtime_identity_rejects_same_serial_on_a_different_namespace() {
        let device = test_device(1.0, None);
        let mut changed = device.verified.clone();
        changed.namespace_minor += 1;
        assert!(!device.identity_matches(&changed));

        changed = device.verified.clone();
        changed.controller_path = PathBuf::from("/dev/nvme1");
        assert!(!device.identity_matches(&changed));
    }

    #[test]
    fn ranking_failure_keeps_the_primary_alert_and_explains_the_gap() {
        let event = SmartThresholdEvent {
            device_hash_id: "a".repeat(64),
            label: "test-disk".to_owned(),
            configured_path: PathBuf::from("/dev/disk/by-id/nvme-test"),
            previous_timestamp: 0,
            current_timestamp: 3_600_000,
            write_amount_bytes: 1_073_741_824,
            threshold_gib: 0.5,
            lookback_minutes: NonZeroU32::new(60).expect("non-zero lookback"),
        };
        let body = threshold_body(
            "test-host",
            &event,
            Err(RankError::QueryParameterOutOfRange {
                parameter: "lookback_minutes",
            }),
        )
        .expect("primary alert remains constructible");

        assert!(body.contains("NVMe host-write threshold exceeded"));
        assert!(body.contains("Write amount: 1.000 GiB"));
        assert!(body.contains("Writer attribution unavailable"));
        assert!(body.contains("lookback_minutes"));
    }

    #[test]
    fn mail_failure_ends_only_that_alert_attempt() {
        let calls = std::cell::Cell::new(0_u8);
        run_alert_mail_attempt("device-a", || {
            calls.set(calls.get() + 1);
            Err(MailError::SmtpRejected {
                stage: crate::mail::SmtpStage::FinalReply,
                code: 550,
                recipient_index: None,
            })
        });
        run_alert_mail_attempt("device-a", || {
            calls.set(calls.get() + 1);
            Ok(SmtpReceipt { code: 250 })
        });
        assert_eq!(calls.get(), 2, "the next alert attempt still runs");
    }
}
