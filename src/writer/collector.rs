use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs,
    hash::{Hash, Hasher},
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    ErrorSource,
    database::{
        CompleteDeviceBucket, DatabaseBatch, DatabaseHandle, WriterAmount, WriterBucketBatch,
    },
};

pub(crate) const CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub(crate) const SAMPLE_PERIOD: Duration = Duration::from_secs(5);
const BUCKET_MILLISECONDS: i64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DeviceNumber {
    pub(crate) major: u32,
    pub(crate) minor: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct MonitoredDevice {
    pub(crate) hash_id: String,
    pub(crate) configured_path: PathBuf,
    pub(crate) number: DeviceNumber,
}

#[derive(Debug, Clone)]
pub(crate) struct WriterBoundaryReport {
    pub(crate) end_timestamp: i64,
    pub(crate) complete_devices: HashSet<String>,
}

impl WriterBoundaryReport {
    pub(crate) fn is_complete(&self, hash_id: &str) -> bool {
        self.complete_devices.contains(hash_id)
    }
}

#[derive(Clone)]
pub(crate) struct WriterBoundaryTracker {
    inner: Arc<(Mutex<Option<WriterBoundaryReport>>, Condvar)>,
}

impl WriterBoundaryTracker {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(None), Condvar::new())),
        }
    }

    fn publish(&self, report: WriterBoundaryReport) {
        let (state, changed) = &*self.inner;
        if let Ok(mut state) = state.lock() {
            *state = Some(report);
            changed.notify_all();
        }
    }

    pub(crate) fn wait_until_processed(
        &self,
        end_timestamp: i64,
        device_hash_id: &str,
        stop: &AtomicBool,
    ) -> Result<Option<bool>, ErrorSource> {
        let (state, changed) = &*self.inner;
        let mut state = state.lock().map_err(|_| {
            Box::new(io::Error::other("writer boundary state is unavailable")) as ErrorSource
        })?;
        while state
            .as_ref()
            .is_none_or(|report| report.end_timestamp < end_timestamp)
        {
            if stop.load(Ordering::Acquire) {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "daemon stopped while waiting for writer boundary",
                )));
            }
            let (next, _) = changed
                .wait_timeout(state, Duration::from_millis(200))
                .map_err(|_| {
                    Box::new(io::Error::other("writer boundary state is unavailable"))
                        as ErrorSource
                })?;
            state = next;
        }
        Ok(state.as_ref().and_then(|report| {
            (report.end_timestamp == end_timestamp).then(|| report.is_complete(device_hash_id))
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BucketIncompleteReason {
    CgroupEnumerationFailed,
    IoStatReadFailed,
    IoStatParseFailed,
    CgroupIdentityChanged,
    CounterReset,
    SamplingDeadlineMissed,
    AccumulatorOverflow,
    DeviceMappingLost,
    DatabaseBackpressure,
}

impl BucketIncompleteReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupEnumerationFailed => "cgroup_enumeration_failed",
            Self::IoStatReadFailed => "io_stat_read_failed",
            Self::IoStatParseFailed => "io_stat_parse_failed",
            Self::CgroupIdentityChanged => "cgroup_identity_changed",
            Self::CounterReset => "counter_reset",
            Self::SamplingDeadlineMissed => "sampling_deadline_missed",
            Self::AccumulatorOverflow => "accumulator_overflow",
            Self::DeviceMappingLost => "device_mapping_lost",
            Self::DatabaseBackpressure => "database_backpressure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CgroupInstanceId {
    device: u64,
    inode: u64,
    birth_time: Option<CgroupBirthTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CgroupBirthTime {
    seconds: i64,
    nanoseconds: u32,
}

#[derive(Clone, Eq)]
struct CounterKey {
    path: Vec<u8>,
    instance: CgroupInstanceId,
    device_hash_id: String,
    device: DeviceNumber,
}

impl PartialEq for CounterKey {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.instance == other.instance
            && self.device_hash_id == other.device_hash_id
            && self.device == other.device
    }
}

impl Hash for CounterKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
        self.instance.hash(state);
        self.device_hash_id.hash(state);
        self.device.hash(state);
    }
}

#[derive(Debug)]
struct Observation {
    path: Vec<u8>,
    instance: CgroupInstanceId,
    workload_name: String,
    counters: HashMap<DeviceNumber, u128>,
}

#[derive(Debug)]
struct ScanOutcome {
    observations: Vec<Observation>,
    incomplete: ScanIncomplete,
}

impl ScanOutcome {
    #[cfg(test)]
    fn complete(observations: Vec<Observation>) -> Self {
        Self {
            observations,
            incomplete: ScanIncomplete::default(),
        }
    }

    fn global_failure(reason: BucketIncompleteReason) -> Self {
        Self {
            observations: Vec::new(),
            incomplete: ScanIncomplete {
                global_reason: Some(reason),
                ..ScanIncomplete::default()
            },
        }
    }
}

#[derive(Debug, Default)]
struct ScanIncomplete {
    global_reason: Option<BucketIncompleteReason>,
    device_reasons: HashMap<DeviceNumber, BucketIncompleteReason>,
    cgroup_failures: Vec<CgroupScanFailure>,
}

#[derive(Debug)]
struct CgroupScanFailure {
    path: Vec<u8>,
    instance: Option<CgroupInstanceId>,
    observed_devices: HashSet<DeviceNumber>,
    reason: BucketIncompleteReason,
}

#[derive(Debug)]
struct ParsedIoStat {
    counters: HashMap<DeviceNumber, u128>,
    failed_devices: HashSet<DeviceNumber>,
    unscoped_failure: bool,
}

#[derive(Debug)]
struct ClosedBucket {
    timestamp: i64,
    batch: Option<WriterBucketBatch>,
    complete_devices: HashSet<String>,
    incomplete_devices: Vec<IncompleteDeviceBucket>,
    startup_bucket: bool,
}

#[derive(Debug)]
struct IncompleteDeviceBucket {
    device_hash_id: String,
    configured_path: PathBuf,
    reason: BucketIncompleteReason,
}

struct CollectorState {
    devices: Vec<MonitoredDevice>,
    current_bucket: i64,
    initialized: bool,
    baselines: HashMap<CounterKey, (String, u128)>,
    seen_instances: HashSet<CounterKey>,
    currently_mapped: HashSet<String>,
    amounts: HashMap<(String, String), u128>,
    incomplete: HashMap<String, BucketIncompleteReason>,
    startup_bucket: bool,
}

impl CollectorState {
    fn new(devices: Vec<MonitoredDevice>, now_ms: i64) -> Self {
        let mut incomplete = HashMap::new();
        for device in &devices {
            incomplete.insert(
                device.hash_id.clone(),
                BucketIncompleteReason::CgroupIdentityChanged,
            );
        }
        let currently_mapped = devices
            .iter()
            .map(|device| device.hash_id.clone())
            .collect();
        Self {
            devices,
            current_bucket: bucket_start(now_ms),
            initialized: false,
            baselines: HashMap::new(),
            seen_instances: HashSet::new(),
            currently_mapped,
            amounts: HashMap::new(),
            incomplete,
            startup_bucket: true,
        }
    }

    fn mark_all(&mut self, reason: BucketIncompleteReason) {
        for device in &self.devices {
            self.incomplete
                .entry(device.hash_id.clone())
                .or_insert(reason);
        }
    }

    fn mark_device(&mut self, hash_id: &str, reason: BucketIncompleteReason) {
        self.incomplete.entry(hash_id.to_owned()).or_insert(reason);
    }

    fn update_device_mappings(
        &mut self,
        mapped_devices: &[MonitoredDevice],
        mapping_lost: &[String],
    ) {
        self.currently_mapped.clear();
        self.currently_mapped
            .extend(mapped_devices.iter().map(|device| device.hash_id.clone()));
        for hash_id in mapping_lost {
            self.mark_device(hash_id, BucketIncompleteReason::DeviceMappingLost);
        }
    }

    fn resolve_scan_incomplete(
        &self,
        incomplete: &ScanIncomplete,
    ) -> HashMap<String, BucketIncompleteReason> {
        let mut reasons = HashMap::new();

        if let Some(reason) = incomplete.global_reason {
            for device in &self.devices {
                reasons.insert(device.hash_id.clone(), reason);
            }
        }

        for (number, reason) in &incomplete.device_reasons {
            if let Some(device) = self.devices.iter().find(|device| device.number == *number) {
                reasons.entry(device.hash_id.clone()).or_insert(*reason);
            }
        }

        for failure in &incomplete.cgroup_failures {
            for number in &failure.observed_devices {
                if let Some(device) = self.devices.iter().find(|device| device.number == *number) {
                    reasons
                        .entry(device.hash_id.clone())
                        .or_insert(failure.reason);
                }
            }
            for key in self.baselines.keys().filter(|key| {
                key.path == failure.path
                    && failure
                        .instance
                        .is_none_or(|instance| key.instance == instance)
            }) {
                reasons
                    .entry(key.device_hash_id.clone())
                    .or_insert(failure.reason);
            }
        }

        reasons
    }

    fn mark_resolved_incomplete(&mut self, reasons: &HashMap<String, BucketIncompleteReason>) {
        for (hash_id, reason) in reasons {
            self.mark_device(hash_id, *reason);
        }
    }

    fn process_scan(&mut self, now_ms: i64, outcome: ScanOutcome) -> Option<ClosedBucket> {
        let ScanOutcome {
            observations,
            incomplete,
        } = outcome;
        let next_bucket = bucket_start(now_ms);
        let scan_incomplete = self.resolve_scan_incomplete(&incomplete);
        self.mark_resolved_incomplete(&scan_incomplete);
        let deltas = self.calculate_deltas(&observations);

        if next_bucket == self.current_bucket {
            self.accumulate(deltas);
            self.initialized = true;
            return None;
        }

        if next_bucket < self.current_bucket {
            self.mark_all(BucketIncompleteReason::CgroupIdentityChanged);
            self.initialized = true;
            return None;
        }

        self.accumulate(deltas);
        if next_bucket - self.current_bucket > BUCKET_MILLISECONDS {
            self.mark_all(BucketIncompleteReason::SamplingDeadlineMissed);
        }
        let closed = self.close_current_bucket();
        self.current_bucket = next_bucket;
        self.amounts.clear();
        self.incomplete.clear();
        // A failed boundary scan leaves no trustworthy baseline for the new
        // bucket. Carry that gap forward so a later successful read cannot be
        // mistaken for a newly created cgroup and counted from zero.
        self.mark_resolved_incomplete(&scan_incomplete);
        if next_bucket - closed.timestamp > BUCKET_MILLISECONDS {
            self.mark_all(BucketIncompleteReason::SamplingDeadlineMissed);
        }
        self.initialized = true;
        Some(closed)
    }

    fn calculate_deltas(&mut self, observations: &[Observation]) -> Vec<(String, String, u128)> {
        let mut next_baselines = HashMap::new();
        let mut deltas = Vec::new();

        for observation in observations {
            for device in &self.devices {
                if !self.currently_mapped.contains(&device.hash_id) {
                    continue;
                }
                let Some(current) = observation.counters.get(&device.number).copied() else {
                    continue;
                };
                let key = CounterKey {
                    path: observation.path.clone(),
                    instance: observation.instance,
                    device_hash_id: device.hash_id.clone(),
                    device: device.number,
                };
                let was_seen = self.seen_instances.contains(&key);
                let delta = match self.baselines.get(&key) {
                    Some((_, previous)) if current >= *previous => Some(current - *previous),
                    Some(_) => {
                        self.incomplete
                            .entry(device.hash_id.clone())
                            .or_insert(BucketIncompleteReason::CounterReset);
                        None
                    }
                    None if self.initialized && !was_seen => Some(current),
                    None if self.initialized => {
                        self.incomplete
                            .entry(device.hash_id.clone())
                            .or_insert(BucketIncompleteReason::CgroupIdentityChanged);
                        None
                    }
                    None => None,
                };

                if let Some(delta) = delta.filter(|delta| *delta > 0) {
                    deltas.push((
                        device.hash_id.clone(),
                        observation.workload_name.clone(),
                        delta,
                    ));
                }
                self.seen_instances.insert(key.clone());
                next_baselines.insert(key, (observation.workload_name.clone(), current));
            }
        }

        let previous_baselines = std::mem::take(&mut self.baselines);
        for (key, _) in previous_baselines {
            if !next_baselines.contains_key(&key) {
                if let Some(device) = self
                    .devices
                    .iter()
                    .find(|device| device.hash_id == key.device_hash_id)
                {
                    self.incomplete
                        .entry(device.hash_id.clone())
                        .or_insert(BucketIncompleteReason::CgroupIdentityChanged);
                } else {
                    self.mark_all(BucketIncompleteReason::DeviceMappingLost);
                }
            }
        }
        self.baselines = next_baselines;
        deltas
    }

    fn accumulate(&mut self, deltas: Vec<(String, String, u128)>) {
        for (hash_id, workload, delta) in deltas {
            let key = (hash_id.clone(), workload);
            match self
                .amounts
                .get(&key)
                .copied()
                .unwrap_or(0)
                .checked_add(delta)
            {
                Some(amount) => {
                    self.amounts.insert(key, amount);
                }
                None => {
                    self.incomplete
                        .entry(hash_id)
                        .or_insert(BucketIncompleteReason::AccumulatorOverflow);
                }
            }
        }
    }

    fn close_current_bucket(&mut self) -> ClosedBucket {
        let mut complete_devices = HashSet::new();
        let mut incomplete_devices = Vec::new();
        let mut device_buckets = Vec::new();

        for device in &self.devices {
            if let Some(reason) = self.incomplete.get(&device.hash_id).copied() {
                incomplete_devices.push(IncompleteDeviceBucket {
                    device_hash_id: device.hash_id.clone(),
                    configured_path: device.configured_path.clone(),
                    reason,
                });
                continue;
            }
            let mut amounts = Vec::new();
            let mut out_of_range = false;
            for ((hash_id, workload_name), amount) in &self.amounts {
                if hash_id != &device.hash_id || *amount == 0 {
                    continue;
                }
                if let Ok(write_amount_bytes) = i64::try_from(*amount) {
                    amounts.push(WriterAmount {
                        workload_name: workload_name.clone(),
                        write_amount_bytes,
                    });
                } else {
                    out_of_range = true;
                    break;
                }
            }
            if out_of_range {
                self.incomplete.insert(
                    device.hash_id.clone(),
                    BucketIncompleteReason::AccumulatorOverflow,
                );
                incomplete_devices.push(IncompleteDeviceBucket {
                    device_hash_id: device.hash_id.clone(),
                    configured_path: device.configured_path.clone(),
                    reason: BucketIncompleteReason::AccumulatorOverflow,
                });
                continue;
            }
            amounts.sort_by(|left, right| left.workload_name.cmp(&right.workload_name));
            complete_devices.insert(device.hash_id.clone());
            device_buckets.push(CompleteDeviceBucket {
                device_hash_id: device.hash_id.clone(),
                amounts,
            });
        }

        let batch = (!device_buckets.is_empty()).then_some(WriterBucketBatch {
            timestamp: self.current_bucket,
            devices: device_buckets,
        });
        let startup_bucket = self.startup_bucket;
        self.startup_bucket = false;
        ClosedBucket {
            timestamp: self.current_bucket,
            batch,
            complete_devices,
            incomplete_devices,
            startup_bucket,
        }
    }
}

pub(crate) struct WriterCollector {
    root: PathBuf,
    devices: Vec<MonitoredDevice>,
    database: DatabaseHandle,
    boundary_tracker: WriterBoundaryTracker,
    stop: Arc<AtomicBool>,
}

impl WriterCollector {
    pub(crate) fn new(
        devices: Vec<MonitoredDevice>,
        database: DatabaseHandle,
        boundary_tracker: WriterBoundaryTracker,
        stop: Arc<AtomicBool>,
    ) -> Self {
        Self {
            root: PathBuf::from(CGROUP_ROOT),
            devices,
            database,
            boundary_tracker,
            stop,
        }
    }

    pub(crate) fn run(self) -> Result<(), ErrorSource> {
        tracing::info!(
            device_count = self.devices.len(),
            cgroup_root = %log_safe_path(&self.root),
            sample_period_seconds = SAMPLE_PERIOD.as_secs(),
            "writer attribution collector starting"
        );
        validate_cgroup_root(&self.root)?;
        let mut state = CollectorState::new(self.devices.clone(), unix_milliseconds()?);
        let mut deadline = Instant::now();
        tracing::info!(
            open_bucket_start_unix_ms = state.current_bucket,
            "cgroup v2 I/O controller verified; writer attribution collector is active"
        );

        while !self.stop.load(Ordering::Acquire) {
            let scan_started = Instant::now();
            let now_ms = unix_milliseconds()?;
            let (mapped_devices, mapping_lost) = current_device_mappings(&self.devices);
            state.update_device_mappings(&mapped_devices, &mapping_lost);
            let outcome = match scan_cgroups(&self.root, &mapped_devices) {
                Ok(outcome) => outcome,
                Err(_) => {
                    ScanOutcome::global_failure(BucketIncompleteReason::CgroupEnumerationFailed)
                }
            };
            if scan_started > deadline + SAMPLE_PERIOD {
                state.mark_all(BucketIncompleteReason::SamplingDeadlineMissed);
            }

            if let Some(closed) = state.process_scan(now_ms, outcome) {
                let ClosedBucket {
                    timestamp,
                    batch,
                    complete_devices,
                    incomplete_devices,
                    startup_bucket,
                } = closed;
                for hash_id in &mapping_lost {
                    state.mark_device(hash_id, BucketIncompleteReason::DeviceMappingLost);
                }
                if !closed_bucket_submission_allowed(&self.stop) {
                    break;
                }
                let writer_record_count = batch.as_ref().map_or(0, |batch| {
                    batch
                        .devices
                        .iter()
                        .map(|device| device.amounts.len())
                        .sum::<usize>()
                });
                let submit_started = Instant::now();
                if let Some(batch) = batch
                    && self
                        .database
                        .submit_until_stopped(DatabaseBatch::WriterBucket(batch), &self.stop)
                        .map_err(|error| Box::new(error) as ErrorSource)?
                        .is_none()
                {
                    break;
                }
                let submit_elapsed = submit_started.elapsed();
                if submit_elapsed > SAMPLE_PERIOD {
                    state.mark_all(BucketIncompleteReason::DatabaseBackpressure);
                    tracing::warn!(
                        bucket_start_unix_ms = state.current_bucket,
                        database_submit_elapsed_ms = ?submit_elapsed.as_millis(),
                        "database submission delayed writer sampling; the open bucket is incomplete"
                    );
                }
                let complete_device_count = complete_devices.len();
                self.boundary_tracker.publish(WriterBoundaryReport {
                    end_timestamp: timestamp + BUCKET_MILLISECONDS,
                    complete_devices,
                });
                log_writer_bucket_result(
                    timestamp,
                    complete_device_count,
                    &incomplete_devices,
                    writer_record_count,
                    startup_bucket,
                );
            }

            deadline += SAMPLE_PERIOD;
            while !self.stop.load(Ordering::Acquire) {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                thread::sleep((deadline - now).min(Duration::from_millis(200)));
            }
        }
        tracing::info!(
            open_bucket_start_unix_ms = state.current_bucket,
            "writer attribution collector stopped; open bucket discarded"
        );
        Ok(())
    }
}

fn log_writer_bucket_result(
    timestamp: i64,
    complete_device_count: usize,
    incomplete_devices: &[IncompleteDeviceBucket],
    writer_record_count: usize,
    startup_bucket: bool,
) {
    if startup_bucket {
        tracing::info!(
            bucket_start_unix_ms = timestamp,
            bucket_end_unix_ms = timestamp + BUCKET_MILLISECONDS,
            affected_device_count = incomplete_devices.len(),
            "startup writer attribution bucket was discarded as incomplete"
        );
    } else {
        for device in incomplete_devices {
            tracing::warn!(
                device_hash_id = device.device_hash_id.as_str(),
                configured_path = %log_safe_path(&device.configured_path),
                bucket_start_unix_ms = timestamp,
                bucket_end_unix_ms = timestamp + BUCKET_MILLISECONDS,
                reason = device.reason.as_str(),
                "writer attribution bucket is incomplete"
            );
        }
    }
    tracing::info!(
        bucket_start_unix_ms = timestamp,
        bucket_end_unix_ms = timestamp + BUCKET_MILLISECONDS,
        complete_device_count,
        incomplete_device_count = incomplete_devices.len(),
        writer_record_count,
        "writer attribution bucket processed"
    );
}

fn closed_bucket_submission_allowed(stop: &AtomicBool) -> bool {
    !stop.load(Ordering::Acquire)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceMappingObservation {
    is_block_device: bool,
    number: DeviceNumber,
}

fn current_device_mappings(devices: &[MonitoredDevice]) -> (Vec<MonitoredDevice>, Vec<String>) {
    let mut mapped = Vec::with_capacity(devices.len());
    let mut lost = Vec::new();
    for device in devices {
        if device_mapping_matches(device.number, observe_mapping(&device.configured_path)) {
            mapped.push(device.clone());
        } else {
            lost.push(device.hash_id.clone());
        }
    }
    (mapped, lost)
}

fn observe_mapping(path: &Path) -> Option<DeviceMappingObservation> {
    let metadata = fs::metadata(path).ok()?;
    Some(DeviceMappingObservation {
        is_block_device: metadata.file_type().is_block_device(),
        number: DeviceNumber {
            major: libc::major(metadata.rdev()),
            minor: libc::minor(metadata.rdev()),
        },
    })
}

fn device_mapping_matches(
    expected: DeviceNumber,
    observed: Option<DeviceMappingObservation>,
) -> bool {
    observed.is_some_and(|observed| observed.is_block_device && observed.number == expected)
}

fn validate_cgroup_root(root: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup root is not a directory",
        ));
    }
    let controllers = fs::read_to_string(root.join("cgroup.controllers"))?;
    if !controllers
        .split_ascii_whitespace()
        .any(|item| item == "io")
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroup v2 io controller is unavailable",
        ));
    }
    Ok(())
}

fn scan_cgroups(root: &Path, devices: &[MonitoredDevice]) -> io::Result<ScanOutcome> {
    let leaves = leaf_cgroups(root)?;
    let monitored_devices = devices.iter().map(|device| device.number).collect();
    let mut observations = Vec::new();
    let mut incomplete = ScanIncomplete::default();

    for leaf in leaves {
        let path = leaf.as_os_str().as_bytes().to_vec();
        let metadata = match fs::symlink_metadata(&leaf) {
            Ok(metadata) => metadata,
            Err(source) => {
                if let Some(reason) = leaf_read_failure(&source) {
                    incomplete.cgroup_failures.push(CgroupScanFailure {
                        path,
                        instance: None,
                        observed_devices: HashSet::new(),
                        reason,
                    });
                }
                continue;
            }
        };
        let instance = cgroup_instance_id(&leaf, &metadata);
        let contents = match fs::read_to_string(leaf.join("io.stat")) {
            Ok(contents) => contents,
            Err(source) => {
                if let Some(reason) = leaf_read_failure(&source) {
                    incomplete.cgroup_failures.push(CgroupScanFailure {
                        path,
                        instance: Some(instance),
                        observed_devices: HashSet::new(),
                        reason,
                    });
                }
                continue;
            }
        };
        let parsed = parse_io_stat(&contents, &monitored_devices);
        for device in &parsed.failed_devices {
            incomplete
                .device_reasons
                .entry(*device)
                .or_insert(BucketIncompleteReason::IoStatParseFailed);
        }
        if parsed.unscoped_failure {
            incomplete.cgroup_failures.push(CgroupScanFailure {
                path: path.clone(),
                instance: Some(instance),
                observed_devices: parsed.counters.keys().copied().collect(),
                reason: BucketIncompleteReason::IoStatParseFailed,
            });
        }
        observations.push(Observation {
            path,
            instance,
            workload_name: canonical_workload_name(root, &leaf),
            counters: parsed.counters,
        });
    }
    Ok(ScanOutcome {
        observations,
        incomplete,
    })
}

fn cgroup_instance_id(path: &Path, metadata: &fs::Metadata) -> CgroupInstanceId {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    if let Some(instance) = statx_cgroup_instance_id(path) {
        return instance;
    }

    CgroupInstanceId {
        device: metadata.dev(),
        inode: metadata.ino(),
        birth_time: None,
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
fn statx_cgroup_instance_id(path: &Path) -> Option<CgroupInstanceId> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();

    // SAFETY: `path` is NUL-terminated and remains alive for the call. `stat`
    // points to writable storage of exactly the type and size required by
    // `statx`; the storage is not read unless the kernel reports success.
    let status = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS | libc::STATX_BTIME,
            stat.as_mut_ptr(),
        )
    };
    if status != 0 {
        return None;
    }

    // SAFETY: a successful `statx` call initialized the complete output
    // structure supplied above.
    let stat = unsafe { stat.assume_init() };
    let birth_time = (stat.stx_mask & libc::STATX_BTIME != 0).then_some(CgroupBirthTime {
        seconds: stat.stx_btime.tv_sec,
        nanoseconds: stat.stx_btime.tv_nsec,
    });
    Some(CgroupInstanceId {
        device: libc::makedev(stat.stx_dev_major, stat.stx_dev_minor),
        inode: stat.stx_ino,
        birth_time,
    })
}

fn leaf_read_failure(source: &io::Error) -> Option<BucketIncompleteReason> {
    (source.kind() != io::ErrorKind::NotFound).then_some(BucketIncompleteReason::IoStatReadFailed)
}

fn leaf_cgroups(root: &Path) -> io::Result<Vec<PathBuf>> {
    let root_device = fs::symlink_metadata(root)?.dev();
    let mut stack = vec![root.to_path_buf()];
    let mut leaves = Vec::new();
    while let Some(directory) = stack.pop() {
        let mut children = Vec::new();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(source) if directory != root && source.kind() == io::ErrorKind::NotFound => {
                continue;
            }
            Err(source) => return Err(source),
        };
        for entry in entries {
            let entry = entry?;
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
                Err(source) => return Err(source),
            };
            if metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.dev() == root_device
            {
                children.push(entry.path());
            }
        }
        if children.is_empty() && directory != root {
            leaves.push(directory);
        } else {
            stack.extend(children);
        }
    }
    leaves.sort();
    Ok(leaves)
}

fn parse_io_stat(input: &str, monitored_devices: &HashSet<DeviceNumber>) -> ParsedIoStat {
    let mut counters = HashMap::new();
    let mut failed_devices = HashSet::new();
    let mut unscoped_failure = false;

    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let Some(device) = fields
            .next()
            .and_then(|value| parse_device_number(value).ok())
        else {
            unscoped_failure = true;
            continue;
        };
        if !monitored_devices.contains(&device) {
            continue;
        }

        let mut wbytes = None;
        let mut failed = false;
        for field in fields {
            let Some((name, value)) = field.split_once('=') else {
                failed = true;
                continue;
            };
            if name == "wbytes" {
                if wbytes.is_some() {
                    failed = true;
                    continue;
                }
                match value.parse::<u128>() {
                    Ok(value) => wbytes = Some(value),
                    Err(_) => {
                        failed = true;
                    }
                }
            }
        }

        let Some(amount) = wbytes else {
            failed_devices.insert(device);
            counters.remove(&device);
            continue;
        };
        if failed || failed_devices.contains(&device) || counters.insert(device, amount).is_some() {
            failed_devices.insert(device);
            counters.remove(&device);
        }
    }

    ParsedIoStat {
        counters,
        failed_devices,
        unscoped_failure,
    }
}

fn parse_device_number(value: &str) -> Result<DeviceNumber, ()> {
    let (major, minor) = value.split_once(':').ok_or(())?;
    Ok(DeviceNumber {
        major: major.parse().map_err(|_| ())?,
        minor: minor.parse().map_err(|_| ())?,
    })
}

fn canonical_workload_name(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let components: Vec<&OsStr> = relative
        .components()
        .map(std::path::Component::as_os_str)
        .collect();
    if let Some((uid, unit)) = unique_user_unit(&components) {
        return format!("systemd:user:{uid}:{unit}");
    }
    if let Some(unit) = unique_system_unit(&components) {
        return format!("systemd:system:{unit}");
    }

    let mut absolute = vec![b'/'];
    absolute.extend_from_slice(relative.as_os_str().as_bytes());
    format!("cgroup:{}", escape_cgroup_path(&absolute))
}

fn unique_user_unit<'a>(components: &'a [&OsStr]) -> Option<(u32, &'a str)> {
    let names = components
        .iter()
        .map(|component| component.to_str())
        .collect::<Option<Vec<_>>>()?;
    let ["user.slice", user_slice, manager, middle @ .., unit] = names.as_slice() else {
        return None;
    };
    let uid = user_slice
        .strip_prefix("user-")?
        .strip_suffix(".slice")?
        .parse::<u32>()
        .ok()?;
    if manager != &format!("user@{uid}.service")
        || !middle.iter().all(|name| is_slice_name(name))
        || !is_safe_unit_name(unit)
    {
        return None;
    }
    Some((uid, unit))
}

fn unique_system_unit<'a>(components: &'a [&OsStr]) -> Option<&'a str> {
    let (unit, parents) = components.split_last()?;
    let unit = unit.to_str()?;
    if parents.is_empty()
        || !parents
            .iter()
            .all(|component| component.to_str().is_some_and(is_slice_name))
        || !is_safe_unit_name(unit)
    {
        return None;
    }
    Some(unit)
}

fn is_safe_unit_name(name: &str) -> bool {
    [".service", ".scope"].into_iter().any(|suffix| {
        name.strip_suffix(suffix)
            .is_some_and(|stem| !stem.is_empty())
    }) && name
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'/')
}

fn is_slice_name(name: &str) -> bool {
    name.strip_suffix(".slice")
        .is_some_and(|stem| !stem.is_empty())
}

fn escape_cgroup_path(bytes: &[u8]) -> String {
    let mut escaped = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':' | b'@') {
            escaped.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(escaped, "\\x{byte:02x}");
        }
    }
    escaped
}

fn log_safe_path(path: &Path) -> String {
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut escaped = String::new();
    for byte in bytes.iter().take(512) {
        escaped.extend(std::ascii::escape_default(*byte).map(char::from));
    }
    if bytes.len() > 512 {
        escaped.push_str("...");
    }
    escaped
}

fn unix_milliseconds() -> Result<i64, ErrorSource> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Box::new(error) as ErrorSource)?;
    i64::try_from(duration.as_millis()).map_err(|_| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "system time is outside the supported range",
        )) as ErrorSource
    })
}

const fn bucket_start(timestamp: i64) -> i64 {
    timestamp - timestamp.rem_euclid(BUCKET_MILLISECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devices() -> Vec<MonitoredDevice> {
        vec![MonitoredDevice {
            hash_id: "a".repeat(64),
            configured_path: PathBuf::from("/dev/disk/by-id/test-a"),
            number: DeviceNumber {
                major: 259,
                minor: 0,
            },
        }]
    }

    fn two_devices() -> Vec<MonitoredDevice> {
        let mut result = devices();
        result.push(MonitoredDevice {
            hash_id: "b".repeat(64),
            configured_path: PathBuf::from("/dev/disk/by-id/test-b"),
            number: DeviceNumber {
                major: 259,
                minor: 1,
            },
        });
        result
    }

    fn observation(path: &[u8], inode: u64, workload: &str, amount: u128) -> Observation {
        observation_with_birth_time(path, inode, None, workload, amount)
    }

    fn observation_with_birth_time(
        path: &[u8],
        inode: u64,
        birth_time: Option<CgroupBirthTime>,
        workload: &str,
        amount: u128,
    ) -> Observation {
        Observation {
            path: path.to_vec(),
            instance: CgroupInstanceId {
                device: 1,
                inode,
                birth_time,
            },
            workload_name: workload.to_owned(),
            counters: HashMap::from([(
                DeviceNumber {
                    major: 259,
                    minor: 0,
                },
                amount,
            )]),
        }
    }

    fn two_device_observation(amount_a: u128, amount_b: u128) -> Observation {
        Observation {
            path: b"/a".to_vec(),
            instance: CgroupInstanceId {
                device: 1,
                inode: 1,
                birth_time: None,
            },
            workload_name: "cgroup:/a".to_owned(),
            counters: HashMap::from([
                (
                    DeviceNumber {
                        major: 259,
                        minor: 0,
                    },
                    amount_a,
                ),
                (
                    DeviceNumber {
                        major: 259,
                        minor: 1,
                    },
                    amount_b,
                ),
            ]),
        }
    }

    #[test]
    fn io_stat_parses_unordered_fields_and_large_values() {
        let monitored_devices = HashSet::from([
            DeviceNumber {
                major: 259,
                minor: 0,
            },
            DeviceNumber {
                major: 259,
                minor: 1,
            },
        ]);
        let parsed = parse_io_stat(
            "259:0 rios=2 wios=3 wbytes=18446744073709551616 rbytes=1\n8:0 malformed\n",
            &monitored_devices,
        );
        assert_eq!(
            parsed.counters[&DeviceNumber {
                major: 259,
                minor: 0
            }],
            18_446_744_073_709_551_616
        );
        assert!(parsed.failed_devices.is_empty());
        assert!(!parsed.unscoped_failure);

        let invalid = parse_io_stat("259:0 rbytes=1\n259:1 wbytes=x\n", &monitored_devices);
        assert_eq!(invalid.failed_devices, monitored_devices);
        assert!(invalid.counters.is_empty());
        assert!(!invalid.unscoped_failure);

        let unscoped = parse_io_stat("invalid-device wbytes=1\n", &monitored_devices);
        assert!(unscoped.counters.is_empty());
        assert!(unscoped.failed_devices.is_empty());
        assert!(unscoped.unscoped_failure);
    }

    #[test]
    fn scan_filters_unmonitored_devices_and_uses_only_leaf_cgroups() {
        let directory = tempfile::tempdir().expect("temporary cgroup tree");
        let ancestor = directory.path().join("system.slice");
        let leaf = ancestor.join("test.service");
        fs::create_dir(&ancestor).expect("ancestor cgroup");
        fs::create_dir(&leaf).expect("leaf cgroup");
        fs::write(
            leaf.join("io.stat"),
            "259:0 rbytes=1 wbytes=20\n259:1 rbytes=2\n8:0 malformed\n",
        )
        .expect("leaf io.stat");
        fs::write(ancestor.join("io.stat"), "259:0 wbytes=500\n").expect("ancestor io.stat");

        let monitored_devices = two_devices();
        let outcome = scan_cgroups(directory.path(), &monitored_devices).expect("scan cgroups");
        assert_eq!(outcome.observations.len(), 1);
        assert_eq!(outcome.observations[0].path, leaf.as_os_str().as_bytes());
        assert_eq!(outcome.observations[0].instance.device, metadata_dev(&leaf));
        assert_eq!(outcome.observations[0].counters.len(), 1);
        assert_eq!(outcome.incomplete.device_reasons.len(), 1);
        assert_eq!(
            outcome
                .incomplete
                .device_reasons
                .get(&monitored_devices[1].number),
            Some(&BucketIncompleteReason::IoStatParseFailed)
        );
        assert!(outcome.incomplete.cgroup_failures.is_empty());
        assert_eq!(
            outcome.observations[0].counters[&DeviceNumber {
                major: 259,
                minor: 0,
            }],
            20
        );
    }

    fn metadata_dev(path: &Path) -> u64 {
        fs::symlink_metadata(path).expect("cgroup metadata").dev()
    }

    #[test]
    fn newly_enumerated_cgroup_disappearance_before_baseline_is_skippable() {
        assert_eq!(
            leaf_read_failure(&io::Error::from(io::ErrorKind::NotFound)),
            None
        );
        assert_eq!(
            leaf_read_failure(&io::Error::from(io::ErrorKind::PermissionDenied)),
            Some(BucketIncompleteReason::IoStatReadFailed)
        );
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn cgroup_identity_uses_statx_fields_when_available() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        let metadata = fs::symlink_metadata(directory.path()).expect("cgroup metadata");
        let identity = cgroup_instance_id(directory.path(), &metadata);

        if let Some(statx_identity) = statx_cgroup_instance_id(directory.path()) {
            assert_eq!(identity, statx_identity);
        } else {
            assert_eq!(identity.device, metadata.dev());
            assert_eq!(identity.inode, metadata.ino());
            assert_eq!(identity.birth_time, None);
        }
    }

    #[test]
    fn device_mapping_match_rejects_missing_nonblock_and_changed_targets() {
        let expected = DeviceNumber {
            major: 259,
            minor: 0,
        };
        assert!(device_mapping_matches(
            expected,
            Some(DeviceMappingObservation {
                is_block_device: true,
                number: expected,
            })
        ));
        assert!(!device_mapping_matches(expected, None));
        assert!(!device_mapping_matches(
            expected,
            Some(DeviceMappingObservation {
                is_block_device: false,
                number: expected,
            })
        ));
        assert!(!device_mapping_matches(
            expected,
            Some(DeviceMappingObservation {
                is_block_device: true,
                number: DeviceNumber {
                    major: 259,
                    minor: 1,
                },
            })
        ));
    }

    #[test]
    fn path_encoding_is_ascii_and_reversible() {
        assert_eq!(
            escape_cgroup_path(b"/machine.slice/name \\ \xff"),
            "/machine.slice/name\\x20\\x5c\\x20\\xff"
        );
    }

    #[test]
    fn workload_names_are_conservative() {
        let root = Path::new("/sys/fs/cgroup");
        assert_eq!(
            canonical_workload_name(root, Path::new("/sys/fs/cgroup/system.slice/db.service")),
            "systemd:system:db.service"
        );
        assert_eq!(
            canonical_workload_name(
                root,
                Path::new(
                    "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/ui.service"
                )
            ),
            "systemd:user:1000:ui.service"
        );
        assert_eq!(
            canonical_workload_name(
                root,
                Path::new("/sys/fs/cgroup/system.slice/session-1.scope")
            ),
            "systemd:system:session-1.scope"
        );
        assert_eq!(
            canonical_workload_name(
                root,
                Path::new(
                    "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/app-a.scope"
                )
            ),
            "systemd:user:1000:app-a.scope"
        );
        assert_eq!(
            canonical_workload_name(
                root,
                Path::new("/sys/fs/cgroup/machine.slice/libpod-a.scope/container")
            ),
            "cgroup:/machine.slice/libpod-a.scope/container"
        );
        assert_eq!(
            canonical_workload_name(
                root,
                Path::new("/sys/fs/cgroup/system.slice/delegated.service/child.service")
            ),
            "cgroup:/system.slice/delegated.service/child.service"
        );
        assert_eq!(
            canonical_workload_name(root, Path::new("/sys/fs/cgroup/system.slice/db.socket")),
            "cgroup:/system.slice/db.socket"
        );
    }

    #[test]
    fn existing_cgroup_first_scan_only_establishes_baseline() {
        let mut state = CollectorState::new(devices(), 1_000);
        assert!(
            state
                .process_scan(
                    2_000,
                    ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 100)]),
                )
                .is_none()
        );
        assert!(state.amounts.is_empty());
        state.incomplete.clear();
        state.process_scan(
            3_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 140)]),
        );
        assert_eq!(state.amounts.values().copied().sum::<u128>(), 40);
    }

    #[test]
    fn new_cgroup_first_read_counts_from_zero_and_names_merge() {
        let mut state = CollectorState::new(devices(), 1_000);
        state.process_scan(2_000, ScanOutcome::complete(vec![]));
        state.incomplete.clear();
        state.process_scan(
            3_000,
            ScanOutcome::complete(vec![
                observation(b"/a", 1, "systemd:system:x.service", 10),
                observation(b"/b", 2, "systemd:system:x.service", 20),
            ]),
        );
        assert_eq!(state.amounts.len(), 1);
        assert_eq!(state.amounts.values().copied().sum::<u128>(), 30);
    }

    #[test]
    fn previously_seen_instance_reappearance_reestablishes_baseline() {
        let mut state = CollectorState::new(devices(), 1_000);
        state.process_scan(
            2_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 100)]),
        );
        state.process_scan(
            60_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 120)]),
        );
        state.process_scan(65_000, ScanOutcome::complete(Vec::new()));
        let missing = state
            .process_scan(120_000, ScanOutcome::complete(Vec::new()))
            .expect("missing-instance bucket closes");
        assert!(missing.batch.is_none());

        state.process_scan(
            125_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 150)]),
        );
        assert!(state.amounts.is_empty());
        assert_eq!(
            state.incomplete.values().next(),
            Some(&BucketIncompleteReason::CgroupIdentityChanged)
        );

        state.process_scan(
            130_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 170)]),
        );
        assert_eq!(state.amounts.values().copied().sum::<u128>(), 20);
    }

    #[test]
    fn mapping_loss_invalidates_only_the_affected_device() {
        let all_devices = two_devices();
        let mut state = CollectorState::new(all_devices.clone(), 1_000);
        state.process_scan(
            2_000,
            ScanOutcome::complete(vec![two_device_observation(100, 200)]),
        );
        state.process_scan(
            60_000,
            ScanOutcome::complete(vec![two_device_observation(110, 210)]),
        );

        let mapped = vec![all_devices[1].clone()];
        let lost = vec![all_devices[0].hash_id.clone()];
        state.update_device_mappings(&mapped, &lost);
        state.process_scan(
            65_000,
            ScanOutcome::complete(vec![two_device_observation(0, 220)]),
        );
        state.update_device_mappings(&mapped, &lost);
        let closed = state
            .process_scan(
                120_000,
                ScanOutcome::complete(vec![two_device_observation(0, 230)]),
            )
            .expect("mapping-loss bucket closes");

        let batch = closed.batch.expect("unaffected device remains complete");
        assert_eq!(batch.devices.len(), 1);
        assert_eq!(batch.devices[0].device_hash_id, all_devices[1].hash_id);
        assert_eq!(batch.devices[0].amounts[0].write_amount_bytes, 20);
    }

    #[test]
    fn parse_failure_invalidates_only_the_affected_device() {
        let all_devices = two_devices();
        let mut state = CollectorState::new(all_devices.clone(), 1_000);
        state.process_scan(
            2_000,
            ScanOutcome::complete(vec![two_device_observation(100, 200)]),
        );
        state.process_scan(
            60_000,
            ScanOutcome::complete(vec![two_device_observation(110, 210)]),
        );
        state.process_scan(
            65_000,
            ScanOutcome::complete(vec![two_device_observation(120, 220)]),
        );

        let failed_number = all_devices[1].number;
        let mut incomplete = ScanIncomplete::default();
        incomplete
            .device_reasons
            .insert(failed_number, BucketIncompleteReason::IoStatParseFailed);
        let closed = state
            .process_scan(
                120_000,
                ScanOutcome {
                    observations: vec![observation(b"/a", 1, "cgroup:/a", 150)],
                    incomplete,
                },
            )
            .expect("parse-failure bucket closes");

        let batch = closed.batch.expect("unaffected device remains complete");
        assert_eq!(batch.devices.len(), 1);
        assert_eq!(batch.devices[0].device_hash_id, all_devices[0].hash_id);
        assert_eq!(batch.devices[0].amounts[0].write_amount_bytes, 40);
        assert_eq!(closed.incomplete_devices.len(), 1);
        assert_eq!(
            closed.incomplete_devices[0].device_hash_id,
            all_devices[1].hash_id
        );
        assert_eq!(
            closed.incomplete_devices[0].reason,
            BucketIncompleteReason::IoStatParseFailed
        );
    }

    #[test]
    fn disappearing_cgroup_invalidates_only_devices_with_a_baseline() {
        let all_devices = two_devices();
        let mut state = CollectorState::new(all_devices.clone(), 1_000);
        state.process_scan(
            2_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 100)]),
        );
        state.process_scan(
            60_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 110)]),
        );
        state.process_scan(
            65_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 120)]),
        );
        state.process_scan(70_000, ScanOutcome::complete(Vec::new()));
        let closed = state
            .process_scan(120_000, ScanOutcome::complete(Vec::new()))
            .expect("cgroup-disappearance bucket closes");

        let batch = closed.batch.expect("unaffected device remains complete");
        assert_eq!(batch.devices.len(), 1);
        assert_eq!(batch.devices[0].device_hash_id, all_devices[1].hash_id);
        assert!(batch.devices[0].amounts.is_empty());
        assert_eq!(closed.incomplete_devices.len(), 1);
        assert_eq!(
            closed.incomplete_devices[0].device_hash_id,
            all_devices[0].hash_id
        );
        assert_eq!(
            closed.incomplete_devices[0].reason,
            BucketIncompleteReason::CgroupIdentityChanged
        );
    }

    #[test]
    fn cgroup_read_failure_uses_only_established_device_baselines() {
        let all_devices = two_devices();
        let mut state = CollectorState::new(all_devices.clone(), 1_000);
        state.process_scan(
            2_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 100)]),
        );

        let incomplete = ScanIncomplete {
            cgroup_failures: vec![CgroupScanFailure {
                path: b"/a".to_vec(),
                instance: Some(CgroupInstanceId {
                    device: 1,
                    inode: 1,
                    birth_time: None,
                }),
                observed_devices: HashSet::new(),
                reason: BucketIncompleteReason::IoStatReadFailed,
            }],
            ..ScanIncomplete::default()
        };
        let reasons = state.resolve_scan_incomplete(&incomplete);

        assert_eq!(reasons.len(), 1);
        assert_eq!(
            reasons.get(&all_devices[0].hash_id),
            Some(&BucketIncompleteReason::IoStatReadFailed)
        );
        assert!(!reasons.contains_key(&all_devices[1].hash_id));
    }

    #[test]
    fn birth_time_distinguishes_recreated_cgroup_instances() {
        let first = observation_with_birth_time(
            b"/a",
            1,
            Some(CgroupBirthTime {
                seconds: 10,
                nanoseconds: 20,
            }),
            "cgroup:/a",
            1,
        );
        let rebuilt = observation_with_birth_time(
            b"/a",
            1,
            Some(CgroupBirthTime {
                seconds: 10,
                nanoseconds: 21,
            }),
            "cgroup:/a",
            1,
        );
        assert_ne!(first.instance, rebuilt.instance);
    }

    #[test]
    fn stop_request_prevents_closed_bucket_submission() {
        let stop = AtomicBool::new(false);
        assert!(closed_bucket_submission_allowed(&stop));
        stop.store(true, Ordering::Release);
        assert!(!closed_bucket_submission_allowed(&stop));
    }

    #[test]
    fn complete_and_incomplete_buckets_have_distinct_output() {
        let mut state = CollectorState::new(devices(), 1_000);
        state.process_scan(2_000, ScanOutcome::complete(vec![]));
        let startup = state
            .process_scan(60_000, ScanOutcome::complete(vec![]))
            .expect("startup bucket closes");
        assert!(startup.batch.is_none());
        assert!(startup.startup_bucket);
        assert_eq!(startup.incomplete_devices.len(), 1);
        assert_eq!(
            startup.incomplete_devices[0].reason,
            BucketIncompleteReason::CgroupIdentityChanged
        );

        let complete = state
            .process_scan(120_000, ScanOutcome::complete(vec![]))
            .expect("complete bucket closes");
        assert!(complete.batch.is_some());
        assert!(!complete.startup_bucket);
        assert_eq!(complete.complete_devices.len(), 1);
        assert!(complete.incomplete_devices.is_empty());

        state.mark_all(BucketIncompleteReason::IoStatReadFailed);
        let incomplete = state
            .process_scan(180_000, ScanOutcome::complete(vec![]))
            .expect("incomplete bucket closes");
        assert!(incomplete.batch.is_none());
        assert_eq!(incomplete.incomplete_devices.len(), 1);
        assert_eq!(
            incomplete.incomplete_devices[0].reason,
            BucketIncompleteReason::IoStatReadFailed
        );
    }

    #[test]
    fn complete_written_bucket_contains_the_aggregated_delta() {
        let mut state = CollectorState::new(devices(), 1_000);
        state.process_scan(
            2_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "systemd:system:x.service", 100)]),
        );
        state.process_scan(
            60_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "systemd:system:x.service", 110)]),
        );
        state.process_scan(
            65_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "systemd:system:x.service", 120)]),
        );
        let closed = state
            .process_scan(
                120_000,
                ScanOutcome::complete(vec![observation(b"/a", 1, "systemd:system:x.service", 150)]),
            )
            .expect("complete bucket");
        let batch = closed.batch.expect("writer batch");
        assert_eq!(batch.devices.len(), 1);
        assert_eq!(batch.devices[0].amounts.len(), 1);
        assert_eq!(batch.devices[0].amounts[0].write_amount_bytes, 40);
    }

    #[test]
    fn failed_boundary_scan_also_invalidates_the_new_bucket() {
        let mut state = CollectorState::new(devices(), 1_000);
        state.process_scan(
            2_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 100)]),
        );

        let startup = state
            .process_scan(
                60_000,
                ScanOutcome::global_failure(BucketIncompleteReason::IoStatReadFailed),
            )
            .expect("startup bucket closes");
        assert!(startup.batch.is_none());

        state.process_scan(
            65_000,
            ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 150)]),
        );
        let after_failure = state
            .process_scan(
                120_000,
                ScanOutcome::complete(vec![observation(b"/a", 1, "cgroup:/a", 160)]),
            )
            .expect("post-failure bucket closes");
        assert!(after_failure.batch.is_none());
    }

    #[test]
    fn bucket_alignment_uses_utc_minute_boundaries() {
        assert_eq!(bucket_start(0), 0);
        assert_eq!(bucket_start(59_999), 0);
        assert_eq!(bucket_start(60_000), 60_000);
        assert_eq!(bucket_start(123_456), 120_000);
    }
}
