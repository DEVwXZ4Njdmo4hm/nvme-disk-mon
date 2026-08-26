use std::{
    error::Error,
    io,
    num::NonZeroUsize,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use signal_hook::consts::{SIGINT, SIGTERM};

mod cli;
mod config;
mod database;
mod mail;
mod monitor;
mod writer;

pub(crate) type ErrorSource = Box<dyn Error + Send + Sync + 'static>;

#[tokio::main]
async fn main() {
    let action = cli::parse();
    if action.logs_lifecycle() {
        let _ = tracing_subscriber::fmt()
            .compact()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_thread_names(true)
            .with_writer(std::io::stderr)
            .try_init();
    }

    if let Err(error) = run(action).await {
        if action.logs_lifecycle() {
            tracing::error!(error = %error, "nvme-disk-mon stopped with an error");
        } else {
            eprintln!("nvme-disk-mon stopped with an error: {error}");
        }
        std::process::exit(1);
    }
}

async fn run(action: cli::Action) -> Result<(), ErrorSource> {
    if action.logs_lifecycle() {
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            process_id = std::process::id(),
            command = action.as_str(),
            "nvme-disk-mon starting"
        );
        tracing::info!(
            config_path = config::CONF_PATH,
            "loading configuration and verifying its embedded checksum"
        );
    }
    tracing::debug!(
        reads_config = action.reads_config(),
        facility = ?action.facility_plan(),
        "selected command facilities"
    );
    let config = if action.reads_config() {
        Some(config::load_config()?)
    } else {
        None
    };
    if let Some(config) = &config
        && action.logs_lifecycle()
    {
        tracing::info!(
            config_path = config::CONF_PATH,
            schema_version = config.general.schema_version,
            device_count = config.device.disk_list.len(),
            writer_rank_length = config.writer_rank.rank_length,
            smtp_auth_method = config.mail.smtp_auth_method.as_str(),
            "configuration loaded and checksum verified"
        );
    }

    match action {
        cli::Action::Help => cli::print_help().map_err(|error| Box::new(error) as ErrorSource),
        cli::Action::Version => {
            cli::print_version();
            Ok(())
        }
        cli::Action::Stats => {
            let config = required_dispatch_config(config.as_ref())?;
            cli::print_stats(config)
        }
        cli::Action::Mail(command) => {
            let config = required_dispatch_config(config.as_ref())?;
            match command {
                cli::MailCommand::Authorize => mail::authorize_mail(&config.mail).await?,
                cli::MailCommand::Validate => mail::validate_mail(&config.mail).await?,
                cli::MailCommand::TestSend => {
                    let receipt = mail::test_send_mail(&config.mail).await?;
                    println!(
                        "SMTP server accepted the test message (status={})",
                        receipt.code
                    );
                }
            }
            Ok(())
        }
        cli::Action::Daemon => {
            let config = required_dispatch_config(config.as_ref())?;
            run_daemon(config)
        }
    }
}

fn required_dispatch_config(
    config: Option<&config::Config>,
) -> Result<&config::Config, ErrorSource> {
    config.ok_or_else(|| {
        Box::new(io::Error::other(
            "command dispatch omitted its required configuration",
        )) as ErrorSource
    })
}

#[allow(clippy::too_many_lines)]
fn run_daemon(config: &config::Config) -> Result<(), ErrorSource> {
    tracing::info!(
        device_count = config.device.disk_list.len(),
        "initializing daemon facilities"
    );
    let mut verified_devices = Vec::with_capacity(config.device.disk_list.len());
    let mut registrations = Vec::with_capacity(config.device.disk_list.len());
    for disk in &config.device.disk_list {
        tracing::info!(
            device_label = %log_safe_text(&disk.label),
            configured_path = %log_safe_path(&disk.path),
            detect_window_hours = disk.detect_window_hr,
            threshold_gib = disk.w_delta_threshold_gib,
            "verifying configured NVMe device"
        );
        let target = monitor::NvmeTarget {
            configured_path: disk.path.clone(),
            expected_serial: disk.serial.clone(),
        };
        let (verified, health) = monitor::read_verified_smart(&target)?;
        if health.data_units_written.is_none() {
            return Err(Box::new(
                monitor::SmartReadError::RequiredCounterUnavailable {
                    field: "data_units_written",
                },
            ));
        }
        tracing::info!(
            device_label = %log_safe_text(&disk.label),
            configured_path = %log_safe_path(&disk.path),
            controller_path = %log_safe_path(&verified.controller_path),
            namespace_major = verified.namespace_major,
            namespace_minor = verified.namespace_minor,
            device_hash_id = verified.hash_id.as_str(),
            "NVMe device identity and SMART access verified"
        );
        registrations.push(database::DeviceRegistration {
            hash_id: verified.hash_id.clone(),
            label: disk.label.clone(),
            serial: disk.serial.clone(),
            by_id_path: disk.path.clone(),
            major: verified.namespace_major,
            minor: verified.namespace_minor,
        });
        verified_devices.push(verified);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let _term_signal = signal_hook::flag::register(SIGTERM, Arc::clone(&stop))?;
    let _interrupt_signal = signal_hook::flag::register(SIGINT, Arc::clone(&stop))?;

    let mut database = database::start_database(Path::new(config::STATS_PATH), &registrations)?;
    let recovered_baselines = database.recovery.len();
    tracing::info!(
        database_path = config::STATS_PATH,
        registered_devices = registrations.len(),
        recovered_smart_baselines = recovered_baselines,
        "statistics database is ready"
    );
    let history = database.take_history().ok_or_else(|| {
        Box::new(io::Error::other("writer history facility is unavailable")) as ErrorSource
    })?;
    let recovery = std::mem::take(&mut database.recovery);

    let mut monitor_devices = Vec::with_capacity(verified_devices.len());
    let mut writer_devices = Vec::with_capacity(verified_devices.len());
    for ((disk, verified), registration) in config
        .device
        .disk_list
        .iter()
        .zip(verified_devices)
        .zip(&registrations)
    {
        monitor_devices.push(monitor::SmartMonitorDevice::new(
            disk,
            verified,
            recovery.get(&registration.hash_id).copied(),
        )?);
        writer_devices.push(writer::collector::MonitoredDevice {
            hash_id: registration.hash_id.clone(),
            configured_path: registration.by_id_path.clone(),
            number: writer::collector::DeviceNumber {
                major: registration.major,
                minor: registration.minor,
            },
        });
    }

    let rank_limit = usize::try_from(config.writer_rank.rank_length)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "writer rank length is outside the supported range",
            )) as ErrorSource
        })?;
    let boundary_tracker = writer::collector::WriterBoundaryTracker::new();
    let alerts = monitor::SmartAlertFacility::new(
        history,
        boundary_tracker.clone(),
        config.mail.clone(),
        config.device.host.clone(),
        Arc::clone(&stop),
        tokio::runtime::Handle::current(),
        rank_limit,
    );

    let (task_sender, task_receiver) = mpsc::channel();
    let writer_collector = writer::collector::WriterCollector::new(
        writer_devices,
        database.handle.clone(),
        boundary_tracker,
        Arc::clone(&stop),
    );
    let writer_sender = task_sender.clone();
    let writer_task = match thread::Builder::new()
        .name("ndm-writer-collector".to_owned())
        .spawn(move || {
            let result = writer_collector.run();
            let _ = writer_sender.send(TaskExit::Writer(result));
        }) {
        Ok(task) => task,
        Err(error) => {
            let _ = database.shutdown();
            return Err(Box::new(error));
        }
    };

    let smart_monitor = monitor::SmartMonitorTask::new(
        monitor_devices,
        database.handle.clone(),
        Arc::clone(&stop),
        alerts,
    );
    let monitor_sender = task_sender;
    let monitor_task = match thread::Builder::new()
        .name("ndm-smart-monitor".to_owned())
        .spawn(move || {
            let result = smart_monitor.run();
            let _ = monitor_sender.send(TaskExit::Monitor(result));
        }) {
        Ok(task) => task,
        Err(error) => {
            stop.store(true, Ordering::Release);
            let _ = writer_task.join();
            let _ = database.shutdown();
            return Err(Box::new(error));
        }
    };

    tracing::info!(
        device_count = registrations.len(),
        writer_sample_period_seconds = writer::collector::SAMPLE_PERIOD.as_secs(),
        "daemon startup completed; monitoring is active"
    );

    let mut first_failure = supervise_long_tasks(stop.as_ref(), &task_receiver, || {
        if database.writer_is_finished() {
            Some("database writer")
        } else if writer_task.is_finished() {
            Some("writer collector")
        } else if monitor_task.is_finished() {
            Some("SMART monitor")
        } else {
            None
        }
    });

    if first_failure.is_some() {
        tracing::warn!("a core daemon task stopped; beginning controlled shutdown");
    } else {
        tracing::info!("shutdown requested; stopping daemon tasks");
    }

    let writer_join = join_long_task(writer_task, "writer collector");
    let monitor_join = join_long_task(monitor_task, "SMART monitor");
    let database_result = database.shutdown();

    for exit in task_receiver.try_iter() {
        if let Some(error) = exit.into_failure(true) {
            retain_first_failure(&mut first_failure, error, "late task exit");
        }
    }
    if let Err(error) = writer_join {
        retain_first_failure(&mut first_failure, error, "writer collector join");
    }
    if let Err(error) = monitor_join {
        retain_first_failure(&mut first_failure, error, "SMART monitor join");
    }
    if let Err(error) = database_result {
        retain_first_failure(
            &mut first_failure,
            Box::new(error),
            "database writer shutdown",
        );
    }
    if let Some(error) = first_failure {
        return Err(error);
    }
    tracing::info!("nvme-disk-mon daemon stopped cleanly");
    Ok(())
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

fn supervise_long_tasks(
    stop: &AtomicBool,
    task_receiver: &mpsc::Receiver<TaskExit>,
    mut finished_core_task: impl FnMut() -> Option<&'static str>,
) -> Option<ErrorSource> {
    loop {
        match task_receiver.try_recv() {
            Ok(exit) => {
                if let Some(error) = exit.into_failure(stop.load(Ordering::Acquire)) {
                    stop.store(true, Ordering::Release);
                    return Some(error);
                }
                return None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) if stop.load(Ordering::Acquire) => {
                return None;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                stop.store(true, Ordering::Release);
                return Some(Box::new(io::Error::other(
                    "long-running task supervision channel closed",
                )));
            }
        }
        if stop.load(Ordering::Acquire) {
            return None;
        }
        if let Some(task_name) = finished_core_task() {
            if let Ok(exit) = task_receiver.try_recv() {
                if let Some(error) = exit.into_failure(stop.load(Ordering::Acquire)) {
                    stop.store(true, Ordering::Release);
                    return Some(error);
                }
                return None;
            }
            stop.store(true, Ordering::Release);
            return Some(Box::new(io::Error::other(format!(
                "{task_name} exited before daemon shutdown"
            ))));
        }
        match task_receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(exit) => {
                if let Some(error) = exit.into_failure(stop.load(Ordering::Acquire)) {
                    stop.store(true, Ordering::Release);
                    return Some(error);
                }
                return None;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) if stop.load(Ordering::Acquire) => {
                return None;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop.store(true, Ordering::Release);
                return Some(Box::new(io::Error::other(
                    "long-running task supervision channel closed",
                )));
            }
        }
    }
}

enum TaskExit {
    Writer(Result<(), ErrorSource>),
    Monitor(Result<(), ErrorSource>),
}

impl TaskExit {
    fn into_failure(self, shutdown_requested: bool) -> Option<ErrorSource> {
        match self {
            Self::Writer(Err(error)) | Self::Monitor(Err(error)) => Some(error),
            Self::Writer(Ok(())) if !shutdown_requested => Some(Box::new(io::Error::other(
                "writer collector exited before daemon shutdown",
            ))),
            Self::Monitor(Ok(())) if !shutdown_requested => Some(Box::new(io::Error::other(
                "SMART monitor exited before daemon shutdown",
            ))),
            Self::Writer(Ok(())) | Self::Monitor(Ok(())) => None,
        }
    }
}

fn retain_first_failure(
    first_failure: &mut Option<ErrorSource>,
    candidate: ErrorSource,
    stage: &'static str,
) {
    if first_failure.is_none() {
        *first_failure = Some(candidate);
    } else {
        tracing::error!(error = %candidate, stage, "secondary failure during daemon shutdown");
    }
}

fn join_long_task(task: thread::JoinHandle<()>, name: &'static str) -> Result<(), ErrorSource> {
    task.join()
        .map_err(|_| Box::new(io::Error::other(format!("{name} task panicked"))) as ErrorSource)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unexpected_core_task_exit_requests_shutdown_and_preserves_failure() {
        let stop = AtomicBool::new(false);
        let (sender, receiver) = mpsc::channel();
        sender
            .send(TaskExit::Monitor(Err(Box::new(io::Error::other(
                "monitor failure",
            )))))
            .expect("send task exit");

        let error =
            supervise_long_tasks(&stop, &receiver, || None).expect("unexpected exit is fatal");
        assert!(stop.load(Ordering::Acquire));
        assert_eq!(error.to_string(), "monitor failure");
    }

    #[test]
    fn normal_stop_does_not_turn_clean_task_shutdown_into_failure() {
        let stop = AtomicBool::new(true);
        let (_sender, receiver) = mpsc::channel();
        assert!(supervise_long_tasks(&stop, &receiver, || None).is_none());
    }

    #[test]
    fn queued_task_error_is_preserved_when_stop_is_already_set() {
        let stop = AtomicBool::new(true);
        let (sender, receiver) = mpsc::channel();
        sender
            .send(TaskExit::Writer(Err(Box::new(io::Error::other(
                "writer failed before its exit was observed",
            )))))
            .expect("send task exit");

        let error = supervise_long_tasks(&stop, &receiver, || None)
            .expect("queued error remains fatal during the stop race");
        assert_eq!(
            error.to_string(),
            "writer failed before its exit was observed"
        );
    }

    #[test]
    fn shutdown_cleanup_failure_does_not_replace_first_failure() {
        let mut first = Some(Box::new(io::Error::other("collector failed")) as ErrorSource);
        retain_first_failure(
            &mut first,
            Box::new(io::Error::other("database shutdown failed")),
            "test cleanup",
        );
        assert_eq!(
            first.expect("first failure retained").to_string(),
            "collector failed"
        );
    }

    #[test]
    fn database_writer_exit_is_a_core_failure() {
        let stop = AtomicBool::new(false);
        let (_sender, receiver) = mpsc::channel();
        let error = supervise_long_tasks(&stop, &receiver, || Some("database writer"))
            .expect("database writer exit is fatal");
        assert!(stop.load(Ordering::Acquire));
        assert!(error.to_string().contains("database writer"));
    }
}
