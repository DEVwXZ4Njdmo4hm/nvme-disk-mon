use std::{
    io::{self, IsTerminal, Write as _},
    process::Command as ProcessCommand,
};

use clap::{CommandFactory, Parser, Subcommand};

use crate::{ErrorSource, config, database};

#[derive(Debug, Parser)]
#[command(
    name = "nvme-disk-mon",
    version,
    about = "Monitor NVMe host writes and attribute cgroup workloads",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
enum Command {
    /// Show command help.
    Help,
    /// Show the program version.
    Version,
    /// Show daemon and monitored-device status.
    Stats,
    /// Authorize, validate, or test the configured mail account.
    Mail {
        #[command(subcommand)]
        command: MailCommand,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Subcommand)]
pub(crate) enum MailCommand {
    /// Complete interactive OAuth authorization.
    Authorize,
    /// Establish a fresh authenticated SMTP session.
    Validate,
    /// Submit one test message.
    TestSend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Daemon,
    Help,
    Version,
    Stats,
    Mail(MailCommand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FacilityPlan {
    None,
    ReadOnlyStats,
    InteractiveAuthorization,
    MailValidation,
    MailTestSend,
    FullDaemon,
}

impl Action {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Help => "help",
            Self::Version => "version",
            Self::Stats => "stats",
            Self::Mail(MailCommand::Authorize) => "mail authorize",
            Self::Mail(MailCommand::Validate) => "mail validate",
            Self::Mail(MailCommand::TestSend) => "mail test-send",
        }
    }

    pub(crate) const fn reads_config(self) -> bool {
        !matches!(self, Self::Help | Self::Version)
    }

    pub(crate) const fn logs_lifecycle(self) -> bool {
        matches!(self, Self::Daemon)
    }

    pub(crate) const fn facility_plan(self) -> FacilityPlan {
        match self {
            Self::Help | Self::Version => FacilityPlan::None,
            Self::Stats => FacilityPlan::ReadOnlyStats,
            Self::Mail(MailCommand::Authorize) => FacilityPlan::InteractiveAuthorization,
            Self::Mail(MailCommand::Validate) => FacilityPlan::MailValidation,
            Self::Mail(MailCommand::TestSend) => FacilityPlan::MailTestSend,
            Self::Daemon => FacilityPlan::FullDaemon,
        }
    }
}

pub(crate) fn parse() -> Action {
    Cli::parse().into()
}

pub(crate) fn print_help() -> Result<(), std::io::Error> {
    Cli::command().print_help()?;
    println!();
    Ok(())
}

pub(crate) fn print_version() {
    println!("nvme-disk-mon {}", env!("CARGO_PKG_VERSION"));
}

pub(crate) fn print_stats(config: &config::Config) -> Result<(), ErrorSource> {
    let daemon_status = query_daemon_status()?;
    let mut devices = Vec::with_capacity(config.device.disk_list.len());
    for disk in &config.device.disk_list {
        let stats = database::read_smart_device_stats(
            std::path::Path::new(config::STATS_PATH),
            &disk.serial,
            &disk.path,
            disk.detect_window_hr,
            disk.w_delta_threshold_gib,
        )?;
        let (last_write_amount, last_sample_time) = match stats.latest_sample {
            Some(latest) => (
                format_data_units_written_gib(latest.data_units_written),
                format_utc_timestamp(latest.timestamp)?,
            ),
            None => (NO_STATS.to_owned(), NO_STATS.to_owned()),
        };
        let last_error = stats
            .last_threshold_timestamp
            .map(format_utc_timestamp)
            .transpose()?
            .unwrap_or_else(|| NO_STATS.to_owned());
        devices.push(StatsDevice {
            label: log_safe_text(&disk.label),
            serial: log_safe_text(&disk.serial),
            last_write_amount,
            last_sample_time,
            last_error,
        });
    }

    let stdout = io::stdout();
    let output = render_stats(daemon_status, &devices, stdout.is_terminal());
    stdout.lock().write_all(output.as_bytes())?;
    Ok(())
}

const SERVICE_UNIT: &str = "nvme-disk-mon.service";
const MAX_SYSTEMCTL_OUTPUT_BYTES: usize = 4 * 1024;
const TABLE_CELL_PADDING: usize = 4;
const TABLE_MIN_WIDTHS: [usize; 5] = [16, 20, 21, 24, 14];
const NO_STATS: &str = "------";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonStatus {
    Running,
    Stopped,
    Failed,
}

impl DaemonStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Running => "Running",
            Self::Stopped => "Stopped",
            Self::Failed => "Failed",
        }
    }

    const fn ansi(self) -> &'static str {
        match self {
            Self::Running => "\x1b[1;32m",
            Self::Stopped => "\x1b[1;90m",
            Self::Failed => "\x1b[1;31m",
        }
    }
}

struct StatsDevice {
    label: String,
    serial: String,
    last_write_amount: String,
    last_sample_time: String,
    last_error: String,
}

fn query_daemon_status() -> Result<DaemonStatus, ErrorSource> {
    let output = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "--system",
            "show",
            SERVICE_UNIT,
            "--property=LoadState",
            "--property=ActiveState",
            "--no-pager",
        ])
        .output()
        .map_err(|source| {
            Box::new(io::Error::new(
                source.kind(),
                "cannot query the nvme-disk-mon systemd unit",
            )) as ErrorSource
        })?;
    if !output.status.success() {
        return Err(Box::new(io::Error::other(format!(
            "systemctl could not query the nvme-disk-mon unit (status={})",
            output
                .status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| code.to_string())
        ))));
    }
    parse_daemon_status(&output.stdout).map_err(|error| Box::new(error) as ErrorSource)
}

fn parse_daemon_status(output: &[u8]) -> io::Result<DaemonStatus> {
    if output.len() > MAX_SYSTEMCTL_OUTPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "systemctl unit state output is too large",
        ));
    }
    let output = std::str::from_utf8(output).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "systemctl unit state output is not UTF-8",
        )
    })?;
    let mut load_state = None;
    let mut active_state = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            if load_state.replace(value).is_some() {
                return Err(invalid_systemd_unit_state());
            }
        } else if let Some(value) = line.strip_prefix("ActiveState=")
            && active_state.replace(value).is_some()
        {
            return Err(invalid_systemd_unit_state());
        }
    }
    if load_state != Some("loaded") {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "nvme-disk-mon systemd unit is not loaded",
        ));
    }
    match active_state {
        Some("active" | "activating" | "reloading") => Ok(DaemonStatus::Running),
        Some("inactive" | "deactivating") => Ok(DaemonStatus::Stopped),
        Some("failed") => Ok(DaemonStatus::Failed),
        Some(_) | None => Err(invalid_systemd_unit_state()),
    }
}

fn invalid_systemd_unit_state() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "systemctl returned an invalid nvme-disk-mon unit state",
    )
}

fn render_stats(status: DaemonStatus, devices: &[StatsDevice], color: bool) -> String {
    let status = if color {
        format!("{}{}\x1b[0m", status.ansi(), status.label())
    } else {
        status.label().to_owned()
    };
    let mut output = format!(
        "\nNVMe-Disk-Mon Version {}\n\nDaemon: {status}\n\nDevs:\n",
        env!("CARGO_PKG_VERSION")
    );
    output.push_str(&render_device_table(devices));
    output
}

fn render_device_table(devices: &[StatsDevice]) -> String {
    let label_width = column_width(
        "Label",
        devices.iter().map(|device| device.label.as_str()),
        TABLE_MIN_WIDTHS[0],
    );
    let serial_width = column_width(
        "Serial",
        devices.iter().map(|device| device.serial.as_str()),
        TABLE_MIN_WIDTHS[1],
    );
    let last_write_amount_width = column_width(
        "Last Write Amount",
        devices
            .iter()
            .map(|device| device.last_write_amount.as_str()),
        TABLE_MIN_WIDTHS[2],
    );
    let last_sample_time_width = column_width(
        "Last Sample Time",
        devices
            .iter()
            .map(|device| device.last_sample_time.as_str()),
        TABLE_MIN_WIDTHS[3],
    );
    let last_error_width = column_width(
        "Last Error",
        devices.iter().map(|device| device.last_error.as_str()),
        TABLE_MIN_WIDTHS[4],
    );
    let widths = [
        label_width,
        serial_width,
        last_write_amount_width,
        last_sample_time_width,
        last_error_width,
    ];
    let mut table = table_row(
        [
            "Label",
            "Serial",
            "Last Write Amount",
            "Last Sample Time",
            "Last Error",
        ],
        widths,
    );
    for device in devices {
        table.push_str(&table_row(
            [
                &device.label,
                &device.serial,
                &device.last_write_amount,
                &device.last_sample_time,
                &device.last_error,
            ],
            widths,
        ));
    }
    table
}

fn column_width<'a>(heading: &str, values: impl Iterator<Item = &'a str>, minimum: usize) -> usize {
    (values.fold(heading.len(), |width, value| width.max(value.len())) + TABLE_CELL_PADDING)
        .max(minimum)
}

fn table_row(values: [&str; 5], widths: [usize; 5]) -> String {
    format!(
        "|{}|{}|{}|{}|{}|\n",
        centered(values[0], widths[0]),
        centered(values[1], widths[1]),
        centered(values[2], widths[2]),
        centered(values[3], widths[3]),
        centered(values[4], widths[4]),
    )
}

fn centered(value: &str, width: usize) -> String {
    let padding = width - value.len();
    let left = padding / 2;
    let right = padding - left;
    format!("{}{}{}", " ".repeat(left), value, " ".repeat(right))
}

fn format_utc_timestamp(timestamp_ms: i64) -> Result<String, ErrorSource> {
    let timestamp_nanos = i128::from(timestamp_ms)
        .checked_mul(1_000_000)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "timestamp is out of range")
        })?;
    let timestamp = time::OffsetDateTime::from_unix_timestamp_nanos(timestamp_nanos)?;
    timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| Box::new(error) as ErrorSource)
}

fn format_data_units_written_gib(data_units_written: u128) -> String {
    const DATA_UNITS_PER_GIB_DENOMINATOR: u128 = 262_144;
    const HUNDREDTHS_PER_DATA_UNIT_NUMERATOR: u128 = 12_500;

    let quotient = data_units_written / DATA_UNITS_PER_GIB_DENOMINATOR;
    let remainder = data_units_written % DATA_UNITS_PER_GIB_DENOMINATOR;
    let rounded_hundredths = quotient * HUNDREDTHS_PER_DATA_UNIT_NUMERATOR
        + (remainder * HUNDREDTHS_PER_DATA_UNIT_NUMERATOR + DATA_UNITS_PER_GIB_DENOMINATOR / 2)
            / DATA_UNITS_PER_GIB_DENOMINATOR;
    let whole = rounded_hundredths / 100;
    let fraction = rounded_hundredths % 100;
    format!("{whole}.{fraction:02} GiB")
}

fn log_safe_text(value: &str) -> String {
    let mut output = String::new();
    for byte in value.as_bytes().iter().take(256) {
        output.extend(std::ascii::escape_default(*byte).map(char::from));
    }
    if value.len() > 256 {
        output.push_str("...");
    }
    output
}

impl From<Cli> for Action {
    fn from(cli: Cli) -> Self {
        match cli.command {
            None => Self::Daemon,
            Some(Command::Help) => Self::Help,
            Some(Command::Version) => Self::Version,
            Some(Command::Stats) => Self::Stats,
            Some(Command::Mail { command }) => Self::Mail(command),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    fn action(arguments: &[&str]) -> Action {
        Cli::try_parse_from(arguments)
            .expect("valid command line")
            .into()
    }

    #[test]
    fn command_matrix_selects_only_the_required_facility() {
        let cases = [
            (
                &["ndm"][..],
                Action::Daemon,
                FacilityPlan::FullDaemon,
                true,
                true,
            ),
            (
                &["ndm", "help"],
                Action::Help,
                FacilityPlan::None,
                false,
                false,
            ),
            (
                &["ndm", "version"],
                Action::Version,
                FacilityPlan::None,
                false,
                false,
            ),
            (
                &["ndm", "stats"],
                Action::Stats,
                FacilityPlan::ReadOnlyStats,
                true,
                false,
            ),
            (
                &["ndm", "mail", "authorize"],
                Action::Mail(MailCommand::Authorize),
                FacilityPlan::InteractiveAuthorization,
                true,
                false,
            ),
            (
                &["ndm", "mail", "validate"],
                Action::Mail(MailCommand::Validate),
                FacilityPlan::MailValidation,
                true,
                false,
            ),
            (
                &["ndm", "mail", "test-send"],
                Action::Mail(MailCommand::TestSend),
                FacilityPlan::MailTestSend,
                true,
                false,
            ),
        ];

        for (arguments, expected_action, expected_plan, reads_config, logs_lifecycle) in cases {
            let actual = action(arguments);
            assert_eq!(actual, expected_action);
            assert_eq!(actual.facility_plan(), expected_plan);
            assert_eq!(actual.reads_config(), reads_config);
            assert_eq!(actual.logs_lifecycle(), logs_lifecycle);
        }
    }

    #[test]
    fn systemd_active_state_maps_to_the_three_stats_states() {
        let cases = [
            ("active", DaemonStatus::Running),
            ("activating", DaemonStatus::Running),
            ("reloading", DaemonStatus::Running),
            ("inactive", DaemonStatus::Stopped),
            ("deactivating", DaemonStatus::Stopped),
            ("failed", DaemonStatus::Failed),
        ];
        for (active_state, expected) in cases {
            let output = format!("LoadState=loaded\nActiveState={active_state}\n");
            assert_eq!(
                parse_daemon_status(output.as_bytes()).expect("valid systemd state"),
                expected
            );
        }
        assert!(parse_daemon_status(b"LoadState=not-found\nActiveState=inactive\n").is_err());
        assert!(parse_daemon_status(b"LoadState=loaded\nActiveState=unknown\n").is_err());
    }

    #[test]
    fn stats_table_is_centered_and_has_aligned_boundaries() {
        let devices = [
            StatsDevice {
                label: "Test Disk A".to_owned(),
                serial: "TESTSERIAL00001".to_owned(),
                last_write_amount: "1000.00 GiB".to_owned(),
                last_sample_time: "2026-08-26T12:34:56Z".to_owned(),
                last_error: "------".to_owned(),
            },
            StatsDevice {
                label: "Test Disk B".to_owned(),
                serial: "TESTSERIAL00002".to_owned(),
                last_write_amount: "------".to_owned(),
                last_sample_time: "------".to_owned(),
                last_error: "------".to_owned(),
            },
        ];
        let table = render_device_table(&devices);
        let lines = table.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|line| line.len() == lines[0].len()));
        assert_eq!(
            lines,
            [
                "|     Label      |       Serial       |  Last Write Amount  |    Last Sample Time    |  Last Error  |",
                "|  Test Disk A   |  TESTSERIAL00001   |     1000.00 GiB     |  2026-08-26T12:34:56Z  |    ------    |",
                "|  Test Disk B   |  TESTSERIAL00002   |       ------        |         ------         |    ------    |",
            ]
        );
    }

    #[test]
    fn stats_write_amount_uses_cumulative_smart_units_and_two_decimal_places() {
        assert_eq!(format_data_units_written_gib(2_097_152), "1000.00 GiB");
        assert_eq!(format_data_units_written_gib(1), "0.00 GiB");
        assert_eq!(
            format_data_units_written_gib(u128::MAX),
            "162259276829213363391578010288128000.00 GiB"
        );
    }

    #[test]
    fn stats_colors_only_the_status_value() {
        let plain = render_stats(DaemonStatus::Stopped, &[], false);
        assert!(plain.contains("Daemon: Stopped"));
        assert!(!plain.contains('\x1b'));

        let colored = render_stats(DaemonStatus::Failed, &[], true);
        assert!(colored.contains("Daemon: \x1b[1;31mFailed\x1b[0m"));
    }

    #[test]
    fn action_names_are_stable_and_human_readable() {
        let cases = [
            (Action::Daemon, "daemon"),
            (Action::Help, "help"),
            (Action::Version, "version"),
            (Action::Stats, "stats"),
            (Action::Mail(MailCommand::Authorize), "mail authorize"),
            (Action::Mail(MailCommand::Validate), "mail validate"),
            (Action::Mail(MailCommand::TestSend), "mail test-send"),
        ];

        for (action, expected) in cases {
            assert_eq!(action.as_str(), expected);
        }
    }
}
