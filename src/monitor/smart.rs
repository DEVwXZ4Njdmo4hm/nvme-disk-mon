use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
    time::SystemTime,
};

use sha2::{Digest, Sha256};

const SYS_DEV_BLOCK: &str = "/sys/dev/block";
const DEV_ROOT: &str = "/dev";
const SMART_LOG_LEN: usize = 512;
const SMART_LOG_DATA_LEN: u32 = 512;
const NVME_ADMIN_GET_LOG_PAGE: u8 = 0x02;
const NVME_SMART_LOG_IDENTIFIER: u32 = 0x02;
const NVME_CONTROLLER_NSID: u32 = u32::MAX;
const SMART_LOG_NUMD_ZERO_BASED: u32 = 127;
const NVME_ADMIN_COMMAND_SIZE: u32 = 72;

// Linux asm-generic/ioctl.h layout, used by the only supported target,
// x86_64-unknown-linux-gnu.
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

#[derive(Clone)]
pub(crate) struct NvmeTarget {
    pub(crate) configured_path: PathBuf,
    pub(crate) expected_serial: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SmartEndpoint {
    ControllerChar,
    // Required by the brief's SMART data model. This implementation always
    // uses the verified controller character device for admin commands.
    #[allow(dead_code)]
    NamespaceBlock,
}

// The brief requires the complete 512-byte SMART model even though the daemon
// currently consumes only the sample time and data-units-written counter.
#[allow(dead_code)]
pub(crate) struct NvmeSmartHealth {
    pub(crate) endpoint: SmartEndpoint,
    pub(crate) sampled_at: SystemTime,
    pub(crate) raw_log: [u8; SMART_LOG_LEN],

    pub(crate) critical_warning: u8,
    pub(crate) temperature_kelvin: u16,
    pub(crate) available_spare_pct: u8,
    pub(crate) spare_threshold_pct: u8,
    pub(crate) percentage_used: u8,

    pub(crate) data_units_read: Option<u128>,
    pub(crate) data_units_written: Option<u128>,
    pub(crate) host_read_commands: u128,
    pub(crate) host_write_commands: u128,
    pub(crate) controller_busy_minutes: u128,
    pub(crate) power_cycles: u128,
    pub(crate) power_on_hours: u128,
    pub(crate) unsafe_shutdowns: u128,
    pub(crate) media_errors: u128,
    pub(crate) error_log_entries: u128,

    pub(crate) temperature_sensors_kelvin: [u16; 8],
}

pub(crate) enum SmartReadError {
    ResolveById {
        path: PathBuf,
        source: io::Error,
    },
    NotBlockDevice {
        path: PathBuf,
    },
    DeviceNumberUnavailable {
        path: PathBuf,
    },
    ReadSysfs {
        path: PathBuf,
        source: io::Error,
    },
    TopologyNotFound {
        major: u32,
        minor: u32,
    },
    NotNvmeNamespace {
        major: u32,
        minor: u32,
    },
    SerialRead {
        path: PathBuf,
        source: io::Error,
    },
    SerialMismatch {
        path: PathBuf,
    },
    InsufficientPrivileges {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    OpenController {
        path: PathBuf,
        source: io::Error,
    },
    AdminCommandIo {
        path: PathBuf,
        source: io::Error,
    },
    AdminCommandRejected {
        status: u16,
    },
    InvalidSmartLog {
        field: &'static str,
    },
    RequiredCounterUnavailable {
        field: &'static str,
    },
}

impl fmt::Display for SmartReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResolveById { path, .. } => write!(
                formatter,
                "cannot resolve configured device {}",
                log_safe_path(path)
            ),
            Self::NotBlockDevice { path } => write!(
                formatter,
                "configured path is not a block device: {}",
                log_safe_path(path)
            ),
            Self::DeviceNumberUnavailable { path } => write!(
                formatter,
                "configured device has no usable device number: {}",
                log_safe_path(path)
            ),
            Self::ReadSysfs { path, .. } => {
                write!(
                    formatter,
                    "cannot read NVMe topology at {}",
                    log_safe_path(path)
                )
            }
            Self::TopologyNotFound { major, minor } => {
                write!(
                    formatter,
                    "no block topology exists for device {major}:{minor}"
                )
            }
            Self::NotNvmeNamespace { major, minor } => {
                write!(formatter, "device {major}:{minor} is not an NVMe namespace")
            }
            Self::SerialRead { path, .. } => write!(
                formatter,
                "cannot read NVMe serial from {}",
                log_safe_path(path)
            ),
            Self::SerialMismatch { path } => write!(
                formatter,
                "NVMe serial verification failed for {}",
                log_safe_path(path)
            ),
            Self::InsufficientPrivileges {
                operation, path, ..
            } => write!(
                formatter,
                "insufficient privileges to {operation} at {}",
                log_safe_path(path)
            ),
            Self::OpenController { path, .. } => write!(
                formatter,
                "cannot open NVMe controller {}",
                log_safe_path(path)
            ),
            Self::AdminCommandIo { path, .. } => write!(
                formatter,
                "NVMe SMART ioctl failed for {}",
                log_safe_path(path)
            ),
            Self::AdminCommandRejected { status } => write!(
                formatter,
                "NVMe controller rejected SMART command (status=0x{status:04x})"
            ),
            Self::InvalidSmartLog { field } => {
                write!(
                    formatter,
                    "NVMe SMART log contains an invalid {field} field"
                )
            }
            Self::RequiredCounterUnavailable { field } => {
                write!(
                    formatter,
                    "required NVMe SMART counter is unavailable: {field}"
                )
            }
        }
    }
}

impl fmt::Debug for SmartReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for SmartReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ResolveById { source, .. }
            | Self::ReadSysfs { source, .. }
            | Self::SerialRead { source, .. }
            | Self::InsufficientPrivileges { source, .. }
            | Self::OpenController { source, .. }
            | Self::AdminCommandIo { source, .. } => Some(source),
            Self::NotBlockDevice { .. }
            | Self::DeviceNumberUnavailable { .. }
            | Self::TopologyNotFound { .. }
            | Self::NotNvmeNamespace { .. }
            | Self::SerialMismatch { .. }
            | Self::AdminCommandRejected { .. }
            | Self::InvalidSmartLog { .. }
            | Self::RequiredCounterUnavailable { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedNvmeDevice {
    pub(crate) configured_path: PathBuf,
    pub(crate) namespace_major: u32,
    pub(crate) namespace_minor: u32,
    pub(crate) controller_path: PathBuf,
    pub(crate) hash_id: String,
}

struct ResolvedNvmeDevice {
    verified: VerifiedNvmeDevice,
}

#[repr(C)]
#[derive(Debug, Default)]
struct NvmeAdminCommand {
    opcode: u8,
    flags: u8,
    reserved1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    address: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

const fn ioctl_request(direction: u32, kind: u8, number: u8, size: u32) -> libc::c_ulong {
    ((direction << IOC_DIRSHIFT)
        | ((kind as u32) << IOC_TYPESHIFT)
        | ((number as u32) << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)) as libc::c_ulong
}

const NVME_IOCTL_ADMIN_CMD: libc::c_ulong =
    ioctl_request(IOC_READ | IOC_WRITE, b'N', 0x41, NVME_ADMIN_COMMAND_SIZE);

const _: () = assert!(size_of::<NvmeAdminCommand>() == 72);

#[allow(dead_code)]
pub(crate) fn verify_nvme_target(
    target: &NvmeTarget,
) -> Result<VerifiedNvmeDevice, SmartReadError> {
    resolve_nvme_target(target).map(|device| device.verified)
}

#[allow(dead_code)]
pub(crate) fn read_smart_by_disk(target: &NvmeTarget) -> Result<NvmeSmartHealth, SmartReadError> {
    read_verified_smart(target).map(|(_, health)| health)
}

pub(crate) fn read_verified_smart(
    target: &NvmeTarget,
) -> Result<(VerifiedNvmeDevice, NvmeSmartHealth), SmartReadError> {
    let resolved = resolve_nvme_target(target)?;
    let health = read_smart_from_resolved(&resolved)?;
    Ok((resolved.verified, health))
}

fn read_smart_from_resolved(
    resolved: &ResolvedNvmeDevice,
) -> Result<NvmeSmartHealth, SmartReadError> {
    let controller_path = &resolved.verified.controller_path;
    let controller = File::open(controller_path).map_err(|source| {
        if is_permission_error(&source) {
            SmartReadError::InsufficientPrivileges {
                operation: "open NVMe controller",
                path: controller_path.clone(),
                source,
            }
        } else {
            SmartReadError::OpenController {
                path: controller_path.clone(),
                source,
            }
        }
    })?;

    let controller_metadata =
        controller
            .metadata()
            .map_err(|source| SmartReadError::OpenController {
                path: controller_path.clone(),
                source,
            })?;
    if !controller_metadata.file_type().is_char_device() {
        return Err(SmartReadError::TopologyNotFound {
            major: resolved.verified.namespace_major,
            minor: resolved.verified.namespace_minor,
        });
    }

    let mut raw_log = [0_u8; SMART_LOG_LEN];
    let status = issue_smart_admin_command(&controller, &mut raw_log).map_err(|source| {
        if is_permission_error(&source) {
            SmartReadError::InsufficientPrivileges {
                operation: "read NVMe SMART log",
                path: controller_path.clone(),
                source,
            }
        } else {
            SmartReadError::AdminCommandIo {
                path: controller_path.clone(),
                source,
            }
        }
    })?;
    if status != 0 {
        let status = u16::try_from(status).map_err(|_| SmartReadError::InvalidSmartLog {
            field: "command status",
        })?;
        return Err(SmartReadError::AdminCommandRejected { status });
    }

    parse_smart_log(&raw_log, SmartEndpoint::ControllerChar, SystemTime::now())
}

fn resolve_nvme_target(target: &NvmeTarget) -> Result<ResolvedNvmeDevice, SmartReadError> {
    let metadata =
        fs::metadata(&target.configured_path).map_err(|source| SmartReadError::ResolveById {
            path: target.configured_path.clone(),
            source,
        })?;
    if !metadata.file_type().is_block_device() {
        return Err(SmartReadError::NotBlockDevice {
            path: target.configured_path.clone(),
        });
    }

    let device_number = metadata.rdev();
    let (Some(major), Some(minor)) = (
        linux_device_major(device_number),
        linux_device_minor(device_number),
    ) else {
        return Err(SmartReadError::DeviceNumberUnavailable {
            path: target.configured_path.clone(),
        });
    };
    if major == 0 && minor == 0 {
        return Err(SmartReadError::DeviceNumberUnavailable {
            path: target.configured_path.clone(),
        });
    }

    let sysfs_path = PathBuf::from(SYS_DEV_BLOCK).join(format!("{major}:{minor}"));
    let namespace_path = match fs::canonicalize(&sysfs_path) {
        Ok(path) => path,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(SmartReadError::TopologyNotFound { major, minor });
        }
        Err(source) => {
            return Err(SmartReadError::ReadSysfs {
                path: sysfs_path,
                source,
            });
        }
    };

    require_nvme_namespace(&namespace_path, major, minor)?;
    let controller_sysfs_path = canonicalize_sysfs(&namespace_path.join("device"))?;
    let controller_subsystem = canonicalize_sysfs(&controller_sysfs_path.join("subsystem"))?;
    if controller_subsystem
        .file_name()
        .and_then(|name| name.to_str())
        != Some("nvme")
    {
        return Err(SmartReadError::NotNvmeNamespace { major, minor });
    }

    let Some(controller_name) = controller_sysfs_path
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return Err(SmartReadError::TopologyNotFound { major, minor });
    };
    if !is_controller_name(controller_name) {
        return Err(SmartReadError::TopologyNotFound { major, minor });
    }

    let serial_path = controller_sysfs_path.join("serial");
    let serial_bytes = fs::read(&serial_path).map_err(|source| SmartReadError::SerialRead {
        path: serial_path.clone(),
        source,
    })?;
    let serial_matches =
        sysfs_serial_matches(&serial_bytes, &target.expected_serial).map_err(|source| {
            SmartReadError::SerialRead {
                path: serial_path,
                source,
            }
        })?;
    if !serial_matches {
        return Err(SmartReadError::SerialMismatch {
            path: target.configured_path.clone(),
        });
    }

    let controller_path = PathBuf::from(DEV_ROOT).join(controller_name);
    Ok(ResolvedNvmeDevice {
        verified: VerifiedNvmeDevice {
            configured_path: target.configured_path.clone(),
            namespace_major: major,
            namespace_minor: minor,
            controller_path,
            hash_id: device_hash_id(&target.expected_serial, &target.configured_path),
        },
    })
}

fn require_nvme_namespace(
    namespace_path: &Path,
    major: u32,
    minor: u32,
) -> Result<(), SmartReadError> {
    let partition_path = namespace_path.join("partition");
    match partition_path.try_exists() {
        Ok(true) => return Err(SmartReadError::NotNvmeNamespace { major, minor }),
        Ok(false) => {}
        Err(source) => {
            return Err(SmartReadError::ReadSysfs {
                path: partition_path,
                source,
            });
        }
    }

    let nsid_path = namespace_path.join("nsid");
    match fs::read_to_string(&nsid_path) {
        Ok(value) if is_namespace_id(&value) => Ok(()),
        Ok(_) => Err(SmartReadError::NotNvmeNamespace { major, minor }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Err(SmartReadError::NotNvmeNamespace { major, minor })
        }
        Err(source) => Err(SmartReadError::ReadSysfs {
            path: nsid_path,
            source,
        }),
    }
}

fn is_namespace_id(value: &str) -> bool {
    value
        .trim()
        .parse::<u32>()
        .is_ok_and(|nsid| nsid != 0 && nsid != u32::MAX)
}

fn canonicalize_sysfs(path: &Path) -> Result<PathBuf, SmartReadError> {
    fs::canonicalize(path).map_err(|source| SmartReadError::ReadSysfs {
        path: path.to_path_buf(),
        source,
    })
}

fn sysfs_serial_matches(serial_bytes: &[u8], expected_serial: &str) -> io::Result<bool> {
    let serial_bytes = serial_bytes.strip_suffix(b"\n").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "NVMe serial sysfs value has no line terminator",
        )
    })?;
    let serial_len = serial_bytes
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1);
    let serial_bytes = &serial_bytes[..serial_len];
    let actual_serial = std::str::from_utf8(serial_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NVMe serial is not UTF-8"))?;
    Ok(actual_serial == expected_serial)
}

fn smart_log_command(raw_log: &mut [u8; SMART_LOG_LEN]) -> NvmeAdminCommand {
    NvmeAdminCommand {
        opcode: NVME_ADMIN_GET_LOG_PAGE,
        nsid: NVME_CONTROLLER_NSID,
        address: raw_log.as_mut_ptr() as usize as u64,
        data_len: SMART_LOG_DATA_LEN,
        cdw10: (SMART_LOG_NUMD_ZERO_BASED << 16) | NVME_SMART_LOG_IDENTIFIER,
        ..NvmeAdminCommand::default()
    }
}

#[allow(unsafe_code)]
fn issue_smart_admin_command(
    controller: &File,
    raw_log: &mut [u8; SMART_LOG_LEN],
) -> io::Result<i32> {
    let mut command = smart_log_command(raw_log);
    // SAFETY: NvmeAdminCommand is the x86_64 Linux UAPI structure for
    // NVME_IOCTL_ADMIN_CMD. The file, command, and exclusively borrowed SMART
    // buffer referenced by command.address all outlive the ioctl call.
    let status = unsafe {
        libc::ioctl(
            controller.as_raw_fd(),
            NVME_IOCTL_ADMIN_CMD,
            std::ptr::from_mut(&mut command).cast::<libc::c_void>(),
        )
    };
    if status == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(status)
    }
}

fn parse_smart_log(
    raw_log: &[u8; SMART_LOG_LEN],
    endpoint: SmartEndpoint,
    sampled_at: SystemTime,
) -> Result<NvmeSmartHealth, SmartReadError> {
    let available_spare_pct = raw_log[3];
    if available_spare_pct > 100 {
        return Err(SmartReadError::InvalidSmartLog {
            field: "available spare percentage",
        });
    }
    let spare_threshold_pct = raw_log[4];
    if spare_threshold_pct > 100 {
        return Err(SmartReadError::InvalidSmartLog {
            field: "spare threshold percentage",
        });
    }

    let data_units_read = nonzero_u128(read_u128_le(raw_log, 32));
    let data_units_written = nonzero_u128(read_u128_le(raw_log, 48));
    let mut temperature_sensors_kelvin = [0_u16; 8];
    for (index, temperature) in temperature_sensors_kelvin.iter_mut().enumerate() {
        let offset = 200 + index * 2;
        *temperature = u16::from_le_bytes([raw_log[offset], raw_log[offset + 1]]);
    }

    Ok(NvmeSmartHealth {
        endpoint,
        sampled_at,
        critical_warning: raw_log[0],
        temperature_kelvin: u16::from_le_bytes([raw_log[1], raw_log[2]]),
        available_spare_pct,
        spare_threshold_pct,
        percentage_used: raw_log[5],
        data_units_read,
        data_units_written,
        host_read_commands: read_u128_le(raw_log, 64),
        host_write_commands: read_u128_le(raw_log, 80),
        controller_busy_minutes: read_u128_le(raw_log, 96),
        power_cycles: read_u128_le(raw_log, 112),
        power_on_hours: read_u128_le(raw_log, 128),
        unsafe_shutdowns: read_u128_le(raw_log, 144),
        media_errors: read_u128_le(raw_log, 160),
        error_log_entries: read_u128_le(raw_log, 176),
        temperature_sensors_kelvin,
        raw_log: *raw_log,
    })
}

fn read_u128_le(raw_log: &[u8; SMART_LOG_LEN], offset: usize) -> u128 {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&raw_log[offset..offset + 16]);
    u128::from_le_bytes(bytes)
}

const fn nonzero_u128(value: u128) -> Option<u128> {
    if value == 0 { None } else { Some(value) }
}

pub(crate) fn device_hash_id(serial: &str, configured_by_id_path: &Path) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut digest = Sha256::new();
    digest.update(serial.as_bytes());
    digest.update([0]);
    // Configuration strings are UTF-8. as_encoded_bytes preserves that exact
    // configured representation without resolving the by-id symlink.
    digest.update(configured_by_id_path.as_os_str().as_encoded_bytes());
    let digest = digest.finalize();
    let mut hash_id = String::with_capacity(64);
    for byte in digest {
        hash_id.push(char::from(HEX[usize::from(byte >> 4)]));
        hash_id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hash_id
}

pub(crate) fn is_valid_hash_id(hash_id: &str) -> bool {
    hash_id.len() == 64
        && hash_id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_controller_name(name: &str) -> bool {
    name.strip_prefix("nvme").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn linux_device_major(device: u64) -> Option<u32> {
    u32::try_from(
        ((device & 0x0000_0000_000f_ff00) >> 8) | ((device & 0xffff_f000_0000_0000) >> 32),
    )
    .ok()
}

fn linux_device_minor(device: u64) -> Option<u32> {
    u32::try_from((device & 0x0000_0000_0000_00ff) | ((device & 0x0000_0fff_fff0_0000) >> 12)).ok()
}

fn is_permission_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM))
}

fn log_safe_path(path: &Path) -> String {
    const MAX_PATH_BYTES: usize = 512;

    let bytes = path.as_os_str().as_encoded_bytes();
    let mut escaped = String::new();
    for byte in bytes.iter().take(MAX_PATH_BYTES) {
        escaped.extend(std::ascii::escape_default(*byte).map(char::from));
    }
    if bytes.len() > MAX_PATH_BYTES {
        escaped.push_str("...");
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};
    use std::time::UNIX_EPOCH;

    use super::*;

    fn set_u128(raw: &mut [u8; SMART_LOG_LEN], offset: usize, value: u128) {
        raw[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
    }

    fn fixed_log() -> [u8; SMART_LOG_LEN] {
        let mut raw = [0_u8; SMART_LOG_LEN];
        raw[0] = 0x15;
        raw[1..3].copy_from_slice(&321_u16.to_le_bytes());
        raw[3] = 98;
        raw[4] = 10;
        raw[5] = 7;
        set_u128(&mut raw, 32, 0x0102_0304_0506_0708_1112_1314_1516_1718);
        set_u128(&mut raw, 48, 0x2122_2324_2526_2728_3132_3334_3536_3738);
        set_u128(&mut raw, 64, 3);
        set_u128(&mut raw, 80, 4);
        set_u128(&mut raw, 96, 5);
        set_u128(&mut raw, 112, 6);
        set_u128(&mut raw, 128, 7);
        set_u128(&mut raw, 144, 8);
        set_u128(&mut raw, 160, 9);
        set_u128(&mut raw, 176, 10);
        for index in 0..8 {
            let offset = 200 + index * 2;
            raw[offset..offset + 2]
                .copy_from_slice(&(300_u16 + u16::try_from(index).expect("index")).to_le_bytes());
        }
        raw
    }

    #[test]
    fn nvme_uapi_layout_and_smart_command_are_exact() {
        assert_eq!(size_of::<NvmeAdminCommand>(), 72);
        assert_eq!(offset_of!(NvmeAdminCommand, opcode), 0);
        assert_eq!(offset_of!(NvmeAdminCommand, nsid), 4);
        assert_eq!(offset_of!(NvmeAdminCommand, address), 24);
        assert_eq!(offset_of!(NvmeAdminCommand, data_len), 36);
        assert_eq!(offset_of!(NvmeAdminCommand, cdw10), 40);
        assert_eq!(offset_of!(NvmeAdminCommand, result), 68);
        assert_eq!(NVME_IOCTL_ADMIN_CMD, 0xc048_4e41);

        let mut raw = [0_u8; SMART_LOG_LEN];
        let command = smart_log_command(&mut raw);
        assert_eq!(command.opcode, NVME_ADMIN_GET_LOG_PAGE);
        assert_eq!(command.nsid, u32::MAX);
        assert_eq!(command.data_len, 512);
        assert_eq!(command.cdw10, (127 << 16) | 0x02);
        assert_eq!(command.address, raw.as_mut_ptr() as usize as u64);
    }

    #[test]
    fn fixed_smart_log_uses_nvme_offsets_and_little_endian_counters() {
        let sampled_at = UNIX_EPOCH + std::time::Duration::from_secs(123);
        let raw = fixed_log();
        let health = parse_smart_log(&raw, SmartEndpoint::ControllerChar, sampled_at)
            .expect("valid fixed SMART log");

        assert_eq!(health.endpoint, SmartEndpoint::ControllerChar);
        assert_eq!(health.sampled_at, sampled_at);
        assert_eq!(health.raw_log, raw);
        assert_eq!(health.critical_warning, 0x15);
        assert_eq!(health.temperature_kelvin, 321);
        assert_eq!(health.available_spare_pct, 98);
        assert_eq!(health.spare_threshold_pct, 10);
        assert_eq!(health.percentage_used, 7);
        assert_eq!(
            health.data_units_read,
            Some(0x0102_0304_0506_0708_1112_1314_1516_1718)
        );
        assert_eq!(
            health.data_units_written,
            Some(0x2122_2324_2526_2728_3132_3334_3536_3738)
        );
        assert_eq!(health.host_read_commands, 3);
        assert_eq!(health.host_write_commands, 4);
        assert_eq!(health.controller_busy_minutes, 5);
        assert_eq!(health.power_cycles, 6);
        assert_eq!(health.power_on_hours, 7);
        assert_eq!(health.unsafe_shutdowns, 8);
        assert_eq!(health.media_errors, 9);
        assert_eq!(health.error_log_entries, 10);
        assert_eq!(
            health.temperature_sensors_kelvin,
            [300, 301, 302, 303, 304, 305, 306, 307]
        );
    }

    #[test]
    fn zero_data_unit_counters_mean_not_reported() {
        let mut raw = fixed_log();
        set_u128(&mut raw, 32, 0);
        set_u128(&mut raw, 48, 0);
        let health = parse_smart_log(&raw, SmartEndpoint::NamespaceBlock, UNIX_EPOCH)
            .expect("otherwise valid SMART log");
        assert_eq!(health.data_units_read, None);
        assert_eq!(health.data_units_written, None);
    }

    #[test]
    fn reserved_percentage_values_are_rejected() {
        let mut raw = fixed_log();
        raw[3] = 101;
        assert!(matches!(
            parse_smart_log(&raw, SmartEndpoint::ControllerChar, UNIX_EPOCH),
            Err(SmartReadError::InvalidSmartLog {
                field: "available spare percentage"
            })
        ));

        let mut raw = fixed_log();
        raw[4] = 255;
        assert!(matches!(
            parse_smart_log(&raw, SmartEndpoint::ControllerChar, UNIX_EPOCH),
            Err(SmartReadError::InvalidSmartLog {
                field: "spare threshold percentage"
            })
        ));
    }

    #[test]
    fn device_hash_uses_serial_nul_and_configured_path() {
        let hash = device_hash_id("SERIAL0", Path::new("/dev/disk/by-id/nvme-test"));
        assert_eq!(
            hash,
            "eb6b1798867d2bb5423dd9284e3aed83a799e6262a91903eef32ca3b4650038b"
        );
        assert!(is_valid_hash_id(&hash));
        assert!(!is_valid_hash_id(&hash.to_uppercase()));
        assert!(!is_valid_hash_id(&hash[..63]));
        assert!(!is_valid_hash_id(&format!("{}g", &hash[..63])));
    }

    #[test]
    fn linux_device_number_is_decoded_without_truncation() {
        let device = (259_u64 << 8) | 4;
        assert_eq!(linux_device_major(device), Some(259));
        assert_eq!(linux_device_minor(device), Some(4));
    }

    #[test]
    fn error_display_escapes_paths_and_never_contains_serials() {
        let error = SmartReadError::SerialMismatch {
            path: PathBuf::from("/dev/disk/by-id/line\nbreak\t"),
        };
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(rendered.contains("\\n"));
            assert!(rendered.contains("\\t"));
            assert!(!rendered.contains("expected-secret"));
            assert!(!rendered.contains("actual-secret"));
        }
    }

    #[test]
    fn serial_comparison_normalizes_only_nvme_padding_and_the_sysfs_line_terminator() {
        assert!(sysfs_serial_matches(b"SERIAL0\n", "SERIAL0").expect("valid serial"));
        assert!(sysfs_serial_matches(b"SERIAL0     \n", "SERIAL0").expect("padded serial"));
        assert!(!sysfs_serial_matches(b"SERIAL 0\n", "SERIAL0").expect("internal space"));
        assert!(!sysfs_serial_matches(b"serial0\n", "SERIAL0").expect("letter case"));
        assert!(!sysfs_serial_matches(b"SERIAL0\t\n", "SERIAL0").expect("non-space suffix"));
        assert!(sysfs_serial_matches(b"SERIAL0", "SERIAL0").is_err());
        assert!(sysfs_serial_matches(b"\xff\n", "SERIAL0").is_err());
    }

    #[test]
    fn namespace_identifier_rejects_reserved_values() {
        assert!(is_namespace_id("1\n"));
        assert!(!is_namespace_id("0\n"));
        assert!(!is_namespace_id("4294967295\n"));
        assert!(!is_namespace_id("not-a-number\n"));
    }
}
