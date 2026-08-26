use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const CONF_PATH: &str = "/etc/nvme-disk-mon/ndm-cfg.toml";
pub(crate) const STATS_PATH: &str = "/etc/nvme-disk-mon/stats.db";
pub(crate) const OAUTH_TOKEN_PATH: &str = "/etc/nvme-disk-mon/oauth_token.json";
pub(crate) const SUPPORTED_CONFIG_SCHEMA: u32 = 1;

pub(crate) const CONF_FILE_CHECKSUM: &str = match option_env!("NDM_CONF_FILE_CHECKSUM") {
    Some(value) => value,
    None => "",
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) general: GeneralConfig,
    pub(crate) device: DeviceConfig,
    pub(crate) writer_rank: WriterRankConfig,
    pub(crate) mail: MailConfig,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeneralConfig {
    pub(crate) schema_version: u32,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceConfig {
    pub(crate) host: String,
    pub(crate) disk_list: Vec<DiskConfig>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiskConfig {
    pub(crate) label: String,
    pub(crate) serial: String,
    pub(crate) path: PathBuf,
    pub(crate) detect_window_hr: u64,
    pub(crate) w_delta_threshold_gib: f64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WriterRankConfig {
    pub(crate) rank_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum SmtpAuthMethod {
    #[serde(rename = "PLAIN")]
    Plain,
    #[serde(rename = "XOAUTH2")]
    Xoauth2,
    #[serde(rename = "OAUTHBEARER")]
    OauthBearer,
}

impl SmtpAuthMethod {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "PLAIN",
            Self::Xoauth2 => "XOAUTH2",
            Self::OauthBearer => "OAUTHBEARER",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum SmtpTlsMode {
    #[serde(rename = "STARTTLS_REQUIRED")]
    StartTlsRequired,
    #[serde(rename = "IMPLICIT_TLS")]
    ImplicitTls,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MailConfig {
    pub(crate) smtp_host: String,
    pub(crate) smtp_port: u16,
    pub(crate) smtp_auth_method: SmtpAuthMethod,
    pub(crate) smtp_tls_mode: SmtpTlsMode,
    pub(crate) send_as: String,
    pub(crate) send_to: Vec<String>,
    pub(crate) oauth: Option<OAuthConfig>,
    pub(crate) plain: Option<PlainConfig>,
}

#[derive(Clone, Deserialize)]
#[allow(clippy::struct_field_names)]
#[serde(deny_unknown_fields)]
pub(crate) struct OAuthConfig {
    pub(crate) oauth_metadata_url: String,
    pub(crate) oauth_scopes: Vec<String>,
    pub(crate) oauth_username: String,
    pub(crate) oauth_app_id: String,
    pub(crate) oauth_client_secret: SecretString,
    pub(crate) oauth_authorization_extra_params: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize)]
#[allow(clippy::struct_field_names)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlainConfig {
    pub(crate) plain_username: String,
    pub(crate) plain_app_password: SecretString,
}

pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl fmt::Debug for MailConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailConfig")
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("smtp_auth_method", &self.smtp_auth_method)
            .field("smtp_tls_mode", &self.smtp_tls_mode)
            .field("send_as", &"[REDACTED]")
            .field(
                "send_to",
                &format_args!("{} recipient(s)", self.send_to.len()),
            )
            .field("oauth", &self.oauth.as_ref().map(|_| "configured"))
            .field("plain", &self.plain.as_ref().map(|_| "configured"))
            .finish()
    }
}

pub(crate) enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    InvalidEmbeddedChecksum,
    ChecksumMismatch,
    Syntax {
        line: Option<usize>,
        column: Option<usize>,
    },
    UnsupportedConfigSchemaVersion {
        found: u32,
        supported: u32,
    },
    MissingField {
        field: &'static str,
    },
    InvalidValue {
        field: &'static str,
        rule: &'static str,
    },
    DuplicateDevice {
        first_index: usize,
        second_index: usize,
    },
    IncompatibleOptions {
        first: &'static str,
        second: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, .. } => {
                write!(
                    formatter,
                    "cannot read configuration {}",
                    log_safe_path(path)
                )
            }
            Self::InvalidEmbeddedChecksum => {
                formatter.write_str("embedded configuration checksum is invalid")
            }
            Self::ChecksumMismatch => {
                formatter.write_str("configuration checksum does not match the embedded value")
            }
            Self::Syntax { line, column } => match (line, column) {
                (Some(line), Some(column)) => {
                    write!(
                        formatter,
                        "configuration syntax error at line {line}, column {column}"
                    )
                }
                _ => formatter.write_str("configuration syntax error"),
            },
            Self::UnsupportedConfigSchemaVersion { found, supported } => write!(
                formatter,
                "unsupported configuration schema version {found}; supported version is {supported}"
            ),
            Self::MissingField { field } => {
                write!(formatter, "configuration field is missing: {field}")
            }
            Self::InvalidValue { field, rule } => {
                write!(formatter, "configuration field {field} must {rule}")
            }
            Self::DuplicateDevice {
                first_index,
                second_index,
            } => write!(
                formatter,
                "configuration devices {first_index} and {second_index} use the same by-id path"
            ),
            Self::IncompatibleOptions { first, second } => {
                write!(
                    formatter,
                    "configuration options {first} and {second} are incompatible"
                )
            }
        }
    }
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::InvalidEmbeddedChecksum
            | Self::ChecksumMismatch
            | Self::Syntax { .. }
            | Self::UnsupportedConfigSchemaVersion { .. }
            | Self::MissingField { .. }
            | Self::InvalidValue { .. }
            | Self::DuplicateDevice { .. }
            | Self::IncompatibleOptions { .. } => None,
        }
    }
}

pub(crate) fn load_config() -> Result<Config, ConfigError> {
    load_config_from(Path::new(CONF_PATH), CONF_FILE_CHECKSUM)
}

pub(crate) fn load_config_from(
    path: &Path,
    embedded_checksum: &str,
) -> Result<Config, ConfigError> {
    if !is_sha256_hex(embedded_checksum) {
        return Err(ConfigError::InvalidEmbeddedChecksum);
    }

    let bytes = std::fs::read(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let actual_checksum = sha256_hex(&bytes);
    if actual_checksum.as_bytes() != embedded_checksum.as_bytes() {
        return Err(ConfigError::ChecksumMismatch);
    }

    parse_and_validate(&bytes)
}

fn parse_and_validate(bytes: &[u8]) -> Result<Config, ConfigError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ConfigError::Syntax {
        line: None,
        column: None,
    })?;

    let value = toml::from_str::<toml::Value>(text)
        .map_err(|error| syntax_error(text, error.span().map(|span| span.start)))?;
    validate_required_fields(&value)?;

    let config = toml::from_str::<Config>(text)
        .map_err(|error| syntax_error(text, error.span().map(|span| span.start)))?;
    validate_config(&config)?;
    Ok(config)
}

fn syntax_error(text: &str, offset: Option<usize>) -> ConfigError {
    let Some(offset) = offset else {
        return ConfigError::Syntax {
            line: None,
            column: None,
        };
    };
    let prefix = &text[..offset.min(text.len())];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.chars().count() + 1, |(_, tail)| {
            tail.chars().count() + 1
        });
    ConfigError::Syntax {
        line: Some(line),
        column: Some(column),
    }
}

fn validate_required_fields(value: &toml::Value) -> Result<(), ConfigError> {
    for (path, name) in [
        (&["general", "schema_version"][..], "general.schema_version"),
        (&["device", "host"][..], "device.host"),
        (&["device", "disk_list"][..], "device.disk_list"),
        (
            &["writer_rank", "rank_length"][..],
            "writer_rank.rank_length",
        ),
        (&["mail", "smtp_host"][..], "mail.smtp_host"),
        (&["mail", "smtp_port"][..], "mail.smtp_port"),
        (&["mail", "smtp_auth_method"][..], "mail.smtp_auth_method"),
        (&["mail", "smtp_tls_mode"][..], "mail.smtp_tls_mode"),
        (&["mail", "send_as"][..], "mail.send_as"),
        (&["mail", "send_to"][..], "mail.send_to"),
    ] {
        if lookup_value(value, path).is_none() {
            return Err(ConfigError::MissingField { field: name });
        }
    }

    if let Some(disks) =
        lookup_value(value, &["device", "disk_list"]).and_then(toml::Value::as_array)
    {
        for disk in disks {
            for (key, name) in [
                ("label", "device.disk_list[].label"),
                ("serial", "device.disk_list[].serial"),
                ("path", "device.disk_list[].path"),
                ("detect_window_hr", "device.disk_list[].detect_window_hr"),
                (
                    "w_delta_threshold_gib",
                    "device.disk_list[].w_delta_threshold_gib",
                ),
            ] {
                if disk.get(key).is_none() {
                    return Err(ConfigError::MissingField { field: name });
                }
            }
        }
    }
    Ok(())
}

fn lookup_value<'a>(mut value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
    for component in path {
        value = value.get(*component)?;
    }
    Some(value)
}

#[allow(clippy::too_many_lines)]
fn validate_config(config: &Config) -> Result<(), ConfigError> {
    if config.general.schema_version != SUPPORTED_CONFIG_SCHEMA {
        return Err(ConfigError::UnsupportedConfigSchemaVersion {
            found: config.general.schema_version,
            supported: SUPPORTED_CONFIG_SCHEMA,
        });
    }
    if config.device.disk_list.is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "device.disk_list",
            rule: "contain at least one device",
        });
    }
    if config.device.host.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "device.host",
            rule: "not be empty",
        });
    }

    let mut paths = HashMap::<&Path, usize>::new();
    for (index, disk) in config.device.disk_list.iter().enumerate() {
        if disk.label.trim().is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "device.disk_list[].label",
                rule: "not be empty",
            });
        }
        if disk.serial.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "device.disk_list[].serial",
                rule: "not be empty",
            });
        }
        if !is_by_id_path(&disk.path) {
            return Err(ConfigError::InvalidValue {
                field: "device.disk_list[].path",
                rule: "be a direct path below /dev/disk/by-id",
            });
        }
        if let Some(first_index) = paths.insert(&disk.path, index) {
            return Err(ConfigError::DuplicateDevice {
                first_index,
                second_index: index,
            });
        }
        if disk.detect_window_hr == 0
            || disk
                .detect_window_hr
                .checked_mul(3_600_000)
                .and_then(|value| i64::try_from(value).ok())
                .is_none()
            || disk
                .detect_window_hr
                .checked_mul(60)
                .and_then(|value| u32::try_from(value).ok())
                .is_none()
        {
            return Err(ConfigError::InvalidValue {
                field: "device.disk_list[].detect_window_hr",
                rule: "be positive and convertible to milliseconds and ranking minutes",
            });
        }
        if !disk.w_delta_threshold_gib.is_finite() || disk.w_delta_threshold_gib < 0.0 {
            return Err(ConfigError::InvalidValue {
                field: "device.disk_list[].w_delta_threshold_gib",
                rule: "be finite and non-negative",
            });
        }
    }

    if config.writer_rank.rank_length == 0 || i64::try_from(config.writer_rank.rank_length).is_err()
    {
        return Err(ConfigError::InvalidValue {
            field: "writer_rank.rank_length",
            rule: "be positive and fit in a SQLite INTEGER",
        });
    }
    if config.mail.smtp_host.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "mail.smtp_host",
            rule: "not be empty",
        });
    }
    if config.mail.smtp_port == 0 {
        return Err(ConfigError::InvalidValue {
            field: "mail.smtp_port",
            rule: "be in the range 1 through 65535",
        });
    }
    if config.mail.send_as.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "mail.send_as",
            rule: "not be empty",
        });
    }
    if config.mail.send_to.is_empty()
        || config
            .mail
            .send_to
            .iter()
            .any(|recipient| recipient.trim().is_empty())
    {
        return Err(ConfigError::InvalidValue {
            field: "mail.send_to",
            rule: "contain only non-empty recipients",
        });
    }

    match config.mail.smtp_auth_method {
        SmtpAuthMethod::Plain => {
            if config.mail.oauth.is_some() {
                return Err(ConfigError::IncompatibleOptions {
                    first: "mail.smtp_auth_method=PLAIN",
                    second: "mail.oauth",
                });
            }
            let plain = config
                .mail
                .plain
                .as_ref()
                .ok_or(ConfigError::MissingField {
                    field: "mail.plain",
                })?;
            if plain.plain_username.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "mail.plain.plain_username",
                    rule: "not be empty",
                });
            }
            if plain.plain_app_password.expose_secret().is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "mail.plain.plain_app_password",
                    rule: "not be empty",
                });
            }
            Ok(())
        }
        SmtpAuthMethod::Xoauth2 | SmtpAuthMethod::OauthBearer => {
            if config.mail.plain.is_some() {
                return Err(ConfigError::IncompatibleOptions {
                    first: match config.mail.smtp_auth_method {
                        SmtpAuthMethod::Xoauth2 => "mail.smtp_auth_method=XOAUTH2",
                        SmtpAuthMethod::OauthBearer => "mail.smtp_auth_method=OAUTHBEARER",
                        SmtpAuthMethod::Plain => unreachable!(),
                    },
                    second: "mail.plain",
                });
            }
            let oauth = config
                .mail
                .oauth
                .as_ref()
                .ok_or(ConfigError::MissingField {
                    field: "mail.oauth",
                })?;
            if oauth.oauth_metadata_url.trim().is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "mail.oauth.oauth_metadata_url",
                    rule: "not be empty",
                });
            }
            if oauth.oauth_scopes.is_empty()
                || oauth
                    .oauth_scopes
                    .iter()
                    .any(|scope| scope.trim().is_empty())
            {
                return Err(ConfigError::InvalidValue {
                    field: "mail.oauth.oauth_scopes",
                    rule: "contain only non-empty scopes",
                });
            }
            if oauth.oauth_username.trim().is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "mail.oauth.oauth_username",
                    rule: "not be empty",
                });
            }
            if oauth.oauth_app_id.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "mail.oauth.oauth_app_id",
                    rule: "not be empty",
                });
            }
            if oauth.oauth_client_secret.expose_secret().is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: "mail.oauth.oauth_client_secret",
                    rule: "not be empty",
                });
            }
            if oauth.oauth_authorization_extra_params.keys().any(|key| {
                matches!(
                    key.as_str(),
                    "response_type"
                        | "client_id"
                        | "redirect_uri"
                        | "scope"
                        | "state"
                        | "code_challenge"
                        | "code_challenge_method"
                )
            }) {
                return Err(ConfigError::InvalidValue {
                    field: "mail.oauth.oauth_authorization_extra_params",
                    rule: "not override fixed OAuth authorization parameters",
                });
            }
            Ok(())
        }
    }
}

fn is_by_id_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::RootDir))
        && matches!(components.next(), Some(Component::Normal(value)) if value == "dev")
        && matches!(components.next(), Some(Component::Normal(value)) if value == "disk")
        && matches!(components.next(), Some(Component::Normal(value)) if value == "by-id")
        && matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn log_safe_path(path: &Path) -> String {
    let mut escaped = String::new();
    for byte in path.as_os_str().as_encoded_bytes().iter().take(512) {
        escaped.extend(std::ascii::escape_default(*byte).map(char::from));
    }
    if path.as_os_str().as_encoded_bytes().len() > 512 {
        escaped.push_str("...");
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const VALID: &str = r#"
[general]
schema_version = 1

[device]
host = "test-host"
disk_list = [
  { label = "Disk 0", serial = "SERIAL0", path = "/dev/disk/by-id/nvme-test", detect_window_hr = 3, w_delta_threshold_gib = 0.5 },
]

[writer_rank]
rank_length = 20

[mail]
smtp_host = "smtp.example.test"
smtp_port = 587
smtp_auth_method = "XOAUTH2"
smtp_tls_mode = "STARTTLS_REQUIRED"
send_as = "sender@example.test"
send_to = ["receiver@example.test"]

[mail.oauth]
oauth_metadata_url = "https://issuer.example.test/.well-known/oauth-authorization-server"
oauth_scopes = ["mail.send"]
oauth_username = "oauth-user@example.test"
oauth_app_id = "client-id"
oauth_client_secret = "client-secret"
oauth_authorization_extra_params = { access_type = "offline" }
"#;

    const OAUTH_SECTION: &str = r#"
[mail.oauth]
oauth_metadata_url = "https://issuer.example.test/.well-known/oauth-authorization-server"
oauth_scopes = ["mail.send"]
oauth_username = "oauth-user@example.test"
oauth_app_id = "client-id"
oauth_client_secret = "client-secret"
oauth_authorization_extra_params = { access_type = "offline" }
"#;

    const PLAIN_SECTION: &str = r#"
[mail.plain]
plain_username = "plain-user@example.test"
plain_app_password = "app-password"
"#;

    fn write_config(contents: &str) -> (tempfile::TempDir, PathBuf, String) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("ndm-cfg.toml");
        let mut file = std::fs::File::create(&path).expect("create config");
        file.write_all(contents.as_bytes()).expect("write config");
        let checksum = sha256_hex(contents.as_bytes());
        (directory, path, checksum)
    }

    #[test]
    fn valid_configuration_is_accepted() {
        let (_directory, path, checksum) = write_config(VALID);
        let config = load_config_from(&path, &checksum).expect("valid configuration");
        assert_eq!(config.general.schema_version, 1);
        assert_eq!(config.device.disk_list.len(), 1);
        assert_eq!(config.mail.smtp_auth_method, SmtpAuthMethod::Xoauth2);
        let oauth = config.mail.oauth.expect("OAuth configuration");
        assert_eq!(oauth.oauth_username, "oauth-user@example.test");
        assert_eq!(oauth.oauth_app_id, "client-id");
        assert_eq!(oauth.oauth_client_secret.expose_secret(), "client-secret");
    }

    #[test]
    fn packaging_template_matches_the_runtime_config_model() {
        let contents = include_str!("../packaging/config.example.toml")
            .replace(
                "oauth_metadata_url = \"\"",
                "oauth_metadata_url = \"https://issuer.example.test/.well-known/oauth-authorization-server\"",
            )
            .replace(
                "oauth_username = \"\"",
                "oauth_username = \"oauth-user@example.test\"",
            )
            .replace("oauth_app_id = \"\"", "oauth_app_id = \"client-id\"")
            .replace(
                "oauth_client_secret = \"\"",
                "oauth_client_secret = \"client-secret\"",
            );
        let (_directory, path, checksum) = write_config(&contents);
        load_config_from(&path, &checksum).expect("packaging template accepted by runtime");
    }

    #[test]
    fn embedded_checksum_and_mismatch_are_distinct() {
        let (_directory, path, checksum) = write_config(VALID);
        assert!(matches!(
            load_config_from(&path, "bad"),
            Err(ConfigError::InvalidEmbeddedChecksum)
        ));
        let other = format!("{}0", &checksum[..63]);
        assert!(matches!(
            load_config_from(&path, &other),
            Err(ConfigError::ChecksumMismatch)
        ));
    }

    #[test]
    fn representative_semantic_errors_are_rejected() {
        let cases = [
            (
                "schema version",
                VALID.replace("schema_version = 1", "schema_version = 2"),
            ),
            (
                "empty disk list",
                VALID.replace(
                    "disk_list = [\n  { label = \"Disk 0\", serial = \"SERIAL0\", path = \"/dev/disk/by-id/nvme-test\", detect_window_hr = 3, w_delta_threshold_gib = 0.5 },\n]",
                    "disk_list = []",
                ),
            ),
            (
                "wrong path",
                VALID.replace("/dev/disk/by-id/nvme-test", "/dev/nvme0n1"),
            ),
            (
                "duplicate path",
                VALID.replace(
                    "  { label = \"Disk 0\", serial = \"SERIAL0\", path = \"/dev/disk/by-id/nvme-test\", detect_window_hr = 3, w_delta_threshold_gib = 0.5 },",
                    "  { label = \"Disk 0\", serial = \"SERIAL0\", path = \"/dev/disk/by-id/nvme-test\", detect_window_hr = 3, w_delta_threshold_gib = 0.5 },\n  { label = \"Disk 1\", serial = \"SERIAL1\", path = \"/dev/disk/by-id/nvme-test\", detect_window_hr = 3, w_delta_threshold_gib = 0.5 },",
                ),
            ),
            (
                "zero window",
                VALID.replace("detect_window_hr = 3", "detect_window_hr = 0"),
            ),
            (
                "window conversion overflow",
                VALID.replace("detect_window_hr = 3", "detect_window_hr = 2562047789"),
            ),
            (
                "negative threshold",
                VALID.replace("w_delta_threshold_gib = 0.5", "w_delta_threshold_gib = -1.0"),
            ),
            (
                "non-finite NaN threshold",
                VALID.replace("w_delta_threshold_gib = 0.5", "w_delta_threshold_gib = nan"),
            ),
            (
                "non-finite infinite threshold",
                VALID.replace("w_delta_threshold_gib = 0.5", "w_delta_threshold_gib = inf"),
            ),
            (
                "zero rank",
                VALID.replace("rank_length = 20", "rank_length = 0"),
            ),
            (
                "zero port",
                VALID.replace("smtp_port = 587", "smtp_port = 0"),
            ),
            (
                "empty recipients",
                VALID.replace(
                    "send_to = [\"receiver@example.test\"]",
                    "send_to = []",
                ),
            ),
            (
                "empty sender",
                VALID.replace(
                    "send_as = \"sender@example.test\"",
                    "send_as = \"\"",
                ),
            ),
            (
                "missing OAuth section",
                VALID.replace(OAUTH_SECTION, "\n"),
            ),
            (
                "unsupported authentication method",
                VALID.replace("smtp_auth_method = \"XOAUTH2\"", "smtp_auth_method = \"LOGIN\""),
            ),
            (
                "unsupported TLS mode",
                VALID.replace(
                    "smtp_tls_mode = \"STARTTLS_REQUIRED\"",
                    "smtp_tls_mode = \"OPPORTUNISTIC\"",
                ),
            ),
        ];

        for (name, contents) in cases {
            let (_directory, path, checksum) = write_config(&contents);
            assert!(load_config_from(&path, &checksum).is_err(), "{name}");
        }
    }

    #[test]
    fn supported_authentication_and_tls_values_are_recognized() {
        let oauth_cases = [
            ("XOAUTH2", SmtpAuthMethod::Xoauth2),
            ("OAUTHBEARER", SmtpAuthMethod::OauthBearer),
        ];
        for (name, expected) in oauth_cases {
            let contents = VALID.replace(
                "smtp_auth_method = \"XOAUTH2\"",
                &format!("smtp_auth_method = \"{name}\""),
            );
            let (_directory, path, checksum) = write_config(&contents);
            let config = load_config_from(&path, &checksum).expect("supported OAuth method");
            assert_eq!(config.mail.smtp_auth_method, expected);
        }

        let plain = VALID
            .replace(
                "smtp_auth_method = \"XOAUTH2\"",
                "smtp_auth_method = \"PLAIN\"",
            )
            .replace(OAUTH_SECTION, PLAIN_SECTION);
        let (_directory, path, checksum) = write_config(&plain);
        let config = load_config_from(&path, &checksum).expect("supported PLAIN method");
        assert_eq!(config.mail.smtp_auth_method, SmtpAuthMethod::Plain);
        assert!(config.mail.oauth.is_none());
        let plain = config.mail.plain.expect("PLAIN configuration");
        assert_eq!(plain.plain_username, "plain-user@example.test");
        assert_eq!(plain.plain_app_password.expose_secret(), "app-password");

        for (name, expected) in [
            ("STARTTLS_REQUIRED", SmtpTlsMode::StartTlsRequired),
            ("IMPLICIT_TLS", SmtpTlsMode::ImplicitTls),
        ] {
            let contents = VALID.replace(
                "smtp_tls_mode = \"STARTTLS_REQUIRED\"",
                &format!("smtp_tls_mode = \"{name}\""),
            );
            let (_directory, path, checksum) = write_config(&contents);
            let config = load_config_from(&path, &checksum).expect("supported TLS mode");
            assert_eq!(config.mail.smtp_tls_mode, expected);
        }
    }

    #[test]
    fn oauth_extra_parameters_cannot_override_fixed_authorization_fields() {
        for reserved in [
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
        ] {
            let contents = VALID.replace(
                "oauth_authorization_extra_params = { access_type = \"offline\" }",
                &format!("oauth_authorization_extra_params = {{ {reserved} = \"override\" }}"),
            );
            let (_directory, path, checksum) = write_config(&contents);
            assert!(matches!(
                load_config_from(&path, &checksum),
                Err(ConfigError::InvalidValue {
                    field: "mail.oauth.oauth_authorization_extra_params",
                    ..
                })
            ));
        }
    }

    #[test]
    fn numeric_boundaries_are_checked_without_narrowing() {
        let maximum_port = VALID.replace("smtp_port = 587", "smtp_port = 65535");
        let (_directory, path, checksum) = write_config(&maximum_port);
        assert_eq!(
            load_config_from(&path, &checksum)
                .expect("maximum SMTP port")
                .mail
                .smtp_port,
            u16::MAX
        );

        let zero_threshold =
            VALID.replace("w_delta_threshold_gib = 0.5", "w_delta_threshold_gib = 0.0");
        let (_directory, path, checksum) = write_config(&zero_threshold);
        let threshold = load_config_from(&path, &checksum)
            .expect("zero threshold")
            .device
            .disk_list[0]
            .w_delta_threshold_gib;
        assert!(threshold.abs() < f64::EPSILON);

        let (_directory, path, checksum) = write_config(VALID);
        let mut config = load_config_from(&path, &checksum).expect("valid configuration");
        config.writer_rank.rank_length = (i64::MAX as u64) + 1;
        assert!(matches!(
            validate_config(&config),
            Err(ConfigError::InvalidValue {
                field: "writer_rank.rank_length",
                ..
            })
        ));
    }

    #[test]
    fn plain_rejects_oauth_section() {
        let plain = VALID.replace(
            "smtp_auth_method = \"XOAUTH2\"",
            "smtp_auth_method = \"PLAIN\"",
        );
        let (_directory, path, checksum) = write_config(&plain);
        assert!(matches!(
            load_config_from(&path, &checksum),
            Err(ConfigError::IncompatibleOptions { .. })
        ));
    }

    #[test]
    fn oauth_rejects_plain_section() {
        let oauth_with_plain = format!("{VALID}{PLAIN_SECTION}");
        let (_directory, path, checksum) = write_config(&oauth_with_plain);
        assert!(matches!(
            load_config_from(&path, &checksum),
            Err(ConfigError::IncompatibleOptions { .. })
        ));
    }

    #[test]
    fn legacy_credential_fields_are_rejected() {
        let legacy = VALID.replace(
            "send_as = \"sender@example.test\"",
            "smtp_cred_line_1 = \"client-id\"\nsmtp_cred_line_2 = \"client-secret\"\nsend_as = \"sender@example.test\"",
        );
        let (_directory, path, checksum) = write_config(&legacy);
        assert!(matches!(
            load_config_from(&path, &checksum),
            Err(ConfigError::Syntax { .. })
        ));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretString::new("do-not-print".to_owned());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("do-not-print"));
    }

    #[test]
    fn syntax_error_keeps_only_corrected_location() {
        let invalid = VALID.replace("smtp_port = 587", "smtp_port = [");
        let (_directory, path, checksum) = write_config(&invalid);
        let error = load_config_from(&path, &checksum)
            .err()
            .expect("invalid TOML");
        let ConfigError::Syntax {
            line: Some(line),
            column: Some(column),
        } = error
        else {
            panic!("expected located syntax error");
        };
        assert!(line > 1);
        assert!(column > 0);
    }

    #[test]
    fn syntax_error_chain_does_not_retain_configuration_credentials() {
        let invalid = VALID.replace(
            "oauth_client_secret = \"client-secret\"",
            "oauth_client_secret = \"credential-must-not-leak",
        );
        let (_directory, path, checksum) = write_config(&invalid);
        let error = load_config_from(&path, &checksum)
            .err()
            .expect("invalid credential line syntax");
        assert!(!error.to_string().contains("credential-must-not-leak"));
        assert!(!format!("{error:?}").contains("credential-must-not-leak"));
        let mut source = error.source();
        while let Some(current) = source {
            assert!(!current.to_string().contains("credential-must-not-leak"));
            source = current.source();
        }
    }

    #[test]
    fn paths_are_escaped_for_logs() {
        let error = ConfigError::Read {
            path: PathBuf::from("/tmp/line\nbreak\t"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(rendered.contains("\\n"));
            assert!(rendered.contains("\\t"));
            assert!(!rendered.contains('\n'));
            assert!(!rendered.contains("line\nbreak"));
        }
    }
}
