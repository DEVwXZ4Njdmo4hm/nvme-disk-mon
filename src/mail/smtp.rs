use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rustls::{ClientConfig, ClientConnection, StreamOwned, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{MailConfig, SecretString, SmtpTlsMode};

use super::{ErrorSource, MailError, PreparedMessage, SmtpReceipt, SmtpStage};

const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
const SMTP_MAX_REPLY_BYTES: usize = 100_000;
const SMTP_MAX_REPLY_LINE_BYTES: usize = 1_000;
const SMTP_EHLO_NAME: &str = "localhost";

pub(crate) enum SmtpAuth<'a> {
    Plain {
        username: &'a str,
        password: &'a SecretString,
    },
    Xoauth2 {
        username: &'a str,
        access_token: &'a SecretString,
    },
    OauthBearer {
        authzid: Option<&'a str>,
        access_token: &'a SecretString,
    },
}

impl SmtpAuth<'_> {
    const fn mechanism(&self) -> &'static str {
        match self {
            Self::Plain { .. } => "PLAIN",
            Self::Xoauth2 { .. } => "XOAUTH2",
            Self::OauthBearer { .. } => "OAUTHBEARER",
        }
    }

    const fn is_oauth(&self) -> bool {
        matches!(self, Self::Xoauth2 { .. } | Self::OauthBearer { .. })
    }
}

pub(crate) struct AuthenticatedSmtp {
    connection: SmtpConnection,
}

impl AuthenticatedSmtp {
    pub(crate) fn quit_best_effort(&mut self) {
        let _result = self.connection.command(SmtpStage::Quit, b"QUIT\r\n");
        self.connection.shutdown();
    }
}

pub(crate) async fn open_authenticated_smtp(
    cfg: &MailConfig,
    auth: SmtpAuth<'_>,
) -> Result<AuthenticatedSmtp, MailError> {
    open_authenticated_smtp_blocking(cfg, &auth)
}

pub(super) fn open_authenticated_smtp_blocking(
    cfg: &MailConfig,
    auth: &SmtpAuth<'_>,
) -> Result<AuthenticatedSmtp, MailError> {
    if cfg.smtp_auth_method.as_str() != auth.mechanism() {
        return Err(MailError::WrongAuthMethod);
    }

    let mut connection = SmtpConnection::open(cfg)?;
    connection.authenticate(cfg, auth)?;
    Ok(AuthenticatedSmtp { connection })
}

pub(crate) async fn submit_mail(
    smtp: &mut AuthenticatedSmtp,
    message: &PreparedMessage,
) -> Result<SmtpReceipt, MailError> {
    submit_mail_blocking(smtp, message)
}

pub(super) fn submit_mail_blocking(
    smtp: &mut AuthenticatedSmtp,
    message: &PreparedMessage,
) -> Result<SmtpReceipt, MailError> {
    let mail_from = format!("MAIL FROM:<{}>\r\n", message.envelope_from());
    let response = smtp
        .connection
        .command(SmtpStage::MailFrom, mail_from.as_bytes())?;
    require_positive_completion(response.code, SmtpStage::MailFrom, None)?;

    for (index, recipient) in message.envelope_recipients().iter().enumerate() {
        let command = format!("RCPT TO:<{recipient}>\r\n");
        let response = smtp
            .connection
            .command(SmtpStage::RcptTo, command.as_bytes())?;
        require_positive_completion(response.code, SmtpStage::RcptTo, Some(index))?;
    }

    let response = smtp
        .connection
        .command(SmtpStage::DataCommand, b"DATA\r\n")?;
    if response.code != 354 {
        return Err(MailError::SmtpRejected {
            stage: SmtpStage::DataCommand,
            code: response.code,
            recipient_index: None,
        });
    }

    let body = dot_stuff(message.formatted());
    smtp.connection
        .write_all(SmtpStage::DataBody, body.as_slice())?;

    write_data_terminator(&mut smtp.connection.stream)?;

    let response = smtp
        .connection
        .read_response(SmtpStage::FinalReply)
        .map_err(|error| match error {
            MailError::SmtpTransport { source, .. } => MailError::SubmissionOutcomeUnknown {
                source: Some(Box::new(source)),
            },
            other => other,
        })?;
    require_positive_completion(response.code, SmtpStage::FinalReply, None)?;

    let receipt = SmtpReceipt {
        code: response.code,
    };
    smtp.quit_best_effort();
    Ok(receipt)
}

struct SmtpConnection {
    stream: SmtpStream,
    capabilities: Capabilities,
}

impl SmtpConnection {
    fn open(cfg: &MailConfig) -> Result<Self, MailError> {
        let tls_config = platform_tls_config()?;
        Self::open_with_tls_config(cfg, tls_config)
    }

    fn open_with_tls_config(
        cfg: &MailConfig,
        tls_config: Arc<ClientConfig>,
    ) -> Result<Self, MailError> {
        let tcp = connect_tcp(&cfg.smtp_host, cfg.smtp_port)?;
        let stream = match cfg.smtp_tls_mode {
            SmtpTlsMode::ImplicitTls => SmtpStream::Tls(Box::new(open_tls(
                tcp,
                &cfg.smtp_host,
                Arc::clone(&tls_config),
            )?)),
            SmtpTlsMode::StartTlsRequired => SmtpStream::Plain(Some(tcp)),
        };
        let mut connection = Self {
            stream,
            capabilities: Capabilities::default(),
        };

        let greeting = connection.read_response(SmtpStage::Greeting)?;
        if greeting.code != 220 {
            return Err(MailError::SmtpRejected {
                stage: SmtpStage::Greeting,
                code: greeting.code,
                recipient_index: None,
            });
        }

        connection.ehlo()?;
        if cfg.smtp_tls_mode == SmtpTlsMode::StartTlsRequired {
            if !connection.capabilities.starttls {
                connection.shutdown();
                return Err(MailError::StartTlsUnavailable);
            }
            let response = connection.command(SmtpStage::StartTls, b"STARTTLS\r\n")?;
            if response.code != 220 {
                return Err(MailError::SmtpRejected {
                    stage: SmtpStage::StartTls,
                    code: response.code,
                    recipient_index: None,
                });
            }
            connection.upgrade_tls(&cfg.smtp_host, tls_config)?;
            connection.ehlo()?;
        }
        Ok(connection)
    }

    fn ehlo(&mut self) -> Result<(), MailError> {
        let command = format!("EHLO {SMTP_EHLO_NAME}\r\n");
        let response = self.command(SmtpStage::Ehlo, command.as_bytes())?;
        if response.code != 250 {
            return Err(MailError::SmtpRejected {
                stage: SmtpStage::Ehlo,
                code: response.code,
                recipient_index: None,
            });
        }
        self.capabilities = Capabilities::from_ehlo(&response.lines);
        Ok(())
    }

    fn upgrade_tls(&mut self, host: &str, tls_config: Arc<ClientConfig>) -> Result<(), MailError> {
        let tcp = match &mut self.stream {
            SmtpStream::Plain(stream) => stream.take().ok_or_else(|| MailError::TlsTransport {
                source: safe_source("SMTP plaintext stream was unavailable"),
            })?,
            SmtpStream::Tls(_) => {
                return Err(MailError::TlsTransport {
                    source: safe_source("SMTP connection was already encrypted"),
                });
            }
        };
        self.stream = SmtpStream::Tls(Box::new(open_tls(tcp, host, tls_config)?));
        Ok(())
    }

    fn authenticate(&mut self, cfg: &MailConfig, auth: &SmtpAuth<'_>) -> Result<(), MailError> {
        let mechanism = auth.mechanism();
        if !self.capabilities.auth.contains(mechanism) {
            self.shutdown();
            return Err(MailError::AuthMechanismUnavailable { mechanism });
        }

        let encoded = encode_auth(cfg, auth)?;
        let mut command =
            Zeroizing::new(String::with_capacity(mechanism.len() + encoded.len() + 9));
        command.push_str("AUTH ");
        command.push_str(mechanism);
        command.push(' ');
        command.push_str(encoded.as_str());
        command.push_str("\r\n");
        let mut response = self.command(SmtpStage::Auth, command.as_bytes())?;

        if response.code == 334 {
            if let Some(follow_up) = oauth_challenge_response(auth) {
                response = self.command(SmtpStage::Auth, follow_up)?;
            } else {
                // Some servers request the PLAIN initial response despite receiving one.
                // Repeating the same response completes that defined challenge exchange.
                command.zeroize();
                let mut repeated = Zeroizing::new(encoded.to_string());
                repeated.push_str("\r\n");
                response = self.command(SmtpStage::Auth, repeated.as_bytes())?;
            }
        }

        if response.code == 235 {
            return Ok(());
        }
        self.shutdown();
        if auth.is_oauth() {
            Err(MailError::OAuthAuthenticationRejected {
                code: response.code,
                refresh_attempted: false,
            })
        } else {
            Err(MailError::PlainAuthenticationRejected {
                code: response.code,
            })
        }
    }

    fn command(&mut self, stage: SmtpStage, bytes: &[u8]) -> Result<Response, MailError> {
        self.write_all(stage, bytes)?;
        self.read_response(stage)
    }

    fn write_all(&mut self, stage: SmtpStage, bytes: &[u8]) -> Result<(), MailError> {
        self.write_and_flush(bytes)
            .map_err(|source| MailError::SmtpTransport {
                stage,
                source: sanitize_io(&source, "SMTP write failed"),
            })
    }

    fn write_and_flush(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes)?;
        self.stream.flush()
    }

    fn read_response(&mut self, stage: SmtpStage) -> Result<Response, MailError> {
        read_response_from(&mut self.stream).map_err(|source| MailError::SmtpTransport {
            stage,
            source: sanitize_io(&source, "SMTP response read failed"),
        })
    }

    fn shutdown(&mut self) {
        self.stream.shutdown();
    }
}

fn oauth_challenge_response(auth: &SmtpAuth<'_>) -> Option<&'static [u8]> {
    match auth {
        SmtpAuth::Xoauth2 { .. } => Some(b"\r\n"),
        SmtpAuth::OauthBearer { .. } => Some(b"AQ==\r\n"),
        SmtpAuth::Plain { .. } => None,
    }
}

enum SmtpStream {
    Plain(Option<TcpStream>),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for SmtpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(Some(stream)) => stream.read(buffer),
            Self::Plain(None) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP stream is unavailable",
            )),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for SmtpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(Some(stream)) => stream.write(buffer),
            Self::Plain(None) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP stream is unavailable",
            )),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(Some(stream)) => stream.flush(),
            Self::Plain(None) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "SMTP stream is unavailable",
            )),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

impl SmtpStream {
    fn shutdown(&mut self) {
        match self {
            Self::Plain(Some(stream)) => {
                let _result = stream.shutdown(Shutdown::Both);
            }
            Self::Plain(None) => {}
            Self::Tls(stream) => {
                stream.conn.send_close_notify();
                let _result = stream.flush();
                let _result = stream.sock.shutdown(Shutdown::Both);
            }
        }
    }
}

#[derive(Default)]
struct Capabilities {
    starttls: bool,
    auth: BTreeSet<&'static str>,
}

impl Capabilities {
    fn from_ehlo(lines: &[String]) -> Self {
        let mut capabilities = Self::default();
        for line in lines {
            let mut words = line.split_ascii_whitespace();
            let Some(first) = words.next() else {
                continue;
            };
            if first.eq_ignore_ascii_case("STARTTLS") {
                capabilities.starttls = true;
            }
            if first.eq_ignore_ascii_case("AUTH") {
                for mechanism in words {
                    if mechanism.eq_ignore_ascii_case("PLAIN") {
                        capabilities.auth.insert("PLAIN");
                    } else if mechanism.eq_ignore_ascii_case("XOAUTH2") {
                        capabilities.auth.insert("XOAUTH2");
                    } else if mechanism.eq_ignore_ascii_case("OAUTHBEARER") {
                        capabilities.auth.insert("OAUTHBEARER");
                    }
                }
            }
        }
        capabilities
    }
}

struct Response {
    code: u16,
    lines: Vec<String>,
}

fn read_response_from(reader: &mut impl Read) -> io::Result<Response> {
    let mut total = 0usize;
    let mut code = None;
    let mut lines = Vec::new();

    loop {
        let line = read_smtp_line(reader, &mut total)?;
        if line.len() < 5 || !line.ends_with(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SMTP response framing",
            ));
        }
        let current_code = parse_code(&line[..3])?;
        if code.is_some_and(|expected| expected != current_code) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inconsistent SMTP response code",
            ));
        }
        code = Some(current_code);
        let separator = line[3];
        if separator != b'-' && separator != b' ' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SMTP response separator",
            ));
        }
        let text = std::str::from_utf8(&line[4..line.len() - 2])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-ASCII SMTP response"))?;
        lines.push(text.to_owned());
        if separator == b' ' {
            return Ok(Response {
                code: current_code,
                lines,
            });
        }
    }
}

fn read_smtp_line(reader: &mut impl Read, total: &mut usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let read = reader.read(&mut byte)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SMTP peer closed the connection",
            ));
        }
        line.push(byte[0]);
        *total = total.saturating_add(1);
        if line.len() > SMTP_MAX_REPLY_LINE_BYTES || *total > SMTP_MAX_REPLY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMTP response exceeded the size limit",
            ));
        }
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}

fn parse_code(bytes: &[u8]) -> io::Result<u16> {
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SMTP response code",
        ));
    }
    Ok(u16::from(bytes[0] - b'0') * 100
        + u16::from(bytes[1] - b'0') * 10
        + u16::from(bytes[2] - b'0'))
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, MailError> {
    let endpoint_host = host.to_owned();
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|source| MailError::SmtpConnect {
            host: endpoint_host.clone(),
            port,
            source: sanitize_io(&source, "SMTP address resolution failed"),
        })?;

    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, SMTP_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(SMTP_TIMEOUT))
                    .map_err(|source| MailError::SmtpConnect {
                        host: endpoint_host.clone(),
                        port,
                        source: sanitize_io(&source, "SMTP read timeout setup failed"),
                    })?;
                stream
                    .set_write_timeout(Some(SMTP_TIMEOUT))
                    .map_err(|source| MailError::SmtpConnect {
                        host: endpoint_host.clone(),
                        port,
                        source: sanitize_io(&source, "SMTP write timeout setup failed"),
                    })?;
                return Ok(stream);
            }
            Err(source) => last_error = Some(source),
        }
    }
    Err(MailError::SmtpConnect {
        host: endpoint_host,
        port,
        source: sanitize_io(
            &last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::AddrNotAvailable, "no SMTP address resolved")
            }),
            "SMTP connection failed",
        ),
    })
}

fn platform_tls_config() -> Result<Arc<ClientConfig>, MailError> {
    ClientConfig::with_platform_verifier()
        .map(Arc::new)
        .map_err(|_| MailError::TlsValidation {
            source: safe_source("cannot initialize the platform TLS verifier"),
        })
}

fn open_tls(
    stream: TcpStream,
    host: &str,
    config: Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, MailError> {
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| MailError::TlsValidation {
            source: safe_source("SMTP TLS server name is invalid"),
        })?;
    let connection =
        ClientConnection::new(config, server_name).map_err(|_| MailError::TlsValidation {
            source: safe_source("cannot initialize the SMTP TLS client"),
        })?;
    let mut tls = StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        if let Err(source) = tls.conn.complete_io(&mut tls.sock) {
            let safe = safe_source("SMTP TLS handshake failed");
            return if source.kind() == io::ErrorKind::InvalidData {
                Err(MailError::TlsValidation { source: safe })
            } else {
                Err(MailError::TlsTransport { source: safe })
            };
        }
    }
    Ok(tls)
}

fn encode_auth(cfg: &MailConfig, auth: &SmtpAuth<'_>) -> Result<Zeroizing<String>, MailError> {
    let payload = match auth {
        SmtpAuth::Plain { username, password } => {
            let mut payload = Zeroizing::new(String::with_capacity(
                username.len() + password.expose_secret().len() + 2,
            ));
            payload.push('\0');
            payload.push_str(username);
            payload.push('\0');
            payload.push_str(password.expose_secret());
            payload
        }
        SmtpAuth::Xoauth2 {
            username,
            access_token,
        } => {
            let mut payload = Zeroizing::new(String::with_capacity(
                username.len() + access_token.expose_secret().len() + 20,
            ));
            payload.push_str("user=");
            payload.push_str(username);
            payload.push_str("\x01auth=Bearer ");
            payload.push_str(access_token.expose_secret());
            payload.push_str("\x01\x01");
            payload
        }
        SmtpAuth::OauthBearer {
            authzid,
            access_token,
        } => {
            let authzid = authzid.map(gs2_escape).transpose()?;
            let mut payload = Zeroizing::new(String::with_capacity(
                authzid.as_ref().map_or(0, String::len)
                    + cfg.smtp_host.len()
                    + access_token.expose_secret().len()
                    + 48,
            ));
            payload.push_str("n,");
            if let Some(authzid) = authzid {
                payload.push_str("a=");
                payload.push_str(&authzid);
            }
            payload.push_str(",\x01host=");
            payload.push_str(&cfg.smtp_host);
            payload.push_str("\x01port=");
            payload.push_str(&cfg.smtp_port.to_string());
            payload.push_str("\x01auth=Bearer ");
            payload.push_str(access_token.expose_secret());
            payload.push_str("\x01\x01");
            payload
        }
    };
    Ok(Zeroizing::new(BASE64_STANDARD.encode(payload.as_bytes())))
}

fn gs2_escape(value: &str) -> Result<String, MailError> {
    if value.chars().any(char::is_control) {
        return Err(MailError::InvalidMessage {
            field: "OAuth authzid",
        });
    }
    Ok(value.replace('=', "=3D").replace(',', "=2C"))
}

fn dot_stuff(message: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(message.len() + 2);
    let mut line_start = true;
    for byte in message {
        if line_start && *byte == b'.' {
            output.push(b'.');
        }
        output.push(*byte);
        line_start = *byte == b'\n';
    }
    if !output.ends_with(b"\r\n") {
        output.extend_from_slice(b"\r\n");
    }
    output
}

fn write_data_terminator(writer: &mut impl Write) -> Result<(), MailError> {
    writer
        .write_all(b".\r\n")
        .map_err(|source| MailError::SmtpTransport {
            stage: SmtpStage::DataBody,
            source: sanitize_io(&source, "SMTP DATA terminator write failed"),
        })?;
    writer
        .flush()
        .map_err(|source| MailError::SubmissionOutcomeUnknown {
            source: Some(Box::new(sanitize_io(
                &source,
                "SMTP DATA terminator flush failed",
            ))),
        })
}

fn require_positive_completion(
    code: u16,
    stage: SmtpStage,
    recipient_index: Option<usize>,
) -> Result<(), MailError> {
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(MailError::SmtpRejected {
            stage,
            code,
            recipient_index,
        })
    }
}

pub(super) fn sanitize_io(source: &io::Error, message: &'static str) -> io::Error {
    io::Error::new(source.kind(), message)
}

#[derive(Debug)]
struct SafeSource(&'static str);

impl std::fmt::Display for SafeSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for SafeSource {}

fn safe_source(message: &'static str) -> ErrorSource {
    Box::new(SafeSource(message))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{BufRead, BufReader},
        net::TcpListener,
        thread,
    };

    use crate::config::{OAuthConfig, PlainConfig, SmtpAuthMethod};
    use rustls::{
        DigitallySignedStruct, Error as TlsError, ServerConfig, ServerConnection, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    };

    use super::*;

    const TEST_CERTIFICATE_CHAIN: &str = "-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUUg3keFcU1xXWK8BNVb1KynPulV8wCgYIKoZIzj0EAwIw
JjEkMCIGA1UEAwwbUnVzdGxzIFJvYnVzdCBSb290IC0gUnVuZyAyMCAXDTc1MDEw
MTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAhMR8wHQYDVQQDDBZyY2dlbiBzZWxm
IHNpZ25lZCBjZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEud6w4gtZ0xbw
J3E69SSMy5TZfdIifl9L5ZY+hgEe4UiUsBWS32f6Y5NR5Jo8FO1f6o13b3+FvVHR
EHCGdvppL6NoMGYwFQYDVR0RBA4wDIIKZm9vYmFyLmNvbTAdBgNVHSUEFjAUBggr
BgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFELvxbj5tD75n4pYFvJyr+c8qVEi
MA8GA1UdEwEB/wQFMAMBAQAwCgYIKoZIzj0EAwIDSAAwRQIhALxSSdUsrRFnwNMu
/doBqI8i8u5HdohVAheFTDwObkOMAiASSjULUtkWSD15u/7Sr01Wm9J1MpqW1pob
BVqU3CNRlA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBiTCCATCgAwIBAgIUHWiVYIvMMWoZEFYvSz46COf2FqowCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY
DzQwOTYwMTAxMDAwMDAwWjAmMSQwIgYDVQQDDBtSdXN0bHMgUm9idXN0IFJvb3Qg
LSBSdW5nIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATAOCcBD7dXjmAZ3te5
D47cCJ9ec93PWv7BKYIL826CJsKfXQOGrBTthLm77hXLhHu6uv8E5QXNLZpfowLQ
Do1ao0MwQTAPBgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRdza76r11Ok9vRmlg6
Nn/wL/N+jTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIFmZrXeK
hnfkahocvkhhNT3cDv1LWf6WBoFaCiBwZXFPAiARaKRiSCMG7PCHmSqFe82TBVmL
odHGogAVax1Dh/aYAA==
-----END CERTIFICATE-----
";
    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTbAQpfjAT46fgF4B
mP15n37woNG5ZNJmwcqsred/7tmhRANCAAS53rDiC1nTFvAncTr1JIzLlNl90iJ+
X0vllj6GAR7hSJSwFZLfZ/pjk1HkmjwU7V/qjXdvf4W9UdEQcIZ2+mkv
-----END PRIVATE KEY-----
";

    #[derive(Debug)]
    struct TestServerVerifier;

    impl ServerCertVerifier for TestServerVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, TlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }

    fn test_client_tls_config() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TestServerVerifier))
                .with_no_client_auth(),
        )
    }

    fn test_server_tls_config() -> Arc<ServerConfig> {
        let certificates = CertificateDer::pem_slice_iter(TEST_CERTIFICATE_CHAIN.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse test certificate chain");
        let private_key = PrivateKeyDer::from_pem_slice(TEST_PRIVATE_KEY.as_bytes())
            .expect("parse test private key");
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certificates, private_key)
                .expect("build test TLS server configuration"),
        )
    }

    #[derive(Default)]
    struct OneByteWriter {
        bytes: Vec<u8>,
    }

    impl Write for OneByteWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(1);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct FailAfterOneByte {
        wrote_one: bool,
    }

    impl Write for FailAfterOneByte {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.wrote_one {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlled write failure",
                ));
            }
            self.wrote_one = true;
            Ok(bytes.len().min(1))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct FailTerminatorFlush {
        bytes: Vec<u8>,
    }

    impl Write for FailTerminatorFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "controlled flush failure",
            ))
        }
    }

    fn plain_authenticated_pair() -> (AuthenticatedSmtp, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind scripted SMTP peer");
        let address = listener.local_addr().expect("scripted SMTP address");
        let client = TcpStream::connect(address).expect("connect scripted SMTP peer");
        let (server, _) = listener.accept().expect("accept scripted SMTP client");
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set scripted SMTP read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("set scripted SMTP write timeout");
        }
        let smtp = AuthenticatedSmtp {
            connection: SmtpConnection {
                stream: SmtpStream::Plain(Some(client)),
                capabilities: Capabilities::default(),
            },
        };
        (smtp, server)
    }

    fn receive_line<R: Read>(reader: &mut BufReader<R>) -> String {
        let mut line = String::new();
        let count = reader
            .read_line(&mut line)
            .expect("read scripted SMTP command");
        assert_ne!(count, 0, "SMTP client disconnected before the next command");
        line
    }

    fn send_reply<S: Read + Write>(reader: &mut BufReader<S>, reply: &[u8]) {
        reader
            .get_mut()
            .write_all(reply)
            .expect("write scripted SMTP reply");
        reader.get_mut().flush().expect("flush scripted SMTP reply");
    }

    fn complete_server_tls(stream: TcpStream) -> StreamOwned<ServerConnection, TcpStream> {
        let connection =
            ServerConnection::new(test_server_tls_config()).expect("create test TLS server");
        let mut tls = StreamOwned::new(connection, stream);
        while tls.conn.is_handshaking() {
            tls.conn
                .complete_io(&mut tls.sock)
                .expect("complete test TLS handshake");
        }
        tls
    }

    fn mail_config(auth: SmtpAuthMethod) -> MailConfig {
        let oauth =
            matches!(auth, SmtpAuthMethod::Xoauth2 | SmtpAuthMethod::OauthBearer).then(|| {
                OAuthConfig {
                    oauth_metadata_url:
                        "https://issuer.example.test/.well-known/oauth-authorization-server"
                            .to_owned(),
                    oauth_scopes: vec!["mail.send".to_owned()],
                    oauth_username: "oauth-user@example.test".to_owned(),
                    oauth_app_id: "client".to_owned(),
                    oauth_client_secret: SecretString::new("secret".to_owned()),
                    oauth_authorization_extra_params: BTreeMap::default(),
                }
            });
        let plain = (auth == SmtpAuthMethod::Plain).then(|| PlainConfig {
            plain_username: "plain-user@example.test".to_owned(),
            plain_app_password: SecretString::new("app-password".to_owned()),
        });
        MailConfig {
            smtp_host: "smtp.example.test".to_owned(),
            smtp_port: 587,
            smtp_auth_method: auth,
            smtp_tls_mode: SmtpTlsMode::StartTlsRequired,
            send_as: "sender@example.test".to_owned(),
            send_to: vec!["receiver@example.test".to_owned()],
            oauth,
            plain,
        }
    }

    fn decode(value: &str) -> String {
        String::from_utf8(BASE64_STANDARD.decode(value).expect("base64")).expect("UTF-8")
    }

    #[test]
    fn sasl_payloads_are_exact() {
        let plain_cfg = mail_config(SmtpAuthMethod::Plain);
        let plain = encode_auth(
            &plain_cfg,
            &SmtpAuth::Plain {
                username: "alice",
                password: &SecretString::new("password".to_owned()),
            },
        )
        .expect("PLAIN");
        assert_eq!(decode(&plain), "\0alice\0password");

        let oauth_cfg = mail_config(SmtpAuthMethod::Xoauth2);
        let token = SecretString::new("access-token".to_owned());
        let xoauth2 = encode_auth(
            &oauth_cfg,
            &SmtpAuth::Xoauth2 {
                username: "alice@example.test",
                access_token: &token,
            },
        )
        .expect("XOAUTH2");
        assert_eq!(
            decode(&xoauth2),
            "user=alice@example.test\x01auth=Bearer access-token\x01\x01"
        );

        let bearer_cfg = mail_config(SmtpAuthMethod::OauthBearer);
        let bearer = encode_auth(
            &bearer_cfg,
            &SmtpAuth::OauthBearer {
                authzid: Some("a,b=c"),
                access_token: &token,
            },
        )
        .expect("OAUTHBEARER");
        assert_eq!(
            decode(&bearer),
            "n,a=a=2Cb=3Dc,\x01host=smtp.example.test\x01port=587\x01auth=Bearer access-token\x01\x01"
        );
    }

    #[test]
    fn oauth_failure_challenge_responses_follow_each_sasl_mechanism() {
        let token = SecretString::new("access-token".to_owned());
        let password = SecretString::new("password".to_owned());
        assert_eq!(
            oauth_challenge_response(&SmtpAuth::Xoauth2 {
                username: "alice@example.test",
                access_token: &token,
            }),
            Some(b"\r\n".as_slice())
        );
        assert_eq!(
            oauth_challenge_response(&SmtpAuth::OauthBearer {
                authzid: Some("alice@example.test"),
                access_token: &token,
            }),
            Some(b"AQ==\r\n".as_slice())
        );
        assert_eq!(
            oauth_challenge_response(&SmtpAuth::Plain {
                username: "alice",
                password: &password,
            }),
            None
        );
    }

    #[test]
    fn ehlo_capabilities_are_case_insensitive_and_explicit() {
        let capabilities = Capabilities::from_ehlo(&[
            "example.test".to_owned(),
            "starttls".to_owned(),
            "AuTh PLAIN XOAUTH2 OAUTHBEARER LOGIN".to_owned(),
        ]);
        assert!(capabilities.starttls);
        assert!(capabilities.auth.contains("PLAIN"));
        assert!(capabilities.auth.contains("XOAUTH2"));
        assert!(capabilities.auth.contains("OAUTHBEARER"));
        assert!(!capabilities.auth.contains("LOGIN"));
    }

    #[test]
    fn implicit_tls_encrypts_the_session_before_smtp_greeting_and_authentication() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind implicit TLS peer");
        let address = listener.local_addr().expect("implicit TLS peer address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept implicit TLS client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set implicit TLS read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("set implicit TLS write timeout");
            let mut reader = BufReader::new(complete_server_tls(stream));
            send_reply(&mut reader, b"220 implicit TLS ready\r\n");
            let ehlo = receive_line(&mut reader);
            send_reply(&mut reader, b"250-local peer\r\n250 AUTH PLAIN\r\n");
            let auth = receive_line(&mut reader);
            send_reply(&mut reader, b"235 authenticated\r\n");
            (ehlo, auth)
        });

        let mut cfg = mail_config(SmtpAuthMethod::Plain);
        cfg.smtp_host = address.ip().to_string();
        cfg.smtp_port = address.port();
        cfg.smtp_tls_mode = SmtpTlsMode::ImplicitTls;
        let mut connection = SmtpConnection::open_with_tls_config(&cfg, test_client_tls_config())
            .expect("open implicit TLS SMTP session");
        let plain = cfg.plain.as_ref().expect("PLAIN configuration");
        connection
            .authenticate(
                &cfg,
                &SmtpAuth::Plain {
                    username: &plain.plain_username,
                    password: &plain.plain_app_password,
                },
            )
            .expect("authenticate over implicit TLS");
        connection.shutdown();

        let (ehlo, auth) = server.join().expect("join implicit TLS peer");
        assert_eq!(ehlo, "EHLO localhost\r\n");
        assert!(auth.starts_with("AUTH PLAIN "));
    }

    #[test]
    fn starttls_reissues_ehlo_and_sends_no_credentials_before_tls() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind STARTTLS peer");
        let address = listener.local_addr().expect("STARTTLS peer address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept STARTTLS client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set STARTTLS read timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .expect("set STARTTLS write timeout");
            let mut plaintext = BufReader::new(stream);
            send_reply(&mut plaintext, b"220 STARTTLS ready\r\n");
            let first_ehlo = receive_line(&mut plaintext);
            send_reply(
                &mut plaintext,
                b"250-local peer\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
            );
            let starttls = receive_line(&mut plaintext);
            send_reply(&mut plaintext, b"220 begin TLS\r\n");

            let mut encrypted = BufReader::new(complete_server_tls(plaintext.into_inner()));
            let second_ehlo = receive_line(&mut encrypted);
            send_reply(&mut encrypted, b"250-local peer\r\n250 AUTH PLAIN\r\n");
            let auth = receive_line(&mut encrypted);
            send_reply(&mut encrypted, b"235 authenticated\r\n");
            (first_ehlo, starttls, second_ehlo, auth)
        });

        let mut cfg = mail_config(SmtpAuthMethod::Plain);
        cfg.smtp_host = address.ip().to_string();
        cfg.smtp_port = address.port();
        cfg.smtp_tls_mode = SmtpTlsMode::StartTlsRequired;
        let mut connection = SmtpConnection::open_with_tls_config(&cfg, test_client_tls_config())
            .expect("open STARTTLS SMTP session");
        let plain = cfg.plain.as_ref().expect("PLAIN configuration");
        connection
            .authenticate(
                &cfg,
                &SmtpAuth::Plain {
                    username: &plain.plain_username,
                    password: &plain.plain_app_password,
                },
            )
            .expect("authenticate after STARTTLS");
        connection.shutdown();

        let (first_ehlo, starttls, second_ehlo, auth) = server.join().expect("join STARTTLS peer");
        assert_eq!(first_ehlo, "EHLO localhost\r\n");
        assert_eq!(starttls, "STARTTLS\r\n");
        assert_eq!(second_ehlo, "EHLO localhost\r\n");
        assert!(auth.starts_with("AUTH PLAIN "));
    }

    #[test]
    fn response_parser_handles_multiline_ehlo_without_retaining_codes() {
        let input = b"250-example.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n";
        let response = read_response_from(&mut &input[..]).expect("response");
        assert_eq!(response.code, 250);
        assert_eq!(response.lines, ["example.test", "STARTTLS", "AUTH PLAIN"]);
    }

    #[test]
    fn data_transparency_and_terminator_boundary_are_exact() {
        assert_eq!(
            dot_stuff(b".first\r\nnormal\r\n.second"),
            b"..first\r\nnormal\r\n..second\r\n"
        );
    }

    #[test]
    fn data_terminator_handles_short_writes_and_classifies_write_failure_as_transport() {
        let mut short_writer = OneByteWriter::default();
        write_data_terminator(&mut short_writer).expect("short writes must be completed");
        assert_eq!(short_writer.bytes, b".\r\n");

        let error = write_data_terminator(&mut FailAfterOneByte::default())
            .expect_err("partial terminator must fail");
        assert!(matches!(
            error,
            MailError::SmtpTransport {
                stage: SmtpStage::DataBody,
                ..
            }
        ));

        let mut flush_failure = FailTerminatorFlush::default();
        let error = write_data_terminator(&mut flush_failure)
            .expect_err("flush failure after the complete terminator is outcome-unknown");
        assert_eq!(flush_failure.bytes, b".\r\n");
        assert!(matches!(error, MailError::SubmissionOutcomeUnknown { .. }));
        assert!(!super::super::is_transient_smtp_error(&error));
    }

    #[tokio::test]
    async fn submission_uses_envelope_order_and_data_transparency() {
        let (mut smtp, server_stream) = plain_authenticated_pair();
        let server = thread::spawn(move || {
            let mut reader = BufReader::new(server_stream);
            let mut transcript = Vec::new();

            transcript.push(receive_line(&mut reader));
            send_reply(&mut reader, b"250 sender accepted\r\n");
            transcript.push(receive_line(&mut reader));
            send_reply(&mut reader, b"250 first recipient accepted\r\n");
            transcript.push(receive_line(&mut reader));
            send_reply(&mut reader, b"250 second recipient accepted\r\n");
            transcript.push(receive_line(&mut reader));
            send_reply(&mut reader, b"354 send message\r\n");
            loop {
                let line = receive_line(&mut reader);
                let complete = line == ".\r\n";
                transcript.push(line);
                if complete {
                    break;
                }
            }
            send_reply(&mut reader, b"250 queued\r\n");
            transcript.push(receive_line(&mut reader));
            send_reply(&mut reader, b"221 closing\r\n");
            transcript
        });

        let recipients = vec![
            "first@example.test".to_owned(),
            "second@example.test".to_owned(),
        ];
        let message = PreparedMessage::from_formatted(
            "sender@example.test",
            &recipients,
            b"Subject: scripted\r\n\r\n.first\r\nlast".to_vec(),
        )
        .expect("prepare scripted message");
        let receipt = submit_mail(&mut smtp, &message)
            .await
            .expect("submit scripted message");
        assert_eq!(receipt.code, 250);
        assert_eq!(
            server.join().expect("join scripted SMTP peer"),
            [
                "MAIL FROM:<sender@example.test>\r\n",
                "RCPT TO:<first@example.test>\r\n",
                "RCPT TO:<second@example.test>\r\n",
                "DATA\r\n",
                "Subject: scripted\r\n",
                "\r\n",
                "..first\r\n",
                "last\r\n",
                ".\r\n",
                "QUIT\r\n",
            ]
        );
    }

    #[tokio::test]
    async fn missing_reply_after_complete_terminator_has_unknown_outcome() {
        let (mut smtp, server_stream) = plain_authenticated_pair();
        let server = thread::spawn(move || {
            let mut reader = BufReader::new(server_stream);
            assert_eq!(
                receive_line(&mut reader),
                "MAIL FROM:<sender@example.test>\r\n"
            );
            send_reply(&mut reader, b"250 sender accepted\r\n");
            assert_eq!(
                receive_line(&mut reader),
                "RCPT TO:<receiver@example.test>\r\n"
            );
            send_reply(&mut reader, b"250 recipient accepted\r\n");
            assert_eq!(receive_line(&mut reader), "DATA\r\n");
            send_reply(&mut reader, b"354 send message\r\n");
            loop {
                if receive_line(&mut reader) == ".\r\n" {
                    break;
                }
            }
        });

        let recipients = vec!["receiver@example.test".to_owned()];
        let message = PreparedMessage::from_formatted(
            "sender@example.test",
            &recipients,
            b"Subject: scripted\r\n\r\nbody".to_vec(),
        )
        .expect("prepare scripted message");
        let error = submit_mail(&mut smtp, &message)
            .await
            .expect_err("final response is intentionally missing");
        server.join().expect("join scripted SMTP peer");
        assert!(matches!(error, MailError::SubmissionOutcomeUnknown { .. }));
        assert!(!super::super::is_transient_smtp_error(&error));
    }

    #[test]
    fn malformed_response_is_rejected_without_using_reply_text() {
        let input = b"250-first\r\n550 final\r\n";
        let error = read_response_from(&mut &input[..])
            .err()
            .expect("inconsistent response");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!error.to_string().contains("final"));
    }
}
