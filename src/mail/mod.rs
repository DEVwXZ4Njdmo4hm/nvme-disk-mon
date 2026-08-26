mod oauth;
mod smtp;

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use lettre::{Message, message::Mailbox};

use crate::config::{MailConfig, SmtpAuthMethod};

use oauth::acquire_smtp_oauth_token_blocking;
pub(crate) use oauth::{OAuthAccessToken, OAuthTokenMode, acquire_smtp_oauth_token};
pub(crate) use smtp::{AuthenticatedSmtp, SmtpAuth, open_authenticated_smtp, submit_mail};
use smtp::{open_authenticated_smtp_blocking, submit_mail_blocking};

pub(crate) type ErrorSource = Box<dyn Error + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SmtpStage {
    #[allow(dead_code)]
    Connect,
    Greeting,
    Ehlo,
    StartTls,
    Auth,
    MailFrom,
    RcptTo,
    DataCommand,
    DataBody,
    FinalReply,
    Quit,
}

impl SmtpStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Greeting => "greeting",
            Self::Ehlo => "EHLO",
            Self::StartTls => "STARTTLS",
            Self::Auth => "AUTH",
            Self::MailFrom => "MAIL FROM",
            Self::RcptTo => "RCPT TO",
            Self::DataCommand => "DATA command",
            Self::DataBody => "DATA body",
            Self::FinalReply => "final DATA reply",
            Self::Quit => "QUIT",
        }
    }
}

pub(crate) enum MailError {
    WrongAuthMethod,
    ReauthorizationRequired,
    OAuthMetadataInvalid {
        field: &'static str,
    },
    UnsupportedTokenEndpointAuth {
        method: String,
    },
    OAuthStateMismatch,
    AuthorizationDenied {
        error_code: String,
    },
    OAuthTransport {
        stage: &'static str,
        source: ErrorSource,
    },
    OAuthServerRejected {
        status: u16,
        error_code: Option<String>,
    },
    TokenResponseInvalid {
        field: &'static str,
    },
    TokenCacheRead {
        path: PathBuf,
        source: std::io::Error,
    },
    TokenCacheWrite {
        path: PathBuf,
        source: std::io::Error,
    },
    TokenCacheInvalid,
    TokenCacheSecurity {
        path: PathBuf,
        rule: &'static str,
    },
    SmtpConnect {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    TlsValidation {
        source: ErrorSource,
    },
    TlsTransport {
        source: ErrorSource,
    },
    StartTlsUnavailable,
    AuthMechanismUnavailable {
        mechanism: &'static str,
    },
    OAuthAuthenticationRejected {
        code: u16,
        refresh_attempted: bool,
    },
    PlainAuthenticationRejected {
        code: u16,
    },
    SmtpTransport {
        stage: SmtpStage,
        source: std::io::Error,
    },
    SmtpRejected {
        stage: SmtpStage,
        code: u16,
        recipient_index: Option<usize>,
    },
    SubmissionOutcomeUnknown {
        source: Option<ErrorSource>,
    },
    InvalidMessage {
        field: &'static str,
    },
}

impl fmt::Display for MailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongAuthMethod => formatter.write_str("mail authentication method mismatch"),
            Self::ReauthorizationRequired => {
                formatter.write_str("mail OAuth authorization must be completed again")
            }
            Self::OAuthMetadataInvalid { field } => {
                write!(formatter, "OAuth metadata field is invalid: {field}")
            }
            Self::UnsupportedTokenEndpointAuth { method } => write!(
                formatter,
                "OAuth token endpoint authentication method is unsupported: {}",
                log_safe_dynamic(method)
            ),
            Self::OAuthStateMismatch => {
                formatter.write_str("OAuth authorization callback state did not match")
            }
            Self::AuthorizationDenied { error_code } => write!(
                formatter,
                "OAuth authorization was denied ({})",
                log_safe_dynamic(error_code)
            ),
            Self::OAuthTransport { stage, .. } => {
                write!(formatter, "OAuth transport failed during {stage}")
            }
            Self::OAuthServerRejected { status, error_code } => {
                fmt_oauth_rejection(formatter, *status, error_code.as_deref())
            }
            Self::TokenResponseInvalid { field } => {
                write!(formatter, "OAuth token response field is invalid: {field}")
            }
            Self::TokenCacheRead { path, .. } => {
                write!(
                    formatter,
                    "cannot read OAuth token cache {}",
                    log_safe_path(path)
                )
            }
            Self::TokenCacheWrite { path, .. } => {
                write!(
                    formatter,
                    "cannot write OAuth token cache {}",
                    log_safe_path(path)
                )
            }
            Self::TokenCacheInvalid => formatter.write_str("OAuth token cache is invalid"),
            Self::TokenCacheSecurity { path, rule } => write!(
                formatter,
                "OAuth token cache {} must {rule}",
                log_safe_path(path)
            ),
            Self::SmtpConnect { host, port, .. } => write!(
                formatter,
                "cannot connect to SMTP endpoint {}:{port}",
                log_safe_dynamic(host)
            ),
            Self::TlsValidation { .. } => formatter.write_str("SMTP TLS peer validation failed"),
            Self::TlsTransport { .. } => formatter.write_str("SMTP TLS transport failed"),
            Self::StartTlsUnavailable => {
                formatter.write_str("SMTP server does not offer required STARTTLS")
            }
            Self::AuthMechanismUnavailable { mechanism } => write!(
                formatter,
                "SMTP server does not offer configured AUTH mechanism {mechanism}"
            ),
            Self::OAuthAuthenticationRejected {
                code,
                refresh_attempted,
            } => write!(
                formatter,
                "SMTP OAuth authentication was rejected (code={code}, refresh_attempted={refresh_attempted})"
            ),
            Self::PlainAuthenticationRejected { code } => write!(
                formatter,
                "SMTP PLAIN authentication was rejected (code={code})"
            ),
            Self::SmtpTransport { stage, .. } => {
                write!(formatter, "SMTP transport failed during {}", stage.as_str())
            }
            Self::SmtpRejected {
                stage,
                code,
                recipient_index,
            } => fmt_smtp_rejection(formatter, *stage, *code, *recipient_index),
            Self::SubmissionOutcomeUnknown { .. } => formatter.write_str(
                "SMTP submission outcome is unknown after the complete DATA terminator was sent",
            ),
            Self::InvalidMessage { field } => {
                write!(formatter, "mail message field is invalid: {field}")
            }
        }
    }
}

impl fmt::Debug for MailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

fn fmt_oauth_rejection(
    formatter: &mut fmt::Formatter<'_>,
    status: u16,
    error_code: Option<&str>,
) -> fmt::Result {
    write!(
        formatter,
        "OAuth server rejected the request (HTTP {status}"
    )?;
    if let Some(error_code) = error_code {
        write!(formatter, ", code={}", log_safe_dynamic(error_code))?;
    }
    formatter.write_str(")")
}

fn fmt_smtp_rejection(
    formatter: &mut fmt::Formatter<'_>,
    stage: SmtpStage,
    code: u16,
    recipient_index: Option<usize>,
) -> fmt::Result {
    write!(
        formatter,
        "SMTP server rejected {} (code={code}",
        stage.as_str()
    )?;
    if let Some(index) = recipient_index {
        write!(formatter, ", recipient_index={index}")?;
    }
    formatter.write_str(")")
}

impl Error for MailError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OAuthTransport { source, .. }
            | Self::TlsValidation { source }
            | Self::TlsTransport { source }
            | Self::SubmissionOutcomeUnknown {
                source: Some(source),
            } => Some(source.as_ref()),
            Self::TokenCacheRead { source, .. }
            | Self::TokenCacheWrite { source, .. }
            | Self::SmtpConnect { source, .. }
            | Self::SmtpTransport { source, .. } => Some(source),
            Self::WrongAuthMethod
            | Self::ReauthorizationRequired
            | Self::OAuthMetadataInvalid { .. }
            | Self::UnsupportedTokenEndpointAuth { .. }
            | Self::OAuthStateMismatch
            | Self::AuthorizationDenied { .. }
            | Self::OAuthServerRejected { .. }
            | Self::TokenResponseInvalid { .. }
            | Self::TokenCacheInvalid
            | Self::TokenCacheSecurity { .. }
            | Self::StartTlsUnavailable
            | Self::AuthMechanismUnavailable { .. }
            | Self::OAuthAuthenticationRejected { .. }
            | Self::PlainAuthenticationRejected { .. }
            | Self::SmtpRejected { .. }
            | Self::SubmissionOutcomeUnknown { source: None }
            | Self::InvalidMessage { .. } => None,
        }
    }
}

pub(crate) struct PreparedMessage {
    envelope_from: String,
    envelope_recipients: Vec<String>,
    formatted: Vec<u8>,
}

impl PreparedMessage {
    pub(crate) fn text(
        envelope_from: &str,
        envelope_recipients: &[String],
        subject: &str,
        body: &str,
    ) -> Result<Self, MailError> {
        let from = parse_mailbox(envelope_from, "envelope_from")?;
        if envelope_recipients.is_empty() {
            return Err(MailError::InvalidMessage {
                field: "envelope_recipients",
            });
        }

        let mut builder = Message::builder().from(from).subject(subject);
        for recipient in envelope_recipients {
            builder = builder.to(parse_mailbox(recipient, "envelope_recipient")?);
        }
        let message = builder
            .body(body.to_owned())
            .map_err(|_| MailError::InvalidMessage {
                field: "RFC 5322 message",
            })?;

        Self::from_formatted(envelope_from, envelope_recipients, message.formatted())
    }

    pub(crate) fn from_formatted(
        envelope_from: &str,
        envelope_recipients: &[String],
        formatted: Vec<u8>,
    ) -> Result<Self, MailError> {
        let envelope_from = parse_mailbox(envelope_from, "envelope_from")?
            .email
            .to_string();
        if envelope_recipients.is_empty() {
            return Err(MailError::InvalidMessage {
                field: "envelope_recipients",
            });
        }
        let envelope_recipients = envelope_recipients
            .iter()
            .map(|recipient| {
                parse_mailbox(recipient, "envelope_recipient")
                    .map(|mailbox| mailbox.email.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if formatted.is_empty() {
            return Err(MailError::InvalidMessage {
                field: "RFC 5322 message",
            });
        }
        Ok(Self {
            envelope_from,
            envelope_recipients,
            formatted,
        })
    }

    pub(super) fn envelope_from(&self) -> &str {
        &self.envelope_from
    }

    pub(super) fn envelope_recipients(&self) -> &[String] {
        &self.envelope_recipients
    }

    pub(super) fn formatted(&self) -> &[u8] {
        &self.formatted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SmtpReceipt {
    pub(crate) code: u16,
}

const TRANSIENT_RETRY_LIMIT: usize = 2;
const RETRY_BASE_DELAY: Duration = Duration::from_millis(200);

pub(crate) async fn authorize_mail(cfg: &MailConfig) -> Result<(), MailError> {
    if cfg.smtp_auth_method == SmtpAuthMethod::Plain {
        return Err(MailError::WrongAuthMethod);
    }
    let _token = acquire_smtp_oauth_token(cfg, OAuthTokenMode::InteractiveAuthorize).await?;
    Ok(())
}

pub(crate) async fn validate_mail(cfg: &MailConfig) -> Result<(), MailError> {
    match cfg.smtp_auth_method {
        SmtpAuthMethod::Plain => validate_plain_mail(cfg).await,
        SmtpAuthMethod::Xoauth2 | SmtpAuthMethod::OauthBearer => validate_oauth_mail(cfg).await,
    }
}

pub(crate) async fn test_send_mail(cfg: &MailConfig) -> Result<SmtpReceipt, MailError> {
    let message = PreparedMessage::text(
        &cfg.send_as,
        &cfg.send_to,
        "NVMe-Disk-Mon test message",
        "NVMe-Disk-Mon successfully authenticated and submitted this test message.",
    )?;
    send_mail(cfg, &message).await
}

pub(crate) async fn send_mail(
    cfg: &MailConfig,
    message: &PreparedMessage,
) -> Result<SmtpReceipt, MailError> {
    match cfg.smtp_auth_method {
        SmtpAuthMethod::Plain => send_plain_mail(cfg, message).await,
        SmtpAuthMethod::Xoauth2 | SmtpAuthMethod::OauthBearer => {
            send_oauth_mail(cfg, message).await
        }
    }
}

#[allow(clippy::unused_async)]
pub(crate) async fn send_oauth_mail(
    cfg: &MailConfig,
    message: &PreparedMessage,
) -> Result<SmtpReceipt, MailError> {
    send_oauth_mail_with(
        |mode| acquire_smtp_oauth_token_blocking(cfg, mode),
        |token| open_with_oauth_token_blocking(cfg, token),
        |smtp| submit_mail_blocking(smtp, message),
    )
}

fn send_oauth_mail_with<Token, Session>(
    mut acquire: impl FnMut(OAuthTokenMode) -> Result<Token, MailError>,
    mut open: impl FnMut(&Token) -> Result<Session, MailError>,
    mut submit: impl FnMut(&mut Session) -> Result<SmtpReceipt, MailError>,
) -> Result<SmtpReceipt, MailError> {
    let mut token = acquire(OAuthTokenMode::Runtime)?;
    let mut refresh_attempted = false;
    let mut transient_retries = 0;

    loop {
        let result = match open(&token) {
            Ok(mut smtp) => submit(&mut smtp),
            Err(MailError::OAuthAuthenticationRejected { code: 535, .. }) if !refresh_attempted => {
                tracing::warn!(
                    smtp_status = 535,
                    "SMTP OAuth authentication was rejected; refreshing the token and retrying once"
                );
                token = acquire(OAuthTokenMode::ForceRefresh)?;
                refresh_attempted = true;
                continue;
            }
            Err(error) => Err(error),
        };

        let result = if refresh_attempted {
            result.map_err(mark_refresh_attempted)
        } else {
            result
        };
        match result {
            Err(error)
                if is_transient_smtp_error(&error) && transient_retries < TRANSIENT_RETRY_LIMIT =>
            {
                tracing::warn!(
                    error = %error,
                    next_attempt = transient_retries + 2,
                    maximum_attempts = TRANSIENT_RETRY_LIMIT + 1,
                    "transient SMTP failure; retrying message submission"
                );
                wait_before_retry(transient_retries);
                transient_retries += 1;
            }
            other => return other,
        }
    }
}

pub(crate) async fn authenticate_plain(cfg: &MailConfig) -> Result<AuthenticatedSmtp, MailError> {
    let plain = cfg.plain.as_ref().ok_or(MailError::WrongAuthMethod)?;
    open_authenticated_smtp(
        cfg,
        SmtpAuth::Plain {
            username: &plain.plain_username,
            password: &plain.plain_app_password,
        },
    )
    .await
}

pub(crate) async fn send_plain_mail(
    cfg: &MailConfig,
    message: &PreparedMessage,
) -> Result<SmtpReceipt, MailError> {
    let mut transient_retries = 0;
    loop {
        let result = match authenticate_plain(cfg).await {
            Ok(mut smtp) => submit_mail(&mut smtp, message).await,
            Err(error) => Err(error),
        };
        match result {
            Err(error)
                if is_transient_smtp_error(&error) && transient_retries < TRANSIENT_RETRY_LIMIT =>
            {
                tracing::warn!(
                    error = %error,
                    next_attempt = transient_retries + 2,
                    maximum_attempts = TRANSIENT_RETRY_LIMIT + 1,
                    "transient SMTP failure; retrying message submission"
                );
                wait_before_retry(transient_retries);
                transient_retries += 1;
            }
            other => return other,
        }
    }
}

async fn validate_oauth_mail(cfg: &MailConfig) -> Result<(), MailError> {
    let mut token = acquire_smtp_oauth_token(cfg, OAuthTokenMode::Runtime).await?;
    let mut refresh_attempted = false;
    let mut transient_retries = 0;

    loop {
        match open_with_oauth_token(cfg, &token).await {
            Ok(mut smtp) => {
                smtp.quit_best_effort();
                return Ok(());
            }
            Err(MailError::OAuthAuthenticationRejected { code: 535, .. }) if !refresh_attempted => {
                tracing::warn!(
                    smtp_status = 535,
                    "SMTP OAuth authentication was rejected; refreshing the token and retrying once"
                );
                token = acquire_smtp_oauth_token(cfg, OAuthTokenMode::ForceRefresh).await?;
                refresh_attempted = true;
            }
            Err(error) => {
                let error = if refresh_attempted {
                    mark_refresh_attempted(error)
                } else {
                    error
                };
                if !is_transient_smtp_error(&error) || transient_retries == TRANSIENT_RETRY_LIMIT {
                    return Err(error);
                }
                tracing::warn!(
                    error = %error,
                    next_attempt = transient_retries + 2,
                    maximum_attempts = TRANSIENT_RETRY_LIMIT + 1,
                    "transient SMTP failure; retrying mail validation"
                );
                wait_before_retry(transient_retries);
                transient_retries += 1;
            }
        }
    }
}

async fn validate_plain_mail(cfg: &MailConfig) -> Result<(), MailError> {
    let mut transient_retries = 0;
    loop {
        match authenticate_plain(cfg).await {
            Ok(mut smtp) => {
                smtp.quit_best_effort();
                return Ok(());
            }
            Err(error)
                if is_transient_smtp_error(&error) && transient_retries < TRANSIENT_RETRY_LIMIT =>
            {
                tracing::warn!(
                    error = %error,
                    next_attempt = transient_retries + 2,
                    maximum_attempts = TRANSIENT_RETRY_LIMIT + 1,
                    "transient SMTP failure; retrying mail validation"
                );
                wait_before_retry(transient_retries);
                transient_retries += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn open_with_oauth_token(
    cfg: &MailConfig,
    token: &OAuthAccessToken,
) -> Result<AuthenticatedSmtp, MailError> {
    let auth = oauth_smtp_auth(cfg, token)?;
    open_authenticated_smtp(cfg, auth).await
}

fn open_with_oauth_token_blocking(
    cfg: &MailConfig,
    token: &OAuthAccessToken,
) -> Result<AuthenticatedSmtp, MailError> {
    let auth = oauth_smtp_auth(cfg, token)?;
    open_authenticated_smtp_blocking(cfg, &auth)
}

fn oauth_smtp_auth<'a>(
    cfg: &'a MailConfig,
    token: &'a OAuthAccessToken,
) -> Result<SmtpAuth<'a>, MailError> {
    let oauth = cfg.oauth.as_ref().ok_or(MailError::WrongAuthMethod)?;
    let auth = match cfg.smtp_auth_method {
        SmtpAuthMethod::Xoauth2 => SmtpAuth::Xoauth2 {
            username: &oauth.oauth_username,
            access_token: token.secret(),
        },
        SmtpAuthMethod::OauthBearer => SmtpAuth::OauthBearer {
            authzid: Some(&oauth.oauth_username),
            access_token: token.secret(),
        },
        SmtpAuthMethod::Plain => return Err(MailError::WrongAuthMethod),
    };
    Ok(auth)
}

fn mark_refresh_attempted(error: MailError) -> MailError {
    match error {
        MailError::OAuthAuthenticationRejected { code, .. } => {
            MailError::OAuthAuthenticationRejected {
                code,
                refresh_attempted: true,
            }
        }
        other => other,
    }
}

fn is_transient_smtp_error(error: &MailError) -> bool {
    match error {
        MailError::SmtpConnect { .. }
        | MailError::TlsTransport { .. }
        | MailError::SmtpTransport { .. } => true,
        MailError::OAuthAuthenticationRejected { code, .. }
        | MailError::PlainAuthenticationRejected { code }
        | MailError::SmtpRejected { code, .. } => (400..500).contains(code),
        MailError::WrongAuthMethod
        | MailError::ReauthorizationRequired
        | MailError::OAuthMetadataInvalid { .. }
        | MailError::UnsupportedTokenEndpointAuth { .. }
        | MailError::OAuthStateMismatch
        | MailError::AuthorizationDenied { .. }
        | MailError::OAuthTransport { .. }
        | MailError::OAuthServerRejected { .. }
        | MailError::TokenResponseInvalid { .. }
        | MailError::TokenCacheRead { .. }
        | MailError::TokenCacheWrite { .. }
        | MailError::TokenCacheInvalid
        | MailError::TokenCacheSecurity { .. }
        | MailError::TlsValidation { .. }
        | MailError::StartTlsUnavailable
        | MailError::AuthMechanismUnavailable { .. }
        | MailError::SubmissionOutcomeUnknown { .. }
        | MailError::InvalidMessage { .. } => false,
    }
}

fn wait_before_retry(retry_index: usize) {
    let shift = u32::try_from(retry_index).unwrap_or(31).min(31);
    thread::sleep(RETRY_BASE_DELAY.saturating_mul(1_u32 << shift));
}

fn parse_mailbox(value: &str, field: &'static str) -> Result<Mailbox, MailError> {
    value
        .parse::<Mailbox>()
        .map_err(|_| MailError::InvalidMessage { field })
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

pub(super) fn log_safe_dynamic(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.as_bytes().iter().take(256) {
        escaped.extend(std::ascii::escape_default(*byte).map(char::from));
    }
    if value.len() > 256 {
        escaped.push_str("...");
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use crate::config::{OAuthConfig, SecretString, SmtpTlsMode};

    use super::*;

    fn oauth_mail_config(method: SmtpAuthMethod) -> MailConfig {
        MailConfig {
            smtp_host: "smtp.example.test".to_owned(),
            smtp_port: 587,
            smtp_auth_method: method,
            smtp_tls_mode: SmtpTlsMode::StartTlsRequired,
            send_as: "sending-alias@example.test".to_owned(),
            send_to: vec!["receiver@example.test".to_owned()],
            oauth: Some(OAuthConfig {
                oauth_metadata_url:
                    "https://issuer.example.test/.well-known/oauth-authorization-server".to_owned(),
                oauth_scopes: vec!["mail.send".to_owned()],
                oauth_username: "oauth-user@example.test".to_owned(),
                oauth_app_id: "client-id".to_owned(),
                oauth_client_secret: SecretString::new("client-secret".to_owned()),
                oauth_authorization_extra_params: BTreeMap::new(),
            }),
            plain: None,
        }
    }

    #[test]
    fn prepared_message_rejects_header_injection() {
        let recipients = vec!["receiver@example.test".to_owned()];
        assert!(matches!(
            PreparedMessage::text(
                "sender@example.test\r\nBcc: stolen@example.test",
                &recipients,
                "subject",
                "body",
            ),
            Err(MailError::InvalidMessage { .. })
        ));
    }

    #[test]
    fn oauth_smtp_identity_is_independent_from_sending_alias() {
        let token = OAuthAccessToken::for_test("access-token");

        let xoauth2 = oauth_mail_config(SmtpAuthMethod::Xoauth2);
        assert!(matches!(
            oauth_smtp_auth(&xoauth2, &token).expect("XOAUTH2 identity"),
            SmtpAuth::Xoauth2 {
                username: "oauth-user@example.test",
                ..
            }
        ));

        let oauth_bearer = oauth_mail_config(SmtpAuthMethod::OauthBearer);
        assert!(matches!(
            oauth_smtp_auth(&oauth_bearer, &token).expect("OAUTHBEARER identity"),
            SmtpAuth::OauthBearer {
                authzid: Some("oauth-user@example.test"),
                ..
            }
        ));
    }

    #[test]
    fn sensitive_error_variants_do_not_render_sources() {
        let unsafe_source = std::io::Error::other("secret-token-value");
        let errors = [
            MailError::OAuthTransport {
                stage: "token request",
                source: oauth::safe_source("OAuth HTTP transport failed"),
            },
            MailError::SmtpTransport {
                stage: SmtpStage::DataBody,
                source: smtp::sanitize_io(&unsafe_source, "SMTP DATA write failed"),
            },
        ];
        for error in &errors {
            assert!(!error.to_string().contains("secret-token-value"));
            assert!(!format!("{error:?}").contains("secret-token-value"));
            let mut source = error.source();
            while let Some(current) = source {
                assert!(!current.to_string().contains("secret-token-value"));
                source = current.source();
            }
        }
    }

    #[test]
    fn dynamic_error_text_is_control_escaped() {
        let error = MailError::AuthorizationDenied {
            error_code: "denied\n\t\u{1b}".to_owned(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("\\n"));
        assert!(rendered.contains("\\t"));
        assert!(!rendered.contains('\n'));
    }

    #[test]
    fn smtp_retry_policy_excludes_permanent_and_unknown_outcomes() {
        assert!(is_transient_smtp_error(&MailError::SmtpRejected {
            stage: SmtpStage::MailFrom,
            code: 451,
            recipient_index: None,
        }));
        assert!(!is_transient_smtp_error(&MailError::SmtpRejected {
            stage: SmtpStage::MailFrom,
            code: 550,
            recipient_index: None,
        }));
        assert!(is_transient_smtp_error(&MailError::SmtpRejected {
            stage: SmtpStage::FinalReply,
            code: 451,
            recipient_index: None,
        }));
        assert!(!is_transient_smtp_error(
            &MailError::SubmissionOutcomeUnknown { source: None }
        ));
    }

    #[test]
    fn second_oauth_rejection_records_that_refresh_was_attempted() {
        let error = mark_refresh_attempted(MailError::OAuthAuthenticationRejected {
            code: 535,
            refresh_attempted: false,
        });
        assert!(matches!(
            error,
            MailError::OAuthAuthenticationRejected {
                code: 535,
                refresh_attempted: true
            }
        ));
    }

    #[test]
    fn oauth_535_refreshes_once_and_opens_exactly_one_fresh_connection() {
        struct FakeSession;

        let acquired_modes = RefCell::new(Vec::new());
        let opened_with_tokens = RefCell::new(Vec::new());
        let error = send_oauth_mail_with(
            |mode| {
                acquired_modes.borrow_mut().push(mode);
                Ok(match mode {
                    OAuthTokenMode::Runtime => 1_u8,
                    OAuthTokenMode::ForceRefresh => 2_u8,
                    OAuthTokenMode::InteractiveAuthorize => unreachable!("not a send mode"),
                })
            },
            |token| -> Result<FakeSession, MailError> {
                opened_with_tokens.borrow_mut().push(*token);
                Err(MailError::OAuthAuthenticationRejected {
                    code: 535,
                    refresh_attempted: false,
                })
            },
            |_: &mut FakeSession| unreachable!("authentication never succeeded"),
        )
        .expect_err("the second 535 must be returned");

        assert_eq!(
            acquired_modes.into_inner(),
            [OAuthTokenMode::Runtime, OAuthTokenMode::ForceRefresh]
        );
        assert_eq!(opened_with_tokens.into_inner(), [1, 2]);
        assert!(matches!(
            error,
            MailError::OAuthAuthenticationRejected {
                code: 535,
                refresh_attempted: true
            }
        ));
    }
}
