use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, BufRead, Read, Write},
    net::TcpListener,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{StatusCode, blocking::Client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::config::{MailConfig, OAUTH_TOKEN_PATH, SecretString, SmtpAuthMethod};

use super::{ErrorSource, MailError};

const TOKEN_CACHE_SCHEMA: u32 = 1;
const TOKEN_VALIDITY_MARGIN_SECS: u64 = 60;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CALLBACK_BYTES: usize = 8 * 1024;
const MAX_TOKEN_CACHE_BYTES: u64 = 1024 * 1024;
const HTTP_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OAuthTokenMode {
    InteractiveAuthorize,
    Runtime,
    ForceRefresh,
}

impl OAuthTokenMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveAuthorize => "interactive_authorize",
            Self::Runtime => "runtime",
            Self::ForceRefresh => "force_refresh",
        }
    }
}

pub(crate) struct OAuthAccessToken {
    secret: SecretString,
}

impl OAuthAccessToken {
    pub(crate) fn secret(&self) -> &SecretString {
        &self.secret
    }

    #[cfg(test)]
    pub(super) fn for_test(value: &str) -> Self {
        Self {
            secret: SecretString::new(value.to_owned()),
        }
    }
}

impl std::fmt::Debug for OAuthAccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OAuthAccessToken([REDACTED])")
    }
}

pub(crate) async fn acquire_smtp_oauth_token(
    cfg: &MailConfig,
    mode: OAuthTokenMode,
) -> Result<OAuthAccessToken, MailError> {
    acquire_smtp_oauth_token_blocking(cfg, mode)
}

pub(super) fn acquire_smtp_oauth_token_blocking(
    cfg: &MailConfig,
    mode: OAuthTokenMode,
) -> Result<OAuthAccessToken, MailError> {
    acquire_token(cfg, mode, Path::new(OAUTH_TOKEN_PATH))
}

fn acquire_token(
    cfg: &MailConfig,
    mode: OAuthTokenMode,
    cache_path: &Path,
) -> Result<OAuthAccessToken, MailError> {
    if !matches!(
        cfg.smtp_auth_method,
        SmtpAuthMethod::Xoauth2 | SmtpAuthMethod::OauthBearer
    ) {
        return Err(MailError::WrongAuthMethod);
    }
    let oauth = cfg.oauth.as_ref().ok_or(MailError::WrongAuthMethod)?;
    let client = http_client()?;
    let metadata = fetch_metadata(&client, &oauth.oauth_metadata_url)?;
    let now = unix_time_secs()?;
    let existing = read_cache(cache_path)?;

    if let Some(cache) = existing.as_ref() {
        validate_cache_binding(cache, &metadata, &oauth.oauth_app_id, &oauth.oauth_scopes)?;
    }

    let decision = decide_cache(existing.as_ref(), mode, now);
    tracing::info!(
        mode = mode.as_str(),
        action = decision.as_str(),
        "OAuth token acquisition path selected"
    );
    match decision {
        CacheDecision::UseAccessToken => {
            let cache = existing.as_ref().ok_or(MailError::TokenCacheInvalid)?;
            Ok(OAuthAccessToken {
                secret: SecretString::new(cache.access_token.clone()),
            })
        }
        CacheDecision::Refresh => {
            let cache = existing
                .as_ref()
                .ok_or(MailError::ReauthorizationRequired)?;
            let refresh_token = cache
                .refresh_token
                .as_deref()
                .ok_or(MailError::ReauthorizationRequired)?;
            let response = request_token(
                &client,
                cfg,
                &metadata,
                TokenGrant::Refresh { refresh_token },
            )?;
            persist_response(cfg, &metadata, existing.as_ref(), response, cache_path, now)
        }
        CacheDecision::Authorize => {
            let authorization = interactive_authorization(cfg, &metadata)?;
            let response = request_token(
                &client,
                cfg,
                &metadata,
                TokenGrant::AuthorizationCode {
                    code: authorization.code.as_str(),
                    redirect_uri: authorization.redirect_uri.as_str(),
                    pkce_verifier: authorization.pkce_verifier.as_str(),
                },
            )?;
            persist_response(cfg, &metadata, None, response, cache_path, now)
        }
        CacheDecision::RequireAuthorization => Err(MailError::ReauthorizationRequired),
    }
}

fn http_client() -> Result<Client, MailError> {
    Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| MailError::OAuthTransport {
            stage: "HTTP client initialization",
            source: safe_source("OAuth HTTP client initialization failed"),
        })
}

#[derive(Deserialize)]
struct AuthorizationServerMetadataWire {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: Url,
    token_endpoint_auth: TokenEndpointAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenEndpointAuth {
    ClientSecretBasic,
    ClientSecretPost,
}

fn fetch_metadata(client: &Client, url: &str) -> Result<AuthorizationServerMetadata, MailError> {
    let metadata_url = parse_https_url(url, "oauth_metadata_url")?;
    let response = send_with_retry("metadata request", || client.get(metadata_url.clone()))?;
    let status = response.status();
    if !status.is_success() {
        let error_code = response
            .json::<OAuthErrorWire>()
            .ok()
            .and_then(|error| sanitize_error_code(error.error.as_deref()));
        return Err(MailError::OAuthServerRejected {
            status: status.as_u16(),
            error_code,
        });
    }
    let wire = response
        .json::<AuthorizationServerMetadataWire>()
        .map_err(|_| MailError::OAuthMetadataInvalid { field: "document" })?;

    let issuer = parse_issuer_url(&wire.issuer)?;
    let authorization_endpoint =
        parse_https_url(&wire.authorization_endpoint, "authorization_endpoint")?;
    let token_endpoint = parse_https_url(&wire.token_endpoint, "token_endpoint")?;
    let token_endpoint_auth =
        select_token_endpoint_auth(wire.token_endpoint_auth_methods_supported.as_deref())?;
    Ok(AuthorizationServerMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint,
        token_endpoint,
        token_endpoint_auth,
    })
}

fn parse_https_url(value: &str, field: &'static str) -> Result<Url, MailError> {
    let url = Url::parse(value).map_err(|_| MailError::OAuthMetadataInvalid { field })?;
    if url.scheme() != "https" || url.host_str().is_none() || url.fragment().is_some() {
        return Err(MailError::OAuthMetadataInvalid { field });
    }
    Ok(url)
}

fn parse_issuer_url(value: &str) -> Result<Url, MailError> {
    let issuer = parse_https_url(value, "issuer")?;
    if issuer.query().is_some() {
        return Err(MailError::OAuthMetadataInvalid { field: "issuer" });
    }
    Ok(issuer)
}

fn select_token_endpoint_auth(methods: Option<&[String]>) -> Result<TokenEndpointAuth, MailError> {
    let Some(methods) = methods else {
        // RFC 8414 defines client_secret_basic as the omitted-field default.
        return Ok(TokenEndpointAuth::ClientSecretBasic);
    };
    if methods.iter().any(|method| method == "client_secret_basic") {
        return Ok(TokenEndpointAuth::ClientSecretBasic);
    }
    if methods.iter().any(|method| method == "client_secret_post") {
        return Ok(TokenEndpointAuth::ClientSecretPost);
    }
    let method = methods
        .first()
        .and_then(|method| sanitize_error_code(Some(method)))
        .unwrap_or_else(|| "none-advertised".to_owned());
    Err(MailError::UnsupportedTokenEndpointAuth { method })
}

#[derive(Clone, Copy)]
enum TokenGrant<'a> {
    Refresh {
        refresh_token: &'a str,
    },
    AuthorizationCode {
        code: &'a str,
        redirect_uri: &'a str,
        pkce_verifier: &'a str,
    },
}

#[derive(Deserialize)]
struct TokenResponseWire {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: Option<String>,
}

impl Drop for TokenResponseWire {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(refresh_token) = &mut self.refresh_token {
            refresh_token.zeroize();
        }
    }
}

#[derive(Deserialize)]
struct OAuthErrorWire {
    error: Option<String>,
}

fn request_token(
    client: &Client,
    cfg: &MailConfig,
    metadata: &AuthorizationServerMetadata,
    grant: TokenGrant<'_>,
) -> Result<TokenResponseWire, MailError> {
    let oauth = cfg.oauth.as_ref().ok_or(MailError::WrongAuthMethod)?;
    let client_id = oauth.oauth_app_id.as_str();
    let client_secret = oauth.oauth_client_secret.expose_secret();
    for attempt in 0..HTTP_ATTEMPTS {
        let mut request = client.post(metadata.token_endpoint.clone());
        request = match metadata.token_endpoint_auth {
            TokenEndpointAuth::ClientSecretBasic => {
                request.basic_auth(client_id, Some(client_secret))
            }
            TokenEndpointAuth::ClientSecretPost => request,
        };

        let mut form = Vec::<(&str, &str)>::new();
        match grant {
            TokenGrant::Refresh { refresh_token } => {
                form.push(("grant_type", "refresh_token"));
                form.push(("refresh_token", refresh_token));
            }
            TokenGrant::AuthorizationCode {
                code,
                redirect_uri,
                pkce_verifier,
            } => {
                form.push(("grant_type", "authorization_code"));
                form.push(("code", code));
                form.push(("redirect_uri", redirect_uri));
                form.push(("code_verifier", pkce_verifier));
            }
        }
        if metadata.token_endpoint_auth == TokenEndpointAuth::ClientSecretPost {
            form.push(("client_id", client_id));
            form.push(("client_secret", client_secret));
        }

        let response = match request.form(&form).send() {
            Ok(response) => response,
            Err(_) if attempt + 1 < HTTP_ATTEMPTS => {
                wait_before_http_retry(attempt);
                continue;
            }
            Err(_) => {
                return Err(MailError::OAuthTransport {
                    stage: "token request",
                    source: safe_source("OAuth HTTP transport failed"),
                });
            }
        };

        let status = response.status();
        if status.is_success() {
            let response = response
                .json::<TokenResponseWire>()
                .map_err(|_| MailError::TokenResponseInvalid { field: "document" })?;
            validate_token_response(&response)?;
            return Ok(response);
        }

        let error_code = response
            .json::<OAuthErrorWire>()
            .ok()
            .and_then(|wire| sanitize_error_code(wire.error.as_deref()));
        if error_code.as_deref() == Some("invalid_grant") {
            return Err(MailError::ReauthorizationRequired);
        }
        if oauth_response_is_retryable(status, error_code.as_deref()) && attempt + 1 < HTTP_ATTEMPTS
        {
            wait_before_http_retry(attempt);
            continue;
        }
        return Err(MailError::OAuthServerRejected {
            status: status.as_u16(),
            error_code,
        });
    }
    Err(MailError::OAuthTransport {
        stage: "token request",
        source: safe_source("OAuth HTTP retry limit was reached"),
    })
}

fn validate_token_response(response: &TokenResponseWire) -> Result<(), MailError> {
    if response.access_token.is_empty() {
        return Err(MailError::TokenResponseInvalid {
            field: "access_token",
        });
    }
    if !response.token_type.eq_ignore_ascii_case("Bearer") {
        return Err(MailError::TokenResponseInvalid {
            field: "token_type",
        });
    }
    if response.expires_in == 0 {
        return Err(MailError::TokenResponseInvalid {
            field: "expires_in",
        });
    }
    Ok(())
}

fn oauth_response_is_retryable(status: StatusCode, error_code: Option<&str>) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
        || error_code == Some("temporarily_unavailable")
}

fn wait_before_http_retry(attempt: usize) {
    thread::sleep(Duration::from_millis(200 * (1u64 << attempt)));
}

fn send_with_retry(
    stage: &'static str,
    mut request: impl FnMut() -> reqwest::blocking::RequestBuilder,
) -> Result<reqwest::blocking::Response, MailError> {
    for attempt in 0..HTTP_ATTEMPTS {
        let result = request().send();
        match result {
            Ok(response)
                if (response.status() == StatusCode::TOO_MANY_REQUESTS
                    || response.status().is_server_error())
                    && attempt + 1 < HTTP_ATTEMPTS =>
            {
                wait_before_http_retry(attempt);
            }
            Ok(response) => return Ok(response),
            Err(_) if attempt + 1 < HTTP_ATTEMPTS => {
                wait_before_http_retry(attempt);
            }
            Err(_) => {
                return Err(MailError::OAuthTransport {
                    stage,
                    source: safe_source("OAuth HTTP transport failed"),
                });
            }
        }
    }
    Err(MailError::OAuthTransport {
        stage,
        source: safe_source("OAuth HTTP retry limit was reached"),
    })
}

struct InteractiveAuthorization {
    code: Zeroizing<String>,
    redirect_uri: Url,
    pkce_verifier: Zeroizing<String>,
}

fn interactive_authorization(
    cfg: &MailConfig,
    metadata: &AuthorizationServerMetadata,
) -> Result<InteractiveAuthorization, MailError> {
    let oauth = cfg.oauth.as_ref().ok_or(MailError::WrongAuthMethod)?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| MailError::OAuthTransport {
        stage: "authorization callback bind",
        source: safe_source("OAuth callback listener could not be created"),
    })?;
    let address = listener
        .local_addr()
        .map_err(|_| MailError::OAuthTransport {
            stage: "authorization callback setup",
            source: safe_source("OAuth callback address was unavailable"),
        })?;
    drop(listener);
    let redirect_uri = build_redirect_uri(address.port())?;
    let state = Uuid::new_v4().simple().to_string();
    let pkce_verifier = Zeroizing::new(format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    ));
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
    let authorization_url = build_authorization_url(
        metadata,
        &oauth.oauth_app_id,
        redirect_uri.as_str(),
        &oauth.oauth_scopes,
        &oauth.oauth_authorization_extra_params,
        &state,
        &challenge,
    );

    let stdin = io::stdin();
    let stdout = io::stdout();
    let code = prompt_for_callback(
        &mut stdin.lock(),
        &mut stdout.lock(),
        &authorization_url,
        &redirect_uri,
        &state,
    )?;
    Ok(InteractiveAuthorization {
        code: Zeroizing::new(code),
        redirect_uri,
        pkce_verifier,
    })
}

fn build_redirect_uri(port: u16) -> Result<Url, MailError> {
    Url::parse(&format!("http://localhost:{port}/")).map_err(|_| MailError::OAuthTransport {
        stage: "authorization callback setup",
        source: safe_source("OAuth callback address was invalid"),
    })
}

fn build_authorization_url(
    metadata: &AuthorizationServerMetadata,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    extra_parameters: &BTreeMap<String, String>,
    state: &str,
    challenge: &str,
) -> Url {
    let mut url = metadata.authorization_endpoint.clone();
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        for (name, value) in extra_parameters {
            query.append_pair(name, value);
        }
    }
    url
}

fn prompt_for_callback(
    input: &mut impl BufRead,
    output: &mut impl Write,
    authorization_url: &Url,
    redirect_uri: &Url,
    expected_state: &str,
) -> Result<String, MailError> {
    writeln!(output, "请在浏览器中打开以下链接完成授权:")
        .and_then(|()| writeln!(output, "{authorization_url}"))
        .and_then(|()| write!(output, "请粘贴回调链接: "))
        .and_then(|()| output.flush())
        .map_err(|_| MailError::OAuthTransport {
            stage: "authorization instructions",
            source: safe_source("OAuth authorization instructions could not be written"),
        })?;

    let mut callback = String::new();
    input
        .take((MAX_CALLBACK_BYTES + 1) as u64)
        .read_line(&mut callback)
        .map_err(|_| MailError::OAuthTransport {
            stage: "authorization callback input",
            source: safe_source("OAuth callback URL could not be read"),
        })?;
    if callback.len() > MAX_CALLBACK_BYTES {
        return Err(MailError::OAuthTransport {
            stage: "authorization callback parse",
            source: safe_source("OAuth callback exceeded the size limit"),
        });
    }
    parse_callback_url(callback.trim(), redirect_uri, expected_state)
}

fn parse_callback_url(
    value: &str,
    redirect_uri: &Url,
    expected_state: &str,
) -> Result<String, MailError> {
    let callback = Url::parse(value).map_err(|_| MailError::OAuthTransport {
        stage: "authorization callback parse",
        source: safe_source("OAuth callback URL was invalid"),
    })?;
    if callback.scheme() != redirect_uri.scheme()
        || callback.username() != redirect_uri.username()
        || callback.password() != redirect_uri.password()
        || callback.host_str() != redirect_uri.host_str()
        || callback.port_or_known_default() != redirect_uri.port_or_known_default()
        || callback.path() != redirect_uri.path()
        || callback.fragment().is_some()
    {
        return Err(MailError::OAuthTransport {
            stage: "authorization callback parse",
            source: safe_source("OAuth callback URL did not match the redirect URI"),
        });
    }

    let parameters = callback.query_pairs().collect::<BTreeMap<_, _>>();
    if parameters.get("state").map(AsRef::as_ref) != Some(expected_state) {
        Err(MailError::OAuthStateMismatch)
    } else if let Some(error) = parameters.get("error") {
        Err(MailError::AuthorizationDenied {
            error_code: sanitize_error_code(Some(error.as_ref()))
                .unwrap_or_else(|| "authorization_denied".to_owned()),
        })
    } else {
        parameters
            .get("code")
            .filter(|code| !code.is_empty())
            .map(ToString::to_string)
            .ok_or(MailError::TokenResponseInvalid {
                field: "authorization_code",
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheDecision {
    UseAccessToken,
    Refresh,
    Authorize,
    RequireAuthorization,
}

impl CacheDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UseAccessToken => "use_cached_access_token",
            Self::Refresh => "refresh_access_token",
            Self::Authorize => "interactive_authorization",
            Self::RequireAuthorization => "authorization_required",
        }
    }
}

fn decide_cache(cache: Option<&TokenCache>, mode: OAuthTokenMode, now: u64) -> CacheDecision {
    let valid_access = cache.is_some_and(|cache| {
        cache
            .expires_at
            .checked_sub(now)
            .is_some_and(|remaining| remaining >= TOKEN_VALIDITY_MARGIN_SECS)
            && !cache.access_token.is_empty()
    });
    let has_refresh = cache
        .and_then(|cache| cache.refresh_token.as_deref())
        .is_some_and(|token| !token.is_empty());

    match mode {
        OAuthTokenMode::ForceRefresh if has_refresh => CacheDecision::Refresh,
        OAuthTokenMode::InteractiveAuthorize | OAuthTokenMode::Runtime if valid_access => {
            CacheDecision::UseAccessToken
        }
        OAuthTokenMode::InteractiveAuthorize | OAuthTokenMode::Runtime if has_refresh => {
            CacheDecision::Refresh
        }
        OAuthTokenMode::InteractiveAuthorize => CacheDecision::Authorize,
        OAuthTokenMode::ForceRefresh | OAuthTokenMode::Runtime => {
            CacheDecision::RequireAuthorization
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenCache {
    schema_version: u32,
    issuer: String,
    client_id: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: u64,
    granted_scopes: Vec<String>,
}

impl std::fmt::Debug for TokenCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenCache")
            .field("schema_version", &self.schema_version)
            .field("issuer", &self.issuer)
            .field("client_id", &"[REDACTED]")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .field("granted_scopes", &self.granted_scopes.len())
            .finish()
    }
}

impl Drop for TokenCache {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(refresh_token) = &mut self.refresh_token {
            refresh_token.zeroize();
        }
    }
}

fn validate_cache_binding(
    cache: &TokenCache,
    metadata: &AuthorizationServerMetadata,
    client_id: &str,
    scopes: &[String],
) -> Result<(), MailError> {
    if cache.schema_version != TOKEN_CACHE_SCHEMA
        || cache.issuer != metadata.issuer
        || cache.client_id != client_id
        || !scopes
            .iter()
            .filter(|scope| is_access_token_scope(scope))
            .all(|scope| cache.granted_scopes.contains(scope))
    {
        return Err(MailError::TokenCacheInvalid);
    }
    Ok(())
}

fn persist_response(
    cfg: &MailConfig,
    metadata: &AuthorizationServerMetadata,
    previous: Option<&TokenCache>,
    mut response: TokenResponseWire,
    cache_path: &Path,
    now: u64,
) -> Result<OAuthAccessToken, MailError> {
    let expires_at =
        now.checked_add(response.expires_in)
            .ok_or(MailError::TokenResponseInvalid {
                field: "expires_in",
            })?;
    let oauth = cfg.oauth.as_ref().ok_or(MailError::WrongAuthMethod)?;
    let granted_scopes =
        resolve_granted_access_token_scopes(&oauth.oauth_scopes, response.scope.as_deref())?;
    let refresh_token = take_refresh_token(&mut response, previous);
    let access_token = std::mem::take(&mut response.access_token);
    let cache = TokenCache {
        schema_version: TOKEN_CACHE_SCHEMA,
        issuer: metadata.issuer.clone(),
        client_id: oauth.oauth_app_id.clone(),
        access_token: access_token.clone(),
        refresh_token,
        expires_at,
        granted_scopes,
    };
    write_cache(cache_path, &cache)?;
    Ok(OAuthAccessToken {
        secret: SecretString::new(access_token),
    })
}

fn resolve_granted_access_token_scopes(
    requested_scopes: &[String],
    response_scope: Option<&str>,
) -> Result<Vec<String>, MailError> {
    let required_scopes = requested_scopes
        .iter()
        .filter(|scope| is_access_token_scope(scope))
        .collect::<Vec<_>>();
    let granted_scopes: Vec<String> = response_scope.map_or_else(
        || {
            required_scopes
                .iter()
                .map(|scope| (*scope).clone())
                .collect()
        },
        |scope| scope.split_ascii_whitespace().map(str::to_owned).collect(),
    );
    if granted_scopes.is_empty()
        || !required_scopes
            .iter()
            .all(|scope| granted_scopes.contains(scope))
    {
        return Err(MailError::TokenResponseInvalid {
            field: "granted_scopes",
        });
    }
    Ok(granted_scopes)
}

fn is_access_token_scope(scope: &str) -> bool {
    scope != "offline_access"
}

fn take_refresh_token(
    response: &mut TokenResponseWire,
    previous: Option<&TokenCache>,
) -> Option<String> {
    match response.refresh_token.take() {
        Some(token) if !token.is_empty() => Some(token),
        Some(mut empty_token) => {
            empty_token.zeroize();
            previous.and_then(|cache| cache.refresh_token.clone())
        }
        None => previous.and_then(|cache| cache.refresh_token.clone()),
    }
}

fn read_cache(path: &Path) -> Result<Option<TokenCache>, MailError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) if source.raw_os_error() == Some(libc::ELOOP) => {
            return Err(MailError::TokenCacheSecurity {
                path: path.to_path_buf(),
                rule: "be a regular file and not a symbolic link",
            });
        }
        Err(source) => {
            return Err(MailError::TokenCacheRead {
                path: path.to_path_buf(),
                source: sanitize_io(&source, "OAuth token cache open failed"),
            });
        }
    };
    let metadata = file
        .metadata()
        .map_err(|source| MailError::TokenCacheRead {
            path: path.to_path_buf(),
            source: sanitize_io(&source, "OAuth token cache metadata read failed"),
        })?;
    validate_cache_metadata(path, &metadata, 0, 0)?;

    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_TOKEN_CACHE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| MailError::TokenCacheRead {
            path: path.to_path_buf(),
            source: sanitize_io(&source, "OAuth token cache read failed"),
        })?;
    if bytes.len() as u64 > MAX_TOKEN_CACHE_BYTES {
        bytes.zeroize();
        return Err(MailError::TokenCacheInvalid);
    }
    let cache = serde_json::from_slice::<TokenCache>(&bytes).map_err(|_| {
        bytes.zeroize();
        MailError::TokenCacheInvalid
    })?;
    bytes.zeroize();
    Ok(Some(cache))
}

fn validate_cache_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    required_owner: u32,
    required_group: u32,
) -> Result<(), MailError> {
    if !metadata.file_type().is_file() {
        return Err(MailError::TokenCacheSecurity {
            path: path.to_path_buf(),
            rule: "be a regular file",
        });
    }
    if metadata.uid() != required_owner || metadata.gid() != required_group {
        return Err(MailError::TokenCacheSecurity {
            path: path.to_path_buf(),
            rule: "be owned by root:root",
        });
    }
    if metadata.mode() & 0o7777 != 0o600 {
        return Err(MailError::TokenCacheSecurity {
            path: path.to_path_buf(),
            rule: "have mode 0600",
        });
    }
    Ok(())
}

fn write_cache(path: &Path, cache: &TokenCache) -> Result<(), MailError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => validate_cache_metadata(path, &metadata, 0, 0)?,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(MailError::TokenCacheWrite {
                path: path.to_path_buf(),
                source: sanitize_io(&source, "OAuth token cache metadata read failed"),
            });
        }
    }
    let parent = path.parent().ok_or_else(|| MailError::TokenCacheWrite {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "token cache parent missing"),
    })?;
    let temp_path = temporary_cache_path(parent);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut temp = options
        .open(&temp_path)
        .map_err(|source| MailError::TokenCacheWrite {
            path: path.to_path_buf(),
            source: sanitize_io(&source, "OAuth token cache temporary file creation failed"),
        })?;

    let result = (|| {
        let metadata = temp
            .metadata()
            .map_err(|source| MailError::TokenCacheWrite {
                path: path.to_path_buf(),
                source: sanitize_io(&source, "OAuth token cache temporary metadata read failed"),
            })?;
        validate_cache_metadata(&temp_path, &metadata, 0, 0)?;
        serde_json::to_writer(&mut temp, cache).map_err(|_| MailError::TokenCacheWrite {
            path: path.to_path_buf(),
            source: io::Error::other("OAuth token cache serialization failed"),
        })?;
        temp.write_all(b"\n")
            .map_err(|source| MailError::TokenCacheWrite {
                path: path.to_path_buf(),
                source: sanitize_io(&source, "OAuth token cache write failed"),
            })?;
        temp.sync_all()
            .map_err(|source| MailError::TokenCacheWrite {
                path: path.to_path_buf(),
                source: sanitize_io(&source, "OAuth token cache sync failed"),
            })?;
        std::fs::rename(&temp_path, path).map_err(|source| MailError::TokenCacheWrite {
            path: path.to_path_buf(),
            source: sanitize_io(&source, "OAuth token cache atomic replacement failed"),
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| MailError::TokenCacheWrite {
                path: path.to_path_buf(),
                source: sanitize_io(&source, "OAuth token cache directory sync failed"),
            })?;
        Ok(())
    })();
    if result.is_err() {
        let _cleanup = std::fs::remove_file(&temp_path);
    }
    result
}

fn temporary_cache_path(parent: &Path) -> PathBuf {
    parent.join(format!(".oauth_token.json.{}.tmp", Uuid::new_v4().simple()))
}

fn unix_time_secs() -> Result<u64, MailError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| MailError::TokenResponseInvalid { field: "clock" })
}

fn sanitize_error_code(value: Option<&str>) -> Option<String> {
    let value = value?;
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return None;
    }
    Some(value.to_owned())
}

fn sanitize_io(source: &io::Error, message: &'static str) -> io::Error {
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

pub(super) fn safe_source(message: &'static str) -> ErrorSource {
    Box::new(SafeSource(message))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn cache(expires_at: u64, refresh: Option<&str>) -> TokenCache {
        TokenCache {
            schema_version: TOKEN_CACHE_SCHEMA,
            issuer: "https://issuer.example.test/".to_owned(),
            client_id: "client-id".to_owned(),
            access_token: "access-token".to_owned(),
            refresh_token: refresh.map(str::to_owned),
            expires_at,
            granted_scopes: vec!["mail.send".to_owned()],
        }
    }

    fn metadata(methods: Option<&[String]>) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata {
            issuer: "https://issuer.example.test/".to_owned(),
            authorization_endpoint: Url::parse("https://issuer.example.test/authorize")
                .expect("authorization URL"),
            token_endpoint: Url::parse("https://issuer.example.test/token").expect("token URL"),
            token_endpoint_auth: select_token_endpoint_auth(methods).expect("supported token auth"),
        }
    }

    #[test]
    fn cache_decisions_cover_hit_refresh_and_reauthorization() {
        let valid = cache(1_060, Some("refresh"));
        assert_eq!(
            decide_cache(Some(&valid), OAuthTokenMode::Runtime, 1_000),
            CacheDecision::UseAccessToken
        );
        let expiring = cache(1_059, Some("refresh"));
        assert_eq!(
            decide_cache(Some(&expiring), OAuthTokenMode::Runtime, 1_000),
            CacheDecision::Refresh
        );
        let no_refresh = cache(1_000, None);
        assert_eq!(
            decide_cache(Some(&no_refresh), OAuthTokenMode::Runtime, 1_000),
            CacheDecision::RequireAuthorization
        );
        assert_eq!(
            decide_cache(None, OAuthTokenMode::InteractiveAuthorize, 1_000),
            CacheDecision::Authorize
        );
        assert_eq!(
            decide_cache(Some(&valid), OAuthTokenMode::ForceRefresh, 1_000),
            CacheDecision::Refresh
        );
    }

    #[test]
    fn metadata_auth_default_and_supported_methods_are_deterministic() {
        assert_eq!(
            select_token_endpoint_auth(None).expect("RFC default"),
            TokenEndpointAuth::ClientSecretBasic
        );
        assert_eq!(
            select_token_endpoint_auth(Some(&["client_secret_post".to_owned()])).expect("post"),
            TokenEndpointAuth::ClientSecretPost
        );
        assert!(matches!(
            select_token_endpoint_auth(Some(&["private_key_jwt".to_owned()])),
            Err(MailError::UnsupportedTokenEndpointAuth { .. })
        ));
    }

    #[test]
    fn oauth_retry_classification_is_bounded_to_defined_server_conditions() {
        assert!(oauth_response_is_retryable(
            StatusCode::BAD_REQUEST,
            Some("temporarily_unavailable")
        ));
        assert!(oauth_response_is_retryable(
            StatusCode::TOO_MANY_REQUESTS,
            None
        ));
        assert!(oauth_response_is_retryable(
            StatusCode::SERVICE_UNAVAILABLE,
            None
        ));
        assert!(!oauth_response_is_retryable(
            StatusCode::BAD_REQUEST,
            Some("invalid_client")
        ));
    }

    #[test]
    fn missing_or_empty_refresh_token_preserves_previous_value() {
        let previous = cache(2_000, Some("old-refresh-token"));
        for replacement in [None, Some(String::new())] {
            let mut response = TokenResponseWire {
                access_token: "new-access-token".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: 3_600,
                refresh_token: replacement,
                scope: Some("mail.send".to_owned()),
            };
            assert_eq!(
                take_refresh_token(&mut response, Some(&previous)).as_deref(),
                Some("old-refresh-token")
            );
        }
    }

    #[test]
    fn offline_access_is_not_required_in_access_token_scopes() {
        let requested_scopes = vec!["mail.send".to_owned(), "offline_access".to_owned()];
        assert_eq!(
            resolve_granted_access_token_scopes(&requested_scopes, Some("mail.send"))
                .expect("Microsoft-style token scopes"),
            vec!["mail.send"]
        );
        assert_eq!(
            resolve_granted_access_token_scopes(&requested_scopes, None)
                .expect("omitted unchanged token scopes"),
            vec!["mail.send"]
        );
        assert!(matches!(
            resolve_granted_access_token_scopes(&requested_scopes, Some("other.scope")),
            Err(MailError::TokenResponseInvalid {
                field: "granted_scopes"
            })
        ));

        validate_cache_binding(
            &cache(2_000, Some("refresh")),
            &metadata(None),
            "client-id",
            &requested_scopes,
        )
        .expect("cached resource scope with offline access request");
    }

    #[test]
    fn token_response_requires_bearer_token_type() {
        let mut response = TokenResponseWire {
            access_token: "access-token".to_owned(),
            token_type: "bearer".to_owned(),
            expires_in: 3_600,
            refresh_token: None,
            scope: Some("mail.send".to_owned()),
        };
        validate_token_response(&response).expect("Bearer is case-insensitive");
        response.token_type = "DPoP".to_owned();
        assert!(matches!(
            validate_token_response(&response),
            Err(MailError::TokenResponseInvalid {
                field: "token_type"
            })
        ));
    }

    #[test]
    fn issuer_rejects_query_and_fragment_components() {
        parse_issuer_url("https://issuer.example.test/path").expect("valid issuer");
        for invalid in [
            "https://issuer.example.test/path?tenant=one",
            "https://issuer.example.test/path#fragment",
        ] {
            assert!(matches!(
                parse_issuer_url(invalid),
                Err(MailError::OAuthMetadataInvalid { field: "issuer" })
            ));
        }
    }

    #[test]
    fn authorization_url_contains_pkce_and_unchanged_extra_parameters() {
        let metadata = metadata(None);
        let extras = BTreeMap::from([("access_type".to_owned(), "offline".to_owned())]);
        let url = build_authorization_url(
            &metadata,
            "client-id",
            "http://localhost:12345/",
            &["mail.send".to_owned()],
            &extras,
            "state-value",
            "challenge-value",
        );
        let parameters = url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            parameters.get("response_type").map(AsRef::as_ref),
            Some("code")
        );
        assert_eq!(
            parameters.get("code_challenge_method").map(AsRef::as_ref),
            Some("S256")
        );
        assert_eq!(
            parameters.get("access_type").map(AsRef::as_ref),
            Some("offline")
        );
    }

    #[test]
    fn redirect_uri_matches_registered_localhost_root() {
        assert_eq!(
            build_redirect_uri(12345).expect("redirect URI").as_str(),
            "http://localhost:12345/"
        );
    }

    #[test]
    fn authorization_prompt_prints_url_and_reads_pasted_callback() {
        let authorization_url =
            Url::parse("https://issuer.example.test/authorize?client_id=client-id")
                .expect("authorization URL");
        let redirect_uri = build_redirect_uri(12345).expect("redirect URI");
        let callback = b"http://localhost:12345/?code=authorization-code&state=state-value\n";
        let mut output = Vec::new();

        let code = prompt_for_callback(
            &mut std::io::Cursor::new(callback),
            &mut output,
            &authorization_url,
            &redirect_uri,
            "state-value",
        )
        .expect("pasted callback");

        assert_eq!(code, "authorization-code");
        assert_eq!(
            String::from_utf8(output).expect("UTF-8 output"),
            format!("请在浏览器中打开以下链接完成授权:\n{authorization_url}\n请粘贴回调链接: ")
        );
    }

    #[test]
    fn pasted_callback_requires_exact_redirect_uri_and_state() {
        let redirect_uri = build_redirect_uri(12345).expect("redirect URI");
        for callback in [
            "https://localhost:12345/?code=code&state=state-value",
            "http://127.0.0.1:12345/?code=code&state=state-value",
            "http://localhost:54321/?code=code&state=state-value",
            "http://localhost:12345/callback?code=code&state=state-value",
            "http://localhost:12345/?code=code&state=state-value#fragment",
        ] {
            assert!(matches!(
                parse_callback_url(callback, &redirect_uri, "state-value"),
                Err(MailError::OAuthTransport {
                    stage: "authorization callback parse",
                    ..
                })
            ));
        }
        assert!(matches!(
            parse_callback_url(
                "http://localhost:12345/?code=code&state=other-state",
                &redirect_uri,
                "state-value"
            ),
            Err(MailError::OAuthStateMismatch)
        ));
    }

    #[test]
    fn cache_binding_requires_issuer_client_and_all_scopes() {
        let metadata = metadata(None);
        let cache = cache(2_000, Some("refresh"));
        validate_cache_binding(&cache, &metadata, "client-id", &["mail.send".to_owned()])
            .expect("matching binding");
        assert!(matches!(
            validate_cache_binding(&cache, &metadata, "other-client", &["mail.send".to_owned()]),
            Err(MailError::TokenCacheInvalid)
        ));
    }

    #[test]
    fn cache_metadata_rejects_wrong_mode_without_reading_contents() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("oauth_token.json");
        std::fs::write(&path, b"secret").expect("write cache fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("set mode");
        let metadata = std::fs::metadata(&path).expect("metadata");
        assert!(matches!(
            validate_cache_metadata(&path, &metadata, metadata.uid(), metadata.gid()),
            Err(MailError::TokenCacheSecurity { .. })
        ));
    }

    #[test]
    fn malformed_cache_never_appears_in_error_text() {
        let error = MailError::TokenCacheInvalid;
        assert_eq!(error.to_string(), "OAuth token cache is invalid");
        assert!(!error.to_string().contains("access-token"));
    }
}
