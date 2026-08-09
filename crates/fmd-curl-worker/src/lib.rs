use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

pub mod transfer;

pub const WORKER_PROTOCOL_VERSION: u16 = 2;
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerEnvelope {
    pub protocol_version: u16,
    pub request_id: String,
    pub request: WorkerRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerRequest {
    ResolveRedirects {
        url: String,
        user_agent: String,
        max_redirects: u8,
    },
    ProbeHostKey {
        url: String,
    },
    Download {
        url: String,
        destination: String,
        resume_from: u64,
        expected_validator: Option<String>,
        credentials: Option<Credentials>,
        trusted_host_key: Option<TrustedHostKey>,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credentials {
    Password {
        username: String,
        password: String,
    },
    PrivateKey {
        username: String,
        key_path: String,
        passphrase: Option<String>,
    },
    Bearer {
        token: String,
    },
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Credentials([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostKey {
    pub algorithm: String,
    pub raw_key_base64: String,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerMessage {
    Hello {
        protocol_version: u16,
        package_version: String,
        target: String,
        libcurl: String,
        libssh2: Option<String>,
        openssl: Option<String>,
        nghttp2: Option<String>,
        zlib: Option<String>,
        capabilities: Vec<String>,
    },
    Event {
        request_id: String,
        #[serde(flatten)]
        event: WorkerEvent,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WorkerEvent {
    RedirectResolved {
        effective_url: String,
    },
    HostKey {
        host: String,
        port: u16,
        algorithm: String,
        raw_key_base64: String,
        fingerprint_sha256: String,
    },
    Progress {
        downloaded: u64,
        total: Option<u64>,
        speed: u64,
        effective_url: String,
    },
    Completed {
        bytes: u64,
    },
    Failed {
        code: String,
    },
}

impl WorkerMessage {
    pub fn hello() -> Self {
        let capabilities = vec!["http".into(), "https".into(), "ftp".into(), "http2".into()];
        #[cfg(fmd_native_sftp)]
        let mut capabilities = capabilities;
        #[cfg(fmd_native_sftp)]
        capabilities.push("sftp_hostkey_callback".into());
        Self::Hello {
            protocol_version: WORKER_PROTOCOL_VERSION,
            package_version: env!("CARGO_PKG_VERSION").into(),
            target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            libcurl: curl::Version::get().version().into(),
            libssh2: option_env!("FMD_LIBSSH2_VERSION").map(str::to_owned),
            openssl: option_env!("FMD_OPENSSL_VERSION").map(str::to_owned),
            nghttp2: option_env!("FMD_NGHTTP2_VERSION").map(str::to_owned),
            zlib: option_env!("FMD_ZLIB_VERSION").map(str::to_owned),
            capabilities,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestError {
    #[error("unsupported worker protocol")]
    Protocol,
    #[error("request identifier is invalid")]
    RequestId,
    #[error("URL is invalid")]
    InvalidUrl,
    #[error("URL credentials must be passed through the credential channel")]
    UrlCredentials,
    #[error("unsupported URL scheme")]
    UnsupportedScheme,
    #[error("redirect count is outside the allowed range")]
    RedirectLimit,
    #[error("destination is empty")]
    EmptyDestination,
    #[error("credentials are invalid for this protocol")]
    InvalidCredentials,
}

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("request validation failed: {0}")]
    Request(#[from] RequestError),
    #[error("transfer backend failed: {0}")]
    Curl(#[from] curl::Error),
    #[error("file operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("redirect policy rejected the response")]
    RedirectPolicy,
    #[error("server response was not successful: {0}")]
    HttpStatus(u32),
    #[error("resume metadata does not match the partial file")]
    ResumeMismatch,
    #[error("the requested backend capability is unavailable")]
    BackendUnavailable,
    #[error("SSH host key is not trusted")]
    HostKeyUntrusted,
    #[error("SSH host key has changed")]
    HostKeyMismatch,
    #[error("SSH host key algorithm is not allowed")]
    HostKeyAlgorithm,
}

impl WorkerEnvelope {
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.protocol_version != WORKER_PROTOCOL_VERSION {
            return Err(RequestError::Protocol);
        }
        if self.request_id.is_empty()
            || self.request_id.len() > 128
            || !self
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(RequestError::RequestId);
        }
        self.request.validate()
    }
}

impl WorkerRequest {
    pub fn validate(&self) -> Result<(), RequestError> {
        let (value, is_download) = match self {
            Self::ResolveRedirects {
                url, max_redirects, ..
            } => {
                if !(1..=10).contains(max_redirects) {
                    return Err(RequestError::RedirectLimit);
                }
                (url, false)
            }
            Self::ProbeHostKey { url } => (url, false),
            Self::Download {
                url, destination, ..
            } => {
                if destination.trim().is_empty() {
                    return Err(RequestError::EmptyDestination);
                }
                (url, true)
            }
        };
        let url = Url::parse(value).map_err(|_| RequestError::InvalidUrl)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(RequestError::UrlCredentials);
        }
        let allowed = if is_download {
            matches!(url.scheme(), "http" | "https" | "ftp" | "sftp")
        } else {
            matches!(url.scheme(), "http" | "https" | "sftp")
        };
        if !allowed {
            return Err(RequestError::UnsupportedScheme);
        }
        if matches!(self, Self::ProbeHostKey { .. }) && url.scheme() != "sftp" {
            return Err(RequestError::UnsupportedScheme);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_credentials_embedded_in_url() {
        let request = WorkerRequest::ProbeHostKey {
            url: "sftp://user:secret@example.com/file".into(),
        };
        assert_eq!(request.validate(), Err(RequestError::UrlCredentials));
    }

    #[test]
    fn hello_reports_backend_capabilities() {
        assert!(matches!(
            WorkerMessage::hello(),
            WorkerMessage::Hello {
                protocol_version: 2,
                ..
            }
        ));
    }
}
