use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum EngineErrorKind {
    Unsupported,
    ExtractorBroken,
    ProtocolUnsupported,
    Transient,
    AuthRequired,
    Forbidden,
    GeoRestricted,
    RateLimited,
    ProtectedMedia,
    Integrity,
    Disk,
    Tls,
    HostKey,
    Canceled,
    Internal,
}

impl EngineErrorKind {
    #[must_use]
    pub const fn allows_fallback(self) -> bool {
        matches!(
            self,
            Self::Unsupported | Self::ExtractorBroken | Self::ProtocolUnsupported
        )
    }

    #[must_use]
    pub const fn allows_retry(self) -> bool {
        matches!(self, Self::Transient | Self::RateLimited)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApiError {
    pub code: String,
    pub args: BTreeMap<String, String>,
    pub kind: EngineErrorKind,
}

impl ApiError {
    #[must_use]
    pub fn new(code: impl Into<String>, kind: EngineErrorKind) -> Self {
        Self {
            code: code.into(),
            args: BTreeMap::new(),
            kind,
        }
    }

    #[must_use]
    pub fn with_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid state transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
    #[error("job not found: {0}")]
    JobNotFound(String),
    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("path is not valid UTF-8")]
    NonUtf8Path,
    #[error("supply-chain verification failed: {0}")]
    SupplyChain(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CoreError> for ApiError {
    fn from(value: CoreError) -> Self {
        match value {
            CoreError::InvalidInput(reason) => {
                Self::new("input.invalid", EngineErrorKind::Unsupported).with_arg("reason", reason)
            }
            CoreError::InvalidTransition { from, to } => {
                Self::new("job.invalid_transition", EngineErrorKind::Internal)
                    .with_arg("from", from)
                    .with_arg("to", to)
            }
            CoreError::JobNotFound(id) => {
                Self::new("job.not_found", EngineErrorKind::Internal).with_arg("id", id)
            }
            CoreError::Storage(_) => Self::new("storage.failed", EngineErrorKind::Disk),
            CoreError::Serialization(_) => {
                Self::new("storage.invalid_data", EngineErrorKind::Internal)
            }
            CoreError::NonUtf8Path => Self::new("path.invalid_encoding", EngineErrorKind::Disk),
            CoreError::SupplyChain(_) => {
                Self::new("pack.verification_failed", EngineErrorKind::Integrity)
            }
            CoreError::Io(_) => Self::new("storage.io_failed", EngineErrorKind::Disk),
        }
    }
}
