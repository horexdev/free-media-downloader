use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::error::ApiError;
use crate::source::{InputSource, SourceKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JobId(#[ts(type = "string")] pub Uuid);

impl JobId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum JobState {
    Probing,
    AwaitingSelection,
    Queued,
    Preparing,
    Downloading,
    PostProcessing,
    Paused,
    Interrupted,
    Completed,
    Failed,
    Canceled,
}

impl fmt::Display for JobState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl JobState {
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        use JobState as S;
        matches!(
            (self, next),
            (
                S::Probing,
                S::AwaitingSelection | S::Queued | S::Failed | S::Canceled
            ) | (S::AwaitingSelection, S::Queued | S::Canceled)
                | (S::Queued, S::Preparing | S::Paused | S::Canceled)
                | (
                    S::Preparing,
                    S::Downloading | S::Paused | S::Failed | S::Interrupted | S::Canceled
                )
                | (
                    S::Downloading,
                    S::PostProcessing
                        | S::Completed
                        | S::Paused
                        | S::Failed
                        | S::Interrupted
                        | S::Canceled
                )
                | (
                    S::PostProcessing,
                    S::Completed | S::Failed | S::Interrupted | S::Canceled
                )
                | (S::Paused, S::Queued | S::Canceled)
                | (S::Interrupted, S::Queued | S::Canceled)
                | (S::Failed, S::Probing | S::Queued)
        )
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Canceled)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JobSpec {
    pub source: InputSource,
    pub destination: String,
    pub preferred_kind: Option<SourceKind>,
    pub selected_format: Option<String>,
    pub subtitle_languages: Vec<String>,
    pub selected_playlist_entries: Option<Vec<u32>>,
    pub overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FormatOption {
    pub id: String,
    pub label: String,
    pub container: Option<String>,
    pub estimated_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PlaylistEntry {
    pub index: u32,
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ResolvedPlan {
    pub source_kind: SourceKind,
    pub title: Option<String>,
    pub formats: Vec<FormatOption>,
    pub subtitles: Vec<String>,
    pub playlist_entries: Vec<PlaylistEntry>,
    pub chapters: u32,
    pub files: u32,
    pub warnings: Vec<String>,
    pub auth_requirements: Vec<String>,
    pub required_packs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct JobSnapshot {
    pub id: JobId,
    pub spec: JobSpec,
    pub state: JobState,
    pub plan: Option<ResolvedPlan>,
    pub progress: f64,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub speed_bytes_per_second: Option<u64>,
    pub error: Option<ApiError>,
    #[ts(type = "string")]
    pub created_at: DateTime<Utc>,
    #[ts(type = "string")]
    pub updated_at: DateTime<Utc>,
    pub engine_versions: BTreeMap<String, String>,
}

impl JobSnapshot {
    #[must_use]
    pub fn new(spec: JobSpec) -> Self {
        let now = Utc::now();
        Self {
            id: JobId::new(),
            spec,
            state: JobState::Probing,
            plan: None,
            progress: 0.0,
            downloaded_bytes: 0,
            total_bytes: None,
            speed_bytes_per_second: None,
            error: None,
            created_at: now,
            updated_at: now,
            engine_versions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum JobEvent {
    StateChanged {
        id: JobId,
        state: JobState,
    },
    Progress {
        id: JobId,
        downloaded_bytes: u64,
        total_bytes: Option<u64>,
        speed_bytes_per_second: Option<u64>,
    },
    Failed {
        id: JobId,
        error: ApiError,
    },
    Removed {
        id: JobId,
    },
}
