use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum InputSource {
    Url { value: String },
    LocalManifest { path: String },
    LocalMetalink { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum SourceKind {
    SiteMedia,
    Live,
    Gallery,
    Manifest,
    DirectFile,
    Metalink,
}
