use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path};
use std::str::FromStr;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;

use crate::error::CoreError;

pub const PACK_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export)]
pub enum TargetId {
    WindowsX64,
    WindowsArm64,
    MacosX64,
    MacosArm64,
    LinuxX64,
    LinuxArm64,
}

impl TargetId {
    #[must_use]
    pub fn current() -> Option<Self> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("windows", "x86_64") => Some(Self::WindowsX64),
            ("windows", "aarch64") => Some(Self::WindowsArm64),
            ("macos", "x86_64") => Some(Self::MacosX64),
            ("macos", "aarch64") => Some(Self::MacosArm64),
            ("linux", "x86_64") => Some(Self::LinuxX64),
            ("linux", "aarch64") => Some(Self::LinuxArm64),
            _ => None,
        }
    }
}

impl fmt::Display for TargetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WindowsX64 => "windows-x64",
            Self::WindowsArm64 => "windows-arm64",
            Self::MacosX64 => "macos-x64",
            Self::MacosArm64 => "macos-arm64",
            Self::LinuxX64 => "linux-x64",
            Self::LinuxArm64 => "linux-arm64",
        })
    }
}

impl FromStr for TargetId {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "windows-x64" => Ok(Self::WindowsX64),
            "windows-arm64" => Ok(Self::WindowsArm64),
            "macos-x64" => Ok(Self::MacosX64),
            "macos-arm64" => Ok(Self::MacosArm64),
            "linux-x64" => Ok(Self::LinuxX64),
            "linux-arm64" => Ok(Self::LinuxArm64),
            _ => Err(CoreError::SupplyChain(format!(
                "unknown pack target '{value}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum EngineCapability {
    SiteExtraction,
    LivePlugin,
    GalleryExtraction,
    Hls,
    Dash,
    Mss,
    DirectHttp,
    Ftp,
    Sftp,
    Metalink,
    PostProcessing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum AdapterId {
    YtDlpV1,
    StreamlinkV1,
    NM3u8DlReV1,
    GalleryDlV1,
    FfmpegV1,
    Aria2V1,
    CurlWorkerV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EngineDescriptor {
    pub id: String,
    pub version: String,
    pub adapter_id: AdapterId,
    pub adapter_api: u32,
    pub entrypoint: String,
    pub companions: BTreeMap<String, String>,
    pub capabilities: Vec<EngineCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PackDependency {
    pub pack_id: String,
    pub version_req: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UpstreamComponent {
    pub name: String,
    pub version: String,
    pub source_url: String,
    pub source_revision: String,
    pub source_sha256: String,
    pub license_id: String,
    pub original_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum PackFileRole {
    Executable,
    Library,
    Resource,
    License,
    Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PackFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub role: PackFileRole,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PackSelfTest {
    pub engine_id: String,
    pub expected_version: String,
    pub timeout_seconds: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PackManifestV1 {
    pub schema_version: u32,
    pub id: String,
    pub version: String,
    pub target: TargetId,
    pub core_api_min: u32,
    pub core_api_max: u32,
    pub security_sequence: u64,
    pub dependencies: Vec<PackDependency>,
    pub engines: Vec<EngineDescriptor>,
    pub components: Vec<UpstreamComponent>,
    pub files: Vec<PackFile>,
    pub self_tests: Vec<PackSelfTest>,
}

impl PackManifestV1 {
    pub fn validate(&self, core_api: u32, expected_target: TargetId) -> Result<(), CoreError> {
        if self.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
            return Err(CoreError::SupplyChain(
                "unsupported pack manifest schema".into(),
            ));
        }
        validate_component(&self.id)?;
        Version::parse(&self.version)
            .map_err(|error| CoreError::SupplyChain(format!("invalid pack version: {error}")))?;
        if self.target != expected_target {
            return Err(CoreError::SupplyChain(
                "pack target does not match host".into(),
            ));
        }
        if core_api < self.core_api_min || core_api > self.core_api_max {
            return Err(CoreError::SupplyChain(
                "pack does not support this core API".into(),
            ));
        }
        if self.security_sequence == 0 || self.engines.is_empty() || self.files.is_empty() {
            return Err(CoreError::SupplyChain("pack manifest is incomplete".into()));
        }

        let mut normalized_paths = BTreeSet::new();
        for file in &self.files {
            validate_relative_path(&file.path)?;
            validate_digest(&file.sha256)?;
            let normalized = file.path.replace('\\', "/").to_lowercase();
            if !normalized_paths.insert(normalized) {
                return Err(CoreError::SupplyChain(
                    "pack contains colliding file paths".into(),
                ));
            }
        }
        for engine in &self.engines {
            validate_component(&engine.id)?;
            validate_relative_path(&engine.entrypoint)?;
            if engine.adapter_api != crate::ADAPTER_API_VERSION {
                return Err(CoreError::SupplyChain(
                    "engine adapter API is incompatible".into(),
                ));
            }
            for path in engine.companions.values() {
                validate_relative_path(path)?;
            }
        }
        for dependency in &self.dependencies {
            validate_component(&dependency.pack_id)?;
            VersionReq::parse(&dependency.version_req).map_err(|error| {
                CoreError::SupplyChain(format!("invalid dependency requirement: {error}"))
            })?;
        }
        Ok(())
    }

    pub fn verify_payload(&self, root: &Path) -> Result<(), CoreError> {
        for file in &self.files {
            let path = root.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() || metadata.len() != file.size {
                return Err(CoreError::SupplyChain(format!(
                    "pack file metadata mismatch: {}",
                    file.path
                )));
            }
            let actual = format!("{:x}", Sha256::digest(std::fs::read(&path)?));
            if !constant_time_hex_eq(&actual, &file.sha256) {
                return Err(CoreError::SupplyChain(format!(
                    "pack file hash mismatch: {}",
                    file.path
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PackDescriptor {
    pub id: String,
    pub version: String,
    pub target: TargetId,
    pub dependencies: Vec<PackDependency>,
    pub core_api_min: u32,
    pub core_api_max: u32,
    pub security_sequence: u64,
}

impl PackDescriptor {
    #[must_use]
    pub const fn supports_core_api(&self, api: u32) -> bool {
        api >= self.core_api_min && api <= self.core_api_max
    }
}

pub fn validate_component(value: &str) -> Result<(), CoreError> {
    let valid = !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value != "."
        && value != "..";
    if valid {
        Ok(())
    } else {
        Err(CoreError::SupplyChain(
            "pack path component is unsafe".into(),
        ))
    }
}

pub fn validate_relative_path(value: &str) -> Result<(), CoreError> {
    if value.is_empty()
        || value.len() > 512
        || value.contains('\0')
        || value.contains(':')
        || value.ends_with(['.', ' '])
    {
        return Err(CoreError::SupplyChain("pack path is unsafe".into()));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CoreError::SupplyChain("pack path is unsafe".into()));
    }
    for component in path.components() {
        let Component::Normal(value) = component else {
            continue;
        };
        let value = value.to_string_lossy();
        let stem = value
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err(CoreError::SupplyChain(
                "pack path uses a reserved name".into(),
            ));
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), CoreError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(CoreError::SupplyChain("invalid SHA-256 digest".into()))
    }
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_pack_paths() {
        for value in ["../escape", "C:/escape", "bin/CON", "bin/file. "] {
            assert!(validate_relative_path(value).is_err(), "{value}");
        }
        assert!(validate_relative_path("bin/yt-dlp.exe").is_ok());
    }

    #[test]
    fn target_ids_round_trip() {
        for target in [
            TargetId::WindowsX64,
            TargetId::WindowsArm64,
            TargetId::MacosX64,
            TargetId::MacosArm64,
            TargetId::LinuxX64,
            TargetId::LinuxArm64,
        ] {
            assert_eq!(target.to_string().parse::<TargetId>().unwrap(), target);
        }
    }
}
