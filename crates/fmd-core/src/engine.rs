use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};
use std::str::FromStr;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ts_rs::TS;
use unicode_normalization::UnicodeNormalization;
use url::Url;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, TS)]
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
    #[must_use]
    pub fn license_digest(&self) -> String {
        let mut digest = Sha256::new();
        for component in &self.components {
            digest.update(component.name.as_bytes());
            digest.update([0]);
            digest.update(component.license_id.as_bytes());
            digest.update([0xff]);
        }
        for file in self
            .files
            .iter()
            .filter(|file| matches!(file.role, PackFileRole::License))
        {
            digest.update(file.path.as_bytes());
            digest.update([0]);
            digest.update(file.sha256.as_bytes());
            digest.update([0xff]);
        }
        format!("{:x}", digest.finalize())
    }

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
        if self.core_api_min == 0 || self.core_api_min > self.core_api_max {
            return Err(CoreError::SupplyChain(
                "pack core API range is invalid".into(),
            ));
        }

        let mut normalized_paths = BTreeSet::new();
        let mut files_by_path = BTreeMap::new();
        for file in &self.files {
            validate_relative_path(&file.path)?;
            validate_digest(&file.sha256)?;
            let normalized = collision_key(&file.path);
            if !normalized_paths.insert(normalized) {
                return Err(CoreError::SupplyChain(
                    "pack contains colliding file paths".into(),
                ));
            }
            if file.executable != matches!(file.role, PackFileRole::Executable) {
                return Err(CoreError::SupplyChain(
                    "pack executable flag does not match file role".into(),
                ));
            }
            files_by_path.insert(file.path.as_str(), file);
        }
        let mut engine_ids = BTreeSet::new();
        for engine in &self.engines {
            validate_component(&engine.id)?;
            if !engine_ids.insert(engine.id.as_str()) {
                return Err(CoreError::SupplyChain(
                    "pack contains duplicate engine identifiers".into(),
                ));
            }
            validate_relative_path(&engine.entrypoint)?;
            if engine.adapter_api != crate::ADAPTER_API_VERSION {
                return Err(CoreError::SupplyChain(
                    "engine adapter API is incompatible".into(),
                ));
            }
            if !files_by_path
                .get(engine.entrypoint.as_str())
                .is_some_and(|file| file.executable)
            {
                return Err(CoreError::SupplyChain(
                    "engine entrypoint is not a declared executable".into(),
                ));
            }
            if engine.capabilities.is_empty()
                || engine.capabilities.iter().collect::<BTreeSet<_>>().len()
                    != engine.capabilities.len()
            {
                return Err(CoreError::SupplyChain(
                    "engine capabilities are empty or duplicated".into(),
                ));
            }
            for path in engine.companions.values() {
                validate_relative_path(path)?;
                if !files_by_path.contains_key(path.as_str()) {
                    return Err(CoreError::SupplyChain(
                        "engine companion is not declared in the payload".into(),
                    ));
                }
            }
        }
        let mut dependency_ids = BTreeSet::new();
        for dependency in &self.dependencies {
            validate_component(&dependency.pack_id)?;
            if dependency.pack_id == self.id || !dependency_ids.insert(dependency.pack_id.as_str())
            {
                return Err(CoreError::SupplyChain(
                    "pack dependency is self-referential or duplicated".into(),
                ));
            }
            VersionReq::parse(&dependency.version_req).map_err(|error| {
                CoreError::SupplyChain(format!("invalid dependency requirement: {error}"))
            })?;
        }
        let mut component_names = BTreeSet::new();
        for component in &self.components {
            validate_component(&component.name)?;
            if !component_names.insert(component.name.as_str())
                || component.version.is_empty()
                || component.source_revision.is_empty()
                || component.license_id.is_empty()
            {
                return Err(CoreError::SupplyChain(
                    "upstream component metadata is incomplete or duplicated".into(),
                ));
            }
            let source_url = Url::parse(&component.source_url)
                .map_err(|_| CoreError::SupplyChain("component source URL is invalid".into()))?;
            if source_url.scheme() != "https" || source_url.host_str().is_none() {
                return Err(CoreError::SupplyChain(
                    "component source URL must use HTTPS".into(),
                ));
            }
            validate_digest(&component.source_sha256)?;
            if let Some(original) = &component.original_sha256 {
                validate_digest(original)?;
            }
        }
        let mut tested_engines = BTreeSet::new();
        for test in &self.self_tests {
            let engine = self
                .engines
                .iter()
                .find(|engine| engine.id == test.engine_id)
                .ok_or_else(|| CoreError::SupplyChain("self-test engine is unknown".into()))?;
            if !tested_engines.insert(test.engine_id.as_str())
                || test.expected_version != engine.version
                || !(1..=300).contains(&test.timeout_seconds)
            {
                return Err(CoreError::SupplyChain(
                    "pack self-test is duplicated or inconsistent".into(),
                ));
            }
        }
        if tested_engines.len() != self.engines.len() {
            return Err(CoreError::SupplyChain(
                "every engine must have an exact version self-test".into(),
            ));
        }
        Ok(())
    }

    pub fn verify_payload(&self, root: &Path) -> Result<(), CoreError> {
        let expected = self
            .files
            .iter()
            .map(|file| (file.path.clone(), file))
            .collect::<BTreeMap<_, _>>();
        let mut actual = BTreeSet::new();
        collect_payload_paths(root, root, &mut actual)?;
        let expected_paths = expected.keys().cloned().collect::<BTreeSet<_>>();
        if actual != expected_paths {
            return Err(CoreError::SupplyChain(
                "pack payload contains missing or undeclared files".into(),
            ));
        }
        for file in &self.files {
            let path = root.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() || metadata.len() != file.size {
                return Err(CoreError::SupplyChain(format!(
                    "pack file metadata mismatch: {}",
                    file.path
                )));
            }
            let actual = hash_file(&path)?;
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
        || value.contains('\\')
        || value.ends_with(['.', ' '])
        || value.nfc().collect::<String>() != value
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

pub fn collision_key(value: &str) -> String {
    value.nfc().flat_map(char::to_lowercase).collect()
}

fn collect_payload_paths(
    root: &Path,
    directory: &Path,
    paths: &mut BTreeSet<String>,
) -> Result<(), CoreError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(CoreError::SupplyChain(
                "links are forbidden in pack payloads".into(),
            ));
        }
        if metadata.is_dir() {
            collect_payload_paths(root, &path, paths)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| CoreError::SupplyChain("pack path escaped its root".into()))?;
            let normalized = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            if normalized == "manifest.json" {
                continue;
            }
            validate_relative_path(&normalized)?;
            if !paths.insert(normalized) {
                return Err(CoreError::SupplyChain(
                    "pack contains duplicate payload paths".into(),
                ));
            }
        } else {
            return Err(CoreError::SupplyChain(
                "special files are forbidden in pack payloads".into(),
            ));
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, CoreError> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
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
    use tempfile::tempdir;

    #[test]
    fn rejects_unsafe_pack_paths() {
        for value in [
            "../escape",
            "C:/escape",
            "bin/CON",
            "bin/file. ",
            "bin\\tool",
            "resources/e\u{301}.txt",
        ] {
            assert!(validate_relative_path(value).is_err(), "{value}");
        }
        assert!(validate_relative_path("bin/yt-dlp.exe").is_ok());
        assert!(validate_relative_path("resources/é.txt").is_ok());
    }

    #[test]
    fn payload_verification_rejects_undeclared_files() {
        let temporary = tempdir().unwrap();
        let declared_path = temporary.path().join("declared.txt");
        std::fs::write(&declared_path, b"declared").unwrap();
        std::fs::write(temporary.path().join("extra.txt"), b"extra").unwrap();
        let manifest = PackManifestV1 {
            schema_version: PACK_MANIFEST_SCHEMA_VERSION,
            id: "test-pack".into(),
            version: "1.0.0".into(),
            target: TargetId::current().unwrap(),
            core_api_min: 1,
            core_api_max: 1,
            security_sequence: 1,
            dependencies: Vec::new(),
            engines: Vec::new(),
            components: Vec::new(),
            files: vec![PackFile {
                path: "declared.txt".into(),
                size: 8,
                sha256: format!("{:x}", Sha256::digest(b"declared")),
                role: PackFileRole::Resource,
                executable: false,
            }],
            self_tests: Vec::new(),
        };
        assert!(manifest.verify_payload(temporary.path()).is_err());
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
