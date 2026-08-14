use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use futures_util::StreamExt;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tough::{ExpirationEnforcement, Limits, RepositoryLoader, TargetName};
use url::Url;
use uuid::Uuid;
use zip::ZipArchive;

use crate::ADAPTER_API_VERSION;
use crate::adapter::InstalledEngine;
use crate::engine::{PackManifestV1, TargetId, validate_component};
use crate::error::CoreError;

const MAX_ARCHIVE_FILES: usize = 20_000;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

pub struct TufRepository {
    repository: tough::Repository,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedExternalTarget {
    pub name: String,
    pub pack_id: String,
    pub pack_version: String,
    pub target: TargetId,
    pub security_sequence: u64,
    pub download_url: Url,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedDescriptorTarget {
    pub name: String,
    pub component: String,
    pub version: String,
    pub target: TargetId,
    pub security_sequence: u64,
    pub pack_id: Option<String>,
    pub descriptor_length: u64,
    pub descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptorV1 {
    pub schema_version: u32,
    pub target_name: String,
    pub component: String,
    pub version: String,
    pub target: TargetId,
    pub security_sequence: u64,
    pub pack_id: Option<String>,
    pub artifact_url: Url,
    pub artifact_length: u64,
    pub artifact_sha256: String,
    pub unsigned: bool,
}

impl TufRepository {
    pub async fn load(
        trusted_root: &[u8],
        metadata_base_url: Url,
        targets_base_url: Url,
    ) -> Result<Self, CoreError> {
        Self::load_inner(
            trusted_root,
            metadata_base_url,
            targets_base_url,
            None,
            None,
        )
        .await
    }

    pub async fn load_persistent(
        trusted_root: &[u8],
        metadata_base_url: Url,
        targets_base_url: Url,
        datastore: &Path,
        allowed_https_hosts: &[&str],
    ) -> Result<Self, CoreError> {
        validate_production_origin(&metadata_base_url, allowed_https_hosts)?;
        validate_production_origin(&targets_base_url, allowed_https_hosts)?;
        fs::create_dir_all(datastore)?;
        Self::load_inner(
            trusted_root,
            metadata_base_url,
            targets_base_url,
            Some(datastore),
            Some(Limits {
                max_root_size: 1024 * 1024,
                max_targets_size: 8 * 1024 * 1024,
                max_timestamp_size: 512 * 1024,
                max_snapshot_size: 1024 * 1024,
                max_root_updates: 64,
            }),
        )
        .await
    }

    async fn load_inner(
        trusted_root: &[u8],
        metadata_base_url: Url,
        targets_base_url: Url,
        datastore: Option<&Path>,
        limits: Option<Limits>,
    ) -> Result<Self, CoreError> {
        let mut loader = RepositoryLoader::new(&trusted_root, metadata_base_url, targets_base_url)
            .expiration_enforcement(ExpirationEnforcement::Safe);
        if let Some(datastore) = datastore {
            loader = loader.datastore(datastore);
        }
        if let Some(limits) = limits {
            loader = loader.limits(limits);
        }
        let repository = loader
            .load()
            .await
            .map_err(|error| CoreError::SupplyChain(error.to_string()))?;
        Ok(Self { repository })
    }

    pub async fn download_target(
        &self,
        name: &str,
        destination: &Path,
        max_bytes: u64,
    ) -> Result<DownloadedTarget, CoreError> {
        let name =
            TargetName::new(name).map_err(|error| CoreError::SupplyChain(error.to_string()))?;
        let stream = self
            .repository
            .read_target(&name)
            .await
            .map_err(|error| CoreError::SupplyChain(error.to_string()))?
            .ok_or_else(|| CoreError::SupplyChain("target was not found".into()))?;
        if destination.exists() {
            return Err(CoreError::SupplyChain(
                "target staging path already exists".into(),
            ));
        }
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .await?;
        futures_util::pin_mut!(stream);
        let mut length = 0_u64;
        let mut digest = Sha256::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| CoreError::SupplyChain(error.to_string()))?;
            length = length.saturating_add(chunk.len() as u64);
            if length > max_bytes {
                return Err(CoreError::SupplyChain(
                    "target exceeds the configured size limit".into(),
                ));
            }
            digest.update(&chunk);
            output.write_all(&chunk).await?;
        }
        output.flush().await?;
        output.sync_all().await?;
        Ok(DownloadedTarget {
            length,
            sha256: format!("{:x}", digest.finalize()),
        })
    }

    pub fn descriptor_target(&self, name: &str) -> Result<AuthorizedDescriptorTarget, CoreError> {
        let target_name =
            TargetName::new(name).map_err(|error| CoreError::SupplyChain(error.to_string()))?;
        let (_, target) = self
            .repository
            .targets()
            .signed
            .targets_iter()
            .find(|(candidate, _)| **candidate == target_name)
            .ok_or_else(|| CoreError::SupplyChain("target was not found".into()))?;
        let custom = &target.custom;
        let text = |field: &str| {
            custom
                .get(field)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    CoreError::SupplyChain(format!("target custom field '{field}' is missing"))
                })
        };
        let component = text("component")?;
        if !matches!(component.as_str(), "core" | "engine_pack") {
            return Err(CoreError::SupplyChain(
                "target component is not supported".into(),
            ));
        }
        let security_sequence = custom
            .get("security_sequence")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| CoreError::SupplyChain("target security_sequence is missing".into()))?;
        let target_id = text("target")?
            .parse()
            .map_err(|_| CoreError::SupplyChain("target platform is invalid".into()))?;
        let pack_id = custom
            .get("pack_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if component == "engine_pack" && pack_id.is_none() {
            return Err(CoreError::SupplyChain(
                "engine target pack_id is missing".into(),
            ));
        }
        if component == "core" && pack_id.is_some() {
            return Err(CoreError::SupplyChain(
                "core target cannot declare pack_id".into(),
            ));
        }
        Ok(AuthorizedDescriptorTarget {
            name: name.to_owned(),
            component,
            version: text("version")?,
            target: target_id,
            security_sequence,
            pack_id,
            descriptor_length: target.length,
            descriptor_sha256: encode_hex(target.hashes.sha256.as_ref()),
        })
    }

    pub fn descriptor_targets(&self) -> Result<Vec<AuthorizedDescriptorTarget>, CoreError> {
        self.repository
            .targets()
            .signed
            .targets_iter()
            .map(|(name, _)| self.descriptor_target(name.resolved()))
            .collect()
    }

    pub async fn read_artifact_descriptor(
        &self,
        authorization: &AuthorizedDescriptorTarget,
        max_bytes: u64,
    ) -> Result<ArtifactDescriptorV1, CoreError> {
        if authorization.descriptor_length > max_bytes {
            return Err(CoreError::SupplyChain(
                "update descriptor exceeds the configured size limit".into(),
            ));
        }
        let name = TargetName::new(&authorization.name)
            .map_err(|error| CoreError::SupplyChain(error.to_string()))?;
        let stream = self
            .repository
            .read_target(&name)
            .await
            .map_err(|error| CoreError::SupplyChain(error.to_string()))?
            .ok_or_else(|| CoreError::SupplyChain("target descriptor was not found".into()))?;
        futures_util::pin_mut!(stream);
        let mut bytes = Vec::with_capacity(authorization.descriptor_length as usize);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| CoreError::SupplyChain(error.to_string()))?;
            if bytes.len().saturating_add(chunk.len()) as u64 > max_bytes {
                return Err(CoreError::SupplyChain(
                    "update descriptor exceeds the configured size limit".into(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let descriptor: ArtifactDescriptorV1 = serde_json::from_slice(&bytes)?;
        descriptor.validate_against(authorization)?;
        Ok(descriptor)
    }

    pub async fn download_artifact(
        &self,
        descriptor: &ArtifactDescriptorV1,
        destination: &Path,
        allowed_https_hosts: &[&str],
    ) -> Result<DownloadedTarget, CoreError> {
        let authorization = AuthorizedExternalTarget {
            name: descriptor.target_name.clone(),
            pack_id: descriptor.pack_id.clone().unwrap_or_else(|| "core".into()),
            pack_version: descriptor.version.clone(),
            target: descriptor.target,
            security_sequence: descriptor.security_sequence,
            download_url: descriptor.artifact_url.clone(),
            length: descriptor.artifact_length,
            sha256: descriptor.artifact_sha256.clone(),
        };
        self.download_external_target(&authorization, destination, allowed_https_hosts)
            .await
    }

    pub fn external_target(&self, name: &str) -> Result<AuthorizedExternalTarget, CoreError> {
        let target_name =
            TargetName::new(name).map_err(|error| CoreError::SupplyChain(error.to_string()))?;
        let (_, target) = self
            .repository
            .targets()
            .signed
            .targets_iter()
            .find(|(candidate, _)| **candidate == target_name)
            .ok_or_else(|| CoreError::SupplyChain("target was not found".into()))?;
        let custom = &target.custom;
        let text = |field: &str| {
            custom
                .get(field)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    CoreError::SupplyChain(format!("target custom field '{field}' is missing"))
                })
        };
        let sequence = custom
            .get("security_sequence")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| CoreError::SupplyChain("target security_sequence is missing".into()))?;
        let target_id = text("target")?
            .parse()
            .map_err(|_| CoreError::SupplyChain("target platform is invalid".into()))?;
        Ok(AuthorizedExternalTarget {
            name: name.to_owned(),
            pack_id: text("pack_id")?,
            pack_version: text("pack_version")?,
            target: target_id,
            security_sequence: sequence,
            download_url: Url::parse(&text("download_url")?)
                .map_err(|_| CoreError::SupplyChain("target download URL is invalid".into()))?,
            length: target.length,
            sha256: encode_hex(target.hashes.sha256.as_ref()),
        })
    }

    pub fn external_targets(&self) -> Result<Vec<AuthorizedExternalTarget>, CoreError> {
        self.repository
            .targets()
            .signed
            .targets_iter()
            .map(|(name, _)| self.external_target(name.resolved()))
            .collect()
    }

    pub async fn download_external_target(
        &self,
        target: &AuthorizedExternalTarget,
        destination: &Path,
        allowed_https_hosts: &[&str],
    ) -> Result<DownloadedTarget, CoreError> {
        validate_production_origin(&target.download_url, allowed_https_hosts)?;
        if destination.exists() {
            return Err(CoreError::SupplyChain(
                "target staging path already exists".into(),
            ));
        }
        let hosts = allowed_https_hosts
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                let url = attempt.url();
                if attempt.previous().len() > 5
                    || url.scheme() != "https"
                    || !url
                        .host_str()
                        .is_some_and(|host| hosts.iter().any(|allowed| allowed == host))
                {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .map_err(|error| CoreError::SupplyChain(error.to_string()))?;
        let response = client
            .get(target.download_url.clone())
            .send()
            .await
            .map_err(|error| CoreError::SupplyChain(error.to_string()))?
            .error_for_status()
            .map_err(|error| CoreError::SupplyChain(error.to_string()))?;
        let mut stream = response.bytes_stream();
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .await?;
        let mut length = 0_u64;
        let mut digest = Sha256::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| CoreError::SupplyChain(error.to_string()))?;
            length = length.saturating_add(chunk.len() as u64);
            if length > target.length {
                return Err(CoreError::SupplyChain(
                    "target length exceeds TUF metadata".into(),
                ));
            }
            digest.update(&chunk);
            output.write_all(&chunk).await?;
        }
        output.flush().await?;
        output.sync_all().await?;
        let downloaded = DownloadedTarget {
            length,
            sha256: format!("{:x}", digest.finalize()),
        };
        if downloaded.length != target.length || downloaded.sha256 != target.sha256 {
            let _ = tokio::fs::remove_file(destination).await;
            return Err(CoreError::SupplyChain(
                "external target does not match TUF metadata".into(),
            ));
        }
        Ok(downloaded)
    }
}

impl ArtifactDescriptorV1 {
    pub fn validate_against(
        &self,
        authorization: &AuthorizedDescriptorTarget,
    ) -> Result<(), CoreError> {
        if self.schema_version != 1
            || self.target_name != authorization.name
            || self.component != authorization.component
            || self.version != authorization.version
            || self.target != authorization.target
            || self.security_sequence != authorization.security_sequence
            || self.pack_id != authorization.pack_id
            || self.artifact_length == 0
            || !is_sha256(&self.artifact_sha256)
        {
            return Err(CoreError::SupplyChain(
                "artifact descriptor does not match its TUF authorization".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn external_authorization(&self) -> AuthorizedExternalTarget {
        AuthorizedExternalTarget {
            name: self.target_name.clone(),
            pack_id: self.pack_id.clone().unwrap_or_else(|| "core".into()),
            pack_version: self.version.clone(),
            target: self.target,
            security_sequence: self.security_sequence,
            download_url: self.artifact_url.clone(),
            length: self.artifact_length,
            sha256: self.artifact_sha256.clone(),
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_production_origin(url: &Url, allowed_hosts: &[&str]) -> Result<(), CoreError> {
    let host = url.host_str().unwrap_or_default();
    if url.scheme() != "https" || !allowed_hosts.contains(&host) {
        return Err(CoreError::SupplyChain(
            "TUF origin is not in the production allowlist".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadedTarget {
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    pub max_files: usize,
    pub max_expanded_bytes: u64,
    pub max_compression_ratio: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_ARCHIVE_FILES,
            max_expanded_bytes: 1024 * 1024 * 1024,
            max_compression_ratio: 200,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationPointer {
    pub pack_id: String,
    pub version: String,
    pub target: TargetId,
    pub security_sequence: u64,
    pub manifest_sha256: String,
}

impl ActivationPointer {
    fn validate(&self, expected_pack_id: &str) -> Result<(), CoreError> {
        validate_component(&self.pack_id)?;
        validate_component(&self.version)?;
        if self.pack_id != expected_pack_id || self.security_sequence == 0 {
            return Err(CoreError::SupplyChain(
                "activation pointer identity is invalid".into(),
            ));
        }
        if self.manifest_sha256.len() != 64
            || !self
                .manifest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CoreError::SupplyChain(
                "activation pointer digest is invalid".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PackLayout {
    root: PathBuf,
}

impl PackLayout {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn version_directory(
        &self,
        id: &str,
        version: &str,
        target: TargetId,
    ) -> Result<PathBuf, CoreError> {
        validate_component(id)?;
        validate_component(version)?;
        Ok(self.root.join(id).join(version).join(target.to_string()))
    }

    pub fn active(&self, id: &str) -> Result<Option<ActivationPointer>, CoreError> {
        validate_component(id)?;
        let path = self.root.join("active").join(format!("{id}.json"));
        if !path.is_file() {
            return Ok(None);
        }
        let pointer: ActivationPointer = serde_json::from_slice(&fs::read(path)?)?;
        pointer.validate(id)?;
        Ok(Some(pointer))
    }

    pub fn active_pointers(&self) -> Result<Vec<ActivationPointer>, CoreError> {
        let active = self.root.join("active");
        if !active.is_dir() {
            return Ok(Vec::new());
        }
        let mut pointers = Vec::new();
        for entry in fs::read_dir(active)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| CoreError::SupplyChain("activation filename is invalid".into()))?;
            let pointer: ActivationPointer = serde_json::from_slice(&fs::read(&path)?)?;
            pointer.validate(id)?;
            pointers.push(pointer);
        }
        pointers.sort_by(|left, right| left.pack_id.cmp(&right.pack_id));
        Ok(pointers)
    }

    pub fn installed_engines(&self) -> Result<Vec<InstalledEngine>, CoreError> {
        let active = self.root.join("active");
        if !active.is_dir() {
            return Ok(Vec::new());
        }
        let mut engines = Vec::new();
        for pointer in self.active_pointers()? {
            let root =
                self.version_directory(&pointer.pack_id, &pointer.version, pointer.target)?;
            let manifest_bytes = fs::read(root.join("manifest.json"))?;
            let manifest_sha256 = format!("{:x}", Sha256::digest(&manifest_bytes));
            if manifest_sha256 != pointer.manifest_sha256 {
                return Err(CoreError::SupplyChain(
                    "active pack manifest no longer matches activation pointer".into(),
                ));
            }
            let manifest: PackManifestV1 = serde_json::from_slice(&manifest_bytes)?;
            manifest.validate(ADAPTER_API_VERSION, pointer.target)?;
            if manifest.id != pointer.pack_id
                || manifest.version != pointer.version
                || manifest.security_sequence != pointer.security_sequence
            {
                return Err(CoreError::SupplyChain(
                    "active manifest identity does not match its pointer".into(),
                ));
            }
            manifest.verify_payload(&root)?;
            engines.extend(
                manifest
                    .engines
                    .into_iter()
                    .map(|descriptor| InstalledEngine {
                        descriptor,
                        pack_id: pointer.pack_id.clone(),
                        pack_version: pointer.version.clone(),
                        root: root.clone(),
                        shared_companions: std::collections::BTreeMap::new(),
                    }),
            );
        }
        Ok(engines)
    }

    pub fn activate_existing(
        &self,
        id: &str,
        version: &str,
        target: TargetId,
        minimum_security_sequence: u64,
    ) -> Result<ActivationPointer, CoreError> {
        let root = self.version_directory(id, version, target)?;
        let manifest: PackManifestV1 =
            serde_json::from_slice(&fs::read(root.join("manifest.json"))?)?;
        manifest.validate(ADAPTER_API_VERSION, target)?;
        if manifest.id != id
            || manifest.version != version
            || manifest.security_sequence < minimum_security_sequence
        {
            return Err(CoreError::SupplyChain(
                "rollback candidate is incompatible or below the security high-water mark".into(),
            ));
        }
        self.activate(&manifest)
    }

    pub fn recover_staging(&self) -> Result<usize, CoreError> {
        let staging = self.root.join("staging");
        if !staging.is_dir() {
            return Ok(0);
        }
        let mut removed = 0;
        for entry in fs::read_dir(&staging)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(CoreError::SupplyChain(
                    "pack staging contains an unexpected link".into(),
                ));
            }
            if metadata.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
            removed += 1;
        }
        sync_directory(&staging)?;
        Ok(removed)
    }

    pub fn garbage_collect_unleased(
        &self,
        leases: &std::collections::BTreeSet<(String, String, String)>,
    ) -> Result<Vec<String>, CoreError> {
        if !self.root.is_dir() {
            return Ok(Vec::new());
        }
        let active = self
            .active_pointers()?
            .into_iter()
            .map(|pointer| (pointer.pack_id, pointer.version, pointer.target.to_string()))
            .collect::<std::collections::BTreeSet<_>>();
        let mut removed = Vec::new();
        for pack_entry in fs::read_dir(&self.root)? {
            let pack_path = pack_entry?.path();
            let Some(pack_id) = pack_path.file_name().and_then(|value| value.to_str()) else {
                return Err(CoreError::SupplyChain(
                    "pack directory name is invalid".into(),
                ));
            };
            if matches!(pack_id, "active" | "staging") {
                continue;
            }
            validate_component(pack_id)?;
            reject_link_or_non_directory(&pack_path)?;
            for version_entry in fs::read_dir(&pack_path)? {
                let version_path = version_entry?.path();
                let version = version_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| CoreError::SupplyChain("pack version path is invalid".into()))?;
                validate_component(version)?;
                reject_link_or_non_directory(&version_path)?;
                for target_entry in fs::read_dir(&version_path)? {
                    let target_path = target_entry?.path();
                    let target = target_path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| {
                            CoreError::SupplyChain("pack target path is invalid".into())
                        })?;
                    target.parse::<TargetId>()?;
                    reject_link_or_non_directory(&target_path)?;
                    let identity = (pack_id.to_owned(), version.to_owned(), target.to_owned());
                    if active.contains(&identity) || leases.contains(&identity) {
                        continue;
                    }
                    fs::remove_dir_all(&target_path)?;
                    removed.push(format!("{pack_id}@{version}/{target}"));
                }
                if fs::read_dir(&version_path)?.next().is_none() {
                    fs::remove_dir(&version_path)?;
                }
            }
            if fs::read_dir(&pack_path)?.next().is_none() {
                fs::remove_dir(&pack_path)?;
            }
        }
        removed.sort();
        sync_directory(&self.root)?;
        Ok(removed)
    }

    pub fn resolve_engine(&self, id: &str) -> Result<Option<InstalledEngine>, CoreError> {
        Ok(self
            .installed_engines()?
            .into_iter()
            .find(|engine| engine.descriptor.id == id))
    }

    pub fn activate(&self, manifest: &PackManifestV1) -> Result<ActivationPointer, CoreError> {
        manifest.validate(ADAPTER_API_VERSION, manifest.target)?;
        let directory = self.version_directory(&manifest.id, &manifest.version, manifest.target)?;
        manifest.verify_payload(&directory)?;
        let manifest_bytes = fs::read(directory.join("manifest.json"))?;
        let pointer = ActivationPointer {
            pack_id: manifest.id.clone(),
            version: manifest.version.clone(),
            target: manifest.target,
            security_sequence: manifest.security_sequence,
            manifest_sha256: format!("{:x}", Sha256::digest(manifest_bytes)),
        };
        let active = self.root.join("active");
        fs::create_dir_all(&active)?;
        atomic_write_json(&active.join(format!("{}.json", manifest.id)), &pointer)?;
        Ok(pointer)
    }
}

fn reject_link_or_non_directory(path: &Path) -> Result<(), CoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CoreError::SupplyChain(
            "pack layout contains a link or non-directory entry".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct PackInstaller {
    layout: PackLayout,
    target: TargetId,
    core_api: u32,
    limits: ExtractionLimits,
}

impl PackInstaller {
    #[must_use]
    pub fn new(layout: PackLayout, target: TargetId, limits: ExtractionLimits) -> Self {
        Self {
            layout,
            target,
            core_api: ADAPTER_API_VERSION,
            limits,
        }
    }

    pub fn install_archive(&self, archive_path: &Path) -> Result<PackManifestV1, CoreError> {
        self.install_archive_inner(archive_path, None)
    }

    pub fn install_authorized_archive(
        &self,
        archive_path: &Path,
        authorization: &AuthorizedExternalTarget,
    ) -> Result<PackManifestV1, CoreError> {
        if authorization.target != self.target {
            return Err(CoreError::SupplyChain(
                "authorized target does not match the installer target".into(),
            ));
        }
        self.install_archive_inner(archive_path, Some(authorization))
    }

    fn install_archive_inner(
        &self,
        archive_path: &Path,
        authorization: Option<&AuthorizedExternalTarget>,
    ) -> Result<PackManifestV1, CoreError> {
        let staging = self
            .layout
            .root
            .join("staging")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&staging)?;
        let result = self.install_staged(archive_path, &staging, authorization);
        if staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    fn install_staged(
        &self,
        archive_path: &Path,
        staging: &Path,
        authorization: Option<&AuthorizedExternalTarget>,
    ) -> Result<PackManifestV1, CoreError> {
        let manifest = self.extract_and_verify(archive_path, staging)?;
        if authorization.is_some_and(|expected| {
            manifest.id != expected.pack_id
                || manifest.version != expected.pack_version
                || manifest.target != expected.target
                || manifest.security_sequence != expected.security_sequence
        }) {
            return Err(CoreError::SupplyChain(
                "pack manifest does not match its TUF authorization".into(),
            ));
        }
        for dependency in manifest
            .dependencies
            .iter()
            .filter(|dependency| dependency.required)
        {
            let active = self.layout.active(&dependency.pack_id)?.ok_or_else(|| {
                CoreError::SupplyChain(format!(
                    "required pack dependency is not active: {}",
                    dependency.pack_id
                ))
            })?;
            let version = Version::parse(&active.version).map_err(|error| {
                CoreError::SupplyChain(format!("active dependency version is invalid: {error}"))
            })?;
            let requirement = VersionReq::parse(&dependency.version_req).map_err(|error| {
                CoreError::SupplyChain(format!("dependency requirement is invalid: {error}"))
            })?;
            if !requirement.matches(&version) {
                return Err(CoreError::SupplyChain(format!(
                    "pack dependency version does not match: {}",
                    dependency.pack_id
                )));
            }
        }
        let final_directory =
            self.layout
                .version_directory(&manifest.id, &manifest.version, manifest.target)?;
        if final_directory.exists() {
            let existing: PackManifestV1 =
                serde_json::from_slice(&fs::read(final_directory.join("manifest.json"))?)?;
            if existing != manifest {
                return Err(CoreError::SupplyChain(
                    "immutable pack version already exists with different content".into(),
                ));
            }
            return Ok(existing);
        }
        fs::create_dir_all(
            final_directory
                .parent()
                .ok_or_else(|| CoreError::SupplyChain("pack destination has no parent".into()))?,
        )?;
        replace_file(staging, &final_directory)?;
        sync_directory(
            final_directory
                .parent()
                .ok_or_else(|| CoreError::SupplyChain("pack destination has no parent".into()))?,
        )?;
        Ok(manifest)
    }

    fn extract_and_verify(
        &self,
        archive_path: &Path,
        staging: &Path,
    ) -> Result<PackManifestV1, CoreError> {
        let mut archive = ZipArchive::new(File::open(archive_path)?)
            .map_err(|error| CoreError::SupplyChain(error.to_string()))?;
        if archive.len() > self.limits.max_files {
            return Err(CoreError::SupplyChain(
                "pack contains too many files".into(),
            ));
        }
        let mut expanded = 0_u64;
        let mut archive_paths = std::collections::BTreeSet::new();
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|error| CoreError::SupplyChain(error.to_string()))?;
            let enclosed = entry
                .enclosed_name()
                .ok_or_else(|| CoreError::SupplyChain("unsafe ZIP path".into()))?
                .to_path_buf();
            let name = enclosed.to_string_lossy().replace('\\', "/");
            let name = name.trim_end_matches('/');
            crate::engine::validate_relative_path(name)?;
            if !archive_paths.insert(crate::engine::collision_key(name)) {
                return Err(CoreError::SupplyChain(
                    "ZIP contains duplicate or colliding paths".into(),
                ));
            }
            expanded = expanded.saturating_add(entry.size());
            if expanded > self.limits.max_expanded_bytes {
                return Err(CoreError::SupplyChain(
                    "pack exceeds expanded size limit".into(),
                ));
            }
            let ratio_limit = entry
                .compressed_size()
                .saturating_mul(self.limits.max_compression_ratio)
                .saturating_add(1024 * 1024);
            if entry.size() > ratio_limit {
                return Err(CoreError::SupplyChain(
                    "pack entry exceeds compression ratio limit".into(),
                ));
            }
            if let Some(mode) = entry.unix_mode() {
                let kind = mode & 0o170000;
                if kind != 0 && kind != 0o100000 && kind != 0o040000 {
                    return Err(CoreError::SupplyChain(
                        "links and special files are forbidden in packs".into(),
                    ));
                }
            }
            let output = staging.join(&enclosed);
            if entry.is_dir() {
                fs::create_dir_all(&output)?;
                continue;
            }
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut destination = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            std::io::copy(&mut entry, &mut destination)?;
            destination.flush()?;
            destination.sync_all()?;
        }

        let manifest_path = staging.join("manifest.json");
        let metadata = fs::metadata(&manifest_path)?;
        if metadata.len() > MAX_MANIFEST_BYTES {
            return Err(CoreError::SupplyChain("pack manifest is too large".into()));
        }
        let manifest: PackManifestV1 = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        manifest.validate(self.core_api, self.target)?;
        if !staging.join("LICENSES").is_dir()
            || !staging.join("sbom.spdx.json").is_file()
            || !staging.join("provenance.intoto.jsonl").is_file()
            || !staging.join("sources.json").is_file()
        {
            return Err(CoreError::SupplyChain(
                "pack is missing licenses, SBOM, provenance, or source metadata".into(),
            ));
        }
        manifest.verify_payload(staging)?;
        apply_manifest_permissions(staging, &manifest)?;
        Ok(manifest)
    }
}

#[cfg(unix)]
fn apply_manifest_permissions(root: &Path, manifest: &PackManifestV1) -> Result<(), CoreError> {
    use std::os::unix::fs::PermissionsExt;

    for file in &manifest.files {
        let path = root.join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        let mode = if file.executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_manifest_permissions(_root: &Path, _manifest: &PackManifestV1) -> Result<(), CoreError> {
    Ok(())
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CoreError> {
    let parent = path
        .parent()
        .ok_or_else(|| CoreError::SupplyChain("activation path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let candidate = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&candidate)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    replace_file(&candidate, path)?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), CoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), CoreError> {
    // replace_file uses MOVEFILE_WRITE_THROUGH on Windows. Opening directories for FlushFileBuffers
    // is not portable across supported Windows filesystems, so there is no additional directory
    // flush here.
    Ok(())
}

#[cfg(unix)]
fn replace_file(candidate: &Path, destination: &Path) -> Result<(), CoreError> {
    fs::rename(candidate, destination)?;
    Ok(())
}

#[cfg(windows)]
fn replace_file(candidate: &Path, destination: &Path) -> Result<(), CoreError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_WRITE_THROUGH, MoveFileExW, ReplaceFileW,
    };
    let wide = |path: &Path| {
        path.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    };
    let source = wide(candidate);
    let target = wide(destination);
    let success = unsafe {
        if destination.exists() {
            ReplaceFileW(
                target.as_ptr(),
                source.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } else {
            MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH)
        }
    };
    if success == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        AdapterId, EngineCapability, EngineDescriptor, PackDependency, PackFile, PackFileRole,
        PackSelfTest, UpstreamComponent,
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    fn write_test_pack(
        path: &Path,
        dependencies: Vec<PackDependency>,
        extra: Option<(&str, &[u8])>,
    ) {
        let payload = [
            ("bin/tool", b"tool".as_slice(), PackFileRole::Executable),
            (
                "LICENSES/test.txt",
                b"license".as_slice(),
                PackFileRole::License,
            ),
            ("sbom.spdx.json", b"{}".as_slice(), PackFileRole::Metadata),
            (
                "provenance.intoto.jsonl",
                b"{}\n".as_slice(),
                PackFileRole::Metadata,
            ),
            ("sources.json", b"{}".as_slice(), PackFileRole::Metadata),
        ];
        let files = payload
            .iter()
            .map(|(path, bytes, role)| PackFile {
                path: (*path).into(),
                size: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
                role: *role,
                executable: matches!(*role, PackFileRole::Executable),
            })
            .collect();
        let manifest = PackManifestV1 {
            schema_version: 1,
            id: "test-pack".into(),
            version: "1.0.0".into(),
            target: TargetId::current().unwrap(),
            core_api_min: 1,
            core_api_max: 1,
            security_sequence: 1,
            dependencies,
            engines: vec![EngineDescriptor {
                id: "test-engine".into(),
                version: "1.0.0".into(),
                adapter_id: AdapterId::FfmpegV1,
                adapter_api: 1,
                entrypoint: "bin/tool".into(),
                companions: BTreeMap::new(),
                capabilities: vec![EngineCapability::PostProcessing],
            }],
            components: vec![UpstreamComponent {
                name: "test-component".into(),
                version: "1.0.0".into(),
                source_url: "https://example.test/source.tar.xz".into(),
                source_revision: "v1.0.0".into(),
                source_sha256: "11".repeat(32),
                license_id: "MIT".into(),
                original_sha256: None,
            }],
            files,
            self_tests: vec![PackSelfTest {
                engine_id: "test-engine".into(),
                expected_version: "1.0.0".into(),
                timeout_seconds: 5,
            }],
        };
        let file = File::create(path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        archive.start_file("manifest.json", options).unwrap();
        archive
            .write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        for (name, bytes, _) in payload {
            archive.start_file(name, options).unwrap();
            archive.write_all(bytes).unwrap();
        }
        if let Some((name, bytes)) = extra {
            archive.start_file(name, options).unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap();
    }

    #[test]
    fn production_origins_are_https_and_allowlisted() {
        let hosts = ["updates.example.test"];
        assert!(
            validate_production_origin(
                &Url::parse("https://updates.example.test/core/").unwrap(),
                &hosts
            )
            .is_ok()
        );
        assert!(
            validate_production_origin(
                &Url::parse("http://updates.example.test/core/").unwrap(),
                &hosts
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_zip_traversal() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("bad.zip");
        let file = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("../escape", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"bad").unwrap();
        archive.finish().unwrap();
        let installer = PackInstaller::new(
            PackLayout::new(temporary.path().join("engines")),
            TargetId::current().unwrap(),
            ExtractionLimits::default(),
        );
        assert!(installer.install_archive(&archive_path).is_err());
        assert!(!temporary.path().join("escape").exists());
    }

    #[test]
    fn rejects_zip_symbolic_links() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("link.zip");
        let file = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file(
                "bin/link",
                SimpleFileOptions::default().unix_permissions(0o120777),
            )
            .unwrap();
        archive.write_all(b"../outside").unwrap();
        archive.finish().unwrap();
        let installer = PackInstaller::new(
            PackLayout::new(temporary.path().join("engines")),
            TargetId::current().unwrap(),
            ExtractionLimits::default(),
        );
        assert!(installer.install_archive(&archive_path).is_err());
        assert!(!temporary.path().join("outside").exists());
    }

    #[test]
    fn rejects_undeclared_payload_and_cleans_staging() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("extra.zip");
        write_test_pack(&archive_path, Vec::new(), Some(("extra.txt", b"extra")));
        let layout = PackLayout::new(temporary.path().join("engines"));
        let installer = PackInstaller::new(
            layout.clone(),
            TargetId::current().unwrap(),
            ExtractionLimits::default(),
        );
        assert!(installer.install_archive(&archive_path).is_err());
        assert_eq!(layout.recover_staging().unwrap(), 0);
    }

    #[test]
    fn installs_a_complete_declared_pack_immutably() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("valid.zip");
        write_test_pack(&archive_path, Vec::new(), None);
        let layout = PackLayout::new(temporary.path().join("engines"));
        let installer = PackInstaller::new(
            layout.clone(),
            TargetId::current().unwrap(),
            ExtractionLimits::default(),
        );
        let manifest = installer.install_archive(&archive_path).unwrap();
        let installed = layout
            .version_directory(&manifest.id, &manifest.version, manifest.target)
            .unwrap();
        assert!(installed.join("bin/tool").is_file());
        assert_eq!(layout.recover_staging().unwrap(), 0);
        assert_eq!(installer.install_archive(&archive_path).unwrap(), manifest);
    }

    #[test]
    fn garbage_collection_preserves_only_active_or_leased_versions() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("valid.zip");
        write_test_pack(&archive_path, Vec::new(), None);
        let layout = PackLayout::new(temporary.path().join("engines"));
        let installer = PackInstaller::new(
            layout.clone(),
            TargetId::current().unwrap(),
            ExtractionLimits::default(),
        );
        let manifest = installer.install_archive(&archive_path).unwrap();
        let identity = (
            manifest.id.clone(),
            manifest.version.clone(),
            manifest.target.to_string(),
        );
        let leases = std::collections::BTreeSet::from([identity]);
        assert!(layout.garbage_collect_unleased(&leases).unwrap().is_empty());
        assert!(
            layout
                .version_directory(&manifest.id, &manifest.version, manifest.target)
                .unwrap()
                .is_dir()
        );
        assert_eq!(
            layout
                .garbage_collect_unleased(&Default::default())
                .unwrap()
                .len(),
            1
        );

        let manifest = installer.install_archive(&archive_path).unwrap();
        layout.activate(&manifest).unwrap();
        assert!(
            layout
                .garbage_collect_unleased(&Default::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_case_collisions_before_extraction() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("collision.zip");
        let file = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("bin/Tool", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"one").unwrap();
        archive
            .start_file("bin/tool", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"two").unwrap();
        archive.finish().unwrap();
        let installer = PackInstaller::new(
            PackLayout::new(temporary.path().join("engines")),
            TargetId::current().unwrap(),
            ExtractionLimits::default(),
        );
        assert!(installer.install_archive(&archive_path).is_err());
    }

    #[test]
    fn rejects_excessive_compression_ratio() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("bomb.zip");
        let file = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file(
                "large.bin",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        archive.write_all(&vec![0_u8; 2 * 1024 * 1024]).unwrap();
        archive.finish().unwrap();
        let installer = PackInstaller::new(
            PackLayout::new(temporary.path().join("engines")),
            TargetId::current().unwrap(),
            ExtractionLimits {
                max_files: 10,
                max_expanded_bytes: 4 * 1024 * 1024,
                max_compression_ratio: 2,
            },
        );
        assert!(installer.install_archive(&archive_path).is_err());
    }

    #[test]
    fn dependency_failure_does_not_leave_staging() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("dependency.zip");
        write_test_pack(
            &archive_path,
            vec![PackDependency {
                pack_id: "ffmpeg-standard".into(),
                version_req: "^9.0".into(),
                required: true,
            }],
            None,
        );
        let layout = PackLayout::new(temporary.path().join("engines"));
        let installer = PackInstaller::new(
            layout.clone(),
            TargetId::current().unwrap(),
            ExtractionLimits::default(),
        );
        assert!(installer.install_archive(&archive_path).is_err());
        assert_eq!(layout.recover_staging().unwrap(), 0);
    }

    #[test]
    fn authorization_mismatch_is_rejected_before_finalization() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("authorized.zip");
        write_test_pack(&archive_path, Vec::new(), None);
        let layout = PackLayout::new(temporary.path().join("engines"));
        let installer = PackInstaller::new(
            layout.clone(),
            TargetId::current().unwrap(),
            ExtractionLimits::default(),
        );
        let authorization = AuthorizedExternalTarget {
            name: "packs/test-pack.zip".into(),
            pack_id: "different-pack".into(),
            pack_version: "1.0.0".into(),
            target: TargetId::current().unwrap(),
            security_sequence: 1,
            download_url: Url::parse("https://example.test/test-pack.zip").unwrap(),
            length: fs::metadata(&archive_path).unwrap().len(),
            sha256: "44".repeat(32),
        };
        assert!(
            installer
                .install_authorized_archive(&archive_path, &authorization)
                .is_err()
        );
        assert!(!layout.root().join("different-pack").exists());
        assert!(!layout.root().join("test-pack").exists());
    }

    #[test]
    fn startup_recovery_removes_incomplete_staging() {
        let temporary = tempdir().unwrap();
        let layout = PackLayout::new(temporary.path().join("engines"));
        let abandoned = layout.root().join("staging/transaction/bin");
        fs::create_dir_all(&abandoned).unwrap();
        fs::write(abandoned.join("partial"), b"partial").unwrap();
        assert_eq!(layout.recover_staging().unwrap(), 1);
        assert!(layout.root().join("staging").is_dir());
    }
}
