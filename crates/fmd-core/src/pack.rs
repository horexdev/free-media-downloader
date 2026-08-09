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

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
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
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_ARCHIVE_FILES,
            max_expanded_bytes: 1024 * 1024 * 1024,
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
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }

    pub fn installed_engines(&self) -> Result<Vec<InstalledEngine>, CoreError> {
        let active = self.root.join("active");
        if !active.is_dir() {
            return Ok(Vec::new());
        }
        let mut engines = Vec::new();
        for entry in fs::read_dir(active)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let pointer: ActivationPointer = serde_json::from_slice(&fs::read(&path)?)?;
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

    pub fn resolve_engine(&self, id: &str) -> Result<Option<InstalledEngine>, CoreError> {
        Ok(self
            .installed_engines()?
            .into_iter()
            .find(|engine| engine.descriptor.id == id))
    }

    pub fn activate(&self, manifest: &PackManifestV1) -> Result<ActivationPointer, CoreError> {
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
        let staging = self
            .layout
            .root
            .join("staging")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&staging)?;
        let result = self.extract_and_verify(archive_path, &staging);
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        let manifest = result?;
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
            fs::remove_dir_all(&staging)?;
            return Ok(existing);
        }
        fs::create_dir_all(
            final_directory
                .parent()
                .ok_or_else(|| CoreError::SupplyChain("pack destination has no parent".into()))?,
        )?;
        fs::rename(&staging, &final_directory)?;
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
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .map_err(|error| CoreError::SupplyChain(error.to_string()))?;
            let enclosed = entry
                .enclosed_name()
                .ok_or_else(|| CoreError::SupplyChain("unsafe ZIP path".into()))?
                .to_path_buf();
            let name = enclosed.to_string_lossy().replace('\\', "/");
            crate::engine::validate_relative_path(name.trim_end_matches('/'))?;
            expanded = expanded.saturating_add(entry.size());
            if expanded > self.limits.max_expanded_bytes {
                return Err(CoreError::SupplyChain(
                    "pack exceeds expanded size limit".into(),
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
        {
            return Err(CoreError::SupplyChain(
                "pack is missing licenses, SBOM, or provenance".into(),
            ));
        }
        manifest.verify_payload(staging)?;
        Ok(manifest)
    }
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
    replace_file(&candidate, path)?;
    File::open(parent)?.sync_all()?;
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
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

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
}
