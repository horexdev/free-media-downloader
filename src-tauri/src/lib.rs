use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fmd_core::{
    ApiError, ArtifactDescriptorV1, BuiltinCliAdapter, CoreError, EngineAdapter, EngineErrorKind,
    ExtractionLimits, InputSource, InstalledEngine, JobExecutor, JobId, JobScheduler, JobSnapshot,
    JobSpec, JobStore, PackConsentRecord, PackInstaller, PackLayout, RouteDecision, Router,
    SftpHostKeyRecord, TargetId, TransferAuth, TufRepository, UpdateJournalRecord, UpdateReceipt,
};
use fmd_updater::{
    ApplyRequestV2, ArtifactKind, InstallKind, PROTOCOL_VERSION, RelaunchMode, process_start_token,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio_util::sync::CancellationToken;
use ts_rs::TS;
use url::Url;
use uuid::Uuid;

struct AppState {
    scheduler: JobScheduler,
    executor: Arc<JobExecutor>,
    packs: PackService,
    core_updates: CoreUpdateService,
    paths: AppPaths,
}

#[derive(Clone)]
struct PackService {
    store: JobStore,
    layout: PackLayout,
    state_root: PathBuf,
    updates_root: PathBuf,
}

#[derive(Clone)]
struct CoreUpdateService {
    store: JobStore,
    state_root: PathBuf,
    updates_root: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AvailablePack {
    target_name: String,
    pack_id: String,
    version: String,
    target: String,
    security_sequence: u64,
    size: u64,
    installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
struct CoreUpdateInfo {
    target_name: String,
    version: String,
    target: String,
    security_sequence: u64,
    size: u64,
    unsigned: bool,
    automatic_apply_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
struct CoreUpdateStatus {
    transaction_id: String,
    state: String,
    target_name: String,
    version: String,
    security_sequence: u64,
    diagnostic: Option<String>,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
struct PreparedCoreUpdate {
    update: CoreUpdateInfo,
    status: CoreUpdateStatus,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
struct JobSelectionInput {
    format: Option<String>,
    subtitle_languages: Vec<String>,
    selected_playlist_entries: Option<Vec<u32>>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
struct SftpTrustInfo {
    state: String,
    host: String,
    port: u16,
    algorithm: String,
    fingerprint_sha256: String,
}

#[derive(Debug, Clone, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
struct SftpAuthorizationInput {
    trust_action: String,
    credential_kind: String,
    username: String,
    password: Option<String>,
    key_path: Option<String>,
    passphrase: Option<String>,
}

struct ObservedSftpKey {
    host: String,
    port: u16,
    algorithm: String,
    raw_key_base64: String,
    fingerprint_sha256: String,
}

const MAX_UPDATE_DESCRIPTOR_BYTES: u64 = 1024 * 1024;
const ARTIFACT_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

fn bootstrap_trust_root(trust_root: &Path, embedded_root: &[u8]) -> Result<(), CoreError> {
    let parent = trust_root.parent().ok_or_else(|| {
        CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid trust root path",
        ))
    })?;
    fs::create_dir_all(parent)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::Io(std::io::Error::other("system time is before Unix epoch")))?
        .as_nanos();
    let temp = trust_root.with_extension(format!("tmp.{nonce}"));
    {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        file.write_all(embedded_root)?;
        file.sync_all()?;
    }
    fs::rename(temp, trust_root)?;
    Ok(())
}

async fn load_feed_repository(
    state_root: &Path,
    feed: &str,
    embedded_root: &[u8],
) -> Result<TufRepository, ApiError> {
    let trust_root = state_root.join(format!("tuf/{feed}/root.json"));
    if !trust_root.is_file() {
        bootstrap_trust_root(&trust_root, embedded_root).map_err(ApiError::from)?;
    }
    let root = fs::read(trust_root)
        .map_err(CoreError::from)
        .map_err(ApiError::from)?;
    let base = format!("https://horexdev.github.io/free-media-downloader-updates/{feed}/");
    TufRepository::load_persistent(
        &root,
        Url::parse(&format!("{base}metadata/")).expect("static URL"),
        Url::parse(&format!("{base}targets/")).expect("static URL"),
        &state_root.join(format!("tuf/{feed}/datastore")),
        &["horexdev.github.io"],
    )
    .await
    .map_err(ApiError::from)
}

impl PackService {
    async fn repository(&self) -> Result<TufRepository, ApiError> {
        load_feed_repository(
            &self.state_root,
            "engines",
            include_bytes!("../resources/tuf/engines-root.json"),
        )
        .await
    }

    async fn available(&self) -> Result<Vec<AvailablePack>, ApiError> {
        let current = TargetId::current().ok_or_else(|| {
            ApiError::new("pack.target_unsupported", EngineErrorKind::Unsupported)
        })?;
        let repository = self.repository().await?;
        let targets = repository.descriptor_targets().map_err(ApiError::from)?;
        let mut packs = Vec::new();
        for target in targets
            .into_iter()
            .filter(|target| target.component == "engine_pack" && target.target == current)
        {
            let descriptor = repository
                .read_artifact_descriptor(&target, MAX_UPDATE_DESCRIPTOR_BYTES)
                .await
                .map_err(ApiError::from)?;
            let pack_id = descriptor.pack_id.clone().ok_or_else(|| {
                ApiError::new("pack.authorization_mismatch", EngineErrorKind::Integrity)
            })?;
            packs.push(AvailablePack {
                installed: self
                    .layout
                    .active(&pack_id)
                    .ok()
                    .flatten()
                    .is_some_and(|active| {
                        active.version == descriptor.version
                            && active.security_sequence == descriptor.security_sequence
                    }),
                target_name: descriptor.target_name,
                pack_id,
                version: descriptor.version,
                target: descriptor.target.to_string(),
                security_sequence: descriptor.security_sequence,
                size: descriptor.artifact_length,
            });
        }
        packs.sort_by(|left, right| {
            left.pack_id
                .cmp(&right.pack_id)
                .then(right.security_sequence.cmp(&left.security_sequence))
        });
        Ok(packs)
    }

    async fn install(&self, pack_id: &str, target_name: &str) -> Result<String, ApiError> {
        let repository = self.repository().await?;
        let descriptor_authorization = repository
            .descriptor_target(target_name)
            .map_err(ApiError::from)?;
        let descriptor = repository
            .read_artifact_descriptor(&descriptor_authorization, MAX_UPDATE_DESCRIPTOR_BYTES)
            .await
            .map_err(ApiError::from)?;
        let authorization = descriptor.external_authorization();
        let current_target = TargetId::current().ok_or_else(|| {
            ApiError::new("pack.target_unsupported", EngineErrorKind::Unsupported)
        })?;
        if authorization.pack_id != pack_id || authorization.target != current_target {
            return Err(ApiError::new(
                "pack.authorization_mismatch",
                EngineErrorKind::Integrity,
            ));
        }
        let high_water = self
            .store
            .pack_security_high_water(pack_id)
            .map_err(ApiError::from)?;
        if authorization.security_sequence < high_water {
            return Err(ApiError::new(
                "pack.rollback_rejected",
                EngineErrorKind::Integrity,
            ));
        }
        let staging = self.updates_root.join("pack-staging");
        fs::create_dir_all(&staging)
            .map_err(CoreError::from)
            .map_err(ApiError::from)?;
        let archive = staging.join(format!("{}.zip", Uuid::new_v4()));
        let download_result = repository
            .download_artifact(&descriptor, &archive, ARTIFACT_HOSTS)
            .await;
        if let Err(error) = download_result {
            let _ = fs::remove_file(&archive);
            return Err(ApiError::from(error));
        }
        let installer = PackInstaller::new(
            self.layout.clone(),
            current_target,
            ExtractionLimits::default(),
        );
        let install_result = installer.install_authorized_archive(&archive, &authorization);
        let _ = fs::remove_file(&archive);
        let manifest = install_result.map_err(ApiError::from)?;
        if manifest.id != authorization.pack_id
            || manifest.version != authorization.pack_version
            || manifest.security_sequence != authorization.security_sequence
        {
            return Err(ApiError::new(
                "pack.manifest_authorization_mismatch",
                EngineErrorKind::Integrity,
            ));
        }
        let root = self
            .layout
            .version_directory(&manifest.id, &manifest.version, manifest.target)
            .map_err(ApiError::from)?;
        for descriptor in &manifest.engines {
            let installation = InstalledEngine {
                descriptor: descriptor.clone(),
                pack_id: manifest.id.clone(),
                pack_version: manifest.version.clone(),
                root: root.clone(),
                shared_companions: std::collections::BTreeMap::new(),
            };
            BuiltinCliAdapter::new(descriptor.adapter_id)
                .self_test(&installation, CancellationToken::new())
                .await
                .map_err(|failure| failure.api_error())?;
        }
        let pointer = self.layout.activate(&manifest).map_err(ApiError::from)?;
        self.store
            .commit_pack_activation(&pointer)
            .map_err(ApiError::from)?;
        let now = chrono::Utc::now().to_rfc3339();
        self.store
            .save_pack_consent(&PackConsentRecord {
                pack_id: manifest.id.clone(),
                manifest_sha256: pointer.manifest_sha256,
                license_digest: manifest.license_digest(),
                accepted_size: authorization.length,
                auto_update: false,
                accepted_at: now.clone(),
                updated_at: now,
            })
            .map_err(ApiError::from)?;
        Ok(format!("{}@{}", manifest.id, manifest.version))
    }

    async fn ensure(&self, pack_ids: &[String]) -> Result<(), ApiError> {
        for pack_id in pack_ids {
            if self
                .layout
                .active(pack_id)
                .map_err(ApiError::from)?
                .is_some()
            {
                continue;
            }
            return Err(
                ApiError::new("pack.install_required", EngineErrorKind::Integrity)
                    .with_arg("pack", pack_id),
            );
        }
        Ok(())
    }
}

impl CoreUpdateService {
    async fn repository(&self) -> Result<TufRepository, ApiError> {
        load_feed_repository(
            &self.state_root,
            "core",
            include_bytes!("../resources/tuf/core-root.json"),
        )
        .await
    }

    async fn check(&self, paths: &AppPaths) -> Result<Option<CoreUpdateInfo>, ApiError> {
        let current_target = TargetId::current().ok_or_else(|| {
            ApiError::new("update.target_unsupported", EngineErrorKind::Unsupported)
        })?;
        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| {
            ApiError::new("update.current_version_invalid", EngineErrorKind::Integrity)
        })?;
        let repository = self.repository().await?;
        let mut candidates = repository
            .descriptor_targets()
            .map_err(ApiError::from)?
            .into_iter()
            .filter(|target| target.component == "core" && target.target == current_target)
            .filter_map(|target| {
                Version::parse(&target.version)
                    .ok()
                    .filter(|version| version > &current_version)
                    .map(|version| (version, target))
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then(right.1.security_sequence.cmp(&left.1.security_sequence))
        });
        let Some((_, authorization)) = candidates.into_iter().next() else {
            return Ok(None);
        };
        let descriptor = repository
            .read_artifact_descriptor(&authorization, MAX_UPDATE_DESCRIPTOR_BYTES)
            .await
            .map_err(ApiError::from)?;
        Ok(Some(core_update_info(
            &descriptor,
            automatic_apply_supported(paths),
        )))
    }

    async fn prepare(
        &self,
        paths: &AppPaths,
        target_name: &str,
    ) -> Result<PreparedCoreUpdate, ApiError> {
        let repository = self.repository().await?;
        let authorization = repository
            .descriptor_target(target_name)
            .map_err(ApiError::from)?;
        if authorization.component != "core"
            || TargetId::current().is_none_or(|target| authorization.target != target)
        {
            return Err(ApiError::new(
                "update.authorization_mismatch",
                EngineErrorKind::Integrity,
            ));
        }
        let descriptor = repository
            .read_artifact_descriptor(&authorization, MAX_UPDATE_DESCRIPTOR_BYTES)
            .await
            .map_err(ApiError::from)?;
        let current_version = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| {
            ApiError::new("update.current_version_invalid", EngineErrorKind::Integrity)
        })?;
        let target_version = Version::parse(&descriptor.version).map_err(|_| {
            ApiError::new("update.target_version_invalid", EngineErrorKind::Integrity)
        })?;
        if target_version <= current_version {
            return Err(ApiError::new(
                "update.rollback_rejected",
                EngineErrorKind::Integrity,
            ));
        }

        let transaction_id = Uuid::new_v4();
        let transaction_root = self.transaction_root(transaction_id);
        fs::create_dir_all(&transaction_root)
            .map_err(CoreError::from)
            .map_err(ApiError::from)?;
        let now = chrono::Utc::now().to_rfc3339();
        let metadata_json = serde_json::to_string(&descriptor).map_err(|_| {
            ApiError::new("update.receipt_encode_failed", EngineErrorKind::Internal)
        })?;
        let receipt = UpdateReceipt {
            target_name: descriptor.target_name.clone(),
            version: descriptor.version.clone(),
            security_sequence: descriptor.security_sequence,
            length: descriptor.artifact_length,
            sha256: descriptor.artifact_sha256.clone(),
            metadata_json,
            created_at: now.clone(),
        };
        self.store
            .save_update_receipt(&receipt)
            .map_err(ApiError::from)?;
        write_json_atomic(&transaction_root.join("receipt.json"), &receipt)?;
        let status = CoreUpdateStatus {
            transaction_id: transaction_id.to_string(),
            state: "prepared".into(),
            target_name: descriptor.target_name.clone(),
            version: descriptor.version.clone(),
            security_sequence: descriptor.security_sequence,
            diagnostic: None,
            updated_at: now,
        };
        self.record_status(&status)?;
        Ok(PreparedCoreUpdate {
            update: core_update_info(&descriptor, automatic_apply_supported(paths)),
            status,
        })
    }

    async fn download(&self, transaction_id: &str) -> Result<CoreUpdateStatus, ApiError> {
        let (id, mut status) = self.load_status(transaction_id)?;
        if !matches!(status.state.as_str(), "prepared" | "download_failed") {
            return Err(ApiError::new(
                "update.invalid_state",
                EngineErrorKind::Integrity,
            ));
        }
        let receipt = self
            .store
            .get_update_receipt(&status.target_name)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::new("update.receipt_missing", EngineErrorKind::Integrity))?;
        let descriptor: ArtifactDescriptorV1 = serde_json::from_str(&receipt.metadata_json)
            .map_err(|_| ApiError::new("update.receipt_invalid", EngineErrorKind::Integrity))?;
        if receipt.version != status.version
            || receipt.length != descriptor.artifact_length
            || !receipt
                .sha256
                .eq_ignore_ascii_case(&descriptor.artifact_sha256)
        {
            return Err(ApiError::new(
                "update.receipt_mismatch",
                EngineErrorKind::Integrity,
            ));
        }
        let repository = self.repository().await?;
        let authorization = repository
            .descriptor_target(&receipt.target_name)
            .map_err(ApiError::from)?;
        descriptor
            .validate_against(&authorization)
            .map_err(ApiError::from)?;
        let artifact = self.transaction_root(id).join("artifact.bin");
        if let Err(error) = repository
            .download_artifact(&descriptor, &artifact, ARTIFACT_HOSTS)
            .await
        {
            status.state = "download_failed".into();
            status.diagnostic = Some("download_failed".into());
            status.updated_at = chrono::Utc::now().to_rfc3339();
            self.record_status(&status)?;
            return Err(ApiError::from(error));
        }
        status.state = "downloaded".into();
        status.diagnostic = None;
        status.updated_at = chrono::Utc::now().to_rfc3339();
        self.record_status(&status)?;
        Ok(status)
    }

    fn last_status(&self) -> Result<Option<CoreUpdateStatus>, ApiError> {
        let Some(record) = self
            .store
            .list_update_journals()
            .map_err(ApiError::from)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let status = serde_json::from_str(&record.journal_json)
            .map_err(|_| ApiError::new("update.journal_invalid", EngineErrorKind::Integrity))?;
        Ok(Some(status))
    }

    fn apply(&self, paths: &AppPaths, transaction_id: &str) -> Result<CoreUpdateStatus, ApiError> {
        let (id, mut status) = self.load_status(transaction_id)?;
        if status.state != "downloaded" {
            return Err(ApiError::new(
                "update.invalid_state",
                EngineErrorKind::Integrity,
            ));
        }
        let installation = resolve_update_installation(paths)?.ok_or_else(|| {
            ApiError::new(
                "update.manual_install_required",
                EngineErrorKind::Unsupported,
            )
        })?;
        let receipt_path = self.transaction_root(id).join("receipt.json");
        let artifact_path = self.transaction_root(id).join("artifact.bin");
        let receipt: UpdateReceipt = serde_json::from_slice(
            &fs::read(&receipt_path)
                .map_err(CoreError::from)
                .map_err(ApiError::from)?,
        )
        .map_err(|_| ApiError::new("update.receipt_invalid", EngineErrorKind::Integrity))?;
        if receipt.target_name != status.target_name
            || receipt.version != status.version
            || receipt.security_sequence != status.security_sequence
        {
            return Err(ApiError::new(
                "update.receipt_mismatch",
                EngineErrorKind::Integrity,
            ));
        }
        let current_security_sequence = self
            .store
            .list_update_journals()
            .map_err(ApiError::from)?
            .into_iter()
            .filter_map(|record| {
                serde_json::from_str::<CoreUpdateStatus>(&record.journal_json).ok()
            })
            .filter(|candidate| candidate.state == "committed")
            .map(|candidate| candidate.security_sequence)
            .max()
            .unwrap_or(0);
        if status.security_sequence <= current_security_sequence {
            return Err(ApiError::new(
                "update.rollback_rejected",
                EngineErrorKind::Integrity,
            ));
        }
        let parent_pid = std::process::id();
        let parent_start_token = process_start_token(parent_pid).map_err(|_| {
            ApiError::new("update.parent_identity_failed", EngineErrorKind::Internal)
        })?;
        let request = ApplyRequestV2 {
            protocol_version: PROTOCOL_VERSION,
            transaction_id: id,
            installation_uuid: installation.marker.installation_uuid,
            parent_pid,
            parent_start_token,
            install_kind: installation.marker.install_kind,
            artifact_kind: installation.artifact_kind,
            current_version: env!("CARGO_PKG_VERSION").into(),
            target_version: receipt.version,
            target_build: status.target_name.clone(),
            current_security_sequence,
            target_security_sequence: status.security_sequence,
            authorized_target_name: status.target_name.clone(),
            metadata_receipt_path: path_string(&receipt_path)?,
            artifact_path: path_string(&artifact_path)?,
            updates_root: path_string(&self.updates_root)?,
            artifact_length: receipt.length,
            artifact_sha256: receipt.sha256,
            install_root: path_string(&installation.install_root)?,
            payload_root: path_string(&installation.payload_root)?,
            state_root: path_string(&paths.state)?,
            backup_root: path_string(&installation.backup_root)?,
            relaunch: RelaunchMode::Normal,
            health_token: format!(
                "{}{}",
                Uuid::new_v4().as_simple(),
                Uuid::new_v4().as_simple()
            ),
            health_deadline_seconds: 60,
        };
        request.validate().map_err(|_| {
            ApiError::new("update.apply_request_rejected", EngineErrorKind::Integrity)
        })?;
        let encoded = serde_json::to_vec(&request).map_err(|_| {
            ApiError::new(
                "update.apply_request_encode_failed",
                EngineErrorKind::Internal,
            )
        })?;
        let executable = std::env::current_exe()
            .map_err(|_| ApiError::new("update.helper_unavailable", EngineErrorKind::Internal))?;
        let mut helper = Command::new(executable)
            .arg("--fmd-apply-update-v2")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ApiError::new("update.helper_spawn_failed", EngineErrorKind::Internal))?;
        let write_result = helper
            .stdin
            .take()
            .ok_or_else(|| ApiError::new("update.helper_stdin_failed", EngineErrorKind::Internal))?
            .write_all(&encoded);
        if write_result.is_err() {
            let _ = helper.kill();
            return Err(ApiError::new(
                "update.helper_stdin_failed",
                EngineErrorKind::Internal,
            ));
        }
        status.state = "applying".into();
        status.diagnostic = None;
        status.updated_at = chrono::Utc::now().to_rfc3339();
        self.record_status(&status)?;
        Ok(status)
    }

    fn load_status(&self, transaction_id: &str) -> Result<(Uuid, CoreUpdateStatus), ApiError> {
        let id = Uuid::parse_str(transaction_id)
            .map_err(|_| ApiError::new("update.transaction_invalid", EngineErrorKind::Integrity))?;
        let record = self
            .store
            .list_update_journals()
            .map_err(ApiError::from)?
            .into_iter()
            .find(|record| record.transaction_id == transaction_id)
            .ok_or_else(|| {
                ApiError::new("update.transaction_missing", EngineErrorKind::Integrity)
            })?;
        let status = serde_json::from_str(&record.journal_json)
            .map_err(|_| ApiError::new("update.journal_invalid", EngineErrorKind::Integrity))?;
        Ok((id, status))
    }

    fn transaction_root(&self, transaction_id: Uuid) -> PathBuf {
        self.updates_root
            .join("core")
            .join(transaction_id.to_string())
    }

    fn record_status(&self, status: &CoreUpdateStatus) -> Result<(), ApiError> {
        let journal_json = serde_json::to_string(status).map_err(|_| {
            ApiError::new("update.journal_encode_failed", EngineErrorKind::Internal)
        })?;
        self.store
            .record_update_journal(&UpdateJournalRecord {
                transaction_id: status.transaction_id.clone(),
                state: status.state.clone(),
                journal_json,
                updated_at: status.updated_at.clone(),
            })
            .map_err(ApiError::from)
    }

    fn reconcile(&self) -> Result<(), ApiError> {
        for record in self.store.list_update_journals().map_err(ApiError::from)? {
            let Ok(mut status) = serde_json::from_str::<CoreUpdateStatus>(&record.journal_json)
            else {
                continue;
            };
            if matches!(
                status.state.as_str(),
                "committed" | "rolled_back" | "aborted"
            ) {
                continue;
            }
            let Ok(transaction_id) = Uuid::parse_str(&status.transaction_id) else {
                continue;
            };
            let journal_path = self
                .state_root
                .join("update-transactions")
                .join(transaction_id.to_string())
                .join("transaction.json");
            let Ok(bytes) = fs::read(journal_path) else {
                continue;
            };
            let Ok(journal) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            let Some(state) = journal.get("state").and_then(|value| value.as_str()) else {
                continue;
            };
            status.state = state.to_owned();
            status.diagnostic = journal
                .get("diagnostic")
                .and_then(|value| value.as_str())
                .map(str::to_owned);
            status.updated_at = chrono::Utc::now().to_rfc3339();
            self.record_status(&status)?;
        }
        Ok(())
    }
}

fn core_update_info(
    descriptor: &ArtifactDescriptorV1,
    automatic_apply_supported: bool,
) -> CoreUpdateInfo {
    CoreUpdateInfo {
        target_name: descriptor.target_name.clone(),
        version: descriptor.version.clone(),
        target: descriptor.target.to_string(),
        security_sequence: descriptor.security_sequence,
        size: descriptor.artifact_length,
        unsigned: descriptor.unsigned,
        automatic_apply_supported,
    }
}

fn automatic_apply_supported(paths: &AppPaths) -> bool {
    resolve_update_installation(paths).is_ok_and(|installation| installation.is_some())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallMarker {
    installation_uuid: Uuid,
    install_kind: InstallKind,
    launcher: String,
    payload_executable: String,
}

struct UpdateInstallation {
    marker: InstallMarker,
    artifact_kind: ArtifactKind,
    install_root: PathBuf,
    payload_root: PathBuf,
    backup_root: PathBuf,
}

fn resolve_update_installation(paths: &AppPaths) -> Result<Option<UpdateInstallation>, ApiError> {
    let executable = std::env::current_exe()
        .map_err(|_| ApiError::new("update.install_identity_failed", EngineErrorKind::Internal))?;

    #[cfg(target_os = "windows")]
    let candidate = if paths.portable {
        let Some(root) = paths.state.parent().map(Path::to_path_buf) else {
            return Ok(None);
        };
        let version_root = root.join("app").join(env!("CARGO_PKG_VERSION"));
        let Ok(relative) = executable.strip_prefix(&version_root) else {
            return Ok(None);
        };
        Some((
            root.clone(),
            root.join("app"),
            InstallKind::WindowsPortable,
            ArtifactKind::ZipPayload,
            "fmd-launcher.exe".to_owned(),
            path_string(relative)?,
        ))
    } else {
        None
    };

    #[cfg(target_os = "macos")]
    let candidate = executable
        .ancestors()
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("app"))
        .and_then(|bundle| {
            let root = bundle.parent()?.to_path_buf();
            let relative = executable.strip_prefix(bundle).ok()?;
            Some((
                root,
                bundle.to_path_buf(),
                InstallKind::MacosSelfManaged,
                ArtifactKind::ZipPayload,
                relative.to_string_lossy().into_owned(),
                relative.to_string_lossy().into_owned(),
            ))
        });

    #[cfg(target_os = "linux")]
    let candidate = std::env::var_os("APPIMAGE").and_then(|value| {
        let image = PathBuf::from(value);
        let root = image.parent()?.to_path_buf();
        let name = image.file_name()?.to_string_lossy().into_owned();
        Some((
            root,
            image,
            InstallKind::LinuxAppImage,
            ArtifactKind::AppImage,
            name.clone(),
            name,
        ))
    });

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let candidate: Option<(PathBuf, PathBuf, InstallKind, ArtifactKind, String, String)> = None;

    let Some((
        install_root,
        payload_root,
        install_kind,
        artifact_kind,
        launcher,
        payload_executable,
    )) = candidate
    else {
        return Ok(None);
    };
    let marker_path = install_root.join("install-marker.json");
    let expected = InstallMarker {
        installation_uuid: Uuid::nil(),
        install_kind,
        launcher,
        payload_executable,
    };
    let marker = if marker_path.is_file() {
        let marker: InstallMarker = serde_json::from_slice(
            &fs::read(&marker_path)
                .map_err(CoreError::from)
                .map_err(ApiError::from)?,
        )
        .map_err(|_| ApiError::new("update.install_marker_invalid", EngineErrorKind::Integrity))?;
        if marker.installation_uuid.is_nil()
            || marker.install_kind != expected.install_kind
            || marker.launcher != expected.launcher
            || marker.payload_executable != expected.payload_executable
        {
            return Err(ApiError::new(
                "update.install_marker_mismatch",
                EngineErrorKind::Integrity,
            ));
        }
        marker
    } else {
        let marker = InstallMarker {
            installation_uuid: Uuid::new_v4(),
            ..expected
        };
        write_json_atomic(&marker_path, &marker)?;
        marker
    };
    Ok(Some(UpdateInstallation {
        marker,
        artifact_kind,
        backup_root: if install_kind == InstallKind::WindowsPortable {
            paths.state.join("update-backups")
        } else {
            install_root.join(".fmd-backups")
        },
        install_root,
        payload_root,
    }))
}

fn path_string(path: &Path) -> Result<String, ApiError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| ApiError::new("update.path_encoding_invalid", EngineErrorKind::Integrity))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| ApiError::new("update.file_encode_failed", EngineErrorKind::Internal))?;
    let parent = path
        .parent()
        .ok_or_else(|| ApiError::new("update.path_invalid", EngineErrorKind::Integrity))?;
    fs::create_dir_all(parent)
        .map_err(CoreError::from)
        .map_err(ApiError::from)?;
    let temporary = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(CoreError::from)
        .map_err(ApiError::from)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(ApiError::from(CoreError::from(error)));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(ApiError::from(CoreError::from(error)));
    }
    Ok(())
}

#[derive(Debug)]
struct AppPaths {
    payload: PathBuf,
    state: PathBuf,
    data: PathBuf,
    engines: PathBuf,
    updates: PathBuf,
    portable: bool,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: &'static str,
    portable: bool,
    payload_path: String,
    state_path: String,
    data_path: String,
    engines_path: String,
    updates_path: String,
    max_parallel_jobs: u8,
}

impl AppPaths {
    fn resolve(handle: &AppHandle) -> anyhow::Result<Self> {
        let executable = std::env::current_exe()?;
        let payload = resolve_payload_root(&executable);
        let portable_root = find_portable_root(&executable);
        let portable = portable_root.is_some();
        let (state, data, engines, updates) = if let Some(root) = portable_root {
            (
                root.join("state"),
                root.join("data"),
                root.join("engines"),
                root.join("updates"),
            )
        } else {
            let data = handle.path().app_data_dir()?;
            (
                data.join("state"),
                data.clone(),
                data.join("engines"),
                data.join("updates"),
            )
        };
        for directory in [&state, &data, &engines, &updates] {
            fs::create_dir_all(directory)?;
        }
        Ok(Self {
            payload,
            state,
            data,
            engines,
            updates,
            portable,
        })
    }
}

fn find_portable_root(executable: &Path) -> Option<PathBuf> {
    if let Some(app_image) = std::env::var_os("APPIMAGE") {
        let path = PathBuf::from(app_image);
        if let Some(parent) = path.parent()
            && parent.join("portable.json").is_file()
        {
            return Some(parent.to_path_buf());
        }
    }
    for ancestor in executable.ancestors().take(6) {
        if ancestor.join("portable.json").is_file() {
            return Some(ancestor.to_path_buf());
        }
        if ancestor.extension().and_then(|value| value.to_str()) == Some("app")
            && ancestor
                .parent()
                .is_some_and(|parent| parent.join("portable.json").is_file())
        {
            return ancestor.parent().map(Path::to_path_buf);
        }
    }
    None
}

fn resolve_payload_root(executable: &Path) -> PathBuf {
    executable
        .ancestors()
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("app"))
        .or_else(|| executable.parent())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

impl AppState {
    fn initialize(handle: &AppHandle) -> anyhow::Result<Self> {
        let paths = AppPaths::resolve(handle)?;
        let store = JobStore::open(&paths.data.join("fmd.db"))?;
        store.mark_active_jobs_interrupted()?;
        let pack_layout = PackLayout::new(paths.engines.clone());
        pack_layout.recover_staging()?;
        for pointer in pack_layout.active_pointers()? {
            store.commit_pack_activation(&pointer)?;
        }
        let scheduler = JobScheduler::new(store, 2)?;
        let event_handle = handle.clone();
        let events = Arc::new(move |event| {
            let _ = event_handle.emit("job-event", event);
        });
        let executor = Arc::new(JobExecutor::new(
            scheduler.clone(),
            pack_layout.clone(),
            paths.data.join("staging"),
            events,
        ));
        let packs = PackService {
            store: scheduler.store().clone(),
            layout: pack_layout,
            state_root: paths.state.clone(),
            updates_root: paths.updates.clone(),
        };
        let core_updates = CoreUpdateService {
            store: scheduler.store().clone(),
            state_root: paths.state.clone(),
            updates_root: paths.updates.clone(),
        };
        core_updates.reconcile().map_err(|error| {
            anyhow::anyhow!("core update reconciliation failed: {}", error.code)
        })?;
        Ok(Self {
            scheduler,
            executor,
            packs,
            core_updates,
            paths,
        })
    }
}

#[tauri::command]
fn get_app_info(state: State<'_, AppState>) -> Result<AppInfo, ApiError> {
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        portable: state.paths.portable,
        payload_path: state.paths.payload.to_string_lossy().into_owned(),
        state_path: state.paths.state.to_string_lossy().into_owned(),
        data_path: state.paths.data.to_string_lossy().into_owned(),
        engines_path: state.paths.engines.to_string_lossy().into_owned(),
        updates_path: state.paths.updates.to_string_lossy().into_owned(),
        max_parallel_jobs: state.scheduler.concurrency(),
    })
}

#[tauri::command]
fn classify_source(source: InputSource) -> Result<RouteDecision, ApiError> {
    Router.route(&source).map_err(ApiError::from)
}

#[tauri::command]
async fn create_job(spec: JobSpec, state: State<'_, AppState>) -> Result<JobSnapshot, ApiError> {
    let route = Router.route(&spec.source).map_err(ApiError::from)?;
    state.packs.ensure(&route.required_packs).await?;
    let job = state.scheduler.create(spec).map_err(ApiError::from)?;
    state.executor.submit(job.id).map_err(ApiError::from)?;
    Ok(job)
}

#[tauri::command]
fn list_jobs(state: State<'_, AppState>) -> Vec<JobSnapshot> {
    state.scheduler.list()
}

#[tauri::command]
fn select_format(
    id: JobId,
    format: String,
    state: State<'_, AppState>,
) -> Result<JobSnapshot, ApiError> {
    let job = state
        .scheduler
        .select_format(id, format)
        .map_err(ApiError::from)?;
    state.executor.submit(id).map_err(ApiError::from)?;
    Ok(job)
}

#[tauri::command]
fn complete_job_selection(
    id: JobId,
    selection: JobSelectionInput,
    state: State<'_, AppState>,
) -> Result<JobSnapshot, ApiError> {
    let current = state
        .scheduler
        .get(id)
        .ok_or_else(|| ApiError::new("job.not_found", EngineErrorKind::Internal))?;
    if current
        .plan
        .as_ref()
        .is_some_and(|plan| !plan.auth_requirements.is_empty())
        && !state.executor.has_transfer_auth(id)
    {
        return Err(ApiError::new(
            "sftp.authorization_required",
            EngineErrorKind::AuthRequired,
        ));
    }
    let job = state
        .scheduler
        .complete_selection(
            id,
            selection.format,
            selection.subtitle_languages,
            selection.selected_playlist_entries,
        )
        .map_err(ApiError::from)?;
    state.executor.submit(id).map_err(ApiError::from)?;
    Ok(job)
}

#[tauri::command]
fn sftp_trust_status(id: JobId, state: State<'_, AppState>) -> Result<SftpTrustInfo, ApiError> {
    let observed = observed_sftp_key(&state.scheduler, id)?;
    let trusted = state
        .scheduler
        .store()
        .trusted_sftp_host_keys(&observed.host, observed.port)
        .map_err(ApiError::from)?;
    let trust_state = classify_sftp_trust(&trusted, &observed);
    Ok(SftpTrustInfo {
        state: trust_state.into(),
        host: observed.host,
        port: observed.port,
        algorithm: observed.algorithm,
        fingerprint_sha256: observed.fingerprint_sha256,
    })
}

fn classify_sftp_trust(existing: &[SftpHostKeyRecord], observed: &ObservedSftpKey) -> &'static str {
    if existing.is_empty() {
        "unknown"
    } else if existing.iter().any(|record| {
        record.algorithm == observed.algorithm
            && record.raw_key_base64 == observed.raw_key_base64
            && record
                .fingerprint_sha256
                .eq_ignore_ascii_case(&observed.fingerprint_sha256)
    }) {
        "match"
    } else {
        "mismatch"
    }
}

#[tauri::command]
fn authorize_sftp_job(
    id: JobId,
    authorization: SftpAuthorizationInput,
    state: State<'_, AppState>,
) -> Result<(), ApiError> {
    let observed = observed_sftp_key(&state.scheduler, id)?;
    let existing = state
        .scheduler
        .store()
        .trusted_sftp_host_keys(&observed.host, observed.port)
        .map_err(ApiError::from)?;
    let matching = existing.iter().find(|record| {
        record.algorithm == observed.algorithm
            && record.raw_key_base64 == observed.raw_key_base64
            && record
                .fingerprint_sha256
                .eq_ignore_ascii_case(&observed.fingerprint_sha256)
    });
    let expected_action = if existing.is_empty() {
        "trust"
    } else if matching.is_some() {
        "match"
    } else {
        "replace"
    };
    if authorization.trust_action != expected_action {
        return Err(ApiError::new(
            "sftp.trust_confirmation_required",
            EngineErrorKind::HostKey,
        ));
    }

    if authorization.username.trim().is_empty() {
        return Err(ApiError::new(
            "sftp.credentials_invalid",
            EngineErrorKind::AuthRequired,
        ));
    }
    let credentials = match authorization.credential_kind.as_str() {
        "password" => {
            let password = authorization
                .password
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    ApiError::new("sftp.credentials_invalid", EngineErrorKind::AuthRequired)
                })?;
            fmd_curl_worker::Credentials::Password {
                username: authorization.username,
                password,
            }
        }
        "private_key" => {
            let key_path = authorization.key_path.map(PathBuf::from).ok_or_else(|| {
                ApiError::new("sftp.credentials_invalid", EngineErrorKind::AuthRequired)
            })?;
            if !key_path.is_absolute() || !key_path.is_file() {
                return Err(ApiError::new(
                    "sftp.credentials_invalid",
                    EngineErrorKind::AuthRequired,
                ));
            }
            let key_path = fs::canonicalize(key_path)
                .map_err(CoreError::from)
                .map_err(ApiError::from)?;
            fmd_curl_worker::Credentials::PrivateKey {
                username: authorization.username,
                key_path: path_string(&key_path)?,
                passphrase: authorization.passphrase,
            }
        }
        _ => {
            return Err(ApiError::new(
                "sftp.credentials_invalid",
                EngineErrorKind::AuthRequired,
            ));
        }
    };
    let now = chrono::Utc::now().to_rfc3339();
    let record = SftpHostKeyRecord {
        host: observed.host.clone(),
        port: observed.port,
        algorithm: observed.algorithm.clone(),
        raw_key_base64: observed.raw_key_base64.clone(),
        fingerprint_sha256: observed.fingerprint_sha256.clone(),
        first_seen: matching
            .map(|record| record.first_seen.clone())
            .unwrap_or_else(|| now.clone()),
        last_verified: now,
        revoked: false,
    };
    if expected_action == "replace" {
        state
            .scheduler
            .store()
            .replace_sftp_host_key(&record)
            .map_err(ApiError::from)?;
    } else {
        state
            .scheduler
            .store()
            .trust_sftp_host_key(&record)
            .map_err(ApiError::from)?;
    }
    state
        .executor
        .set_transfer_auth(
            id,
            TransferAuth {
                credentials,
                trusted_host_key: fmd_curl_worker::TrustedHostKey {
                    algorithm: observed.algorithm,
                    raw_key_base64: observed.raw_key_base64,
                    fingerprint_sha256: observed.fingerprint_sha256,
                },
            },
        )
        .map_err(ApiError::from)
}

fn observed_sftp_key(scheduler: &JobScheduler, id: JobId) -> Result<ObservedSftpKey, ApiError> {
    let job = scheduler
        .get(id)
        .ok_or_else(|| ApiError::new("job.not_found", EngineErrorKind::Internal))?;
    if job.state != fmd_core::JobState::AwaitingSelection {
        return Err(ApiError::new(
            "sftp.invalid_state",
            EngineErrorKind::HostKey,
        ));
    }
    let requirement = job
        .plan
        .as_ref()
        .and_then(|plan| {
            plan.auth_requirements
                .iter()
                .find(|value| value.starts_with("sftp_host_key|"))
        })
        .ok_or_else(|| ApiError::new("sftp.host_key_missing", EngineErrorKind::HostKey))?;
    let parts = requirement.split('|').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err(ApiError::new(
            "sftp.host_key_invalid",
            EngineErrorKind::Integrity,
        ));
    }
    let port = parts[2]
        .parse::<u16>()
        .map_err(|_| ApiError::new("sftp.host_key_invalid", EngineErrorKind::Integrity))?;
    if parts[1].is_empty()
        || parts[3].is_empty()
        || parts[4].is_empty()
        || !parts[5].starts_with("SHA256:")
        || parts[5].len() > 128
        || !parts[5].bytes().all(|value| {
            value.is_ascii_alphanumeric() || matches!(value, b':' | b'+' | b'/' | b'=')
        })
    {
        return Err(ApiError::new(
            "sftp.host_key_invalid",
            EngineErrorKind::Integrity,
        ));
    }
    Ok(ObservedSftpKey {
        host: parts[1].into(),
        port,
        algorithm: parts[3].into(),
        raw_key_base64: parts[4].into(),
        fingerprint_sha256: parts[5].into(),
    })
}

#[tauri::command]
fn start_job(id: JobId, state: State<'_, AppState>) -> Result<(), ApiError> {
    state.executor.submit(id).map_err(ApiError::from)
}

#[tauri::command]
fn cancel_job(id: JobId, state: State<'_, AppState>) -> Result<(), ApiError> {
    state.executor.cancel(id).map_err(ApiError::from)
}

#[tauri::command]
fn pause_job(id: JobId, state: State<'_, AppState>) -> Result<(), ApiError> {
    state.executor.pause(id).map_err(ApiError::from)
}

#[tauri::command]
fn resume_job(id: JobId, state: State<'_, AppState>) -> Result<(), ApiError> {
    state.executor.resume(id).map_err(ApiError::from)
}

#[tauri::command]
fn retry_job(id: JobId, state: State<'_, AppState>) -> Result<(), ApiError> {
    state.executor.retry(id).map_err(ApiError::from)
}

#[tauri::command]
fn list_installed_packs(state: State<'_, AppState>) -> Result<Vec<String>, ApiError> {
    let layout = PackLayout::new(state.paths.engines.clone());
    let engines = layout.installed_engines().map_err(ApiError::from)?;
    let mut packs = engines
        .into_iter()
        .map(|engine| format!("{}@{}", engine.pack_id, engine.pack_version))
        .collect::<Vec<_>>();
    packs.sort();
    packs.dedup();
    Ok(packs)
}

#[tauri::command]
async fn list_available_packs(state: State<'_, AppState>) -> Result<Vec<AvailablePack>, ApiError> {
    state.packs.available().await
}

#[tauri::command]
async fn install_pack(
    pack_id: String,
    target_name: String,
    state: State<'_, AppState>,
) -> Result<String, ApiError> {
    state.packs.install(&pack_id, &target_name).await
}

#[tauri::command]
async fn check_for_core_update(
    state: State<'_, AppState>,
) -> Result<Option<CoreUpdateInfo>, ApiError> {
    state.core_updates.check(&state.paths).await
}

#[tauri::command]
async fn prepare_core_update(
    target_name: String,
    state: State<'_, AppState>,
) -> Result<PreparedCoreUpdate, ApiError> {
    state.core_updates.prepare(&state.paths, &target_name).await
}

#[tauri::command]
async fn download_core_update(
    transaction_id: String,
    state: State<'_, AppState>,
) -> Result<CoreUpdateStatus, ApiError> {
    state.core_updates.download(&transaction_id).await
}

#[tauri::command]
fn apply_core_update(
    transaction_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreUpdateStatus, ApiError> {
    let status = state.core_updates.apply(&state.paths, &transaction_id)?;
    app.exit(0);
    Ok(status)
}

#[tauri::command]
fn last_core_update_status(
    state: State<'_, AppState>,
) -> Result<Option<CoreUpdateStatus>, ApiError> {
    state.core_updates.last_status()
}

#[tauri::command]
async fn acknowledge_ui_ready(state: State<'_, AppState>) -> Result<(), ApiError> {
    let has_update_context = std::env::var_os("FMD_UPDATE_HEALTH_PATH").is_some();
    acknowledge_update_health(&state.paths)?;
    if has_update_context {
        for _ in 0..30 {
            tauri::async_runtime::spawn_blocking(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
            })
            .await
            .map_err(|error| {
                ApiError::new(
                    format!("update.health_wait_failed: {error}"),
                    EngineErrorKind::Transient,
                )
            })?;
            state.core_updates.reconcile()?;
            if state.core_updates.last_status()?.is_some_and(|status| {
                matches!(
                    status.state.as_str(),
                    "committed" | "rolled_back" | "aborted" | "rollback_failed"
                )
            }) {
                break;
            }
        }
    }
    Ok(())
}

fn acknowledge_update_health(paths: &AppPaths) -> Result<(), ApiError> {
    let Some(path) = std::env::var_os("FMD_UPDATE_HEALTH_PATH").map(PathBuf::from) else {
        return Ok(());
    };
    let token = std::env::var("FMD_UPDATE_HEALTH_TOKEN")
        .map_err(|_| ApiError::new("update.health_context_invalid", EngineErrorKind::Integrity))?;
    let transaction_id = std::env::var("FMD_UPDATE_TRANSACTION_ID")
        .ok()
        .and_then(|value| Uuid::parse_str(&value).ok())
        .ok_or_else(|| {
            ApiError::new("update.health_context_invalid", EngineErrorKind::Integrity)
        })?;
    let installation_uuid = std::env::var("FMD_INSTALLATION_UUID")
        .ok()
        .and_then(|value| Uuid::parse_str(&value).ok())
        .ok_or_else(|| {
            ApiError::new("update.health_context_invalid", EngineErrorKind::Integrity)
        })?;
    let installation = resolve_update_installation(paths)?.ok_or_else(|| {
        ApiError::new(
            "update.health_identity_rejected",
            EngineErrorKind::Integrity,
        )
    })?;
    let expected_path = paths
        .state
        .join("update-transactions")
        .join(transaction_id.to_string())
        .join("health.ack");
    if path != expected_path
        || installation.marker.installation_uuid != installation_uuid
        || token.len() < 32
    {
        return Err(ApiError::new(
            "update.health_identity_rejected",
            EngineErrorKind::Integrity,
        ));
    }
    if fs::read_to_string(&path).is_ok_and(|value| value == token) {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ApiError::new("update.health_write_failed", EngineErrorKind::Disk))?;
    file.write_all(token.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| ApiError::new("update.health_write_failed", EngineErrorKind::Disk))
}

pub fn maybe_run_update_helper() -> Option<i32> {
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new("--fmd-apply-update-v2"))
    {
        return None;
    }
    const MAX_REQUEST_BYTES: usize = 1024 * 1024;
    let mut input = Vec::new();
    if std::io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > MAX_REQUEST_BYTES
    {
        return Some(2);
    }
    let Ok(request) = serde_json::from_slice::<ApplyRequestV2>(&input) else {
        return Some(2);
    };
    Some(if fmd_updater::apply(&request).is_ok() {
        0
    } else {
        3
    })
}

pub fn maybe_run_smoke_check() -> Option<i32> {
    if std::env::args_os().nth(1).as_deref() != Some(std::ffi::OsStr::new("--fmd-smoke-check")) {
        return None;
    }
    let core = include_bytes!("../resources/tuf/core-root.json");
    let engines = include_bytes!("../resources/tuf/engines-root.json");
    let valid = !env!("CARGO_PKG_VERSION").is_empty()
        && core != engines
        && serde_json::from_slice::<serde_json::Value>(core).is_ok()
        && serde_json::from_slice::<serde_json::Value>(engines).is_ok()
        && TargetId::current().is_some();
    Some(if valid { 0 } else { 4 })
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter("fmd=info,warn")
        .with_target(false)
        .compact()
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let state = AppState::initialize(app.handle())?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_info,
            classify_source,
            create_job,
            list_jobs,
            select_format,
            complete_job_selection,
            sftp_trust_status,
            authorize_sftp_job,
            start_job,
            cancel_job,
            pause_job,
            resume_job,
            retry_job,
            list_installed_packs,
            list_available_packs,
            install_pack,
            check_for_core_update,
            prepare_core_update,
            download_core_update,
            apply_core_update,
            last_core_update_status,
            acknowledge_ui_ready,
        ])
        .run(tauri::generate_context!())
        .expect("desktop runtime failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn portable_marker_is_discovered_above_versioned_payload() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("portable.json"), b"{}").unwrap();
        let executable = temporary.path().join("app/0.1.0/fmd-app.exe");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"").unwrap();
        assert_eq!(
            find_portable_root(&executable),
            Some(temporary.path().to_path_buf())
        );
    }

    #[test]
    fn bootstrap_trust_root_creates_embedded_root() {
        let temporary = tempfile::tempdir().unwrap();
        let trust_root = temporary.path().join("state/tuf/engines/root.json");
        bootstrap_trust_root(
            &trust_root,
            include_bytes!("../resources/tuf/engines-root.json"),
        )
        .unwrap();
        let bytes = std::fs::read(&trust_root).unwrap();
        assert!(bytes.ends_with(b"}\n"));
        assert_eq!(&bytes, include_bytes!("../resources/tuf/engines-root.json"));
        assert!(Path::new(&trust_root).is_file());
    }

    #[test]
    fn core_and_engine_trust_roots_are_distinct() {
        assert_ne!(
            include_bytes!("../resources/tuf/core-root.json"),
            include_bytes!("../resources/tuf/engines-root.json")
        );
    }

    #[test]
    fn sftp_trust_classifies_unknown_match_and_mismatch() {
        let observed = ObservedSftpKey {
            host: "sftp.example.test".into(),
            port: 22,
            algorithm: "ed25519".into(),
            raw_key_base64: "a2V5".into(),
            fingerprint_sha256: "SHA256:a2V5".into(),
        };
        assert_eq!(classify_sftp_trust(&[], &observed), "unknown");
        let record = SftpHostKeyRecord {
            host: observed.host.clone(),
            port: observed.port,
            algorithm: observed.algorithm.clone(),
            raw_key_base64: observed.raw_key_base64.clone(),
            fingerprint_sha256: observed.fingerprint_sha256.clone(),
            first_seen: "2026-08-15T00:00:00Z".into(),
            last_verified: "2026-08-15T00:00:00Z".into(),
            revoked: false,
        };
        assert_eq!(
            classify_sftp_trust(std::slice::from_ref(&record), &observed),
            "match"
        );
        let changed = SftpHostKeyRecord {
            raw_key_base64: "Y2hhbmdlZA==".into(),
            fingerprint_sha256: "SHA256:Y2hhbmdlZA==".into(),
            ..record
        };
        assert_eq!(classify_sftp_trust(&[changed], &observed), "mismatch");
    }
}
