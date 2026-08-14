use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u32 = 2;
const MAX_FILES: usize = 20_000;
const MAX_EXPANDED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    WindowsPortable,
    MacosSelfManaged,
    LinuxAppImage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    ZipPayload,
    AppImage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaunchMode {
    None,
    Normal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyRequestV2 {
    pub protocol_version: u32,
    pub transaction_id: Uuid,
    pub installation_uuid: Uuid,
    pub parent_pid: u32,
    pub parent_start_token: String,
    pub install_kind: InstallKind,
    pub artifact_kind: ArtifactKind,
    pub current_version: String,
    pub target_version: String,
    pub target_build: String,
    pub current_security_sequence: u64,
    pub target_security_sequence: u64,
    pub authorized_target_name: String,
    pub metadata_receipt_path: String,
    pub artifact_path: String,
    pub updates_root: String,
    pub artifact_length: u64,
    pub artifact_sha256: String,
    pub install_root: String,
    pub payload_root: String,
    pub state_root: String,
    pub backup_root: String,
    pub relaunch: RelaunchMode,
    pub health_token: String,
    pub health_deadline_seconds: u16,
}

pub type ApplyRequest = ApplyRequestV2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Prepared,
    WaitingForExit,
    Swapped,
    Launched,
    Healthy,
    Committed,
    RolledBack,
    Aborted,
    RollbackFailed,
}

impl TransactionState {
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        use TransactionState as S;
        matches!(
            (self, next),
            (S::Prepared, S::WaitingForExit | S::Aborted)
                | (S::WaitingForExit, S::Swapped | S::Aborted)
                | (
                    S::Swapped,
                    S::Launched | S::Healthy | S::RolledBack | S::RollbackFailed
                )
                | (S::Launched, S::Healthy | S::RolledBack | S::RollbackFailed)
                | (S::Healthy, S::Committed | S::RolledBack | S::RollbackFailed)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransactionJournal {
    transaction_id: Uuid,
    installation_uuid: Uuid,
    state: TransactionState,
    current_version: String,
    target_version: String,
    target_security_sequence: u64,
    updated_unix_seconds: u64,
    diagnostic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallMarker {
    installation_uuid: Uuid,
    install_kind: InstallKind,
    launcher: String,
    payload_executable: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CurrentPayload {
    version: String,
    executable: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestError {
    #[error("unsupported updater protocol version")]
    Protocol,
    #[error("security sequence must increase")]
    Rollback,
    #[error("invalid SHA-256 digest")]
    Digest,
    #[error("invalid health-check deadline")]
    Deadline,
    #[error("empty or unsafe request field")]
    UnsafeField,
    #[error("artifact and install roots must be absolute")]
    RelativePath,
    #[error("installation roots violate the fixed layout")]
    Layout,
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("request rejected: {0}")]
    Request(#[from] RequestError),
    #[error("file operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("metadata is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("archive is invalid: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("artifact identity does not match authorization")]
    ArtifactIdentity,
    #[error("installation marker does not authorize this request")]
    Marker,
    #[error("another update transaction is active")]
    Concurrent,
    #[error("parent process did not exit")]
    ParentAlive,
    #[error("parent process identity does not match the request")]
    ParentIdentity,
    #[error("candidate did not acknowledge health")]
    HealthTimeout,
    #[error("rollback failed: {0}")]
    Rollback(String),
}

impl ApplyRequestV2 {
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(RequestError::Protocol);
        }
        if self.target_security_sequence <= self.current_security_sequence {
            return Err(RequestError::Rollback);
        }
        if self.artifact_sha256.len() != 64
            || !self
                .artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RequestError::Digest);
        }
        if !(30..=60).contains(&self.health_deadline_seconds) {
            return Err(RequestError::Deadline);
        }
        if self.parent_pid == 0
            || self.parent_start_token.trim().is_empty()
            || self.health_token.len() < 32
            || !safe_component(&self.current_version)
            || !safe_component(&self.target_version)
            || !safe_component(&self.target_build)
            || !safe_component(&self.authorized_target_name)
            || self.artifact_length == 0
        {
            return Err(RequestError::UnsafeField);
        }
        let paths = [
            &self.metadata_receipt_path,
            &self.artifact_path,
            &self.updates_root,
            &self.install_root,
            &self.payload_root,
            &self.state_root,
            &self.backup_root,
        ];
        if paths.iter().any(|value| !Path::new(value).is_absolute()) {
            return Err(RequestError::RelativePath);
        }
        if paths
            .iter()
            .any(|value| has_parent_component(Path::new(value)))
        {
            return Err(RequestError::UnsafeField);
        }
        let install = Path::new(&self.install_root);
        let backup = Path::new(&self.backup_root);
        if !Path::new(&self.payload_root).starts_with(install)
            || (backup != Path::new(&self.state_root).join("update-backups")
                && backup != install.join(".fmd-backups"))
        {
            return Err(RequestError::Layout);
        }
        let transaction = self.transaction_id.to_string();
        let expected_root = Path::new(&self.updates_root).join("core").join(transaction);
        if Path::new(&self.metadata_receipt_path) != expected_root.join("receipt.json")
            || Path::new(&self.artifact_path) != expected_root.join("artifact.bin")
        {
            return Err(RequestError::Layout);
        }
        match (self.install_kind, self.artifact_kind) {
            (InstallKind::LinuxAppImage, ArtifactKind::AppImage)
            | (
                InstallKind::WindowsPortable | InstallKind::MacosSelfManaged,
                ArtifactKind::ZipPayload,
            ) => {}
            _ => return Err(RequestError::Layout),
        }
        Ok(())
    }
}

pub fn apply(request: &ApplyRequestV2) -> Result<TransactionState, UpdateError> {
    request.validate()?;
    if !process_start_token(request.parent_pid)
        .is_ok_and(|token| token == request.parent_start_token)
    {
        return Err(UpdateError::ParentIdentity);
    }
    let install_root = Path::new(&request.install_root);
    let state_root = Path::new(&request.state_root);
    let backup_root = Path::new(&request.backup_root);
    std::fs::create_dir_all(state_root)?;
    std::fs::create_dir_all(backup_root)?;

    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state_root.join("update.lock"))?;
    lock.try_lock_exclusive()
        .map_err(|_| UpdateError::Concurrent)?;
    verify_artifact(request)?;
    let marker: InstallMarker =
        serde_json::from_slice(&std::fs::read(install_root.join("install-marker.json"))?)?;
    validate_marker(request, &marker)?;

    let journal_dir = state_root
        .join("update-transactions")
        .join(request.transaction_id.to_string());
    std::fs::create_dir_all(&journal_dir)?;
    let journal_path = journal_dir.join("transaction.json");
    let mut journal = TransactionJournal {
        transaction_id: request.transaction_id,
        installation_uuid: request.installation_uuid,
        state: TransactionState::Prepared,
        current_version: request.current_version.clone(),
        target_version: request.target_version.clone(),
        target_security_sequence: request.target_security_sequence,
        updated_unix_seconds: now_unix(),
        diagnostic: None,
    };
    write_journal(&journal_path, &journal)?;

    transition(
        &journal_path,
        &mut journal,
        TransactionState::WaitingForExit,
        None,
    )?;
    if !wait_for_process_exit(request.parent_pid, Duration::from_secs(30)) {
        transition(
            &journal_path,
            &mut journal,
            TransactionState::Aborted,
            Some("parent_alive".into()),
        )?;
        return Err(UpdateError::ParentAlive);
    }

    let swap = match request.install_kind {
        InstallKind::WindowsPortable => prepare_windows_swap(request, &marker)?,
        InstallKind::MacosSelfManaged => prepare_bundle_swap(request)?,
        InstallKind::LinuxAppImage => prepare_appimage_swap(request)?,
    };
    swap.activate()?;
    transition(&journal_path, &mut journal, TransactionState::Swapped, None)?;

    if request.relaunch == RelaunchMode::None {
        transition(&journal_path, &mut journal, TransactionState::Healthy, None)?;
        transition(
            &journal_path,
            &mut journal,
            TransactionState::Committed,
            None,
        )?;
        return Ok(TransactionState::Committed);
    }

    let health_path = journal_dir.join("health.ack");
    let mut child = launch_candidate(request, &marker, &health_path)?;
    transition(
        &journal_path,
        &mut journal,
        TransactionState::Launched,
        None,
    )?;
    if wait_for_health(
        &mut child,
        &health_path,
        &request.health_token,
        Duration::from_secs(request.health_deadline_seconds.into()),
    ) {
        transition(&journal_path, &mut journal, TransactionState::Healthy, None)?;
        transition(
            &journal_path,
            &mut journal,
            TransactionState::Committed,
            None,
        )?;
        Ok(TransactionState::Committed)
    } else {
        let _ = child.kill();
        let _ = child.wait();
        if let Err(error) = swap.rollback() {
            transition(
                &journal_path,
                &mut journal,
                TransactionState::RollbackFailed,
                Some(error.to_string()),
            )?;
            return Err(UpdateError::Rollback(error.to_string()));
        }
        transition(
            &journal_path,
            &mut journal,
            TransactionState::RolledBack,
            Some("health_timeout".into()),
        )?;
        let _ = launch_previous(request, &marker);
        Err(UpdateError::HealthTimeout)
    }
}

enum Swap {
    Pointer {
        pointer: PathBuf,
        previous: Vec<u8>,
        next: Vec<u8>,
    },
    Payload {
        current: PathBuf,
        backup: PathBuf,
        candidate: PathBuf,
    },
}

impl Swap {
    fn activate(&self) -> Result<(), UpdateError> {
        match self {
            Self::Pointer { pointer, next, .. } => atomic_write(pointer, next),
            Self::Payload {
                current,
                backup,
                candidate,
            } => {
                if backup.exists() {
                    remove_payload(backup)?;
                }
                std::fs::rename(current, backup)?;
                if let Err(error) = std::fs::rename(candidate, current) {
                    let _ = std::fs::rename(backup, current);
                    return Err(error.into());
                }
                sync_parent(current)?;
                Ok(())
            }
        }
    }

    fn rollback(&self) -> Result<(), UpdateError> {
        match self {
            Self::Pointer {
                pointer, previous, ..
            } => atomic_write(pointer, previous),
            Self::Payload {
                current, backup, ..
            } => {
                let quarantined = current.with_extension(format!("quarantine-{}", Uuid::new_v4()));
                std::fs::rename(current, quarantined)?;
                std::fs::rename(backup, current)?;
                sync_parent(current)?;
                Ok(())
            }
        }
    }
}

fn prepare_windows_swap(
    request: &ApplyRequestV2,
    marker: &InstallMarker,
) -> Result<Swap, UpdateError> {
    let payload_root = Path::new(&request.payload_root);
    std::fs::create_dir_all(payload_root)?;
    let candidate = payload_root.join(format!(
        "{}.staging-{}",
        request.target_version, request.transaction_id
    ));
    extract_zip(Path::new(&request.artifact_path), &candidate)?;
    let final_path = payload_root.join(&request.target_version);
    if final_path.exists() {
        return Err(UpdateError::ArtifactIdentity);
    }
    std::fs::rename(candidate, &final_path)?;
    if !final_path.join(&marker.payload_executable).is_file() {
        return Err(UpdateError::Marker);
    }
    let pointer = Path::new(&request.state_root).join("current.json");
    let previous = std::fs::read(&pointer)?;
    let current: CurrentPayload = serde_json::from_slice(&previous)?;
    if current.version != request.current_version {
        return Err(UpdateError::Marker);
    }
    let next = serde_json::to_vec_pretty(&CurrentPayload {
        version: request.target_version.clone(),
        executable: marker.payload_executable.clone(),
    })?;
    Ok(Swap::Pointer {
        pointer,
        previous,
        next,
    })
}

fn prepare_bundle_swap(request: &ApplyRequestV2) -> Result<Swap, UpdateError> {
    let candidate_root =
        Path::new(&request.backup_root).join(format!("candidate-{}", request.transaction_id));
    extract_zip(Path::new(&request.artifact_path), &candidate_root)?;
    let entries = std::fs::read_dir(&candidate_root)?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() != 1 {
        return Err(UpdateError::ArtifactIdentity);
    }
    Ok(Swap::Payload {
        current: PathBuf::from(&request.payload_root),
        backup: Path::new(&request.backup_root).join("previous-payload"),
        candidate: entries[0].path(),
    })
}

fn prepare_appimage_swap(request: &ApplyRequestV2) -> Result<Swap, UpdateError> {
    let candidate = Path::new(&request.backup_root)
        .join(format!("candidate-{}.AppImage", request.transaction_id));
    std::fs::copy(&request.artifact_path, &candidate)?;
    Ok(Swap::Payload {
        current: PathBuf::from(&request.payload_root),
        backup: Path::new(&request.backup_root).join("previous.AppImage"),
        candidate,
    })
}

fn launch_candidate(
    request: &ApplyRequestV2,
    marker: &InstallMarker,
    health_path: &Path,
) -> Result<Child, UpdateError> {
    let executable = match request.install_kind {
        InstallKind::WindowsPortable => {
            let pointer: CurrentPayload = serde_json::from_slice(&std::fs::read(
                Path::new(&request.state_root).join("current.json"),
            )?)?;
            Path::new(&request.payload_root)
                .join(pointer.version)
                .join(pointer.executable)
        }
        InstallKind::MacosSelfManaged => {
            Path::new(&request.payload_root).join(&marker.payload_executable)
        }
        InstallKind::LinuxAppImage => PathBuf::from(&request.payload_root),
    };
    let child = Command::new(executable)
        .env_clear()
        .env("FMD_UPDATE_HEALTH_PATH", health_path)
        .env("FMD_UPDATE_HEALTH_TOKEN", &request.health_token)
        .env(
            "FMD_UPDATE_TRANSACTION_ID",
            request.transaction_id.to_string(),
        )
        .env(
            "FMD_INSTALLATION_UUID",
            request.installation_uuid.to_string(),
        )
        .spawn()?;
    Ok(child)
}

fn launch_previous(request: &ApplyRequestV2, marker: &InstallMarker) -> Result<Child, UpdateError> {
    let executable = match request.install_kind {
        InstallKind::WindowsPortable => Path::new(&request.install_root).join(&marker.launcher),
        InstallKind::MacosSelfManaged => {
            Path::new(&request.payload_root).join(&marker.payload_executable)
        }
        InstallKind::LinuxAppImage => PathBuf::from(&request.payload_root),
    };
    Ok(Command::new(executable).env_clear().spawn()?)
}

fn wait_for_health(child: &mut Child, path: &Path, token: &str, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if std::fs::read_to_string(path).is_ok_and(|value| value.trim() == token) {
            return true;
        }
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn verify_artifact(request: &ApplyRequestV2) -> Result<(), UpdateError> {
    let metadata = std::fs::metadata(&request.artifact_path)?;
    if metadata.len() != request.artifact_length
        || !Path::new(&request.metadata_receipt_path).is_file()
    {
        return Err(UpdateError::ArtifactIdentity);
    }
    let mut file = File::open(&request.artifact_path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    if format!("{:x}", hasher.finalize()) != request.artifact_sha256.to_ascii_lowercase() {
        return Err(UpdateError::ArtifactIdentity);
    }
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&request.metadata_receipt_path)?)?;
    let receipt_matches = receipt.get("target_name").and_then(|value| value.as_str())
        == Some(request.authorized_target_name.as_str())
        && receipt.get("version").and_then(|value| value.as_str())
            == Some(request.target_version.as_str())
        && receipt
            .get("security_sequence")
            .and_then(|value| value.as_u64())
            == Some(request.target_security_sequence)
        && receipt.get("length").and_then(|value| value.as_u64()) == Some(request.artifact_length)
        && receipt
            .get("sha256")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.eq_ignore_ascii_case(&request.artifact_sha256));
    if !receipt_matches {
        return Err(UpdateError::ArtifactIdentity);
    }
    Ok(())
}

fn validate_marker(request: &ApplyRequestV2, marker: &InstallMarker) -> Result<(), UpdateError> {
    if marker.installation_uuid != request.installation_uuid
        || marker.install_kind != request.install_kind
        || !safe_relative(Path::new(&marker.launcher))
        || !safe_relative(Path::new(&marker.payload_executable))
    {
        return Err(UpdateError::Marker);
    }
    Ok(())
}

fn extract_zip(archive: &Path, destination: &Path) -> Result<(), UpdateError> {
    let file = File::open(archive)?;
    let mut archive = zip::ZipArchive::new(file)?;
    if archive.len() > MAX_FILES {
        return Err(UpdateError::ArtifactIdentity);
    }
    std::fs::create_dir_all(destination)?;
    let mut expanded = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_symlink() || (!entry.is_file() && !entry.is_dir()) {
            return Err(UpdateError::ArtifactIdentity);
        }
        expanded = expanded
            .checked_add(entry.size())
            .ok_or(UpdateError::ArtifactIdentity)?;
        if expanded > MAX_EXPANDED_BYTES {
            return Err(UpdateError::ArtifactIdentity);
        }
        let enclosed = entry.enclosed_name().ok_or(UpdateError::ArtifactIdentity)?;
        if !safe_relative(&enclosed) {
            return Err(UpdateError::ArtifactIdentity);
        }
        let output = destination.join(enclosed);
        if entry.is_dir() {
            std::fs::create_dir_all(&output)?;
            continue;
        }
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        std::io::copy(&mut entry, &mut target)?;
        target.sync_all()?;
    }
    sync_parent(destination)?;
    Ok(())
}

fn transition(
    path: &Path,
    journal: &mut TransactionJournal,
    state: TransactionState,
    diagnostic: Option<String>,
) -> Result<(), UpdateError> {
    if !journal.state.can_transition_to(state) {
        return Err(UpdateError::Marker);
    }
    journal.state = state;
    journal.updated_unix_seconds = now_unix();
    journal.diagnostic = diagnostic;
    write_journal(path, journal)
}

fn write_journal(path: &Path, journal: &TransactionJournal) -> Result<(), UpdateError> {
    atomic_write(path, &serde_json::to_vec_pretty(journal)?)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), UpdateError> {
    let parent = path.parent().ok_or(UpdateError::Marker)?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("state"),
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    replace_file(&temporary, path)?;
    sync_parent(path)?;
    Ok(())
}

#[cfg(unix)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), UpdateError> {
    std::fs::rename(source, destination)?;
    Ok(())
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), UpdateError> {
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
    let source = wide(source);
    let destination_wide = wide(destination);
    let started = Instant::now();
    loop {
        let success = unsafe {
            if destination.exists() {
                ReplaceFileW(
                    destination_wide.as_ptr(),
                    source.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } else {
                MoveFileExW(
                    source.as_ptr(),
                    destination_wide.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            }
        };
        if success != 0 {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(10) {
            return Err(std::io::Error::last_os_error().into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn sync_parent(path: &Path) -> Result<(), UpdateError> {
    #[cfg(unix)]
    {
        let directory = File::open(path.parent().unwrap_or(path))?;
        directory.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn remove_payload(path: &Path) -> Result<(), UpdateError> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn wait_for_process_exit(pid: u32, timeout: Duration) -> bool {
    let started = Instant::now();
    let expected = process_start_token(pid).ok();
    while started.elapsed() < timeout {
        if !process_exists(pid) || process_start_token(pid).ok() != expected {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

pub fn process_start_token(pid: u32) -> Result<String, std::io::Error> {
    process_start_token_impl(pid)
}

#[cfg(target_os = "linux")]
fn process_start_token_impl(pid: u32) -> Result<String, std::io::Error> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let closing = stat.rfind(')').ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid process stat")
    })?;
    stat[closing + 1..]
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing process start token",
            )
        })
}

#[cfg(target_os = "macos")]
fn process_start_token_impl(pid: u32) -> Result<String, std::io::Error> {
    let output = Command::new("/bin/ps")
        .env_clear()
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()?;
    let token = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !output.status.success() || token.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "process start token unavailable",
        ));
    }
    Ok(token)
}

#[cfg(windows)]
fn process_start_token_impl(pid: u32) -> Result<String, std::io::Error> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess};
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let success = GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user);
        CloseHandle(handle);
        if success == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(format!(
            "{:08x}{:08x}",
            created.dwHighDateTime, created.dwLowDateTime
        ))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn process_start_token_impl(_pid: u32) -> Result<String, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process start tokens are not supported",
    ))
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

#[cfg(windows)]
fn process_exists(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject};
    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE_ACCESS, 0, pid);
        if handle.is_null() {
            return false;
        }
        let exists = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
        CloseHandle(handle);
        exists
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn has_parent_component(path: &Path) -> bool {
    path.components().any(|part| part == Component::ParentDir)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request(root: &Path) -> ApplyRequestV2 {
        let transaction_id = Uuid::new_v4();
        let updates_root = root.join("updates");
        let transaction_root = updates_root.join("core").join(transaction_id.to_string());
        std::fs::create_dir_all(&transaction_root).unwrap();
        let artifact = transaction_root.join("artifact.bin");
        std::fs::write(&artifact, b"update payload").unwrap();
        let sha256 = format!("{:x}", Sha256::digest(b"update payload"));
        let receipt = serde_json::json!({
            "target_name": "core-windows-x64.json",
            "version": "0.2.0",
            "security_sequence": 2,
            "length": 14,
            "sha256": sha256,
            "metadata_json": "{}",
            "created_at": "2026-08-15T00:00:00Z"
        });
        std::fs::write(
            transaction_root.join("receipt.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        let install = root.join("install");
        let state = root.join("state");
        ApplyRequestV2 {
            protocol_version: PROTOCOL_VERSION,
            transaction_id,
            installation_uuid: Uuid::new_v4(),
            parent_pid: std::process::id(),
            parent_start_token: process_start_token(std::process::id()).unwrap(),
            install_kind: InstallKind::WindowsPortable,
            artifact_kind: ArtifactKind::ZipPayload,
            current_version: "0.1.0".into(),
            target_version: "0.2.0".into(),
            target_build: "core-windows-x64.json".into(),
            current_security_sequence: 1,
            target_security_sequence: 2,
            authorized_target_name: "core-windows-x64.json".into(),
            metadata_receipt_path: transaction_root
                .join("receipt.json")
                .to_string_lossy()
                .into(),
            artifact_path: artifact.to_string_lossy().into(),
            updates_root: updates_root.to_string_lossy().into(),
            artifact_length: 14,
            artifact_sha256: sha256,
            install_root: install.to_string_lossy().into(),
            payload_root: install.join("app").to_string_lossy().into(),
            state_root: state.to_string_lossy().into(),
            backup_root: state.join("update-backups").to_string_lossy().into(),
            relaunch: RelaunchMode::Normal,
            health_token: "b".repeat(64),
            health_deadline_seconds: 60,
        }
    }

    #[test]
    fn state_machine_cannot_skip_health_check() {
        assert!(!TransactionState::Swapped.can_transition_to(TransactionState::Committed));
        assert!(TransactionState::Healthy.can_transition_to(TransactionState::Committed));
    }

    #[test]
    fn rejects_rollback_sequence() {
        let root = if cfg!(windows) {
            r"C:\Apps\FMD"
        } else {
            "/opt/fmd"
        };
        let request = ApplyRequestV2 {
            protocol_version: PROTOCOL_VERSION,
            transaction_id: Uuid::new_v4(),
            installation_uuid: Uuid::new_v4(),
            parent_pid: 42,
            parent_start_token: "created-123".into(),
            install_kind: InstallKind::WindowsPortable,
            artifact_kind: ArtifactKind::ZipPayload,
            current_version: "0.1.0".into(),
            target_version: "0.2.0".into(),
            target_build: "release-1".into(),
            current_security_sequence: 7,
            target_security_sequence: 7,
            authorized_target_name: "fmd.zip".into(),
            metadata_receipt_path: format!("{root}/state/receipt.json"),
            artifact_path: format!("{root}/state/fmd.zip"),
            updates_root: format!("{root}/updates"),
            artifact_length: 1024,
            artifact_sha256: "a".repeat(64),
            install_root: root.into(),
            payload_root: format!("{root}/app"),
            state_root: format!("{root}/state"),
            backup_root: format!("{root}/backup"),
            relaunch: RelaunchMode::Normal,
            health_token: "b".repeat(32),
            health_deadline_seconds: 60,
        };
        assert_eq!(request.validate(), Err(RequestError::Rollback));
    }

    #[test]
    fn request_paths_are_bound_to_the_transaction() {
        let temporary = tempfile::tempdir().unwrap();
        let mut request = valid_request(temporary.path());
        assert_eq!(request.validate(), Ok(()));
        request.artifact_path = temporary.path().join("other.bin").to_string_lossy().into();
        assert_eq!(request.validate(), Err(RequestError::Layout));
    }

    #[test]
    fn artifact_verification_checks_the_receipt_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let request = valid_request(temporary.path());
        assert!(verify_artifact(&request).is_ok());
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&request.metadata_receipt_path).unwrap())
                .unwrap();
        receipt["security_sequence"] = serde_json::json!(3);
        std::fs::write(
            &request.metadata_receipt_path,
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_artifact(&request),
            Err(UpdateError::ArtifactIdentity)
        ));
    }

    #[test]
    fn current_process_has_a_stable_start_token() {
        let pid = std::process::id();
        let first = process_start_token(pid).unwrap();
        let second = process_start_token(pid).unwrap();
        assert!(!first.is_empty());
        assert_eq!(first, second);
    }

    #[test]
    fn pointer_swap_rolls_back_to_the_previous_payload() {
        let temporary = tempfile::tempdir().unwrap();
        let pointer = temporary.path().join("current.json");
        std::fs::write(&pointer, b"previous").unwrap();
        let swap = Swap::Pointer {
            pointer: pointer.clone(),
            previous: b"previous".to_vec(),
            next: b"next".to_vec(),
        };
        swap.activate().unwrap();
        assert_eq!(std::fs::read(&pointer).unwrap(), b"next");
        swap.rollback().unwrap();
        assert_eq!(std::fs::read(&pointer).unwrap(), b"previous");
    }

    #[test]
    fn payload_swap_quarantines_a_failed_candidate_before_rollback() {
        let temporary = tempfile::tempdir().unwrap();
        let current = temporary.path().join("current");
        let candidate = temporary.path().join("candidate");
        let backup = temporary.path().join("backup");
        std::fs::create_dir(&current).unwrap();
        std::fs::create_dir(&candidate).unwrap();
        std::fs::write(current.join("version"), b"previous").unwrap();
        std::fs::write(candidate.join("version"), b"candidate").unwrap();
        let swap = Swap::Payload {
            current: current.clone(),
            backup,
            candidate,
        };
        swap.activate().unwrap();
        assert_eq!(
            std::fs::read(current.join("version")).unwrap(),
            b"candidate"
        );
        swap.rollback().unwrap();
        assert_eq!(std::fs::read(current.join("version")).unwrap(), b"previous");
    }
}
