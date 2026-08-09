use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fmd_core::{
    ApiError, BuiltinCliAdapter, CoreError, EngineAdapter, EngineErrorKind, ExtractionLimits,
    InputSource, InstalledEngine, JobExecutor, JobId, JobScheduler, JobSnapshot, JobSpec, JobStore,
    PackInstaller, PackLayout, RouteDecision, Router, TargetId, TufRepository,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio_util::sync::CancellationToken;
use ts_rs::TS;
use url::Url;
use uuid::Uuid;

struct AppState {
    scheduler: JobScheduler,
    executor: Arc<JobExecutor>,
    packs: PackService,
    paths: AppPaths,
}

#[derive(Clone)]
struct PackService {
    store: JobStore,
    layout: PackLayout,
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
    installed: bool,
}

impl PackService {
    async fn repository(&self) -> Result<TufRepository, ApiError> {
        let trust_root = self.state_root.join("tuf/engines/root.json");
        if !trust_root.is_file() {
            return Err(ApiError::new(
                "pack.trust_root_missing",
                EngineErrorKind::Integrity,
            ));
        }
        let root = fs::read(trust_root)
            .map_err(CoreError::from)
            .map_err(ApiError::from)?;
        TufRepository::load_persistent(
            &root,
            Url::parse(
                "https://horexdev.github.io/free-media-downloader-updates/engines/metadata/",
            )
            .expect("static URL"),
            Url::parse("https://horexdev.github.io/free-media-downloader-updates/engines/targets/")
                .expect("static URL"),
            &self.state_root.join("tuf/engines/datastore"),
            &["horexdev.github.io"],
        )
        .await
        .map_err(ApiError::from)
    }

    async fn available(&self) -> Result<Vec<AvailablePack>, ApiError> {
        let current = TargetId::current().ok_or_else(|| {
            ApiError::new("pack.target_unsupported", EngineErrorKind::Unsupported)
        })?;
        let repository = self.repository().await?;
        let mut packs = repository
            .external_targets()
            .map_err(ApiError::from)?
            .into_iter()
            .filter(|target| target.target == current)
            .map(|target| AvailablePack {
                installed: self
                    .layout
                    .active(&target.pack_id)
                    .ok()
                    .flatten()
                    .is_some_and(|active| {
                        active.version == target.pack_version
                            && active.security_sequence == target.security_sequence
                    }),
                target_name: target.name,
                pack_id: target.pack_id,
                version: target.pack_version,
                target: target.target.to_string(),
                security_sequence: target.security_sequence,
            })
            .collect::<Vec<_>>();
        packs.sort_by(|left, right| {
            left.pack_id
                .cmp(&right.pack_id)
                .then(right.security_sequence.cmp(&left.security_sequence))
        });
        Ok(packs)
    }

    async fn install(&self, pack_id: &str, target_name: &str) -> Result<String, ApiError> {
        let repository = self.repository().await?;
        let authorization = repository
            .external_target(target_name)
            .map_err(ApiError::from)?;
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
        repository
            .download_external_target(
                &authorization,
                &archive,
                &[
                    "github.com",
                    "objects.githubusercontent.com",
                    "release-assets.githubusercontent.com",
                ],
            )
            .await
            .map_err(ApiError::from)?;
        let installer = PackInstaller::new(
            self.layout.clone(),
            current_target,
            ExtractionLimits::default(),
        );
        let manifest = installer
            .install_archive(&archive)
            .map_err(ApiError::from)?;
        let _ = fs::remove_file(&archive);
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
        self.store
            .advance_pack_security_high_water(pack_id, manifest.security_sequence)
            .map_err(ApiError::from)?;
        let pointer = self.layout.activate(&manifest).map_err(ApiError::from)?;
        self.store
            .record_pack_activation(&pointer)
            .map_err(ApiError::from)?;
        Ok(format!("{}@{}", manifest.id, manifest.version))
    }

    async fn ensure(&self, pack_ids: &[String]) -> Result<(), ApiError> {
        let available = self.available().await?;
        for pack_id in pack_ids {
            if self
                .layout
                .active(pack_id)
                .map_err(ApiError::from)?
                .is_some()
            {
                continue;
            }
            let target = available
                .iter()
                .filter(|candidate| &candidate.pack_id == pack_id)
                .max_by_key(|candidate| candidate.security_sequence)
                .ok_or_else(|| ApiError::new("pack.not_available", EngineErrorKind::Integrity))?;
            self.install(pack_id, &target.target_name).await?;
        }
        Ok(())
    }
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
        let scheduler = JobScheduler::new(store, 2)?;
        let event_handle = handle.clone();
        let events = Arc::new(move |event| {
            let _ = event_handle.emit("job-event", event);
        });
        let executor = Arc::new(JobExecutor::new(
            scheduler.clone(),
            PackLayout::new(paths.engines.clone()),
            paths.data.join("staging"),
            events,
        ));
        let packs = PackService {
            store: scheduler.store().clone(),
            layout: PackLayout::new(paths.engines.clone()),
            state_root: paths.state.clone(),
            updates_root: paths.updates.clone(),
        };
        Ok(Self {
            scheduler,
            executor,
            packs,
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
fn acknowledge_ui_ready(state: State<'_, AppState>) -> Result<(), ApiError> {
    let Some(path) = std::env::var_os("FMD_UPDATE_HEALTH_PATH").map(PathBuf::from) else {
        return Ok(());
    };
    let Some(token) = std::env::var_os("FMD_UPDATE_HEALTH_TOKEN") else {
        return Ok(());
    };
    let allowed_root = state.paths.state.join("update-transactions");
    if !path.is_absolute()
        || !path.starts_with(&allowed_root)
        || path.file_name().and_then(|v| v.to_str()) != Some("health.ack")
    {
        return Err(ApiError::new(
            "update.health_path_rejected",
            EngineErrorKind::Integrity,
        ));
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ApiError::new("update.health_write_failed", EngineErrorKind::Disk))?;
    file.write_all(token.to_string_lossy().as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| ApiError::new("update.health_write_failed", EngineErrorKind::Disk))
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
            start_job,
            cancel_job,
            pause_job,
            resume_job,
            retry_job,
            list_installed_packs,
            list_available_packs,
            install_pack,
            acknowledge_ui_ready
        ])
        .run(tauri::generate_context!())
        .expect("desktop runtime failed");
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
