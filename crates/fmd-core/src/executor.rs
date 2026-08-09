use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::adapter::{
    BuiltinCliAdapter, DownloadContext, EngineAdapter, EngineFailure, EventSink, ProbeContext,
};
use crate::engine::TargetId;
use crate::error::{ApiError, CoreError, EngineErrorKind};
use crate::job::{JobEvent, JobId, JobState};
use crate::pack::PackLayout;
use crate::routing::Router;
use crate::scheduler::JobScheduler;

#[derive(Clone)]
pub struct JobExecutor {
    scheduler: JobScheduler,
    packs: PackLayout,
    staging_root: PathBuf,
    cancellations: Arc<Mutex<BTreeMap<JobId, CancellationToken>>>,
    events: EventSink,
}

impl JobExecutor {
    #[must_use]
    pub fn new(
        scheduler: JobScheduler,
        packs: PackLayout,
        staging_root: PathBuf,
        events: EventSink,
    ) -> Self {
        Self {
            scheduler,
            packs,
            staging_root,
            cancellations: Arc::new(Mutex::new(BTreeMap::new())),
            events,
        }
    }

    pub fn submit(&self, id: JobId) -> Result<(), CoreError> {
        if self.scheduler.get(id).is_none() {
            return Err(CoreError::JobNotFound(id.to_string()));
        }
        let cancellation = CancellationToken::new();
        if self
            .cancellations
            .lock()
            .insert(id, cancellation.clone())
            .is_some()
        {
            return Ok(());
        }
        let executor = self.clone();
        tauri_independent_spawn(async move {
            if let Err(error) = executor.run(id, cancellation).await {
                let _ = executor.scheduler.fail(id, ApiError::from(error));
            }
            if executor
                .scheduler
                .get(id)
                .is_some_and(|job| job.state.is_terminal())
            {
                let _ = executor.scheduler.store().release_engine_leases(id);
            }
            executor.cancellations.lock().remove(&id);
        });
        Ok(())
    }

    pub fn cancel(&self, id: JobId) -> Result<(), CoreError> {
        if let Some(cancellation) = self.cancellations.lock().get(&id) {
            self.scheduler.transition(id, JobState::Canceled)?;
            (self.events)(JobEvent::StateChanged {
                id,
                state: JobState::Canceled,
            });
            cancellation.cancel();
            return Ok(());
        }
        let job = self
            .scheduler
            .get(id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        if matches!(
            job.state,
            JobState::Queued | JobState::Paused | JobState::Interrupted
        ) {
            self.scheduler.transition(id, JobState::Canceled)?;
            (self.events)(JobEvent::StateChanged {
                id,
                state: JobState::Canceled,
            });
            Ok(())
        } else {
            Err(CoreError::InvalidTransition {
                from: job.state.to_string(),
                to: JobState::Canceled.to_string(),
            })
        }
    }

    pub fn pause(&self, id: JobId) -> Result<(), CoreError> {
        let job = self
            .scheduler
            .get(id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        if !matches!(
            job.state,
            JobState::Queued | JobState::Preparing | JobState::Downloading
        ) {
            return Err(CoreError::InvalidTransition {
                from: job.state.to_string(),
                to: JobState::Paused.to_string(),
            });
        }
        self.scheduler.transition(id, JobState::Paused)?;
        (self.events)(JobEvent::StateChanged {
            id,
            state: JobState::Paused,
        });
        if let Some(cancellation) = self.cancellations.lock().get(&id) {
            cancellation.cancel();
        }
        Ok(())
    }

    pub fn resume(&self, id: JobId) -> Result<(), CoreError> {
        let job = self
            .scheduler
            .get(id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        if !matches!(job.state, JobState::Paused | JobState::Interrupted) {
            return Err(CoreError::InvalidTransition {
                from: job.state.to_string(),
                to: JobState::Queued.to_string(),
            });
        }
        if self.cancellations.lock().contains_key(&id) {
            return Err(CoreError::InvalidInput(
                "job process is still stopping".into(),
            ));
        }
        self.scheduler.transition(id, JobState::Queued)?;
        self.submit(id)
    }

    pub fn retry(&self, id: JobId) -> Result<(), CoreError> {
        let job = self
            .scheduler
            .get(id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        if job.state != JobState::Failed {
            return Err(CoreError::InvalidTransition {
                from: job.state.to_string(),
                to: JobState::Queued.to_string(),
            });
        }
        self.scheduler.transition(id, JobState::Queued)?;
        self.submit(id)
    }

    async fn run(&self, id: JobId, cancellation: CancellationToken) -> Result<(), CoreError> {
        let job = self
            .scheduler
            .get(id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        match job.state {
            JobState::Probing => self.probe(id, cancellation.clone()).await?,
            JobState::Queued => {}
            JobState::Interrupted | JobState::Paused => {
                self.transition(id, JobState::Queued)?;
            }
            JobState::AwaitingSelection => return Ok(()),
            _ => {
                return Err(CoreError::InvalidTransition {
                    from: job.state.to_string(),
                    to: JobState::Preparing.to_string(),
                });
            }
        }
        let job = self.scheduler.get(id).unwrap();
        if job.state == JobState::AwaitingSelection {
            return Ok(());
        }
        self.download(id, cancellation).await
    }

    async fn probe(&self, id: JobId, cancellation: CancellationToken) -> Result<(), CoreError> {
        let job = self.scheduler.get(id).unwrap();
        let route = Router.route(&job.spec.source)?;
        let missing = route
            .required_packs
            .iter()
            .filter(|pack| self.packs.active(pack).ok().flatten().is_none())
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let error = ApiError::new("pack.required", EngineErrorKind::Integrity)
                .with_arg("packs", missing.join(","));
            self.scheduler.fail(id, error.clone())?;
            (self.events)(JobEvent::Failed { id, error });
            return Ok(());
        }

        let staging = self.attempt_staging(id, 0);
        std::fs::create_dir_all(&staging)?;
        let mut last_failure = None;
        for engine_id in &route.engines {
            let Some(installation) = self.resolve_installation(engine_id)? else {
                continue;
            };
            let adapter = BuiltinCliAdapter::new(installation.descriptor.adapter_id);
            self.scheduler.store().acquire_engine_lease(
                id,
                &installation.pack_id,
                &installation.pack_version,
                &TargetId::current()
                    .ok_or_else(|| CoreError::SupplyChain("unsupported target".into()))?
                    .to_string(),
            )?;
            let context = ProbeContext {
                job_id: id,
                source: job.spec.source.clone(),
                source_kind: route.source_kind,
                staging: staging.clone(),
                installation: installation.clone(),
            };
            match adapter.probe(context, cancellation.clone()).await {
                Ok(mut plan) => {
                    plan.required_packs = route.required_packs;
                    self.scheduler.record_engine_version(
                        id,
                        engine_id.clone(),
                        installation.pack_version,
                    )?;
                    let snapshot = self.scheduler.set_plan(id, plan)?;
                    (self.events)(JobEvent::StateChanged {
                        id,
                        state: snapshot.state,
                    });
                    return Ok(());
                }
                Err(failure) if failure.kind.allows_fallback() => last_failure = Some(failure),
                Err(failure) => return self.fail_engine(id, failure),
            }
        }
        self.fail_engine(
            id,
            last_failure.unwrap_or_else(|| EngineFailure {
                kind: EngineErrorKind::Unsupported,
                code: "engine.not_installed".into(),
                retry_after_seconds: None,
                diagnostic: "no installed engine matched the route".into(),
            }),
        )
    }

    async fn download(&self, id: JobId, cancellation: CancellationToken) -> Result<(), CoreError> {
        let permit = self
            .scheduler
            .permits()
            .acquire_owned()
            .await
            .map_err(|_| CoreError::InvalidInput("job executor is shutting down".into()))?;
        let _permit = permit;
        let job = self.scheduler.get(id).unwrap();
        let route = Router.route(&job.spec.source)?;
        self.transition(id, JobState::Preparing)?;
        let mut last_failure = None;
        for (attempt, engine_id) in route.engines.iter().enumerate() {
            let Some(installation) = self.resolve_installation(engine_id)? else {
                continue;
            };
            let staging = self.attempt_staging(id, attempt as u32 + 1);
            std::fs::create_dir_all(&staging)?;
            let adapter = BuiltinCliAdapter::new(installation.descriptor.adapter_id);
            self.scheduler.store().acquire_engine_lease(
                id,
                &installation.pack_id,
                &installation.pack_version,
                &TargetId::current()
                    .ok_or_else(|| CoreError::SupplyChain("unsupported target".into()))?
                    .to_string(),
            )?;
            self.scheduler.record_engine_version(
                id,
                engine_id.clone(),
                installation.pack_version.clone(),
            )?;
            self.transition(id, JobState::Downloading)?;
            let context = DownloadContext {
                job_id: id,
                source: job.spec.source.clone(),
                source_kind: route.source_kind,
                selected_format: job.spec.selected_format.clone(),
                staging: staging.clone(),
                output_name: safe_output_name(
                    job.plan.as_ref().and_then(|plan| plan.title.as_deref()),
                ),
                installation,
            };
            let mut tries = 0_u8;
            loop {
                let outcome = adapter
                    .download(
                        context.clone(),
                        Arc::clone(&self.events),
                        cancellation.clone(),
                    )
                    .await;
                match outcome {
                    Ok(outcome) => {
                        let destination = unique_destination(
                            Path::new(&job.spec.destination),
                            outcome.output.file_name().ok_or(CoreError::NonUtf8Path)?,
                            job.spec.overwrite,
                        )?;
                        if outcome.requires_post_processing {
                            self.transition(id, JobState::PostProcessing)?;
                        }
                        std::fs::create_dir_all(destination.parent().ok_or_else(|| {
                            CoreError::InvalidInput("destination has no parent".into())
                        })?)?;
                        std::fs::rename(&outcome.output, &destination)?;
                        self.scheduler.update_progress(
                            id,
                            outcome.bytes,
                            Some(outcome.bytes),
                            None,
                        )?;
                        self.transition(id, JobState::Completed)?;
                        return Ok(());
                    }
                    Err(failure) if failure.kind.allows_retry() && tries < 3 => {
                        tries += 1;
                        let delay = failure.retry_after_seconds.unwrap_or(1_u64 << tries);
                        tokio::time::sleep(Duration::from_secs(delay.min(30))).await;
                    }
                    Err(failure) if failure.kind.allows_fallback() => {
                        last_failure = Some(failure);
                        break;
                    }
                    Err(failure) => return self.fail_engine(id, failure),
                }
            }
        }
        self.fail_engine(
            id,
            last_failure.unwrap_or_else(|| EngineFailure {
                kind: EngineErrorKind::Unsupported,
                code: "engine.not_installed".into(),
                retry_after_seconds: None,
                diagnostic: "no installed engine could execute the download".into(),
            }),
        )
    }

    fn transition(&self, id: JobId, state: JobState) -> Result<(), CoreError> {
        if self.scheduler.get(id).is_some_and(|job| job.state == state) {
            return Ok(());
        }
        self.scheduler.transition(id, state)?;
        (self.events)(JobEvent::StateChanged { id, state });
        Ok(())
    }

    fn fail_engine(&self, id: JobId, failure: EngineFailure) -> Result<(), CoreError> {
        if failure.kind == EngineErrorKind::Canceled
            && self
                .scheduler
                .get(id)
                .is_some_and(|job| matches!(job.state, JobState::Paused | JobState::Canceled))
        {
            return Ok(());
        }
        let error = failure.api_error();
        self.scheduler.fail(id, error.clone())?;
        (self.events)(JobEvent::Failed { id, error });
        Ok(())
    }

    fn attempt_staging(&self, id: JobId, attempt: u32) -> PathBuf {
        self.staging_root
            .join(id.to_string())
            .join(attempt.to_string())
    }

    fn resolve_installation(
        &self,
        engine_id: &str,
    ) -> Result<Option<crate::adapter::InstalledEngine>, CoreError> {
        let Some(mut installation) = self.packs.resolve_engine(engine_id)? else {
            return Ok(None);
        };
        if !matches!(
            installation.descriptor.adapter_id,
            crate::engine::AdapterId::FfmpegV1
        ) && let Some(ffmpeg) = self.packs.resolve_engine("ffmpeg")?
        {
            installation
                .shared_companions
                .insert("ffmpeg".into(), ffmpeg.entrypoint()?);
            if let Some(ffprobe) = ffmpeg.companion("ffprobe")? {
                installation
                    .shared_companions
                    .insert("ffprobe".into(), ffprobe);
            }
        }
        Ok(Some(installation))
    }
}

fn tauri_independent_spawn(future: impl std::future::Future<Output = ()> + Send + 'static) {
    tokio::spawn(future);
}

fn safe_output_name(title: Option<&str>) -> String {
    let title = title.unwrap_or("download");
    let mut value = title
        .chars()
        .map(|character| {
            if character.is_alphanumeric() || matches!(character, ' ' | '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    value = value.trim_matches([' ', '.']).to_owned();
    if value.is_empty() {
        value.push_str("download");
    }
    value.truncate(120);
    value
}

fn unique_destination(
    directory: &Path,
    name: &std::ffi::OsStr,
    overwrite: bool,
) -> Result<PathBuf, CoreError> {
    let initial = directory.join(name);
    if overwrite || !initial.exists() {
        return Ok(initial);
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("download");
    let extension = path.extension().and_then(|value| value.to_str());
    for index in 1..10_000 {
        let file_name = extension.map_or_else(
            || format!("{stem} ({index})"),
            |extension| format!("{stem} ({index}).{extension}"),
        );
        let candidate = directory.join(file_name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(CoreError::InvalidInput(
        "could not allocate a unique destination name".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_names_do_not_escape_destination() {
        assert_eq!(
            safe_output_name(Some("../../example:video")),
            "_.._example_video"
        );
    }
}
