use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::Utc;
use parking_lot::RwLock;
use tokio::sync::Semaphore;

use crate::error::CoreError;
use crate::job::{JobId, JobSnapshot, JobSpec, JobState, ResolvedPlan};
use crate::routing::Router;
use crate::storage::JobStore;

#[derive(Clone)]
pub struct JobScheduler {
    jobs: Arc<RwLock<BTreeMap<JobId, JobSnapshot>>>,
    store: JobStore,
    router: Router,
    concurrency: u8,
    permits: Arc<Semaphore>,
}

impl JobScheduler {
    pub fn new(store: JobStore, concurrency: u8) -> Result<Self, CoreError> {
        if !(1..=8).contains(&concurrency) {
            return Err(CoreError::InvalidInput(
                "concurrency must be between 1 and 8".into(),
            ));
        }
        let jobs = store.list()?.into_iter().map(|job| (job.id, job)).collect();
        Ok(Self {
            jobs: Arc::new(RwLock::new(jobs)),
            store,
            router: Router,
            concurrency,
            permits: Arc::new(Semaphore::new(concurrency.into())),
        })
    }

    #[must_use]
    pub fn store(&self) -> &JobStore {
        &self.store
    }

    #[must_use]
    pub const fn concurrency(&self) -> u8 {
        self.concurrency
    }

    #[must_use]
    pub fn permits(&self) -> Arc<Semaphore> {
        Arc::clone(&self.permits)
    }

    pub fn create(&self, spec: JobSpec) -> Result<JobSnapshot, CoreError> {
        if spec.destination.trim().is_empty() {
            return Err(CoreError::InvalidInput("destination is empty".into()));
        }
        let route = self.router.route(&spec.source)?;
        let mut job = JobSnapshot::new(spec);
        job.plan = Some(ResolvedPlan {
            source_kind: route.source_kind,
            title: None,
            formats: Vec::new(),
            subtitles: Vec::new(),
            chapters: 0,
            files: 1,
            warnings: Vec::new(),
            auth_requirements: Vec::new(),
            required_packs: route.required_packs,
        });
        job.state = JobState::Probing;
        job.updated_at = Utc::now();
        self.store.save(&job)?;
        self.jobs.write().insert(job.id, job.clone());
        Ok(job)
    }

    pub fn transition(&self, id: JobId, next: JobState) -> Result<JobSnapshot, CoreError> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .get_mut(&id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        if !job.state.can_transition_to(next) {
            return Err(CoreError::InvalidTransition {
                from: job.state.to_string(),
                to: next.to_string(),
            });
        }
        job.state = next;
        job.updated_at = Utc::now();
        self.store.save(job)?;
        Ok(job.clone())
    }

    pub fn set_plan(&self, id: JobId, plan: ResolvedPlan) -> Result<JobSnapshot, CoreError> {
        let next = if plan.formats.len() > 1 || !plan.auth_requirements.is_empty() {
            JobState::AwaitingSelection
        } else {
            JobState::Queued
        };
        let mut jobs = self.jobs.write();
        let job = jobs
            .get_mut(&id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        if job.state != JobState::Probing {
            return Err(CoreError::InvalidTransition {
                from: job.state.to_string(),
                to: next.to_string(),
            });
        }
        job.plan = Some(plan);
        job.state = next;
        job.updated_at = Utc::now();
        self.store.save(job)?;
        Ok(job.clone())
    }

    pub fn select_format(&self, id: JobId, format: String) -> Result<JobSnapshot, CoreError> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .get_mut(&id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        if job.state != JobState::AwaitingSelection {
            return Err(CoreError::InvalidTransition {
                from: job.state.to_string(),
                to: JobState::Queued.to_string(),
            });
        }
        let valid = job
            .plan
            .as_ref()
            .is_some_and(|plan| plan.formats.iter().any(|candidate| candidate.id == format));
        if !valid {
            return Err(CoreError::InvalidInput("unknown format selection".into()));
        }
        job.spec.selected_format = Some(format);
        job.state = JobState::Queued;
        job.updated_at = Utc::now();
        self.store.save(job)?;
        Ok(job.clone())
    }

    pub fn update_progress(
        &self,
        id: JobId,
        downloaded_bytes: u64,
        total_bytes: Option<u64>,
        speed_bytes_per_second: Option<u64>,
    ) -> Result<JobSnapshot, CoreError> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .get_mut(&id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        job.downloaded_bytes = downloaded_bytes;
        job.total_bytes = total_bytes;
        job.speed_bytes_per_second = speed_bytes_per_second;
        job.progress = total_bytes
            .filter(|total| *total > 0)
            .map_or(0.0, |total| downloaded_bytes as f64 / total as f64);
        job.updated_at = Utc::now();
        self.store.save(job)?;
        Ok(job.clone())
    }

    pub fn record_engine_version(
        &self,
        id: JobId,
        engine_id: String,
        version: String,
    ) -> Result<JobSnapshot, CoreError> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .get_mut(&id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        job.engine_versions.insert(engine_id, version);
        job.updated_at = Utc::now();
        self.store.save(job)?;
        Ok(job.clone())
    }

    pub fn fail(&self, id: JobId, error: crate::ApiError) -> Result<JobSnapshot, CoreError> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .get_mut(&id)
            .ok_or_else(|| CoreError::JobNotFound(id.to_string()))?;
        if job.state.is_terminal() {
            return Ok(job.clone());
        }
        job.state = JobState::Failed;
        job.error = Some(error);
        job.updated_at = Utc::now();
        self.store.save(job)?;
        Ok(job.clone())
    }

    pub fn list(&self) -> Vec<JobSnapshot> {
        let mut jobs = self.jobs.read().values().cloned().collect::<Vec<_>>();
        jobs.sort_by_key(|job| std::cmp::Reverse(job.updated_at));
        jobs
    }

    pub fn get(&self, id: JobId) -> Option<JobSnapshot> {
        self.jobs.read().get(&id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use crate::job::JobSpec;
    use crate::source::InputSource;

    use super::*;

    fn spec() -> JobSpec {
        JobSpec {
            source: InputSource::Url {
                value: "https://example.com/watch/1".into(),
            },
            destination: "downloads".into(),
            preferred_kind: None,
            selected_format: None,
            subtitle_languages: Vec::new(),
            overwrite: false,
        }
    }

    #[test]
    fn enforces_concurrency_bounds() {
        assert!(JobScheduler::new(JobStore::open_in_memory().unwrap(), 0).is_err());
        assert!(JobScheduler::new(JobStore::open_in_memory().unwrap(), 9).is_err());
    }

    #[test]
    fn creates_planned_queued_job() {
        let scheduler = JobScheduler::new(JobStore::open_in_memory().unwrap(), 2).unwrap();
        let job = scheduler.create(spec()).unwrap();
        assert_eq!(job.state, JobState::Probing);
        assert_eq!(job.plan.unwrap().required_packs[0], "ffmpeg-standard");
    }

    #[test]
    fn rejects_invalid_transition() {
        let scheduler = JobScheduler::new(JobStore::open_in_memory().unwrap(), 2).unwrap();
        let job = scheduler.create(spec()).unwrap();
        let error = scheduler
            .transition(job.id, JobState::Completed)
            .unwrap_err();
        assert!(matches!(error, CoreError::InvalidTransition { .. }));
    }
}
