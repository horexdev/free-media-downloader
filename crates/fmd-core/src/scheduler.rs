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
            playlist_entries: Vec::new(),
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
        if matches!(next, JobState::Probing | JobState::Queued) {
            job.error = None;
        }
        job.updated_at = Utc::now();
        self.store.save(job)?;
        Ok(job.clone())
    }

    pub fn set_plan(&self, id: JobId, plan: ResolvedPlan) -> Result<JobSnapshot, CoreError> {
        let next = if plan.formats.len() > 1
            || !plan.subtitles.is_empty()
            || !plan.playlist_entries.is_empty()
            || !plan.auth_requirements.is_empty()
        {
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
        self.complete_selection(id, Some(format), Vec::new(), None)
    }

    pub fn complete_selection(
        &self,
        id: JobId,
        format: Option<String>,
        subtitle_languages: Vec<String>,
        selected_playlist_entries: Option<Vec<u32>>,
    ) -> Result<JobSnapshot, CoreError> {
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
        let plan = job
            .plan
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("selection plan is missing".into()))?;
        if plan.formats.len() > 1
            && format
                .as_ref()
                .is_none_or(|value| !plan.formats.iter().any(|candidate| &candidate.id == value))
        {
            return Err(CoreError::InvalidInput("unknown format selection".into()));
        }
        if subtitle_languages
            .iter()
            .any(|language| !plan.subtitles.contains(language))
        {
            return Err(CoreError::InvalidInput("unknown subtitle selection".into()));
        }
        if let Some(entries) = &selected_playlist_entries
            && (entries.is_empty()
                || entries.iter().any(|index| {
                    !plan
                        .playlist_entries
                        .iter()
                        .any(|entry| entry.index == *index)
                }))
        {
            return Err(CoreError::InvalidInput("unknown playlist selection".into()));
        }
        job.spec.selected_format =
            format.or_else(|| (plan.formats.len() == 1).then(|| plan.formats[0].id.clone()));
        job.spec.subtitle_languages = subtitle_languages;
        job.spec.selected_playlist_entries = selected_playlist_entries;
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
            selected_playlist_entries: None,
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

    #[test]
    fn completes_format_subtitle_and_playlist_selection_atomically() {
        let scheduler = JobScheduler::new(JobStore::open_in_memory().unwrap(), 2).unwrap();
        let job = scheduler.create(spec()).unwrap();
        let plan = ResolvedPlan {
            source_kind: crate::source::SourceKind::SiteMedia,
            title: Some("Playlist".into()),
            formats: vec![
                crate::job::FormatOption {
                    id: "720".into(),
                    label: "720p".into(),
                    container: Some("mp4".into()),
                    estimated_bytes: None,
                },
                crate::job::FormatOption {
                    id: "1080".into(),
                    label: "1080p".into(),
                    container: Some("mp4".into()),
                    estimated_bytes: None,
                },
            ],
            subtitles: vec!["en".into(), "ru".into()],
            playlist_entries: vec![
                crate::job::PlaylistEntry {
                    index: 1,
                    id: "one".into(),
                    title: "One".into(),
                },
                crate::job::PlaylistEntry {
                    index: 2,
                    id: "two".into(),
                    title: "Two".into(),
                },
            ],
            chapters: 0,
            files: 2,
            warnings: Vec::new(),
            auth_requirements: Vec::new(),
            required_packs: Vec::new(),
        };
        let awaiting = scheduler.set_plan(job.id, plan).unwrap();
        assert_eq!(awaiting.state, JobState::AwaitingSelection);
        assert!(
            scheduler
                .complete_selection(job.id, Some("missing".into()), Vec::new(), None)
                .is_err()
        );
        let queued = scheduler
            .complete_selection(
                job.id,
                Some("1080".into()),
                vec!["en".into()],
                Some(vec![2]),
            )
            .unwrap();
        assert_eq!(queued.state, JobState::Queued);
        assert_eq!(queued.spec.selected_format.as_deref(), Some("1080"));
        assert_eq!(queued.spec.subtitle_languages, vec!["en"]);
        assert_eq!(queued.spec.selected_playlist_entries, Some(vec![2]));
    }
}
