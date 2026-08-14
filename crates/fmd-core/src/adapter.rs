use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::engine::{AdapterId, EngineDescriptor};
use crate::error::{ApiError, CoreError, EngineErrorKind};
use crate::job::{FormatOption, JobEvent, JobId, ResolvedPlan};
use crate::process::{EngineCommand, OutputStream, ProcessSpec, ProcessSupervisor};
use crate::source::{InputSource, SourceKind};

#[derive(Debug, Clone)]
pub struct InstalledEngine {
    pub descriptor: EngineDescriptor,
    pub pack_id: String,
    pub pack_version: String,
    pub root: PathBuf,
    pub shared_companions: BTreeMap<String, PathBuf>,
}

impl InstalledEngine {
    pub fn entrypoint(&self) -> Result<PathBuf, CoreError> {
        let path = self.root.join(
            self.descriptor
                .entrypoint
                .replace('/', std::path::MAIN_SEPARATOR_STR),
        );
        if !path.is_file() {
            return Err(CoreError::SupplyChain(format!(
                "engine entrypoint is missing: {}",
                self.descriptor.id
            )));
        }
        Ok(path)
    }

    pub fn companion(&self, role: &str) -> Result<Option<PathBuf>, CoreError> {
        if let Some(path) = self.shared_companions.get(role) {
            return if path.is_file() {
                Ok(Some(path.clone()))
            } else {
                Err(CoreError::SupplyChain(format!(
                    "shared engine companion '{role}' is missing"
                )))
            };
        }
        self.descriptor
            .companions
            .get(role)
            .map(|value| {
                let path = self
                    .root
                    .join(value.replace('/', std::path::MAIN_SEPARATOR_STR));
                if path.is_file() {
                    Ok(path)
                } else {
                    Err(CoreError::SupplyChain(format!(
                        "engine companion '{role}' is missing"
                    )))
                }
            })
            .transpose()
    }
}

#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub job_id: JobId,
    pub source: InputSource,
    pub source_kind: SourceKind,
    pub staging: PathBuf,
    pub installation: InstalledEngine,
}

#[derive(Debug, Clone)]
pub struct DownloadContext {
    pub job_id: JobId,
    pub source: InputSource,
    pub source_kind: SourceKind,
    pub selected_format: Option<String>,
    pub subtitle_languages: Vec<String>,
    pub selected_playlist_entries: Option<Vec<u32>>,
    pub transfer_auth: Option<TransferAuth>,
    pub staging: PathBuf,
    pub output_name: String,
    pub installation: InstalledEngine,
}

#[derive(Debug, Clone)]
pub struct TransferAuth {
    pub credentials: fmd_curl_worker::Credentials,
    pub trusted_host_key: fmd_curl_worker::TrustedHostKey,
}

pub type EventSink = Arc<dyn Fn(JobEvent) + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadOutcome {
    pub output: PathBuf,
    pub bytes: u64,
    pub requires_post_processing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineFailure {
    pub kind: EngineErrorKind,
    pub code: String,
    pub retry_after_seconds: Option<u64>,
    pub diagnostic: String,
}

impl EngineFailure {
    #[must_use]
    pub fn api_error(&self) -> ApiError {
        ApiError::new(self.code.clone(), self.kind)
    }
}

#[async_trait]
pub trait EngineAdapter: Send + Sync {
    fn adapter_id(&self) -> AdapterId;

    async fn self_test(
        &self,
        installation: &InstalledEngine,
        cancellation: CancellationToken,
    ) -> Result<(), EngineFailure>;

    async fn probe(
        &self,
        context: ProbeContext,
        cancellation: CancellationToken,
    ) -> Result<ResolvedPlan, EngineFailure>;

    async fn download(
        &self,
        context: DownloadContext,
        events: EventSink,
        cancellation: CancellationToken,
    ) -> Result<DownloadOutcome, EngineFailure>;

    fn classify_failure(&self, exit_code: Option<i32>, stderr: &str) -> EngineFailure;
}

#[derive(Debug, Clone, Copy)]
pub struct BuiltinCliAdapter {
    id: AdapterId,
    supervisor: ProcessSupervisor,
}

impl BuiltinCliAdapter {
    #[must_use]
    pub const fn new(id: AdapterId) -> Self {
        Self {
            id,
            supervisor: ProcessSupervisor,
        }
    }

    fn command(
        &self,
        installation: &InstalledEngine,
        staging: &Path,
    ) -> Result<EngineCommand, CoreError> {
        EngineCommand::new(&installation.entrypoint()?, staging)
            .map(|command| command.sanitized_environment(staging))
    }

    fn source_url(source: &InputSource) -> Result<&str, EngineFailure> {
        match source {
            InputSource::Url { value } => Ok(value),
            InputSource::LocalManifest { path } | InputSource::LocalMetalink { path } => Ok(path),
        }
    }

    fn probe_command(&self, context: &ProbeContext) -> Result<EngineCommand, CoreError> {
        let source = Self::source_url(&context.source)
            .map_err(|error| CoreError::InvalidInput(error.diagnostic))?;
        let command = if self.id == AdapterId::FfmpegV1 {
            let ffprobe = context
                .installation
                .companion("ffprobe")?
                .ok_or_else(|| CoreError::SupplyChain("ffprobe companion is missing".into()))?;
            EngineCommand::new(&ffprobe, &context.staging)?.sanitized_environment(&context.staging)
        } else {
            self.command(&context.installation, &context.staging)?
        };
        Ok(match self.id {
            AdapterId::YtDlpV1 => {
                let mut command = command
                    .arg("--ignore-config")
                    .arg("--no-plugin-dirs")
                    .arg("--dump-single-json")
                    .arg("--skip-download");
                if let Some(deno) = context.installation.companion("deno")? {
                    command = command
                        .arg("--js-runtimes")
                        .arg(format!("deno:{}", deno.to_string_lossy()));
                }
                command.arg("--").arg(source)
            }
            AdapterId::StreamlinkV1 => command
                .arg("--no-config")
                .arg("--no-plugin-sideloading")
                .arg("--json")
                .arg("--")
                .arg(source),
            AdapterId::GalleryDlV1 => command
                .arg("--config-ignore")
                .arg("--dump-json")
                .arg("--")
                .arg(source),
            AdapterId::FfmpegV1 => command
                .arg("-v")
                .arg("error")
                .arg("-of")
                .arg("json")
                .arg("-show_format")
                .arg("-show_streams")
                .arg(source),
            AdapterId::NM3u8DlReV1 | AdapterId::Aria2V1 | AdapterId::CurlWorkerV2 => {
                command.arg("--version")
            }
        })
    }

    fn download_command(
        &self,
        context: &DownloadContext,
    ) -> Result<(EngineCommand, PathBuf), CoreError> {
        let source = Self::source_url(&context.source)
            .map_err(|error| CoreError::InvalidInput(error.diagnostic))?;
        let output = context.staging.join(&context.output_name);
        let command = self.command(&context.installation, &context.staging)?;
        let command = match self.id {
            AdapterId::YtDlpV1 => {
                let mut command = command
                    .arg("--ignore-config")
                    .arg("--no-plugin-dirs")
                    .arg("--newline")
                    .arg("--progress-template")
                    .arg("download:FMD_PROGRESS %(progress.downloaded_bytes)s/%(progress.total_bytes)s")
                    .arg("--paths")
                    .arg(context.staging.as_os_str())
                    .arg("--output")
                    .arg(&context.output_name);
                if let Some(format) = &context.selected_format {
                    command = command.arg("--format").arg(format);
                }
                if let Some(entries) = &context.selected_playlist_entries {
                    let items = entries
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    command = command.arg("--playlist-items").arg(items);
                }
                if !context.subtitle_languages.is_empty() {
                    command = command
                        .arg("--write-subs")
                        .arg("--sub-langs")
                        .arg(context.subtitle_languages.join(","));
                }
                if let Some(deno) = context.installation.companion("deno")? {
                    command = command
                        .arg("--js-runtimes")
                        .arg(format!("deno:{}", deno.to_string_lossy()));
                }
                if let Some(ffmpeg) = context.installation.companion("ffmpeg")? {
                    command = command
                        .arg("--ffmpeg-location")
                        .arg(ffmpeg.parent().unwrap_or(&ffmpeg).as_os_str());
                }
                command.arg("--").arg(source)
            }
            AdapterId::StreamlinkV1 => {
                let mut command = command
                    .arg("--no-config")
                    .arg("--no-plugin-sideloading")
                    .arg("--output")
                    .arg(&output);
                if let Some(ffmpeg) = context.installation.companion("ffmpeg")? {
                    command = command.arg("--ffmpeg-ffmpeg").arg(ffmpeg.as_os_str());
                }
                command
                    .arg("--")
                    .arg(source)
                    .arg(context.selected_format.as_deref().unwrap_or("best"))
            }
            AdapterId::GalleryDlV1 => command
                .arg("--config-ignore")
                .arg("--directory")
                .arg(context.staging.as_os_str())
                .arg("--")
                .arg(source),
            AdapterId::NM3u8DlReV1 => {
                let mut command = command
                    .arg(source)
                    .arg("--save-dir")
                    .arg(context.staging.as_os_str())
                    .arg("--save-name")
                    .arg(&context.output_name)
                    .arg("--no-ansi-color");
                if let Some(ffmpeg) = context.installation.companion("ffmpeg")? {
                    command = command.arg("--ffmpeg-binary-path").arg(ffmpeg.as_os_str());
                }
                command
            }
            AdapterId::FfmpegV1 => command
                .arg("-nostdin")
                .arg("-i")
                .arg(source)
                .arg("-progress")
                .arg("pipe:1")
                .arg("-nostats")
                .arg("-c")
                .arg("copy")
                .arg(&output),
            AdapterId::Aria2V1 => command
                .arg("--allow-overwrite=false")
                .arg("--auto-file-renaming=false")
                .arg("--max-http-redirs=0")
                .arg("--dir")
                .arg(context.staging.as_os_str())
                .arg("--out")
                .arg(&context.output_name)
                .arg("--")
                .arg(source),
            AdapterId::CurlWorkerV2 => {
                return Err(CoreError::InvalidInput(
                    "curl worker uses the dedicated worker protocol".into(),
                ));
            }
        };
        Ok((command, output))
    }
}

#[async_trait]
impl EngineAdapter for BuiltinCliAdapter {
    fn adapter_id(&self) -> AdapterId {
        self.id
    }

    async fn self_test(
        &self,
        installation: &InstalledEngine,
        cancellation: CancellationToken,
    ) -> Result<(), EngineFailure> {
        let staging = installation.root.join(".self-test");
        std::fs::create_dir_all(&staging).map_err(|error| internal(error.to_string()))?;
        let command = self
            .command(installation, &staging)
            .map_err(|error| internal(error.to_string()))?
            .arg("--version");
        let mut spec = ProcessSpec::cli(command);
        spec.timeout = Duration::from_secs(15);
        let outcome = self
            .supervisor
            .run(spec, cancellation.clone())
            .await
            .map_err(process_failure)?;
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        if outcome.success {
            Ok(())
        } else {
            Err(self.classify_failure(outcome.exit_code, &join_stderr(&outcome.lines)))
        }
    }

    async fn probe(
        &self,
        context: ProbeContext,
        cancellation: CancellationToken,
    ) -> Result<ResolvedPlan, EngineFailure> {
        if self.id == AdapterId::CurlWorkerV2 {
            return self.probe_curl_worker(context, cancellation).await;
        }
        std::fs::create_dir_all(&context.staging).map_err(|error| internal(error.to_string()))?;
        let command = self
            .probe_command(&context)
            .map_err(|error| internal(error.to_string()))?;
        let mut spec = ProcessSpec::cli(command);
        spec.timeout = Duration::from_secs(90);
        let outcome = self
            .supervisor
            .run(spec, cancellation.clone())
            .await
            .map_err(process_failure)?;
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        if !outcome.success {
            return Err(self.classify_failure(outcome.exit_code, &join_stderr(&outcome.lines)));
        }
        let stdout = outcome
            .lines
            .iter()
            .filter(|line| line.stream == OutputStream::Stdout)
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        Ok(parse_probe_json(&stdout, context.source_kind))
    }

    async fn download(
        &self,
        context: DownloadContext,
        events: EventSink,
        cancellation: CancellationToken,
    ) -> Result<DownloadOutcome, EngineFailure> {
        if self.id == AdapterId::CurlWorkerV2 {
            return self.download_curl_worker(context, cancellation).await;
        }
        std::fs::create_dir_all(&context.staging).map_err(|error| internal(error.to_string()))?;
        let (command, expected_output) = self
            .download_command(&context)
            .map_err(|error| internal(error.to_string()))?;
        let monitor_stop = CancellationToken::new();
        let monitor = tokio::spawn(monitor_staging_progress(
            context.job_id,
            context.staging.clone(),
            Arc::clone(&events),
            cancellation.clone(),
            monitor_stop.clone(),
        ));
        let process_result = self
            .supervisor
            .run(ProcessSpec::cli(command), cancellation.clone())
            .await;
        monitor_stop.cancel();
        let _ = monitor.await;
        let outcome = process_result.map_err(process_failure)?;
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        if !outcome.success {
            return Err(self.classify_failure(outcome.exit_code, &join_stderr(&outcome.lines)));
        }
        let output = if expected_output.is_file() {
            expected_output
        } else {
            first_regular_file(&context.staging).ok_or_else(|| EngineFailure {
                kind: EngineErrorKind::ExtractorBroken,
                code: "engine.output_missing".into(),
                retry_after_seconds: None,
                diagnostic: "engine completed without a regular output file".into(),
            })?
        };
        let bytes = std::fs::metadata(&output)
            .map_err(|error| internal(error.to_string()))?
            .len();
        Ok(DownloadOutcome {
            output,
            bytes,
            requires_post_processing: false,
        })
    }

    fn classify_failure(&self, exit_code: Option<i32>, stderr: &str) -> EngineFailure {
        let lower = stderr.to_ascii_lowercase();
        let (kind, code) = if lower.contains("unsupported url")
            || lower.contains("no plugin can handle")
        {
            (EngineErrorKind::Unsupported, "engine.unsupported")
        } else if lower.contains("sign in") || lower.contains("login") || lower.contains("cookie") {
            (EngineErrorKind::AuthRequired, "engine.auth_required")
        } else if lower.contains("403") || lower.contains("forbidden") {
            (EngineErrorKind::Forbidden, "engine.forbidden")
        } else if lower.contains("429") || lower.contains("rate limit") {
            (EngineErrorKind::RateLimited, "engine.rate_limited")
        } else if lower.contains("drm") || lower.contains("protected") {
            (EngineErrorKind::ProtectedMedia, "engine.protected_media")
        } else if lower.contains("timed out") || lower.contains("temporarily unavailable") {
            (EngineErrorKind::Transient, "engine.transient")
        } else {
            (EngineErrorKind::ExtractorBroken, "engine.failed")
        };
        EngineFailure {
            kind,
            code: code.into(),
            retry_after_seconds: None,
            diagnostic: format!(
                "adapter {:?} exited with {:?}: {}",
                self.id,
                exit_code,
                redact_diagnostic(stderr)
            ),
        }
    }
}

async fn monitor_staging_progress(
    job_id: JobId,
    staging: PathBuf,
    events: EventSink,
    cancellation: CancellationToken,
    stop: CancellationToken,
) {
    let mut previous_bytes = directory_bytes(&staging);
    let mut previous_time = Instant::now();
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            () = stop.cancelled() => break,
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
        let now = Instant::now();
        let downloaded_bytes = directory_bytes(&staging);
        if downloaded_bytes == previous_bytes {
            previous_time = now;
            continue;
        }
        let elapsed = now.duration_since(previous_time).as_secs_f64();
        let speed = (downloaded_bytes.saturating_sub(previous_bytes) as f64 / elapsed.max(0.001))
            .round() as u64;
        (events)(JobEvent::Progress {
            id: job_id,
            downloaded_bytes,
            total_bytes: None,
            speed_bytes_per_second: Some(speed),
        });
        previous_bytes = downloaded_bytes;
        previous_time = now;
    }
}

fn directory_bytes(root: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .map(|path| match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata.len(),
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                directory_bytes(&path)
            }
            _ => 0,
        })
        .sum()
}

impl BuiltinCliAdapter {
    async fn probe_curl_worker(
        &self,
        context: ProbeContext,
        cancellation: CancellationToken,
    ) -> Result<ResolvedPlan, EngineFailure> {
        let source = Self::source_url(&context.source)?;
        let parsed = url::Url::parse(source).map_err(|error| internal(error.to_string()))?;
        let mut plan = ResolvedPlan {
            source_kind: context.source_kind,
            title: parsed
                .path_segments()
                .and_then(|mut parts| parts.next_back())
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            formats: Vec::new(),
            subtitles: Vec::new(),
            playlist_entries: Vec::new(),
            chapters: 0,
            files: 1,
            warnings: Vec::new(),
            auth_requirements: Vec::new(),
            required_packs: Vec::new(),
        };
        if parsed.scheme() == "sftp" {
            let request = fmd_curl_worker::WorkerEnvelope {
                protocol_version: fmd_curl_worker::WORKER_PROTOCOL_VERSION,
                request_id: uuid::Uuid::new_v4().to_string(),
                request: fmd_curl_worker::WorkerRequest::ProbeHostKey {
                    url: source.to_owned(),
                },
            };
            let messages = self
                .run_worker(
                    &context.installation,
                    &context.staging,
                    request,
                    cancellation,
                )
                .await?;
            let hostkey = messages.into_iter().find_map(|message| match message {
                fmd_curl_worker::WorkerMessage::Event { event: fmd_curl_worker::WorkerEvent::HostKey { host, port, algorithm, raw_key_base64, fingerprint_sha256 }, .. } => {
                    Some(format!("sftp_host_key|{host}|{port}|{algorithm}|{raw_key_base64}|{fingerprint_sha256}"))
                }
                _ => None,
            }).ok_or_else(|| EngineFailure {
                kind: EngineErrorKind::HostKey,
                code: "sftp.host_key_probe_failed".into(),
                retry_after_seconds: None,
                diagnostic: "SFTP worker returned no host key".into(),
            })?;
            plan.auth_requirements.push(hostkey);
        }
        Ok(plan)
    }

    async fn download_curl_worker(
        &self,
        context: DownloadContext,
        cancellation: CancellationToken,
    ) -> Result<DownloadOutcome, EngineFailure> {
        let source = Self::source_url(&context.source)?;
        let is_sftp = source.starts_with("sftp:");
        let transfer_auth = context.transfer_auth.as_ref();
        if is_sftp && transfer_auth.is_none() {
            return Err(EngineFailure {
                kind: EngineErrorKind::AuthRequired,
                code: "sftp.credentials_required".into(),
                retry_after_seconds: None,
                diagnostic: "SFTP authorization was not supplied through the in-memory channel"
                    .into(),
            });
        }
        let output = context.staging.join(&context.output_name);
        let resume_from = std::fs::metadata(&output)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let request = fmd_curl_worker::WorkerEnvelope {
            protocol_version: fmd_curl_worker::WORKER_PROTOCOL_VERSION,
            request_id: uuid::Uuid::new_v4().to_string(),
            request: fmd_curl_worker::WorkerRequest::Download {
                url: source.to_owned(),
                destination: output.to_string_lossy().into_owned(),
                resume_from,
                expected_validator: None,
                credentials: transfer_auth.map(|auth| auth.credentials.clone()),
                trusted_host_key: transfer_auth.map(|auth| auth.trusted_host_key.clone()),
            },
        };
        let messages = self
            .run_worker(
                &context.installation,
                &context.staging,
                request,
                cancellation,
            )
            .await?;
        if messages.iter().any(|message| {
            matches!(
                message,
                fmd_curl_worker::WorkerMessage::Event {
                    event: fmd_curl_worker::WorkerEvent::Failed { .. },
                    ..
                }
            )
        }) {
            return Err(self.classify_failure(Some(1), "curl worker transfer failed"));
        }
        let bytes = std::fs::metadata(&output)
            .map_err(|error| internal(error.to_string()))?
            .len();
        Ok(DownloadOutcome {
            output,
            bytes,
            requires_post_processing: false,
        })
    }

    async fn run_worker(
        &self,
        installation: &InstalledEngine,
        staging: &Path,
        request: fmd_curl_worker::WorkerEnvelope,
        cancellation: CancellationToken,
    ) -> Result<Vec<fmd_curl_worker::WorkerMessage>, EngineFailure> {
        std::fs::create_dir_all(staging).map_err(|error| internal(error.to_string()))?;
        let command = self
            .command(installation, staging)
            .map_err(|error| internal(error.to_string()))?
            .piped_stdin();
        let mut input =
            serde_json::to_vec(&request).map_err(|error| internal(error.to_string()))?;
        input.push(b'\n');
        let mut spec = ProcessSpec::cli(command);
        spec.input = Some(input);
        spec.sensitive_input = true;
        let outcome = self
            .supervisor
            .run(spec, cancellation.clone())
            .await
            .map_err(process_failure)?;
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let messages = outcome
            .lines
            .iter()
            .filter(|line| line.stream == OutputStream::Stdout)
            .filter_map(|line| {
                serde_json::from_str::<fmd_curl_worker::WorkerMessage>(&line.text).ok()
            })
            .collect::<Vec<_>>();
        if !outcome.success
            || !matches!(
                messages.first(),
                Some(fmd_curl_worker::WorkerMessage::Hello {
                    protocol_version: 2,
                    ..
                })
            )
        {
            return Err(self.classify_failure(outcome.exit_code, &join_stderr(&outcome.lines)));
        }
        Ok(messages)
    }
}

fn parse_probe_json(value: &str, source_kind: SourceKind) -> ResolvedPlan {
    let json = serde_json::from_str::<Value>(value).unwrap_or(Value::Null);
    let title = json
        .get("title")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let formats = json
        .get("formats")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|format| {
            let id = format.get("format_id")?.as_str()?.to_owned();
            let label = format
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or(&id)
                .to_owned();
            Some(FormatOption {
                id,
                label,
                container: format
                    .get("ext")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                estimated_bytes: format
                    .get("filesize")
                    .or_else(|| format.get("filesize_approx"))
                    .and_then(Value::as_u64),
            })
        })
        .collect();
    let subtitles = json
        .get("subtitles")
        .and_then(Value::as_object)
        .map(|values| values.keys().cloned().collect())
        .unwrap_or_default();
    let playlist_entries = json
        .get("entries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(offset, entry)| {
            let id = entry.get("id").and_then(Value::as_str)?.to_owned();
            let index = entry
                .get("playlist_index")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .unwrap_or(offset as u32 + 1);
            let title = entry
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or(&id)
                .to_owned();
            Some(crate::job::PlaylistEntry { index, id, title })
        })
        .collect::<Vec<_>>();
    let files = u32::try_from(playlist_entries.len().max(1)).unwrap_or(u32::MAX);
    ResolvedPlan {
        source_kind,
        title,
        formats,
        subtitles,
        playlist_entries,
        chapters: json
            .get("chapters")
            .and_then(Value::as_array)
            .map_or(0, |chapters| chapters.len() as u32),
        files,
        warnings: Vec::new(),
        auth_requirements: Vec::new(),
        required_packs: Vec::new(),
    }
}

fn first_regular_file(root: &Path) -> Option<PathBuf> {
    std::fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_file())
}

fn join_stderr(lines: &[crate::process::ProcessLine]) -> String {
    lines
        .iter()
        .filter(|line| line.stream == OutputStream::Stderr)
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn internal(diagnostic: String) -> EngineFailure {
    EngineFailure {
        kind: EngineErrorKind::Internal,
        code: "engine.internal".into(),
        retry_after_seconds: None,
        diagnostic,
    }
}

fn process_failure(error: CoreError) -> EngineFailure {
    if matches!(error, CoreError::ProcessTimedOut) {
        EngineFailure {
            kind: EngineErrorKind::Transient,
            code: "engine.timed_out".into(),
            retry_after_seconds: None,
            diagnostic: error.to_string(),
        }
    } else {
        internal(error.to_string())
    }
}

fn cancelled() -> EngineFailure {
    EngineFailure {
        kind: EngineErrorKind::Canceled,
        code: "job.canceled".into(),
        retry_after_seconds: None,
        diagnostic: "engine process was canceled".into(),
    }
}

fn redact_diagnostic(value: &str) -> String {
    value
        .split_whitespace()
        .map(|token| {
            if token.contains("://") {
                crate::process::redact_url(token)
            } else {
                token.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yt_dlp_probe_without_exposing_extra_fields() {
        let plan = parse_probe_json(
            r#"{"title":"Example","formats":[{"format_id":"18","format":"360p","ext":"mp4","filesize":12}],"subtitles":{"en":[]},"entries":[{"id":"first","title":"First","playlist_index":1}],"chapters":[{}]}"#,
            SourceKind::SiteMedia,
        );
        assert_eq!(plan.title.as_deref(), Some("Example"));
        assert_eq!(plan.formats[0].id, "18");
        assert_eq!(plan.chapters, 1);
        assert_eq!(plan.subtitles, vec!["en"]);
        assert_eq!(plan.playlist_entries[0].index, 1);
        assert_eq!(plan.files, 1);
    }

    #[test]
    fn fallback_taxonomy_stops_on_authentication() {
        let adapter = BuiltinCliAdapter::new(AdapterId::YtDlpV1);
        let failure = adapter.classify_failure(Some(1), "Please sign in to continue");
        assert_eq!(failure.kind, EngineErrorKind::AuthRequired);
        assert!(!failure.kind.allows_fallback());
    }
}
