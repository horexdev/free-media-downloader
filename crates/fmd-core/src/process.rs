use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::error::CoreError;

const BLOCKED_OPTIONS: &[&str] = &[
    "--config-location",
    "--config-locations",
    "--exec",
    "--exec-before-download",
    "--external-downloader",
    "--external-downloader-args",
    "--load-info-json",
    "--paths",
    "--player",
    "--plugin-dirs",
    "--postprocessor-args",
    "--use-postprocessor",
    "--output",
    "-o",
    "-P",
];

#[derive(Debug, Default, Clone, Copy)]
pub struct ExpertArgsPolicy;

impl ExpertArgsPolicy {
    pub fn validate(&self, tokens: &[String]) -> Result<(), CoreError> {
        for token in tokens {
            if token.contains('\0') || token.contains('\n') || token.contains('\r') {
                return Err(CoreError::InvalidInput(
                    "expert argument contains a control character".into(),
                ));
            }
            let option = token.split('=').next().unwrap_or(token);
            if BLOCKED_OPTIONS.contains(&option) {
                return Err(CoreError::InvalidInput(format!(
                    "expert option '{option}' is blocked"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStdin {
    Null,
    Piped,
}

#[derive(Debug, Clone)]
pub struct EngineCommand {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub current_dir: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub stdin: ChildStdin,
}

impl EngineCommand {
    pub fn new(program: &Path, current_dir: &Path) -> Result<Self, CoreError> {
        if !program.is_absolute() || !current_dir.is_absolute() {
            return Err(CoreError::InvalidInput(
                "engine paths must be absolute".into(),
            ));
        }
        Ok(Self {
            program: program.to_path_buf(),
            args: Vec::new(),
            current_dir: current_dir.to_path_buf(),
            environment: BTreeMap::new(),
            stdin: ChildStdin::Null,
        })
    }

    #[must_use]
    pub fn arg(mut self, value: impl Into<OsString>) -> Self {
        self.args.push(value.into());
        self
    }

    #[must_use]
    pub const fn piped_stdin(mut self) -> Self {
        self.stdin = ChildStdin::Piped;
        self
    }

    #[must_use]
    pub fn sanitized_environment(mut self, temp: &Path) -> Self {
        self.environment
            .insert(OsString::from("NO_COLOR"), OsString::from("1"));
        self.environment
            .insert(OsString::from("LANG"), OsString::from("C.UTF-8"));
        self.environment
            .insert(OsString::from("LC_ALL"), OsString::from("C.UTF-8"));
        self.environment
            .insert(OsString::from("TEMP"), temp.as_os_str().to_os_string());
        self.environment
            .insert(OsString::from("TMP"), temp.as_os_str().to_os_string());
        self.environment
            .insert(OsString::from("HOME"), temp.as_os_str().to_os_string());
        self.environment.insert(
            OsString::from("XDG_CONFIG_HOME"),
            temp.join("config").into_os_string(),
        );
        self.environment.insert(
            OsString::from("XDG_CACHE_HOME"),
            temp.join("cache").into_os_string(),
        );
        #[cfg(windows)]
        for key in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                self.environment.insert(OsString::from(key), value);
            }
        }
        self
    }

    pub fn into_tokio_command(self) -> Command {
        let mut command = Command::new(self.program);
        command
            .args(self.args)
            .current_dir(self.current_dir)
            .env_clear()
            .envs(self.environment)
            .kill_on_drop(true)
            .stdin(match self.stdin {
                ChildStdin::Null => Stdio::null(),
                ChildStdin::Piped => Stdio::piped(),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_group(&mut command);
        command
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLine {
    pub stream: OutputStream,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct ProcessSpec {
    pub command: EngineCommand,
    pub input: Option<Vec<u8>>,
    pub timeout: Duration,
    pub cancel_grace: Duration,
    pub max_line_bytes: usize,
    pub max_output_bytes: usize,
    pub max_lines: usize,
}

impl ProcessSpec {
    #[must_use]
    pub fn cli(command: EngineCommand) -> Self {
        Self {
            command,
            input: None,
            timeout: Duration::from_secs(24 * 60 * 60),
            cancel_grace: Duration::from_secs(5),
            max_line_bytes: 1024 * 1024,
            max_output_bytes: 8 * 1024 * 1024,
            max_lines: 50_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutcome {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub lines: Vec<ProcessLine>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessSupervisor;

impl ProcessSupervisor {
    pub async fn run(
        &self,
        spec: ProcessSpec,
        cancellation: CancellationToken,
    ) -> Result<ProcessOutcome, CoreError> {
        let mut child = spec.command.into_tokio_command().spawn()?;
        let process_id = child.id();
        let tree_guard = ProcessTreeGuard::attach(process_id)?;

        if let Some(input) = spec.input {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                CoreError::InvalidInput("process input requires piped stdin".into())
            })?;
            tokio::spawn(async move {
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stdin, &input).await;
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut stdin).await;
            });
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CoreError::Io(std::io::Error::other("stdout pipe missing")))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| CoreError::Io(std::io::Error::other("stderr pipe missing")))?;
        let output_bytes = Arc::new(AtomicUsize::new(0));
        let output_lines = Arc::new(AtomicUsize::new(0));
        let max_line_bytes = spec.max_line_bytes;
        let max_output_bytes = spec.max_output_bytes;
        let max_lines = spec.max_lines;
        let (reader_tx, mut reader_rx) = mpsc::channel(2);
        for (reader, stream) in [
            (
                Box::new(stdout) as Box<dyn AsyncRead + Unpin + Send>,
                OutputStream::Stdout,
            ),
            (
                Box::new(stderr) as Box<dyn AsyncRead + Unpin + Send>,
                OutputStream::Stderr,
            ),
        ] {
            let tx = reader_tx.clone();
            let bytes = Arc::clone(&output_bytes);
            let lines = Arc::clone(&output_lines);
            tokio::spawn(async move {
                let result = read_bounded_lines(
                    reader,
                    stream,
                    max_line_bytes,
                    max_output_bytes,
                    max_lines,
                    bytes,
                    lines,
                )
                .await;
                let _ = tx.send(result).await;
            });
        }
        drop(reader_tx);

        let deadline = tokio::time::sleep(spec.timeout);
        tokio::pin!(deadline);
        let mut collected = Vec::new();
        let mut reader_results = 0;
        let mut reader_error = None;
        let mut timed_out = false;
        let status = loop {
            tokio::select! {
                status = child.wait() => break status?,
                () = cancellation.cancelled() => {
                    break stop_process_tree(
                        &mut child,
                        &tree_guard,
                        process_id,
                        spec.cancel_grace,
                    ).await?;
                }
                () = &mut deadline => {
                    timed_out = true;
                    break stop_process_tree(
                        &mut child,
                        &tree_guard,
                        process_id,
                        spec.cancel_grace,
                    ).await?;
                }
                result = reader_rx.recv() => {
                    let result = result.ok_or_else(|| {
                        CoreError::Io(std::io::Error::other("engine output readers stopped unexpectedly"))
                    })?;
                    reader_results += 1;
                    match result {
                        Ok(lines) => collected.extend(lines),
                        Err(error) => {
                            reader_error = Some(error);
                            break stop_process_tree(
                                &mut child,
                                &tree_guard,
                                process_id,
                                spec.cancel_grace,
                            ).await?;
                        }
                    }
                }
            }
        };
        force_kill_process_tree(&tree_guard, process_id);

        while reader_results < 2 {
            let result = reader_rx.recv().await.ok_or_else(|| {
                CoreError::Io(std::io::Error::other(
                    "engine output reader result is missing",
                ))
            })?;
            reader_results += 1;
            match result {
                Ok(lines) => collected.extend(lines),
                Err(error) if reader_error.is_none() => reader_error = Some(error),
                Err(_) => {}
            }
        }
        if let Some(error) = reader_error {
            return Err(error);
        }
        if timed_out {
            return Err(CoreError::ProcessTimedOut);
        }
        Ok(ProcessOutcome {
            success: status.success(),
            exit_code: status.code(),
            lines: collected,
        })
    }
}

async fn read_bounded_lines<R: AsyncRead + Unpin>(
    mut reader: R,
    stream: OutputStream,
    max_line_bytes: usize,
    max_output_bytes: usize,
    max_lines: usize,
    output_bytes: Arc<AtomicUsize>,
    output_lines: Arc<AtomicUsize>,
) -> Result<Vec<ProcessLine>, CoreError> {
    let mut chunk = [0_u8; 8192];
    let mut buffer = Vec::with_capacity(4096);
    let mut lines = Vec::new();
    loop {
        let bytes = reader.read(&mut chunk).await?;
        if bytes == 0 {
            break;
        }
        let previous = output_bytes.fetch_add(bytes, Ordering::Relaxed);
        if previous.saturating_add(bytes) > max_output_bytes {
            return Err(CoreError::InvalidInput(
                "engine output exceeds total safety limit".into(),
            ));
        }
        for byte in &chunk[..bytes] {
            if *byte == b'\n' {
                push_bounded_line(&mut lines, &mut buffer, stream, max_lines, &output_lines)?;
            } else {
                if buffer.len() >= max_line_bytes {
                    return Err(CoreError::InvalidInput(
                        "engine output line exceeds safety limit".into(),
                    ));
                }
                buffer.push(*byte);
            }
        }
    }
    if !buffer.is_empty() {
        push_bounded_line(&mut lines, &mut buffer, stream, max_lines, &output_lines)?;
    }
    Ok(lines)
}

fn push_bounded_line(
    lines: &mut Vec<ProcessLine>,
    buffer: &mut Vec<u8>,
    stream: OutputStream,
    max_lines: usize,
    output_lines: &AtomicUsize,
) -> Result<(), CoreError> {
    if output_lines.fetch_add(1, Ordering::Relaxed) >= max_lines {
        return Err(CoreError::InvalidInput(
            "engine output exceeds line-count safety limit".into(),
        ));
    }
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    lines.push(ProcessLine {
        stream,
        text: String::from_utf8_lossy(buffer).into_owned(),
    });
    buffer.clear();
    Ok(())
}

async fn stop_process_tree(
    child: &mut tokio::process::Child,
    tree_guard: &ProcessTreeGuard,
    process_id: Option<u32>,
    grace: Duration,
) -> Result<std::process::ExitStatus, CoreError> {
    interrupt_process_tree(process_id);
    match timeout(grace, child.wait()).await {
        Ok(status) => Ok(status?),
        Err(_) => {
            force_kill_process_tree(tree_guard, process_id);
            let _ = child.kill().await;
            Ok(child.wait().await?)
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
}

#[cfg(windows)]
fn configure_process_group(command: &mut Command) {
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
fn interrupt_process_tree(process_id: Option<u32>) {
    if let Some(process_id) = process_id {
        // SAFETY: negative PID addresses only the child process group created above.
        unsafe {
            libc::kill(-(process_id as i32), libc::SIGINT);
        }
    }
}

#[cfg(windows)]
fn interrupt_process_tree(process_id: Option<u32>) {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};

    if let Some(process_id) = process_id {
        // SAFETY: the child was created as a new process group with this process identifier.
        unsafe {
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, process_id);
        }
    }
}

#[cfg(unix)]
fn force_kill_process_tree(_guard: &ProcessTreeGuard, process_id: Option<u32>) {
    if let Some(process_id) = process_id {
        // SAFETY: negative PID addresses only the child process group created above.
        unsafe {
            libc::kill(-(process_id as i32), libc::SIGKILL);
        }
    }
}

#[cfg(windows)]
fn force_kill_process_tree(guard: &ProcessTreeGuard, _process_id: Option<u32>) {
    use windows_sys::Win32::System::JobObjects::TerminateJobObject;

    // SAFETY: the guard exclusively owns a valid job handle.
    unsafe {
        TerminateJobObject(guard.handle, 1);
    }
}

struct ProcessTreeGuard {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
// SAFETY: the handle is exclusively owned, can be closed from any thread, and is not dereferenced.
unsafe impl Send for ProcessTreeGuard {}

#[cfg(windows)]
// SAFETY: Windows job handles may be used across threads, and all operations here are read-only
// with respect to the stored handle value.
unsafe impl Sync for ProcessTreeGuard {}

impl ProcessTreeGuard {
    fn attach(process_id: Option<u32>) -> Result<Self, CoreError> {
        #[cfg(windows)]
        {
            use std::mem::size_of;
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };
            use windows_sys::Win32::System::Threading::{
                OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
            };

            let process_id = process_id.ok_or_else(|| {
                CoreError::Io(std::io::Error::other("child process has no process ID"))
            })?;
            // SAFETY: Windows handles are checked and owned by this guard.
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return Err(CoreError::Io(std::io::Error::last_os_error()));
                }
                let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&raw const information).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ) == 0
                {
                    CloseHandle(job);
                    return Err(CoreError::Io(std::io::Error::last_os_error()));
                }
                let process = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, process_id);
                if process.is_null() || AssignProcessToJobObject(job, process) == 0 {
                    if !process.is_null() {
                        CloseHandle(process);
                    }
                    CloseHandle(job);
                    return Err(CoreError::Io(std::io::Error::last_os_error()));
                }
                CloseHandle(process);
                Ok(Self { handle: job })
            }
        }
        #[cfg(not(windows))]
        {
            let _ = process_id;
            Ok(Self {})
        }
    }
}

#[cfg(windows)]
impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        // SAFETY: the guard exclusively owns this valid job handle.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[must_use]
pub fn redact_url(value: &str) -> String {
    match url::Url::parse(value) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => "<redacted-invalid-url>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn blocks_command_and_path_escape_options() {
        for option in ["--exec=touch file", "--plugin-dirs", "-o"] {
            assert!(ExpertArgsPolicy.validate(&[option.into()]).is_err());
        }
        assert!(
            ExpertArgsPolicy
                .validate(&["--limit-rate".into(), "5M".into()])
                .is_ok()
        );
    }

    #[test]
    fn removes_url_secrets_before_logging() {
        let value = redact_url("https://user:secret@example.com/file?token=abc#part");
        assert_eq!(value, "https://example.com/file");
    }

    #[tokio::test]
    async fn rejects_oversized_lines_without_buffering_the_rest() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let write = tokio::spawn(async move {
            let _ = writer.write_all(&[b'x'; 32]).await;
        });
        let result = read_bounded_lines(
            reader,
            OutputStream::Stdout,
            8,
            128,
            10,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        )
        .await;
        assert!(result.is_err());
        write.await.unwrap();
    }

    #[tokio::test]
    async fn converts_invalid_utf8_and_enforces_total_output_limit() {
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(&[0xff, b'\n']).await.unwrap();
        writer.shutdown().await.unwrap();
        let lines = read_bounded_lines(
            reader,
            OutputStream::Stderr,
            16,
            16,
            2,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        )
        .await
        .unwrap();
        assert_eq!(lines[0].text, "�");

        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"123456789").await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(
            read_bounded_lines(
                reader,
                OutputStream::Stdout,
                16,
                8,
                2,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn process_timeout_helper() {
        if std::env::var_os("FMD_PROCESS_TEST_SLEEP").is_some() {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[tokio::test]
    async fn timeout_terminates_the_child_process() {
        let temporary = tempfile::tempdir().unwrap();
        let mut command = EngineCommand::new(&std::env::current_exe().unwrap(), temporary.path())
            .unwrap()
            .sanitized_environment(temporary.path())
            .arg("--exact")
            .arg("process::tests::process_timeout_helper")
            .arg("--nocapture");
        command.environment.insert(
            OsString::from("FMD_PROCESS_TEST_SLEEP"),
            OsString::from("1"),
        );
        let mut spec = ProcessSpec::cli(command);
        spec.timeout = Duration::from_millis(100);
        spec.cancel_grace = Duration::from_millis(100);
        let started = std::time::Instant::now();
        let result = ProcessSupervisor.run(spec, CancellationToken::new()).await;
        assert!(matches!(result, Err(CoreError::ProcessTimedOut)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
