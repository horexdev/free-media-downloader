use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
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
        let _tree_guard = ProcessTreeGuard::attach(process_id)?;

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
        let stdout_task = tokio::spawn(read_bounded_lines(
            stdout,
            OutputStream::Stdout,
            spec.max_line_bytes,
        ));
        let stderr_task = tokio::spawn(read_bounded_lines(
            stderr,
            OutputStream::Stderr,
            spec.max_line_bytes,
        ));

        let wait = async {
            tokio::select! {
                status = child.wait() => status.map(Some),
                () = cancellation.cancelled() => Ok(None),
            }
        };
        let status = timeout(spec.timeout, wait)
            .await
            .map_err(|_| CoreError::InvalidInput("engine process timed out".into()))??;
        let status = match status {
            Some(status) => status,
            None => {
                interrupt_process_tree(process_id);
                match timeout(spec.cancel_grace, child.wait()).await {
                    Ok(status) => status?,
                    Err(_) => {
                        child.kill().await?;
                        child.wait().await?
                    }
                }
            }
        };

        let mut lines = stdout_task
            .await
            .map_err(|error| CoreError::InvalidInput(error.to_string()))??;
        lines.extend(
            stderr_task
                .await
                .map_err(|error| CoreError::InvalidInput(error.to_string()))??,
        );
        Ok(ProcessOutcome {
            success: status.success(),
            exit_code: status.code(),
            lines,
        })
    }
}

async fn read_bounded_lines<R: AsyncRead + Unpin>(
    reader: R,
    stream: OutputStream,
    max_line_bytes: usize,
) -> Result<Vec<ProcessLine>, CoreError> {
    let mut reader = BufReader::new(reader);
    let mut buffer = Vec::new();
    let mut lines = Vec::new();
    loop {
        buffer.clear();
        let bytes = reader.read_until(b'\n', &mut buffer).await?;
        if bytes == 0 {
            break;
        }
        if buffer.len() > max_line_bytes {
            return Err(CoreError::InvalidInput(
                "engine output line exceeds safety limit".into(),
            ));
        }
        while matches!(buffer.last(), Some(b'\n' | b'\r')) {
            buffer.pop();
        }
        lines.push(ProcessLine {
            stream,
            text: String::from_utf8_lossy(&buffer).into_owned(),
        });
    }
    Ok(lines)
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
fn interrupt_process_tree(_process_id: Option<u32>) {}

struct ProcessTreeGuard {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
// SAFETY: the handle is exclusively owned, can be closed from any thread, and is not dereferenced.
unsafe impl Send for ProcessTreeGuard {}

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
}
