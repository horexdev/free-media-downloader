use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use curl::easy::{Easy, HttpVersion, List};
use url::Url;

use crate::{Credentials, TransferError, TrustedHostKey, WorkerEvent, WorkerRequest};

pub fn execute(
    request: WorkerRequest,
    mut emit: impl FnMut(WorkerEvent),
) -> Result<(), TransferError> {
    request.validate()?;
    match request {
        WorkerRequest::ResolveRedirects {
            url,
            user_agent,
            max_redirects,
        } => {
            emit(WorkerEvent::RedirectResolved {
                effective_url: resolve_redirects(&url, &user_agent, max_redirects)?,
            });
            emit(WorkerEvent::Completed { bytes: 0 });
            Ok(())
        }
        WorkerRequest::ProbeHostKey { url } => probe_host_key(&url, &mut emit),
        WorkerRequest::Download {
            url,
            destination,
            resume_from,
            expected_validator,
            credentials,
            trusted_host_key,
        } => download(
            &url,
            Path::new(&destination),
            resume_from,
            expected_validator.as_deref(),
            credentials.as_ref(),
            trusted_host_key.as_ref(),
            emit,
        ),
    }
}

fn resolve_redirects(
    url: &str,
    user_agent: &str,
    max_redirects: u8,
) -> Result<String, TransferError> {
    let mut current = Url::parse(url).map_err(|_| crate::RequestError::InvalidUrl)?;
    for _ in 0..=max_redirects {
        let mut easy = Easy::new();
        easy.url(current.as_str())?;
        easy.useragent(user_agent)?;
        easy.follow_location(false)?;
        easy.range("0-0")?;
        easy.http_version(HttpVersion::V2TLS)?;
        easy.connect_timeout(Duration::from_secs(20))?;
        easy.timeout(Duration::from_secs(45))?;
        {
            let mut transfer = easy.transfer();
            transfer.write_function(|bytes| Ok(bytes.len()))?;
            transfer.perform()?;
        }
        let status = easy.response_code()?;
        if (300..400).contains(&status) {
            let location = easy.redirect_url()?.ok_or(TransferError::RedirectPolicy)?;
            let next = current
                .join(location)
                .map_err(|_| TransferError::RedirectPolicy)?;
            if current.scheme() == "https" && next.scheme() != "https" {
                return Err(TransferError::RedirectPolicy);
            }
            if !matches!(next.scheme(), "https" | "http") {
                return Err(TransferError::RedirectPolicy);
            }
            current = next;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(TransferError::HttpStatus(status));
        }
        return Ok(current.into());
    }
    Err(TransferError::RedirectPolicy)
}

#[derive(Debug, Clone, Copy)]
enum HeaderRejection {
    Redirect,
    Status(u32),
    Resume,
}

#[derive(Default)]
struct HeaderGate {
    status: u32,
    validator: Option<String>,
    range_start: Option<u64>,
    accepted: bool,
    rejection: Option<HeaderRejection>,
}

impl HeaderGate {
    fn consume(&mut self, line: &[u8], resume_from: u64, expected: Option<&str>) {
        if line.starts_with(b"HTTP/") {
            self.status = std::str::from_utf8(line)
                .ok()
                .and_then(|value| value.split_whitespace().nth(1))
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            self.validator = None;
            self.range_start = None;
            self.accepted = false;
            self.rejection = None;
            return;
        }
        if line == b"\r\n" || line == b"\n" {
            self.rejection = if (300..400).contains(&self.status) {
                Some(HeaderRejection::Redirect)
            } else if !(200..300).contains(&self.status) {
                Some(HeaderRejection::Status(self.status))
            } else if resume_from > 0
                && (self.status != 206
                    || self.range_start != Some(resume_from)
                    || expected.is_some_and(|value| self.validator.as_deref() != Some(value)))
            {
                Some(HeaderRejection::Resume)
            } else {
                None
            };
            self.accepted = self.rejection.is_none();
            return;
        }
        let Ok(line) = std::str::from_utf8(line) else {
            return;
        };
        let Some((name, value)) = line.split_once(':') else {
            return;
        };
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("etag") || name.eq_ignore_ascii_case("last-modified") {
            if self.validator.is_none() || name.eq_ignore_ascii_case("etag") {
                self.validator = Some(value);
            }
        } else if name.eq_ignore_ascii_case("content-range") {
            self.range_start = value
                .strip_prefix("bytes ")
                .and_then(|value| value.split_once('-'))
                .and_then(|(start, _)| start.parse().ok());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn download(
    url: &str,
    destination: &Path,
    resume_from: u64,
    expected_validator: Option<&str>,
    credentials: Option<&Credentials>,
    trusted_host_key: Option<&TrustedHostKey>,
    emit: impl FnMut(WorkerEvent),
) -> Result<(), TransferError> {
    let parsed = Url::parse(url).map_err(|_| crate::RequestError::InvalidUrl)?;
    if parsed.scheme() == "sftp" {
        return download_sftp(
            url,
            destination,
            resume_from,
            credentials,
            trusted_host_key,
            emit,
        );
    }
    if trusted_host_key.is_some() || matches!(credentials, Some(Credentials::PrivateKey { .. })) {
        return Err(crate::RequestError::InvalidCredentials.into());
    }
    download_http_or_ftp(
        url,
        destination,
        resume_from,
        expected_validator,
        credentials,
        emit,
    )
}

fn validate_destination(destination: &Path, resume_from: u64) -> Result<(), TransferError> {
    if resume_from == 0 {
        if destination.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination exists",
            )
            .into());
        }
    } else if std::fs::metadata(destination)?.len() != resume_from {
        return Err(TransferError::ResumeMismatch);
    }
    Ok(())
}

fn open_destination(destination: &Path, resume_from: u64) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.write(true);
    if resume_from == 0 {
        options.create_new(true).open(destination)
    } else {
        options.append(true).open(destination)
    }
}

fn download_http_or_ftp(
    url: &str,
    destination: &Path,
    resume_from: u64,
    expected_validator: Option<&str>,
    credentials: Option<&Credentials>,
    mut emit: impl FnMut(WorkerEvent),
) -> Result<(), TransferError> {
    validate_destination(destination, resume_from)?;
    let parsed = Url::parse(url).map_err(|_| crate::RequestError::InvalidUrl)?;
    let is_http = matches!(parsed.scheme(), "http" | "https");
    let gate = Rc::new(RefCell::new(HeaderGate {
        accepted: !is_http,
        ..HeaderGate::default()
    }));
    let file: Rc<RefCell<Option<File>>> = Rc::new(RefCell::new(None));
    let write_error: Rc<RefCell<Option<std::io::Error>>> = Rc::new(RefCell::new(None));
    let destination = destination.to_path_buf();

    let mut easy = Easy::new();
    easy.url(url)?;
    easy.follow_location(false)?;
    easy.connect_timeout(Duration::from_secs(30))?;
    easy.low_speed_limit(1024)?;
    easy.low_speed_time(Duration::from_secs(30))?;
    easy.progress(true)?;
    if is_http {
        easy.http_version(HttpVersion::V2TLS)?;
    }
    if resume_from > 0 {
        easy.resume_from(resume_from)?;
    }

    let mut headers = List::new();
    let mut has_headers = false;
    if let Some(validator) = expected_validator {
        validate_header_value(validator)?;
        headers.append(&format!("If-Range: {validator}"))?;
        has_headers = true;
    }
    match credentials {
        Some(Credentials::Password { username, password }) => {
            easy.username(username)?;
            easy.password(password)?;
        }
        Some(Credentials::Bearer { token }) => {
            validate_header_value(token)?;
            headers.append(&format!("Authorization: Bearer {token}"))?;
            has_headers = true;
        }
        Some(Credentials::PrivateKey { .. }) => {
            return Err(crate::RequestError::InvalidCredentials.into());
        }
        None => {}
    }
    if has_headers {
        easy.http_headers(headers)?;
    }

    let started = Instant::now();
    let mut last_progress = Instant::now() - Duration::from_secs(1);
    let perform_result;
    {
        let header_gate = Rc::clone(&gate);
        let write_gate = Rc::clone(&gate);
        let write_file = Rc::clone(&file);
        let write_failure = Rc::clone(&write_error);
        let write_destination = destination.clone();
        let mut transfer = easy.transfer();
        if is_http {
            transfer.header_function(move |line| {
                header_gate
                    .borrow_mut()
                    .consume(line, resume_from, expected_validator);
                true
            })?;
        }
        transfer.write_function(move |bytes| {
            if !write_gate.borrow().accepted {
                return Ok(0);
            }
            let mut slot = write_file.borrow_mut();
            if slot.is_none() {
                match open_destination(&write_destination, resume_from) {
                    Ok(opened) => *slot = Some(opened),
                    Err(error) => {
                        *write_failure.borrow_mut() = Some(error);
                        return Ok(0);
                    }
                }
            }
            match slot.as_mut().expect("file opened").write_all(bytes) {
                Ok(()) => Ok(bytes.len()),
                Err(error) => {
                    *write_failure.borrow_mut() = Some(error);
                    Ok(0)
                }
            }
        })?;
        transfer.progress_function(|total, downloaded, _, _| {
            let now = Instant::now();
            if now.duration_since(last_progress) >= Duration::from_millis(250) {
                let elapsed = now.duration_since(started).as_secs_f64().max(0.001);
                emit(WorkerEvent::Progress {
                    downloaded: resume_from.saturating_add(downloaded.max(0.0) as u64),
                    total: (total > 0.0).then_some(resume_from.saturating_add(total as u64)),
                    speed: (downloaded.max(0.0) / elapsed) as u64,
                    effective_url: url.to_owned(),
                });
                last_progress = now;
            }
            true
        })?;
        perform_result = transfer.perform();
    }

    if let Some(error) = write_error.borrow_mut().take() {
        return Err(TransferError::Io(error));
    }
    if let Some(rejection) = gate.borrow().rejection {
        return Err(match rejection {
            HeaderRejection::Redirect => TransferError::RedirectPolicy,
            HeaderRejection::Status(status) => TransferError::HttpStatus(status),
            HeaderRejection::Resume => TransferError::ResumeMismatch,
        });
    }
    perform_result?;
    if file.borrow().is_none() {
        *file.borrow_mut() = Some(open_destination(&destination, resume_from)?);
    }
    file.borrow_mut()
        .as_mut()
        .expect("file opened")
        .sync_all()?;
    let bytes = std::fs::metadata(&destination)?.len();
    emit(WorkerEvent::Completed { bytes });
    Ok(())
}

fn validate_header_value(value: &str) -> Result<(), TransferError> {
    if value.contains(['\r', '\n']) {
        return Err(crate::RequestError::InvalidUrl.into());
    }
    Ok(())
}

#[cfg(not(fmd_native_sftp))]
fn probe_host_key(_url: &str, _emit: &mut impl FnMut(WorkerEvent)) -> Result<(), TransferError> {
    Err(TransferError::BackendUnavailable)
}

#[cfg(not(fmd_native_sftp))]
fn download_sftp(
    _url: &str,
    _destination: &Path,
    _resume_from: u64,
    _credentials: Option<&Credentials>,
    _trusted_host_key: Option<&TrustedHostKey>,
    _emit: impl FnMut(WorkerEvent),
) -> Result<(), TransferError> {
    Err(TransferError::BackendUnavailable)
}

#[cfg(fmd_native_sftp)]
mod native_sftp {
    use std::ffi::{CString, c_char, c_int, c_long, c_uchar, c_void};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};

    use super::*;

    const CURLSSH_AUTH_PASSWORD: c_long = 1 << 1;
    const CURLSSH_AUTH_PUBLICKEY: c_long = 1 << 2;

    #[repr(C)]
    struct CallbackState {
        callback: unsafe extern "C" fn(*mut c_void, c_int, *const c_uchar, usize) -> c_int,
        context: *mut c_void,
    }

    struct HostKeyContext {
        mode: HostKeyMode,
        observed: Option<ObservedHostKey>,
    }

    enum HostKeyMode {
        Probe,
        Verify(TrustedHostKey),
    }

    #[derive(Clone)]
    struct ObservedHostKey {
        algorithm: String,
        raw_key_base64: String,
        fingerprint_sha256: String,
    }

    unsafe extern "C" fn hostkey_callback(
        context: *mut c_void,
        key_type: c_int,
        key: *const c_uchar,
        key_len: usize,
    ) -> c_int {
        let context = unsafe { &mut *(context.cast::<HostKeyContext>()) };
        let Some(algorithm) = algorithm_name(key_type) else {
            return 0;
        };
        let encoded = unsafe { std::slice::from_raw_parts(key, key_len) };
        let Ok(encoded) = std::str::from_utf8(encoded) else {
            return 0;
        };
        let Ok(raw) = STANDARD.decode(encoded.trim_end_matches('\0')) else {
            return 0;
        };
        let fingerprint = format!("SHA256:{}", STANDARD.encode(Sha256::digest(&raw)));
        let observed = ObservedHostKey {
            algorithm: algorithm.into(),
            raw_key_base64: STANDARD.encode(raw),
            fingerprint_sha256: fingerprint,
        };
        let accepted = match &context.mode {
            HostKeyMode::Probe => false,
            HostKeyMode::Verify(expected) => {
                expected.algorithm == observed.algorithm
                    && expected.raw_key_base64 == observed.raw_key_base64
                    && expected.fingerprint_sha256 == observed.fingerprint_sha256
            }
        };
        context.observed = Some(observed);
        i32::from(accepted)
    }

    fn algorithm_name(value: c_int) -> Option<&'static str> {
        match value {
            2 => Some("rsa"),
            4 => Some("ecdsa"),
            5 => Some("ed25519"),
            _ => None,
        }
    }

    unsafe extern "C" {
        fn fmd_curl_set_hostkey_callback(easy: *mut c_void, state: *mut CallbackState) -> c_int;
        fn fmd_curl_set_ssh_auth(
            easy: *mut c_void,
            auth_types: c_long,
            private_key: *const c_char,
            passphrase: *const c_char,
        ) -> c_int;
    }

    fn configure_hostkey(
        easy: &Easy,
        context: &mut HostKeyContext,
    ) -> Result<CallbackState, TransferError> {
        let mut state = CallbackState {
            callback: hostkey_callback,
            context: (context as *mut HostKeyContext).cast(),
        };
        let code = unsafe { fmd_curl_set_hostkey_callback(easy.raw().cast(), &mut state) };
        if code != 0 {
            return Err(TransferError::BackendUnavailable);
        }
        Ok(state)
    }

    pub(super) fn probe(
        url: &str,
        emit: &mut impl FnMut(WorkerEvent),
    ) -> Result<(), TransferError> {
        let parsed = Url::parse(url).map_err(|_| crate::RequestError::InvalidUrl)?;
        let host = parsed
            .host_str()
            .ok_or(crate::RequestError::InvalidUrl)?
            .to_owned();
        let port = parsed.port().unwrap_or(22);
        let mut easy = Easy::new();
        easy.url(url)?;
        easy.connect_timeout(Duration::from_secs(20))?;
        easy.timeout(Duration::from_secs(30))?;
        easy.fresh_connect(true)?;
        easy.forbid_reuse(true)?;
        let mut context = HostKeyContext {
            mode: HostKeyMode::Probe,
            observed: None,
        };
        let _state = configure_hostkey(&easy, &mut context)?;
        let result = easy.perform();
        let observed = context
            .observed
            .ok_or_else(|| result.err().unwrap_or_else(|| curl::Error::new(1)))?;
        emit(WorkerEvent::HostKey {
            host,
            port,
            algorithm: observed.algorithm,
            raw_key_base64: observed.raw_key_base64,
            fingerprint_sha256: observed.fingerprint_sha256,
        });
        emit(WorkerEvent::Completed { bytes: 0 });
        Ok(())
    }

    pub(super) fn download(
        url: &str,
        destination: &Path,
        resume_from: u64,
        credentials: Option<&Credentials>,
        trusted: Option<&TrustedHostKey>,
        mut emit: impl FnMut(WorkerEvent),
    ) -> Result<(), TransferError> {
        validate_destination(destination, resume_from)?;
        let trusted = trusted.ok_or(TransferError::HostKeyUntrusted)?.clone();
        let mut file = open_destination(destination, resume_from)?;
        let mut easy = Easy::new();
        easy.url(url)?;
        easy.follow_location(false)?;
        easy.connect_timeout(Duration::from_secs(30))?;
        easy.progress(true)?;
        if resume_from > 0 {
            easy.resume_from(resume_from)?;
        }
        let mut context = HostKeyContext {
            mode: HostKeyMode::Verify(trusted),
            observed: None,
        };
        let _state = configure_hostkey(&easy, &mut context)?;

        let mut key = None;
        let mut passphrase = None;
        let auth = match credentials {
            Some(Credentials::Password { username, password }) => {
                easy.username(username)?;
                easy.password(password)?;
                CURLSSH_AUTH_PASSWORD
            }
            Some(Credentials::PrivateKey {
                username,
                key_path,
                passphrase: secret,
            }) => {
                easy.username(username)?;
                key = Some(
                    CString::new(key_path.as_str())
                        .map_err(|_| crate::RequestError::InvalidCredentials)?,
                );
                passphrase = secret
                    .as_deref()
                    .map(CString::new)
                    .transpose()
                    .map_err(|_| crate::RequestError::InvalidCredentials)?;
                CURLSSH_AUTH_PUBLICKEY
            }
            _ => return Err(crate::RequestError::InvalidCredentials.into()),
        };
        let code = unsafe {
            fmd_curl_set_ssh_auth(
                easy.raw().cast(),
                auth,
                key.as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                passphrase
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
            )
        };
        if code != 0 {
            return Err(TransferError::BackendUnavailable);
        }

        let mut write_error = None;
        let started = Instant::now();
        let mut last_progress = started - Duration::from_secs(1);
        let result;
        {
            let mut transfer = easy.transfer();
            transfer.write_function(|bytes| match file.write_all(bytes) {
                Ok(()) => Ok(bytes.len()),
                Err(error) => {
                    write_error = Some(error);
                    Ok(0)
                }
            })?;
            transfer.progress_function(|total, downloaded, _, _| {
                let now = Instant::now();
                if now.duration_since(last_progress) >= Duration::from_millis(250) {
                    emit(WorkerEvent::Progress {
                        downloaded: resume_from + downloaded.max(0.0) as u64,
                        total: (total > 0.0).then_some(resume_from + total as u64),
                        speed: (downloaded.max(0.0)
                            / now.duration_since(started).as_secs_f64().max(0.001))
                            as u64,
                        effective_url: url.into(),
                    });
                    last_progress = now;
                }
                true
            })?;
            result = transfer.perform();
        }
        if let Some(error) = write_error {
            return Err(error.into());
        }
        if result.is_err() {
            return match (&context.mode, &context.observed) {
                (_, None) => Err(result.unwrap_err().into()),
                (HostKeyMode::Verify(expected), Some(found))
                    if expected.algorithm != found.algorithm =>
                {
                    Err(TransferError::HostKeyAlgorithm)
                }
                _ => Err(TransferError::HostKeyMismatch),
            };
        }
        file.sync_all()?;
        emit(WorkerEvent::Completed {
            bytes: std::fs::metadata(destination)?.len(),
        });
        Ok(())
    }
}

#[cfg(fmd_native_sftp)]
fn probe_host_key(url: &str, emit: &mut impl FnMut(WorkerEvent)) -> Result<(), TransferError> {
    native_sftp::probe(url, emit)
}

#[cfg(fmd_native_sftp)]
fn download_sftp(
    url: &str,
    destination: &Path,
    resume_from: u64,
    credentials: Option<&Credentials>,
    trusted_host_key: Option<&TrustedHostKey>,
    emit: impl FnMut(WorkerEvent),
) -> Result<(), TransferError> {
    native_sftp::download(
        url,
        destination,
        resume_from,
        credentials,
        trusted_host_key,
        emit,
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use tempfile::tempdir;

    use super::*;

    #[cfg(feature = "native-stack")]
    #[test]
    fn links_expected_libcurl_line() {
        assert!(curl::Version::get().version().starts_with("8.21."));
    }

    #[test]
    fn error_body_does_not_create_destination() {
        let (base, server) = serve(vec![
            "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\noops".into(),
        ]);
        let temporary = tempdir().unwrap();
        let destination = temporary.path().join("file.part");
        let result = execute(
            WorkerRequest::Download {
                url: format!("{base}/file"),
                destination: destination.to_string_lossy().into_owned(),
                resume_from: 0,
                expected_validator: None,
                credentials: None,
                trusted_host_key: None,
            },
            |_| {},
        );
        assert!(matches!(result, Err(TransferError::HttpStatus(404))));
        assert!(!destination.exists());
        server.join().unwrap();
    }

    #[test]
    fn invalid_resume_response_preserves_partial() {
        let (base, server) = serve(vec![
            "HTTP/1.1 200 OK\r\nETag: other\r\nContent-Length: 5\r\nConnection: close\r\n\r\nworld"
                .into(),
        ]);
        let temporary = tempdir().unwrap();
        let destination = temporary.path().join("file.part");
        std::fs::write(&destination, b"hello").unwrap();
        let result = execute(
            WorkerRequest::Download {
                url: format!("{base}/file"),
                destination: destination.to_string_lossy().into_owned(),
                resume_from: 5,
                expected_validator: Some("expected".into()),
                credentials: None,
                trusted_host_key: None,
            },
            |_| {},
        );
        assert!(matches!(result, Err(TransferError::ResumeMismatch)));
        assert_eq!(std::fs::read(destination).unwrap(), b"hello");
        server.join().unwrap();
    }

    #[test]
    fn downloads_local_http_file_and_emits_completion() {
        let (base, server) = serve(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".into(),
        ]);
        let temporary = tempdir().unwrap();
        let destination = temporary.path().join("file.part");
        let mut events = Vec::new();
        execute(
            WorkerRequest::Download {
                url: format!("{base}/file"),
                destination: destination.to_string_lossy().into_owned(),
                resume_from: 0,
                expected_validator: None,
                credentials: None,
                trusted_host_key: None,
            },
            |event| events.push(event),
        )
        .unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"hello");
        assert!(matches!(
            events.last(),
            Some(WorkerEvent::Completed { bytes: 5 })
        ));
        server.join().unwrap();
    }

    fn serve(responses: Vec<String>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request);
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        (format!("http://{address}"), handle)
    }
}
