use std::io::{self, Read, Write};

use fmd_curl_worker::transfer::execute;
use fmd_curl_worker::{
    MAX_REQUEST_BYTES, TransferError, WorkerEnvelope, WorkerEvent, WorkerMessage,
};

fn main() {
    emit(&WorkerMessage::hello());
    let mut input = Vec::new();
    let read_result = io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input);
    if read_result.is_err() || input.len() > MAX_REQUEST_BYTES {
        emit_event(
            "invalid",
            WorkerEvent::Failed {
                code: "worker.request_too_large".into(),
            },
        );
        return;
    }

    let envelope: WorkerEnvelope = match serde_json::from_slice(&input) {
        Ok(value) => value,
        Err(_) => {
            emit_event(
                "invalid",
                WorkerEvent::Failed {
                    code: "worker.invalid_request".into(),
                },
            );
            return;
        }
    };
    let request_id = envelope.request_id.clone();
    if let Err(error) = envelope.validate() {
        emit_event(
            &request_id,
            WorkerEvent::Failed {
                code: error_code(&TransferError::Request(error)).into(),
            },
        );
        return;
    }
    if let Err(error) = execute(envelope.request, |event| emit_event(&request_id, event)) {
        emit_event(
            &request_id,
            WorkerEvent::Failed {
                code: error_code(&error).into(),
            },
        );
    }
}

fn error_code(error: &TransferError) -> &'static str {
    match error {
        TransferError::Request(_) => "worker.request_rejected",
        TransferError::RedirectPolicy => "worker.redirect_rejected",
        TransferError::HttpStatus(_) => "worker.http_failed",
        TransferError::ResumeMismatch => "worker.resume_mismatch",
        TransferError::BackendUnavailable => "worker.backend_unavailable",
        TransferError::HostKeyUntrusted => "worker.sftp_host_key_untrusted",
        TransferError::HostKeyMismatch => "worker.sftp_host_key_mismatch",
        TransferError::HostKeyAlgorithm => "worker.sftp_host_key_algorithm",
        TransferError::Curl(_) => "worker.transfer_failed",
        TransferError::Io(_) => "worker.io_failed",
    }
}

fn emit_event(request_id: &str, event: WorkerEvent) {
    emit(&WorkerMessage::Event {
        request_id: request_id.into(),
        event,
    });
}

fn emit(message: &WorkerMessage) {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, message).expect("worker message is serializable");
    stdout.write_all(b"\n").expect("stdout is writable");
    stdout.flush().expect("stdout is writable");
}
