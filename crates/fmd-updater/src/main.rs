use std::io::{self, Read};

use fmd_updater::{ApplyRequestV2, apply};
use serde::Serialize;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct Response<'a> {
    ok: bool,
    code: &'a str,
}

fn main() {
    let mut input = Vec::new();
    if io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > MAX_REQUEST_BYTES
    {
        exit(false, "request.read_failed", 2);
    }
    let request: ApplyRequestV2 = match serde_json::from_slice(&input) {
        Ok(value) => value,
        Err(_) => exit(false, "request.invalid_json", 2),
    };
    match apply(&request) {
        Ok(_) => exit(true, "update.committed", 0),
        Err(_) => exit(false, "update.failed", 3),
    }
}

fn exit(ok: bool, code: &str, status: i32) -> ! {
    println!(
        "{}",
        serde_json::to_string(&Response { ok, code }).expect("response serializes")
    );
    std::process::exit(status)
}
