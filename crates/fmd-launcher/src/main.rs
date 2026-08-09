use std::path::{Component, Path};
use std::process::Command;

use serde::Deserialize;
use thiserror::Error;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentPayload {
    version: String,
    executable: String,
}

#[derive(Debug, Error)]
enum LaunchError {
    #[error("launcher path has no parent")]
    Root,
    #[error("current payload is invalid")]
    Pointer,
    #[error("current payload cannot be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("current payload cannot be decoded: {0}")]
    Json(#[from] serde_json::Error),
}

fn main() {
    if let Err(error) = run() {
        eprintln!("launcher.failed: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), LaunchError> {
    let launcher = std::env::current_exe()?;
    let root = launcher.parent().ok_or(LaunchError::Root)?;
    let pointer: CurrentPayload =
        serde_json::from_slice(&std::fs::read(root.join("state/current.json"))?)?;
    if !safe_component(&pointer.version) || !safe_relative(Path::new(&pointer.executable)) {
        return Err(LaunchError::Pointer);
    }
    let executable = root
        .join("app")
        .join(&pointer.version)
        .join(&pointer.executable);
    if !executable.is_file() || !executable.starts_with(root.join("app").join(&pointer.version)) {
        return Err(LaunchError::Pointer);
    }
    let mut command = Command::new(executable);
    command.args(std::env::args_os().skip(1));
    command.spawn()?;
    Ok(())
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn safe_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}
