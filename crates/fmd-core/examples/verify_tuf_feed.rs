use std::path::PathBuf;

use fmd_core::TufRepository;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let root_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("missing root path")?;
    let base = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("missing feed base URL")?;
    if arguments.next().is_some() {
        return Err("unexpected arguments".into());
    }
    let root = std::fs::read(root_path)?;
    let repository = TufRepository::load(
        &root,
        Url::parse(&format!("{}/metadata/", base.trim_end_matches('/')))?,
        Url::parse(&format!("{}/targets/", base.trim_end_matches('/')))?,
    )
    .await?;
    let targets = repository.descriptor_targets()?;
    if targets.is_empty() {
        return Err("feed contains no descriptor targets".into());
    }
    for target in &targets {
        repository
            .read_artifact_descriptor(target, 1024 * 1024)
            .await?;
    }
    println!("verified {} TUF descriptor targets", targets.len());
    Ok(())
}
