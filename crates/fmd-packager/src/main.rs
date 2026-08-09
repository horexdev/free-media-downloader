use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use fmd_core::{PackFile, PackFileRole, PackManifestV1};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

fn main() {
    if let Err(error) = run() {
        eprintln!("packaging failed: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err(
            "usage: fmd-packager <manifest-template.json> <payload-directory> <output.zip>".into(),
        );
    }
    let template = PathBuf::from(&arguments[0]);
    let payload = PathBuf::from(&arguments[1]);
    let output = PathBuf::from(&arguments[2]);
    if !payload.is_dir() || output.exists() {
        return Err("payload must exist and output must not exist".into());
    }
    let mut manifest: PackManifestV1 = serde_json::from_slice(&std::fs::read(template)?)?;
    let mut paths = Vec::new();
    collect_files(&payload, &payload, &mut paths)?;
    paths.sort_by_key(|left| normalized(left));
    manifest.files = paths
        .iter()
        .map(|path| describe(&payload, path))
        .collect::<Result<_, _>>()?;
    manifest.validate(fmd_core::ADAPTER_API_VERSION, manifest.target)?;
    manifest.verify_payload(&payload)?;
    require_pack_metadata(&payload)?;

    let archive_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    let mut archive = zip::ZipWriter::new(archive_file);
    let regular = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    archive.start_file("manifest.json", regular)?;
    archive.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    for path in paths {
        let name = normalized(path.strip_prefix(&payload)?);
        let executable = manifest
            .files
            .iter()
            .find(|file| file.path == name)
            .is_some_and(|file| file.executable);
        archive.start_file(
            name,
            regular.unix_permissions(if executable { 0o755 } else { 0o644 }),
        )?;
        let mut source = File::open(path)?;
        std::io::copy(&mut source, &mut archive)?;
    }
    let file = archive.finish()?;
    file.sync_all()?;
    println!("{}", output.display());
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(format!("links are forbidden: {}", path.display()).into());
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root)?;
            if relative == Path::new("manifest.json") {
                return Err("payload must not contain manifest.json".into());
            }
            if relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err("unsafe payload path".into());
            }
            files.push(path);
        } else {
            return Err("special files are forbidden".into());
        }
    }
    Ok(())
}

fn describe(root: &Path, path: &Path) -> Result<PackFile, Box<dyn std::error::Error>> {
    let relative = normalized(path.strip_prefix(root)?);
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let role = if relative.starts_with("LICENSES/") {
        PackFileRole::License
    } else if relative.starts_with("bin/") {
        PackFileRole::Executable
    } else if relative.starts_with("lib/") {
        PackFileRole::Library
    } else if relative.ends_with(".json") || relative.ends_with(".jsonl") {
        PackFileRole::Metadata
    } else {
        PackFileRole::Resource
    };
    Ok(PackFile {
        path: relative,
        size: std::fs::metadata(path)?.len(),
        sha256: format!("{:x}", hasher.finalize()),
        executable: matches!(role, PackFileRole::Executable),
        role,
    })
}

fn require_pack_metadata(payload: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for required in [
        "LICENSES",
        "sbom.spdx.json",
        "provenance.intoto.jsonl",
        "sources.json",
    ] {
        if !payload.join(required).exists() {
            return Err(format!("required pack metadata is missing: {required}").into());
        }
    }
    Ok(())
}

fn normalized(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
