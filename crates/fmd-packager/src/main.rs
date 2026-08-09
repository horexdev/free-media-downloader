use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
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
    match arguments.first().and_then(|value| value.to_str()) {
        Some("package") => package(&arguments[1..]),
        Some("extract-zip-entry") => extract_zip_entry(&arguments[1..]),
        Some("extract-tar-gz-entry") => extract_tar_gz_entry(&arguments[1..]),
        _ => package(&arguments),
    }
}

fn extract_tar_gz_entry(arguments: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 3 {
        return Err(
            "usage: fmd-packager extract-tar-gz-entry <archive.tar.gz> <entry-name> <output-file>"
                .into(),
        );
    }
    let archive_path = PathBuf::from(&arguments[0]);
    let entry_name = arguments[1]
        .to_str()
        .ok_or("tar entry name must be valid UTF-8")?
        .replace('\\', "/");
    fmd_core::engine::validate_relative_path(&entry_name)?;
    let output = PathBuf::from(&arguments[2]);
    if output.exists() {
        return Err("extraction output must not exist".into());
    }

    let compressed = File::open(archive_path)?;
    let decoder = flate2::read::GzDecoder::new(compressed);
    let mut archive = tar::Archive::new(decoder);
    let mut extracted = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let normalized_path = normalized(&path);
        fmd_core::engine::validate_relative_path(&normalized_path)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            return Err("tar archive contains a non-regular entry".into());
        }
        if entry.size() > 512 * 1024 * 1024 {
            return Err("tar entry exceeds the extraction limit".into());
        }
        if normalized_path != entry_name {
            continue;
        }
        if extracted {
            return Err("tar archive contains a duplicate requested entry".into());
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        if let Err(error) = std::io::copy(&mut entry, &mut destination) {
            drop(destination);
            let _ = fs::remove_file(&output);
            return Err(error.into());
        }
        destination.flush()?;
        destination.sync_all()?;
        extracted = true;
    }
    if !extracted {
        return Err("requested tar entry was not found".into());
    }
    println!("{}", output.display());
    Ok(())
}

fn package(arguments: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 3 {
        return Err(
            "usage: fmd-packager package <manifest-template.json> <payload-directory> <output.zip>"
                .into(),
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
        .last_modified_time(zip::DateTime::default())
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

fn extract_zip_entry(arguments: &[OsString]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 3 {
        return Err(
            "usage: fmd-packager extract-zip-entry <archive.zip> <entry-name> <output-file>".into(),
        );
    }
    let archive_path = PathBuf::from(&arguments[0]);
    let entry_name = arguments[1]
        .to_str()
        .ok_or("ZIP entry name must be valid UTF-8")?
        .replace('\\', "/");
    fmd_core::engine::validate_relative_path(&entry_name)?;
    let output = PathBuf::from(&arguments[2]);
    if output.exists() {
        return Err("extraction output must not exist".into());
    }

    let mut archive = zip::ZipArchive::new(File::open(archive_path)?)?;
    let mut matching_index = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let enclosed = entry.enclosed_name().ok_or("unsafe ZIP path")?;
        let normalized = normalized(&enclosed);
        if normalized == entry_name {
            if matching_index.replace(index).is_some() {
                return Err("ZIP contains a duplicate requested entry".into());
            }
            if entry.is_dir() || entry.size() > 512 * 1024 * 1024 {
                return Err("requested ZIP entry is not a bounded regular file".into());
            }
            if let Some(mode) = entry.unix_mode() {
                let kind = mode & 0o170000;
                if kind != 0 && kind != 0o100000 {
                    return Err("requested ZIP entry is not a regular file".into());
                }
            }
        }
    }
    let index = matching_index.ok_or("requested ZIP entry was not found")?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut entry = archive.by_index(index)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    if let Err(error) = std::io::copy(&mut entry, &mut destination) {
        drop(destination);
        let _ = fs::remove_file(&output);
        return Err(error.into());
    }
    destination.flush()?;
    destination.sync_all()?;
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
    let executable = payload_file_is_executable(path, &relative)?;
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
    } else if executable {
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
        executable,
        role,
    })
}

fn payload_file_is_executable(
    path: &Path,
    relative: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !relative.starts_with("bin/") {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return Ok(fs::metadata(path)?.permissions().mode() & 0o111 != 0);
    }
    #[cfg(windows)]
    {
        return Ok(path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("exe")));
    }
    #[allow(unreachable_code)]
    Ok(false)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn extracts_only_a_bounded_regular_entry() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("input.zip");
        let output = temporary.path().join("output").join("deno");
        let file = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("deno", SimpleFileOptions::default().unix_permissions(0o755))
            .unwrap();
        archive.write_all(b"binary").unwrap();
        archive.finish().unwrap();

        extract_zip_entry(&[
            archive_path.into_os_string(),
            OsString::from("deno"),
            output.clone().into_os_string(),
        ])
        .unwrap();
        assert_eq!(fs::read(output).unwrap(), b"binary");
    }

    #[test]
    fn rejects_an_archive_with_an_unsafe_unrelated_entry() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("input.zip");
        let output = temporary.path().join("deno");
        let file = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("../escape", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"bad").unwrap();
        archive
            .start_file("deno", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"binary").unwrap();
        archive.finish().unwrap();

        assert!(
            extract_zip_entry(&[
                archive_path.into_os_string(),
                OsString::from("deno"),
                output.clone().into_os_string(),
            ])
            .is_err()
        );
        assert!(!output.exists());
    }

    #[test]
    fn extracts_only_a_regular_tar_gz_entry() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("input.tar.gz");
        let output = temporary.path().join("output").join("engine");
        let compressed = File::create(&archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(compressed, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let bytes = b"binary";
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive
            .append_data(&mut header, "engine", &bytes[..])
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();

        extract_tar_gz_entry(&[
            archive_path.into_os_string(),
            OsString::from("engine"),
            output.clone().into_os_string(),
        ])
        .unwrap();
        assert_eq!(fs::read(output).unwrap(), bytes);
    }

    #[test]
    fn rejects_a_tar_gz_with_a_link() {
        let temporary = tempdir().unwrap();
        let archive_path = temporary.path().join("input.tar.gz");
        let output = temporary.path().join("engine");
        let compressed = File::create(&archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(compressed, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("target").unwrap();
        header.set_cksum();
        archive
            .append_data(&mut header, "engine", std::io::empty())
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();

        assert!(
            extract_tar_gz_entry(&[
                archive_path.into_os_string(),
                OsString::from("engine"),
                output.clone().into_os_string(),
            ])
            .is_err()
        );
        assert!(!output.exists());
    }
}
