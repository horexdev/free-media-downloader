use std::path::{Component, Path};

use quick_xml::Reader;
use quick_xml::XmlVersion;
use quick_xml::events::Event;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use url::Url;

use crate::error::CoreError;

#[derive(Debug, Clone, Copy)]
pub struct MetalinkLimits {
    pub descriptor_bytes: usize,
    pub files: usize,
    pub mirrors_per_file: usize,
    pub total_bytes: u64,
}

impl Default for MetalinkLimits {
    fn default() -> Self {
        Self {
            descriptor_bytes: 4 * 1024 * 1024,
            files: 256,
            mirrors_per_file: 32,
            total_bytes: 4 * 1024 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetalinkFile {
    pub name: String,
    pub size: Option<u64>,
    pub mirrors: Vec<String>,
    pub hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct MetalinkPreview {
    pub files: Vec<MetalinkFile>,
    pub total_bytes: Option<u64>,
    pub has_insecure_mirrors: bool,
}

impl MetalinkPreview {
    pub fn parse(bytes: &[u8], limits: MetalinkLimits) -> Result<Self, CoreError> {
        if bytes.len() > limits.descriptor_bytes {
            return Err(invalid("Metalink descriptor exceeds 4 MiB"));
        }
        let mut reader = Reader::from_reader(bytes);
        reader.config_mut().trim_text(true);
        let mut files = Vec::new();
        let mut current: Option<MetalinkFile> = None;
        let mut field = Field::None;

        loop {
            match reader.read_event() {
                Ok(Event::Start(event)) => match event.local_name().as_ref() {
                    b"file" => {
                        if current.is_some() || files.len() >= limits.files {
                            return Err(invalid("Metalink file limit was exceeded"));
                        }
                        let mut name = None;
                        for attribute in event.attributes().with_checks(true) {
                            let attribute =
                                attribute.map_err(|_| invalid("invalid XML attribute"))?;
                            if attribute.key.local_name().as_ref() == b"name" {
                                name = Some(
                                    attribute
                                        .decoded_and_normalized_value(
                                            XmlVersion::Implicit1_0,
                                            reader.decoder(),
                                        )
                                        .map_err(|_| invalid("invalid file name"))?
                                        .into_owned(),
                                );
                            }
                        }
                        let name = name.ok_or_else(|| invalid("Metalink file has no name"))?;
                        validate_relative_name(&name)?;
                        current = Some(MetalinkFile {
                            name,
                            size: None,
                            mirrors: Vec::new(),
                            hashes: Vec::new(),
                        });
                    }
                    b"size" if current.is_some() => field = Field::Size,
                    b"url" if current.is_some() => field = Field::Url,
                    b"hash" if current.is_some() => field = Field::Hash,
                    _ => field = Field::None,
                },
                Ok(Event::Text(event)) => {
                    let value = event
                        .decode()
                        .map_err(|_| invalid("invalid XML text"))?
                        .trim()
                        .to_owned();
                    if value.is_empty() {
                        continue;
                    }
                    let Some(file) = current.as_mut() else {
                        continue;
                    };
                    match field {
                        Field::Size => {
                            let size = value
                                .parse::<u64>()
                                .map_err(|_| invalid("invalid Metalink file size"))?;
                            if size > limits.total_bytes {
                                return Err(invalid("Metalink declared size exceeds the limit"));
                            }
                            file.size = Some(size);
                        }
                        Field::Url => {
                            if file.mirrors.len() >= limits.mirrors_per_file {
                                return Err(invalid("Metalink mirror limit was exceeded"));
                            }
                            let url = Url::parse(&value)
                                .map_err(|_| invalid("Metalink contains an invalid mirror URL"))?;
                            if !matches!(url.scheme(), "https" | "http" | "ftp") {
                                return Err(invalid("Metalink mirror scheme is not allowed"));
                            }
                            if !url.username().is_empty() || url.password().is_some() {
                                return Err(invalid("Metalink mirror contains credentials"));
                            }
                            file.mirrors.push(url.into());
                        }
                        Field::Hash => file.hashes.push(value),
                        Field::None => {}
                    }
                }
                Ok(Event::End(event)) => {
                    if event.local_name().as_ref() == b"file" {
                        let file = current
                            .take()
                            .ok_or_else(|| invalid("unexpected Metalink file terminator"))?;
                        if file.mirrors.is_empty() || file.hashes.is_empty() {
                            return Err(invalid("Metalink file needs a mirror and checksum"));
                        }
                        files.push(file);
                    }
                    field = Field::None;
                }
                Ok(Event::DocType(_)) | Ok(Event::PI(_)) => {
                    return Err(invalid("DTD and processing instructions are not allowed"));
                }
                Ok(Event::Eof) => break,
                Err(_) => return Err(invalid("Metalink XML could not be parsed")),
                _ => {}
            }
        }

        if current.is_some() || files.is_empty() {
            return Err(invalid("Metalink does not contain complete files"));
        }
        let total_bytes = files.iter().try_fold(0u64, |total, file| {
            file.size.and_then(|size| total.checked_add(size))
        });
        if total_bytes.is_some_and(|total| total > limits.total_bytes) {
            return Err(invalid("Metalink total size exceeds the limit"));
        }
        let has_insecure_mirrors = files.iter().flat_map(|file| &file.mirrors).any(|mirror| {
            Url::parse(mirror)
                .map(|url| url.scheme() != "https")
                .unwrap_or(true)
        });
        Ok(Self {
            files,
            total_bytes,
            has_insecure_mirrors,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum Field {
    None,
    Size,
    Url,
    Hash,
}

fn validate_relative_name(value: &str) -> Result<(), CoreError> {
    let path = Path::new(value);
    let unsafe_component = path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if value.is_empty()
        || value.contains('\0')
        || value.contains(':')
        || value.contains('\\')
        || unsafe_component
    {
        return Err(invalid("Metalink file path is unsafe"));
    }
    Ok(())
}

fn invalid(message: &str) -> CoreError {
    CoreError::InvalidInput(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_preview() {
        let xml = br#"<?xml version="1.0"?>
            <metalink xmlns="urn:ietf:params:xml:ns:metalink">
              <file name="video.mp4">
                <size>42</size>
                <hash type="sha-256">aaaaaaaa</hash>
                <url>https://cdn.example.com/video.mp4</url>
              </file>
            </metalink>"#;
        let preview = MetalinkPreview::parse(xml, MetalinkLimits::default()).unwrap();
        assert_eq!(preview.files[0].name, "video.mp4");
        assert_eq!(preview.total_bytes, Some(42));
        assert!(!preview.has_insecure_mirrors);
    }

    #[test]
    fn rejects_doctype_and_traversal() {
        let doctype = br#"<!DOCTYPE x [<!ENTITY e SYSTEM "file:///secret">]><metalink/>"#;
        assert!(MetalinkPreview::parse(doctype, MetalinkLimits::default()).is_err());
        let traversal = br#"<metalink><file name="../outside"><hash>x</hash><url>https://example.com/x</url></file></metalink>"#;
        assert!(MetalinkPreview::parse(traversal, MetalinkLimits::default()).is_err());
    }
}
