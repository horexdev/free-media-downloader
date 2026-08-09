use std::path::Path;

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use url::Url;

use crate::error::CoreError;
use crate::source::{InputSource, SourceKind};

const MANIFEST_EXTENSIONS: &[&str] = &["m3u8", "mpd", "ism", "isml"];
const DIRECT_EXTENSIONS: &[&str] = &[
    "7z", "aac", "avi", "flac", "gif", "jpeg", "jpg", "m4a", "mkv", "mov", "mp3", "mp4", "ogg",
    "opus", "pdf", "png", "tar", "wav", "webm", "webp", "zip",
];
const GALLERY_HOSTS: &[&str] = &[
    "500px.com",
    "deviantart.com",
    "flickr.com",
    "imgur.com",
    "pinterest.com",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RouteDecision {
    pub source_kind: SourceKind,
    pub engines: Vec<String>,
    pub required_packs: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Router;

impl Router {
    pub fn route(&self, source: &InputSource) -> Result<RouteDecision, CoreError> {
        match source {
            InputSource::LocalManifest { path } => self.route_local(path, SourceKind::Manifest),
            InputSource::LocalMetalink { path } => self.route_local(path, SourceKind::Metalink),
            InputSource::Url { value } => self.route_url(value),
        }
    }

    fn route_local(&self, path: &str, kind: SourceKind) -> Result<RouteDecision, CoreError> {
        if path.trim().is_empty() {
            return Err(CoreError::InvalidInput("local path is empty".into()));
        }
        Ok(match kind {
            SourceKind::Metalink => RouteDecision::new(kind, &["aria2"], &["general-downloads"]),
            _ => RouteDecision::new(
                kind,
                &["n-m3u8dl-re", "streamlink", "ffmpeg"],
                &["ffmpeg-standard", "live-streams"],
            ),
        })
    }

    fn route_url(&self, value: &str) -> Result<RouteDecision, CoreError> {
        let url = Url::parse(value.trim()).map_err(|error| {
            CoreError::InvalidInput(format!("URL could not be parsed: {error}"))
        })?;
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme == "magnet" || url.path().to_ascii_lowercase().ends_with(".torrent") {
            return Err(CoreError::InvalidInput(
                "peer-to-peer inputs are not supported".into(),
            ));
        }

        match scheme.as_str() {
            "sftp" => Ok(RouteDecision::new(
                SourceKind::DirectFile,
                &["fmd-curl-worker"],
                &["general-downloads"],
            )),
            "ftp" => Ok(RouteDecision::new(
                SourceKind::DirectFile,
                &["aria2"],
                &["general-downloads"],
            )),
            "http" | "https" => self.route_http(&url),
            _ => Err(CoreError::InvalidInput(format!(
                "URL scheme '{scheme}' is not supported"
            ))),
        }
    }

    fn route_http(&self, url: &Url) -> Result<RouteDecision, CoreError> {
        let extension = Path::new(url.path())
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if extension == "torrent" {
            return Err(CoreError::InvalidInput(
                "peer-to-peer inputs are not supported".into(),
            ));
        }
        if extension == "meta4" || extension == "metalink" {
            return Ok(RouteDecision::new(
                SourceKind::Metalink,
                &["aria2"],
                &["general-downloads"],
            ));
        }
        if MANIFEST_EXTENSIONS.contains(&extension.as_str()) {
            return Ok(RouteDecision::new(
                SourceKind::Manifest,
                &["n-m3u8dl-re", "streamlink", "ffmpeg"],
                &["ffmpeg-standard", "live-streams"],
            ));
        }
        if DIRECT_EXTENSIONS.contains(&extension.as_str()) {
            return Ok(RouteDecision::new(
                SourceKind::DirectFile,
                &["fmd-curl-worker", "aria2"],
                &["general-downloads"],
            ));
        }
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        if GALLERY_HOSTS
            .iter()
            .any(|gallery| host == *gallery || host.ends_with(&format!(".{gallery}")))
        {
            return Ok(RouteDecision::new(
                SourceKind::Gallery,
                &["gallery-dl"],
                &["galleries"],
            ));
        }
        Ok(RouteDecision::new(
            SourceKind::SiteMedia,
            &["yt-dlp"],
            &["ffmpeg-standard", "video-core"],
        ))
    }
}

impl RouteDecision {
    fn new(kind: SourceKind, engines: &[&str], packs: &[&str]) -> Self {
        Self {
            source_kind: kind,
            engines: engines.iter().map(ToString::to_string).collect(),
            required_packs: packs.iter().map(ToString::to_string).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> InputSource {
        InputSource::Url {
            value: value.into(),
        }
    }

    #[test]
    fn routes_site_media_to_video_core() {
        let decision = Router.route(&url("https://example.com/watch/42")).unwrap();
        assert_eq!(decision.source_kind, SourceKind::SiteMedia);
        assert_eq!(decision.engines, ["yt-dlp"]);
    }

    #[test]
    fn routes_manifest_to_specialized_fallback_chain() {
        let decision = Router
            .route(&url(
                "https://cdn.example.com/live/master.m3u8?token=secret",
            ))
            .unwrap();
        assert_eq!(decision.source_kind, SourceKind::Manifest);
        assert_eq!(decision.engines[0], "n-m3u8dl-re");
    }

    #[test]
    fn rejects_peer_to_peer_inputs() {
        let error = Router
            .route(&url("magnet:?xt=urn:btih:example"))
            .unwrap_err();
        assert!(error.to_string().contains("peer-to-peer"));
        let error = Router
            .route(&url("https://example.com/file.torrent"))
            .unwrap_err();
        assert!(error.to_string().contains("peer-to-peer"));
    }

    #[test]
    fn routes_sftp_only_to_curl_worker() {
        let decision = Router
            .route(&url("sftp://media.example.com/archive/file.mp4"))
            .unwrap();
        assert_eq!(decision.engines, ["fmd-curl-worker"]);
    }
}
