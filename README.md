# Free Media Downloader

Free Media Downloader is a cross-platform desktop application for downloading web media,
live streams, galleries, direct files, and Metalink selections through independently
updated open-source engine packs.

The v1 application uses a small Tauri shell and a Rust core. Download engines are installed
only when their capabilities are needed. BitTorrent, magnet links, DHT, DRM-license
acquisition, telemetry, advertising, and background URL submission are outside the product
scope.

## Development status

The repository currently contains the initial architecture and a functional local job-planning
slice. Engine packaging, signing, notarization, and production distribution require the release
infrastructure described in the project roadmap.

## Requirements

- Rust 1.97.1 (selected automatically by `rust-toolchain.toml`)
- Node.js 24 or newer
- pnpm 11
- Platform requirements for Tauri 2

Run `pnpm install`, `cargo test --workspace`, and `pnpm check` before opening a change.

## Building first public beta artifacts

For the first public beta (`v0.1.0-beta.1`) we use an unsigned distribution:

- Tag: `v0.1.0-beta.1`
- Release workflow: `.github/workflows/release.yml`

Build sequence:

1. Push a tag matching `v*` to `main`:
   - `git tag v0.1.0-beta.1`
   - `git push origin v0.1.0-beta.1`
2. GitHub Actions runs:
   - `build-core` — 6 platform Tauri core builds + renamed artifacts
   - `build-engines` — unsigned pack artifacts for ffmpeg-standard, video-core,
     live-streams, galleries, general-downloads
   - `release` — creates a draft release and publishes all artifacts + `SHA256SUMS`

Artifacts are placed in GitHub Releases using:

- `FMD-windows-x64-portable.zip`
- `FMD-windows-x64-setup.exe`
- `FMD-windows-arm64-portable.zip`
- `FMD-windows-arm64-setup.exe`
- `FMD-macos-x64.app.zip`
- `FMD-macos-x64.dmg`
- `FMD-macos-arm64.app.zip`
- `FMD-macos-arm64.dmg`
- `FMD-linux-x64.AppImage`
- `FMD-linux-x64.deb`
- `FMD-linux-arm64.AppImage`
- `FMD-linux-arm64.deb`

Engine pack artifacts include unsigned `unsigned-*` names in the same release, with metadata
publication prepared in the `horexdev/free-media-downloader-updates` repository for the next stage.

## License

FMD is licensed under GPL-3.0-or-later. Downloadable engine packs retain their own licenses and
are distributed with separate notices, corresponding source information, build recipes, and
software bills of materials.
