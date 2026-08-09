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

## License

FMD is licensed under GPL-3.0-or-later. Downloadable engine packs retain their own licenses and
are distributed with separate notices, corresponding source information, build recipes, and
software bills of materials.
