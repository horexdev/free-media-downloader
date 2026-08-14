# Update publication

Core application updates and engine-pack updates use independent TUF repositories:

- `https://horexdev.github.io/free-media-downloader-updates/core/`
- `https://horexdev.github.io/free-media-downloader-updates/engines/`

Each feed contains `metadata/` and `targets/`. The targets are small signed JSON descriptors;
application and pack binaries remain GitHub Release assets. A descriptor binds the release URL,
component, platform, version, security sequence, byte length, and SHA-256 digest.

## Trust and keys

The embedded trust roots are `src-tauri/resources/tuf/core-root.json` and
`src-tauri/resources/tuf/engines-root.json`. They must have different root, targets, snapshot, and
timestamp keys. The beta roots use a 1-of-1 threshold. Root private keys stay out of CI and
plaintext storage. The beta key set is stored only as Windows DPAPI `CurrentUser` ciphertext with inherited
ACLs disabled. The primary vault is
`%APPDATA%\FreeMediaDownloader\key-vault\tuf-root-v1`; its verified secondary copy is
`D:\Secure\FreeMediaDownloader\key-vault\tuf-root-v1`. Both vaults contain eight `.dpapi` blobs and
the entropy file required by DPAPI. Plaintext PEM files must not remain after a verified vault copy
is made. Move the secondary copy to offline media before using the root key for a rotation ceremony.

Only the online targets, snapshot, and timestamp private keys are provisioned to the release
environment:

- `FMD_CORE_TUF_TARGETS_KEY`
- `FMD_CORE_TUF_SNAPSHOT_KEY`
- `FMD_CORE_TUF_TIMESTAMP_KEY`
- `FMD_ENGINES_TUF_TARGETS_KEY`
- `FMD_ENGINES_TUF_SNAPSHOT_KEY`
- `FMD_ENGINES_TUF_TIMESTAMP_KEY`

The `FMD_CORE_TUF_ROOT_SHA256` and `FMD_ENGINES_TUF_ROOT_SHA256` repository variables pin the
reviewed public roots. A release stops before publication if either value is absent or differs.

For the beta roots generated on 2026-08-14, the reviewed values are:

- core: `260944e42f87620b8d4d723fce329d53a364d88e38d45f77eb0aa9e6b0be292a`
- engines: `fb874b1b41dc691b37e3d8ba19fc5a1dc1df82ce54c653b617d54ab7e60d0a68`

Generate a replacement root and private-key set outside the worktree with
`scripts/tuf/generate-root.mjs`. Root rotation is a separate reviewed ceremony: sign the new root
with the threshold required by both the old and new root, publish the versioned root metadata, then
embed it in a later application release. Do not use the feed publisher to rotate a root.

## Cross-repository publication

Install a dedicated GitHub App on `horexdev/free-media-downloader-updates` with repository Contents
write permission. Configure its client ID and private key as `FMD_UPDATES_APP_CLIENT_ID` and
`FMD_UPDATES_APP_PRIVATE_KEY`. The release job requests a repository-scoped installation token; a
personal access token is not used.

The updates repository must keep this structure on `main`:

```text
core/
  metadata/
  targets/
engines/
  metadata/
  targets/
manifests/  # optional release provenance
sbom/       # optional release SBOMs
```

Enable GitHub Pages with GitHub Actions as its source. Its Pages workflow must upload the repository
contents and deploy them to the `github-pages` environment. The release workflow waits for the new
timestamp metadata to become visible, downloads the versioned snapshot and targets metadata, then
verifies the hash and length of every published descriptor.

## Release behavior

The beta workflow only accepts a tag exactly matching `v` plus the workspace version, and only a
prerelease version. Distribution artifacts are intentionally unsigned and the release notes state
that explicitly. Automatic core replacement is limited to Windows portable layouts, writable
self-managed macOS app bundles, and Linux AppImages. NSIS and DEB installations use the verified
release notification but require manual installation.
