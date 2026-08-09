# Engine packs

The desktop core is intentionally small. Capabilities are installed as separately versioned packs.

| Pack | Contents | Purpose |
|---|---|---|
| `ffmpeg-standard` | FFmpeg and ffprobe | LGPL-compatible mux, remux, audio, and protocols |
| `video-core` | yt-dlp, EJS, and Deno | VOD, audio, social pages, and playlists |
| `live-streams` | Streamlink and N_m3u8DL-RE | Live plugins and direct stream manifests |
| `galleries` | gallery-dl | Images, galleries, and social collections |
| `general-downloads` | aria2 and the curl worker | HTTP, FTP, SFTP, and Metalink |

Every target archive contains a manifest, exact file hashes, source revision, build flags,
licenses, corresponding-source instructions, an SPDX software bill of materials, provenance, and
a reproducible build recipe. Engine self-updaters are disabled.

The v1 release set intentionally excludes `ffmpeg-full`, regional packs, an offline full bundle,
and store packages. `ffmpeg-standard` is built from the signed `n9.0` tag with GPL and nonfree
features disabled. Streamlink and gallery-dl are one-folder Python bundles and never depend on a
system Python installation.

The native SFTP stack is built only through the `native-stack` feature and an exact static prefix.
The libssh2 1.11.1 base is not releasable unchanged: the locked FMD revision applies upstream
security commits `256d04b60d80bf1190e96b0ad1e91b2174d744b1` and
`97acf3dfda80c91c3a8c9f2372546301d4a1a7a8`. A build without both commits is rejected.

Core and engine metadata use separate TUF trust roots. Metadata expiry, target length and hashes,
monotonic security sequences, and compatible core API ranges are verified before extraction.
Versions are immutable. A running job retains a lease on its selected version, while an update is
activated only for new jobs.

## video-core assembly

`video-core` is assembled natively on each of the six supported targets. The assembler:

- downloads only HTTPS assets and follows redirects only across an explicit host allowlist;
- checks the pinned SHA-256 for yt-dlp, Deno, license texts, and checksum sidecars;
- verifies the signed yt-dlp checksum manifest against the pinned signing-key fingerprint;
- records bundled yt-dlp EJS as a separate `0.8.0` component in the manifest and SBOM;
- extracts only the exact Deno executable from its ZIP, rejecting unsafe or duplicate entries;
- runs yt-dlp and Deno version smoke tests without inheriting `PATH`;
- writes licenses, corresponding-source information, SPDX 2.3 SBOM, and in-toto provenance;
- creates the archive twice and rejects the build unless the SHA-256 values are identical.

The native command is:

```text
node scripts/packs/assemble-video-core.mjs --target <target> --work <empty-dir> \
  --out <archive.zip> --packager <fmd-packager> --gpg <gpg>
```

The `Engine packs` workflow runs this process on Windows, macOS, and Linux for x64 and ARM64.
Its archives are short-lived, explicitly unsigned CI artifacts. They are not eligible for a public
release until platform signing, notarization where applicable, and production TUF metadata have
completed.

## ffmpeg-standard source verification

FFmpeg is built from the official `9.0` source tarball rather than a third-party binary archive.
Before a native build starts, `verify-ffmpeg-source.mjs` enforces the pinned tarball, detached
signature, release-key hash, and exact release-key fingerprint in an isolated keyring. Downloads
are HTTPS-only, origin-restricted, retried at most three times, and capped at 64 MiB.
If the Node transport repeatedly fails against the direct FFmpeg origin, verification may retry
through curl with redirects disabled and the same size, digest, and signature requirements.

The current workflow also performs unsigned native build smoke tests for Linux and macOS on x64 and
ARM64. Linux links a separately verified static OpenSSL build; macOS must select SecureTransport.
The build rejects GPL/nonfree configuration and unexpected runtime TLS dependencies. Windows native
builds and final `ffmpeg-standard` pack assembly remain required before this pack is runnable.
