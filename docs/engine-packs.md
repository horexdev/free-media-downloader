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
