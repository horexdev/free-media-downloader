# Architecture

FMD separates presentation, domain policy, engine adapters, and platform integration.

```text
Svelte UI
   │ typed Tauri commands and events
Tauri shell
   │
fmd-core ── SQLite job store
   │
process-isolated adapters ── immutable engine pack versions
```

The frontend cannot spawn processes, read engine configuration, or access credentials directly.
`fmd-core` owns source classification, job state transitions, routing, persistence, retry policy,
and adapter contracts. The shell provides native windows and dialogs. Each external engine runs
from an explicit absolute path with an argument array, a private staging directory, cleared
environment, piped output, and bounded cancellation.

## Source routing

Routing is deterministic. Site pages use `yt-dlp`; gallery allowlisted hosts use `gallery-dl`;
live plugins prefer Streamlink; direct manifests prefer N_m3u8DL-RE; public direct HTTP transfers
are redirected through the curl worker and handed to aria2; authenticated HTTP and SFTP remain in
the curl worker. Unsupported extractors may fall back, while authorization, TLS, host-key,
integrity, geo, rate-limit, disk, and protected-media failures stop the chain.

Torrent files, magnet links, DHT, UPnP, and peer-to-peer listeners are rejected before an engine
is selected.

## Data layout

Installed mode uses platform application-data directories. When `portable.json` exists beside the
executable, mutable data and engines are stored beside the versioned application payload.

```text
data/
  fmd.db
  staging/<job>/<attempt>/
engines/
  <pack>/<version>/<target>/
  active/<pack>.json
```

Portable Windows keeps a stable launcher beside `app/<version>/` and atomically changes
`state/current.json`. macOS swaps a whole sibling application bundle, while Linux swaps the real
AppImage path. Update journals and the previous payload live on the same filesystem. A candidate
must acknowledge UI health within 60 seconds or the updater restores the previous payload.

The database stores job specifications, history, state, and engine-version leases. It never stores
passwords, cookies, bearer tokens, private-key passphrases, or URL user information.
