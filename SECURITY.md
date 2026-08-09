# Security policy

Please report security issues privately through the repository security advisory form. Do not
open a public issue for a suspected vulnerability involving credentials, update signatures,
engine packs, path traversal, command execution, or protected media handling.

FMD does not upload submitted URLs, cookies, credentials, SSH keys, or download history. Passwords
and key passphrases are session-only in portable mode. The application does not acquire DRM
licenses or keys and does not support peer-to-peer protocols.

Downloaded engine packs are isolated subprocesses, validated through a separately rooted TUF
repository, installed into immutable version directories, and activated only after verification
and a bounded self-test. Reports that demonstrate a bypass of these boundaries are in scope.

## Temporary dependency exception

`RUSTSEC-2024-0429` / `GHSA-wrw7-89jp-8q8g` affects `glib` 0.18 through the Linux
GTK/WebKitGTK stack used by Tauri. FMD does not depend on `glib` directly and does not use the
affected `VariantStrIter` API. A source and dependency-tree audit found no use of that API in FMD,
Tauri, Wry, or their GTK integration path.

This advisory is accepted temporarily for Linux builds because the current Tauri GTK stack pins
the 0.18 binding generation. The exception must be reviewed whenever Tauri or its Linux desktop
dependencies are updated and removed as soon as that stack supports `glib` 0.20 or newer. Any new
reachable use of the affected iterator blocks release immediately.
