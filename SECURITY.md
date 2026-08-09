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
