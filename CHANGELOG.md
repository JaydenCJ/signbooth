# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- `signbooth serve`: a signing daemon that holds Ed25519 private keys in one
  audited process and exposes a loopback-only API (unix socket by default,
  optional 127.0.0.1 TCP; non-loopback binds are refused).
- Per-caller policy: bearer-token callers restricted by key list, artifact
  glob patterns (`*`, `?`, `**` — `*` never crosses `/`), maximum artifact
  size, hourly rate limit, and token expiry. Policy edits apply on the very
  next request, no daemon restart.
- `signbooth sign`: hash an artifact locally (only the SHA-256 digest crosses
  the API), request a signature, and write a self-describing `.sbsig` JSON
  envelope. The client re-verifies the returned envelope before writing it.
- `signbooth verify`: fully offline envelope verification against a pinned
  public key (`--pub` PEM or `--fingerprint`); pinning is mandatory. Domain
  separation stops cross-protocol signature reuse, and a fingerprint
  cross-check defeats key-substitution envelopes.
- Hash-chained JSONL audit log covering grants, policy denials, and rejected
  tokens; `signbooth audit verify` detects edited, deleted, or reordered
  lines. Concurrent writers (daemon + CLI) share one chain via file locking.
- Booth management: `init`, `key new/ls/export` (PKCS#8/PKIX PEM on disk,
  0600/0700 modes), `caller add/ls/rm` (tokens hashed at rest, shown once),
  `status`, `whoami` — plus JSON output flags for scripting.
- 90 deterministic offline tests (`go test ./...`) and an end-to-end
  `scripts/smoke.sh` that prints `SMOKE OK`.

[0.1.0]: https://github.com/JaydenCJ/signbooth/releases/tag/v0.1.0
