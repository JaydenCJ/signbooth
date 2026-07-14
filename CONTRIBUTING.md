# Contributing to signbooth

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go 1.22 or newer; there are no other dependencies of any kind.

```bash
git clone https://github.com/JaydenCJ/signbooth.git
cd signbooth
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and drives the full lifecycle — init,
key creation, caller registration, a live daemon on a unix socket, sign,
offline verify, tamper detection, a policy denial, token revocation, and
audit-chain verification. It must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (all 90 tests).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   packages (`policy`, `envelope`, `audit`) rather than in the CLI layer.

## Ground rules

- Zero runtime dependencies is a core feature: the `go.mod` require list
  stays empty. Adding a dependency needs strong justification in the PR.
- The daemon binds a unix socket or loopback TCP, never anything else, and
  sends nothing anywhere. No telemetry, no network calls at startup.
- Fail closed. Malformed policy, corrupt metadata, and ambiguous tokens
  must deny, and every deny carries a quotable reason into the audit log.
- The envelope and audit formats are versioned; any change bumps the schema
  string and keeps `v1` verification intact.
- Code comments and doc comments are written in English.

## Reporting bugs

Please include the output of `signbooth --version`, the exact command line,
the daemon's stderr, and — for policy questions — the relevant
`signbooth caller ls --json` record and `signbooth audit show -n 20` output
(redact anything sensitive; tokens never appear in either).

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
