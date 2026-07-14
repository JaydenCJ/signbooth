#!/usr/bin/env bash
# Operator role: initialize a booth, create a release key, register a CI
# caller with a tight policy, and start the daemon on the default unix
# socket. The demo booth is recreated from scratch on every run.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
rm -rf /tmp/signbooth-demo
mkdir -p /tmp/signbooth-demo
go build -o /tmp/signbooth-demo/signbooth ./cmd/signbooth
export SIGNBOOTH_HOME=/tmp/signbooth-demo/booth
BIN=/tmp/signbooth-demo/signbooth

"$BIN" init

# One key for release artifacts. Rotation later = a new name (release-2026h2).
"$BIN" key new release

# The CI caller may only sign dist/** with the release key, at most 64 MB
# per artifact, 100 signatures per hour, and the token dies in 30 days.
# The printed token is shown exactly once — put it in your CI secret store.
"$BIN" caller add ci \
  --key release \
  --artifact 'dist/**' \
  --max-size 64MB \
  --rate 100 \
  --ttl 30d

# Publish the public half wherever consumers can pin it.
"$BIN" key export release -o /tmp/signbooth-demo/release.pem
echo "public key written to /tmp/signbooth-demo/release.pem"

echo "starting the daemon (Ctrl-C to stop) ..."
exec "$BIN" serve
