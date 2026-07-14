#!/usr/bin/env bash
# Consumer role: verify a downloaded artifact fully offline. Needs only
# the artifact, its .sbsig envelope, and the publisher's pinned public
# key — no daemon, no booth home, no network.
set -euo pipefail

BIN=/tmp/signbooth-demo/signbooth
ARTIFACT=/tmp/signbooth-demo/dist/app.tar.gz
PUBKEY=/tmp/signbooth-demo/release.pem

# Pin by public key file...
"$BIN" verify "$ARTIFACT" --pub "$PUBKEY"

# ...or pin by fingerprint alone (handy in a Dockerfile or install script
# where shipping a PEM is awkward). Derive it once from the PEM you trust:
FPR="$("$BIN" verify "$ARTIFACT" --pub "$PUBKEY" --json \
  | grep -o '"keyFingerprint": "[^"]*"' | cut -d'"' -f4)"
"$BIN" verify "$ARTIFACT" --fingerprint "$FPR"

echo "artifact is exactly what the booth signed"
