#!/usr/bin/env bash
# CI role: build an artifact and have the booth sign it. This process
# holds a scoped bearer token — never a private key. Expects the daemon
# from booth-setup.sh to be running and SIGNBOOTH_TOKEN to be exported
# (in real CI, inject it from the secret store).
set -euo pipefail

export SIGNBOOTH_HOME=/tmp/signbooth-demo/booth
BIN=/tmp/signbooth-demo/signbooth
: "${SIGNBOOTH_TOKEN:?export SIGNBOOTH_TOKEN with the token booth-setup.sh printed}"

# "Build" the release artifact.
mkdir -p /tmp/signbooth-demo/dist
tar -czf /tmp/signbooth-demo/dist/app.tar.gz -C /tmp/signbooth-demo --exclude booth --exclude dist . 2>/dev/null || true

# Confirm what this token is actually allowed to do.
"$BIN" whoami

# Sign it. The file is hashed locally; only the digest goes to the daemon,
# and the envelope lands next to the artifact as app.tar.gz.sbsig.
"$BIN" sign /tmp/signbooth-demo/dist/app.tar.gz \
  --key release \
  --name dist/app.tar.gz

echo "envelope: /tmp/signbooth-demo/dist/app.tar.gz.sbsig"
