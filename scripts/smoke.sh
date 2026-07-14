#!/usr/bin/env bash
# End-to-end smoke test for signbooth. No network beyond a unix socket in
# a temp dir, idempotent, runs from a clean tree. This script plus
# 'go test ./...' is the whole verification story — the repository
# intentionally ships no CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
SERVE_PID=""
cleanup() {
  [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/signbooth"
BOOTH="$WORKDIR/booth"
ADDR="unix://$BOOTH/booth.sock"
unset SIGNBOOTH_HOME SIGNBOOTH_ADDR SIGNBOOTH_TOKEN 2>/dev/null || true

echo "[1/12] build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/signbooth) || fail "build failed"

echo "[2/12] --version matches the manifest version"
VERSION_OUT="$("$BIN" --version)"
[ "$VERSION_OUT" = "signbooth 0.1.0" ] || fail "unexpected version output: $VERSION_OUT"

echo "[3/12] init a booth home"
"$BIN" init --home "$BOOTH" | grep "initialized signbooth home" >/dev/null || fail "init did not confirm"

echo "[4/12] create a key and register a caller"
"$BIN" key new release --home "$BOOTH" | grep "SHA256:" >/dev/null || fail "key new printed no fingerprint"
TOKEN="$("$BIN" caller add ci --home "$BOOTH" --key release --artifact 'dist/**' --rate 100 --json \
  | grep -o '"sbt_[0-9a-f]*"' | tr -d '"')"
case "$TOKEN" in sbt_*) ;; *) fail "no token captured from caller add" ;; esac

echo "[5/12] start the daemon on a unix socket"
"$BIN" serve --home "$BOOTH" --addr "$ADDR" >"$WORKDIR/serve.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do
  "$BIN" status --addr "$ADDR" >/dev/null 2>&1 && break
  kill -0 "$SERVE_PID" 2>/dev/null || fail "daemon exited early: $(cat "$WORKDIR/serve.log")"
  sleep 0.05
done
"$BIN" status --addr "$ADDR" | grep "daemon    ok" >/dev/null || fail "daemon not healthy"

echo "[6/12] caller sees its own policy"
SIGNBOOTH_TOKEN="$TOKEN" "$BIN" whoami --addr "$ADDR" | grep "dist/\*\*" >/dev/null || fail "whoami missing policy"

echo "[7/12] sign an artifact via the daemon"
mkdir -p "$WORKDIR/dist"
printf 'release payload v1\n' > "$WORKDIR/dist/app.tar.gz"
SIGNBOOTH_TOKEN="$TOKEN" "$BIN" sign "$WORKDIR/dist/app.tar.gz" \
  --key release --name dist/app.tar.gz --addr "$ADDR" \
  | grep "envelope" >/dev/null || fail "sign did not confirm"
[ -f "$WORKDIR/dist/app.tar.gz.sbsig" ] || fail "no .sbsig envelope written"

echo "[8/12] verify offline against the exported public key"
"$BIN" key export release --home "$BOOTH" -o "$WORKDIR/release.pem" >/dev/null
"$BIN" verify "$WORKDIR/dist/app.tar.gz" --pub "$WORKDIR/release.pem" \
  | grep "verified  dist/app.tar.gz" >/dev/null || fail "verify did not pass"

echo "[9/12] tampering with the artifact breaks verification"
printf 'evil payload v1xx\n' > "$WORKDIR/dist/app.tar.gz"
set +e
"$BIN" verify "$WORKDIR/dist/app.tar.gz" --pub "$WORKDIR/release.pem" 2>"$WORKDIR/verify.err"
VERIFY_CODE=$?
set -e
[ "$VERIFY_CODE" -eq 1 ] || fail "expected exit 1 on tampered artifact, got $VERIFY_CODE"
grep -q "verification FAILED" "$WORKDIR/verify.err" || fail "verify failure message missing"

echo "[10/12] policy denies artifacts outside the caller's globs"
printf 'not yours\n' > "$WORKDIR/secret.pem"
set +e
SIGNBOOTH_TOKEN="$TOKEN" "$BIN" sign "$WORKDIR/secret.pem" \
  --key release --name secrets/key.pem --addr "$ADDR" 2>"$WORKDIR/deny.err"
DENY_CODE=$?
set -e
[ "$DENY_CODE" -eq 1 ] || fail "expected exit 1 on policy deny, got $DENY_CODE"
grep -q "denied by policy" "$WORKDIR/deny.err" || fail "deny message missing"

echo "[11/12] removing the caller kills its token, no restart"
"$BIN" caller rm ci --home "$BOOTH" >/dev/null
set +e
SIGNBOOTH_TOKEN="$TOKEN" "$BIN" whoami --addr "$ADDR" >/dev/null 2>&1
REVOKED_CODE=$?
set -e
[ "$REVOKED_CODE" -eq 1 ] || fail "revoked token should exit 1, got $REVOKED_CODE"

echo "[12/12] the audit chain records everything and verifies"
"$BIN" audit verify --home "$BOOTH" | grep "chain intact" >/dev/null || fail "audit chain broken"
"$BIN" audit show --home "$BOOTH" | grep "deny" >/dev/null || fail "deny not in the audit log"
"$BIN" audit show --home "$BOOTH" | grep "sign" >/dev/null || fail "grant not in the audit log"

echo "SMOKE OK"
