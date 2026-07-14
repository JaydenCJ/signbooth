# The signbooth protocol and envelope format

This document specifies what travels over the daemon's loopback API and
what lands in a `.sbsig` file. Both formats are versioned by schema
strings; this page describes `v1`.

## Transport

The daemon listens on **one** of:

- a unix domain socket, `$SIGNBOOTH_HOME/booth.sock` by default, chmod
  `0600` — filesystem permissions are the outer wall;
- loopback TCP (`127.0.0.1:PORT`). Binding any non-loopback address is
  refused at startup; there is no flag to override this.

Plain HTTP/1.1 with JSON bodies. TLS is deliberately absent: the transport
never leaves the machine, and the interesting guarantees (who may sign
what) live in the token + policy layer, not the channel.

## Authentication

Every route except `GET /v1/health` requires `Authorization: Bearer
sbt_<48 hex>`. The daemon stores only SHA-256 hashes of tokens and compares
them in constant time against every record; if the same hash somehow maps
to two callers, authentication fails closed. Caller records are re-read
from `callers.json` per request, so `caller rm` revokes instantly.

## Routes

| Route | Auth | Purpose |
| --- | --- | --- |
| `GET /v1/health` | none | liveness: service name, version, daemon time |
| `GET /v1/keys` | bearer | key names + fingerprints the caller's policy grants |
| `GET /v1/self` | bearer | the caller's own policy (never the token hash) |
| `POST /v1/sign` | bearer | request a signature over a digest |

### `POST /v1/sign`

```json
{
  "key": "release",
  "artifact": "dist/app.tar.gz",
  "digest": "sha256:6f54…1528",
  "size": 29
}
```

The artifact's **bytes never cross the API** — the client hashes locally
and sends the digest. Requests are validated (name alphabet, digest shape,
no control characters, unknown fields rejected, 64 KiB body cap) before
policy runs; validation failures are `400`, policy denials are `403` with
the human-readable reason, rate-limit denials are `429`, and a key the
policy allows but the keystore lacks is `404`. Every deny is audited with
the same reason string the caller sees.

## The signed payload

What gets signed is a canonical JSON document (fixed field order, produced
by one encoder):

```json
{
  "schema": "signbooth-payload/v1",
  "artifact": "dist/app.tar.gz",
  "digest": "sha256:6f54…1528",
  "size": 29,
  "key": "release",
  "keyFingerprint": "SHA256:UV/8YXst…zs1k",
  "caller": "ci",
  "signedAt": "2026-07-13T01:47:40Z"
}
```

The Ed25519 signature is computed over `"signbooth-envelope/v1\x00"` +
payload bytes. The domain prefix means a signbooth signature can never be
replayed as a signature over another protocol's message, and vice versa.
Binding the **caller** into the payload means an envelope also proves *who
requested* the signature, which is what the audit story hinges on.

## The `.sbsig` envelope

```json
{
  "schema": "signbooth-envelope/v1",
  "payload": "<base64 of the exact payload bytes>",
  "publicKey": "<base64 raw 32-byte Ed25519 key>",
  "signature": "<base64 64-byte signature>"
}
```

Verification (`signbooth verify`, or ~20 lines in any language) is:

1. decode; reject unknown fields and wrong schemas;
2. check the signature over domain-prefix + payload bytes with the
   embedded key;
3. cross-check that `keyFingerprint` inside the payload matches the
   embedded key (defeats re-signed payloads naming someone else's key);
4. **pin**: compare the embedded key's fingerprint against the one you
   trust — the envelope alone proves math, pinning proves identity;
5. re-hash the artifact and compare digest and size.

Fingerprints are OpenSSH-style: `"SHA256:" + base64raw(sha256(pubkey))`.

## The audit chain

`audit.log` is JSONL. Each entry carries `seq`, `prev` (the previous
entry's hash) and `hash` (SHA-256 over the entry's canonical JSON with
`hash` blanked). Editing, deleting, or reordering any line breaks every
link after it; `signbooth audit verify` reports the first bad entry.
Appends re-read the chain tail under an exclusive file lock, so the daemon
and CLI commands in other processes extend one linear chain. The log
records grants, denials (with reasons), rejected tokens, and every
key/caller lifecycle event.
