// Package envelope implements the signbooth detached-signature format:
// a small self-describing JSON envelope carrying an Ed25519 signature over
// a canonical payload that names one artifact, its digest, the key, and
// the caller that requested the signature.
//
// The signed message is the exact payload bytes prefixed with a domain
// separator, so a signbooth signature can never be replayed as a signature
// over some other protocol's message (and vice versa). Verification is a
// pure function over (envelope, artifact bytes, pinned key) — it needs no
// daemon, no keystore, and no network.
package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// PayloadSchema identifies the signed statement format.
	PayloadSchema = "signbooth-payload/v1"
	// EnvelopeSchema identifies the outer envelope format.
	EnvelopeSchema = "signbooth-envelope/v1"
	// DigestPrefix is the only digest algorithm accepted in v1.
	DigestPrefix = "sha256:"

	// domain separates signbooth signatures from every other Ed25519 use.
	domain = EnvelopeSchema + "\x00"
)

// Payload is the statement that actually gets signed. Field order is fixed;
// encoding/json marshals struct fields in declaration order, which makes the
// serialized payload canonical for a given input.
type Payload struct {
	Schema   string `json:"schema"`
	Artifact string `json:"artifact"`
	Digest   string `json:"digest"`
	Size     int64  `json:"size"`
	Key      string `json:"key"`
	KeyFP    string `json:"keyFingerprint"`
	Caller   string `json:"caller"`
	SignedAt string `json:"signedAt"`
}

// Envelope is what lands in a .sbsig file: the exact payload bytes
// (base64), the raw Ed25519 public key, and the signature. Embedding the
// public key makes envelopes self-describing, but trust always comes from
// pinning — Open verifies math, the caller verifies identity.
type Envelope struct {
	Schema    string `json:"schema"`
	Payload   string `json:"payload"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

// Fingerprint renders an Ed25519 public key in the OpenSSH style:
// "SHA256:" + unpadded base64 of the SHA-256 of the raw 32-byte key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ValidDigest reports whether s is a well-formed v1 digest reference:
// "sha256:" followed by exactly 64 lowercase hex characters.
func ValidDigest(s string) bool {
	if !strings.HasPrefix(s, DigestPrefix) {
		return false
	}
	hexPart := s[len(DigestPrefix):]
	if len(hexPart) != 64 {
		return false
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// HashReader digests r and returns the "sha256:<hex>" reference plus the
// number of bytes consumed.
func HashReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return DigestPrefix + hex.EncodeToString(h.Sum(nil)), n, nil
}

// HashFile digests the file at path and returns its digest reference and size.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return HashReader(f)
}

// Sign serializes p canonically and signs it with priv. The payload's
// Schema and KeyFP fields are filled in here so they can never disagree
// with the key that actually signed.
func Sign(priv ed25519.PrivateKey, p Payload) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("envelope: private key has wrong length")
	}
	pub := priv.Public().(ed25519.PublicKey)
	p.Schema = PayloadSchema
	p.KeyFP = Fingerprint(pub)
	if !ValidDigest(p.Digest) {
		return Envelope{}, fmt.Errorf("envelope: refusing to sign malformed digest %q", p.Digest)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: encode payload: %w", err)
	}
	sig := ed25519.Sign(priv, append([]byte(domain), raw...))
	return Envelope{
		Schema:    EnvelopeSchema,
		Payload:   base64.StdEncoding.EncodeToString(raw),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Open checks the envelope's signature against its embedded public key and
// returns the decoded payload. It proves the math only: that these exact
// payload bytes were signed by the embedded key. Callers MUST additionally
// pin the key (see Pin) before trusting the payload.
func (e Envelope) Open() (Payload, error) {
	if e.Schema != EnvelopeSchema {
		return Payload{}, fmt.Errorf("envelope: unsupported schema %q", e.Schema)
	}
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return Payload{}, fmt.Errorf("envelope: payload is not valid base64: %w", err)
	}
	pub, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil {
		return Payload{}, fmt.Errorf("envelope: public key is not valid base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return Payload{}, fmt.Errorf("envelope: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return Payload{}, fmt.Errorf("envelope: signature is not valid base64: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), append([]byte(domain), raw...), sig) {
		return Payload{}, errors.New("envelope: signature does not verify")
	}
	var p Payload
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Payload{}, fmt.Errorf("envelope: decode payload: %w", err)
	}
	if p.Schema != PayloadSchema {
		return Payload{}, fmt.Errorf("envelope: unsupported payload schema %q", p.Schema)
	}
	if !ValidDigest(p.Digest) {
		return Payload{}, fmt.Errorf("envelope: malformed digest %q in payload", p.Digest)
	}
	if got := Fingerprint(ed25519.PublicKey(pub)); got != p.KeyFP {
		return Payload{}, fmt.Errorf("envelope: payload names key %s but was signed by %s", p.KeyFP, got)
	}
	return p, nil
}

// Fingerprint returns the OpenSSH-style fingerprint of the embedded key.
func (e Envelope) Fingerprint() (string, error) {
	pub, err := base64.StdEncoding.DecodeString(e.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("envelope: malformed embedded public key")
	}
	return Fingerprint(ed25519.PublicKey(pub)), nil
}

// Pin checks that the envelope was signed by the expected key, given as an
// OpenSSH-style fingerprint string. Comparison is constant-time.
func (e Envelope) Pin(fingerprint string) error {
	got, err := e.Fingerprint()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(fingerprint)) != 1 {
		return fmt.Errorf("envelope: signed by %s, expected %s", got, fingerprint)
	}
	return nil
}

// CheckFile re-hashes the file at path and compares digest and size against
// the payload. A mismatch means the artifact changed after signing (or the
// signature belongs to a different artifact).
func (p Payload) CheckFile(path string) error {
	digest, size, err := HashFile(path)
	if err != nil {
		return err
	}
	if digest != p.Digest {
		return fmt.Errorf("digest mismatch: artifact is %s, envelope says %s", digest, p.Digest)
	}
	if size != p.Size {
		return fmt.Errorf("size mismatch: artifact is %d bytes, envelope says %d", size, p.Size)
	}
	return nil
}

// Marshal renders the envelope as indented JSON with a trailing newline —
// the on-disk .sbsig representation.
func Marshal(e Envelope) []byte {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		// Envelope contains only strings; this cannot happen.
		panic(err)
	}
	return append(b, '\n')
}

// Parse reads a .sbsig document. Unknown top-level fields are rejected so a
// tampered or foreign file fails loudly instead of half-verifying.
func Parse(b []byte) (Envelope, error) {
	var e Envelope
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Envelope{}, fmt.Errorf("envelope: parse: %w", err)
	}
	return e, nil
}
