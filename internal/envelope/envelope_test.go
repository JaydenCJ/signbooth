// Tests for the signature envelope: the format every verifier depends on.
// Tampering cases are exhaustive on purpose — each field an attacker could
// alter has a case proving the alteration is detected.
package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testPayload() Payload {
	return Payload{
		Artifact: "dist/app.tar.gz",
		Digest:   "sha256:" + strings.Repeat("ab", 32),
		Size:     1234,
		Key:      "release",
		Caller:   "ci",
		SignedAt: "2026-07-01T12:00:00Z",
	}
}

func TestSignThenOpenRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	env, err := Sign(priv, testPayload())
	if err != nil {
		t.Fatal(err)
	}
	p, err := env.Open()
	if err != nil {
		t.Fatalf("freshly signed envelope failed to open: %v", err)
	}
	if p.Artifact != "dist/app.tar.gz" || p.Size != 1234 || p.Caller != "ci" {
		t.Fatalf("payload fields mangled in round trip: %+v", p)
	}
	if p.Schema != PayloadSchema {
		t.Fatalf("Sign must stamp the payload schema, got %q", p.Schema)
	}
	if p.KeyFP != Fingerprint(pub) {
		t.Fatalf("Sign must stamp the actual signing key, got %q want %q", p.KeyFP, Fingerprint(pub))
	}
}

func TestSignRefusesBadInputs(t *testing.T) {
	_, priv := testKey(t)
	p := testPayload()
	p.Digest = "md5:abcdef"
	if _, err := Sign(priv, p); err == nil {
		t.Fatal("signing a non-sha256 digest must fail")
	}
	if _, err := Sign(ed25519.PrivateKey([]byte("short")), testPayload()); err == nil {
		t.Fatal("a truncated private key must be rejected before signing")
	}
}

func TestOpenDetectsBitFlips(t *testing.T) {
	_, priv := testKey(t)

	// Altered payload bytes: point the signature at a different artifact.
	env, _ := Sign(priv, testPayload())
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	tampered := strings.Replace(string(raw), "dist/app.tar.gz", "dist/evil.tar.gz", 1)
	env.Payload = base64.StdEncoding.EncodeToString([]byte(tampered))
	if _, err := env.Open(); err == nil {
		t.Fatal("altered payload bytes must not verify")
	}

	// Altered signature bytes.
	env, _ = Sign(priv, testPayload())
	sig, _ := base64.StdEncoding.DecodeString(env.Signature)
	sig[0] ^= 0x01
	env.Signature = base64.StdEncoding.EncodeToString(sig)
	if _, err := env.Open(); err == nil {
		t.Fatal("a flipped signature bit must not verify")
	}
}

func TestOpenDetectsKeySubstitution(t *testing.T) {
	// An attacker swapping in their own public key still fails, because
	// the signature was made by the original key.
	otherPub, _ := testKey(t)
	_, priv := testKey(t)
	env, _ := Sign(priv, testPayload())
	env.PublicKey = base64.StdEncoding.EncodeToString(otherPub)
	if _, err := env.Open(); err == nil {
		t.Fatal("substituted public key must not verify")
	}
}

func TestOpenDetectsResignedPayloadNamingOriginalKey(t *testing.T) {
	// The subtle attack: re-sign the ORIGINAL payload bytes (which still
	// name the victim's KeyFP) with the attacker's key and embed the
	// attacker's public key. Math verifies; the KeyFP cross-check catches it.
	_, victimPriv := testKey(t)
	attackerPub, attackerPriv := testKey(t)
	env, _ := Sign(victimPriv, testPayload())
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	sig := ed25519.Sign(attackerPriv, append([]byte(EnvelopeSchema+"\x00"), raw...))
	env.PublicKey = base64.StdEncoding.EncodeToString(attackerPub)
	env.Signature = base64.StdEncoding.EncodeToString(sig)
	if _, err := env.Open(); err == nil {
		t.Fatal("payload naming key A but signed by key B must be rejected")
	}
}

func TestOpenRejectsMalformedEnvelopes(t *testing.T) {
	_, priv := testKey(t)
	env, _ := Sign(priv, testPayload())
	env.Schema = "someone-elses-format/v9"
	if _, err := env.Open(); err == nil {
		t.Fatal("unknown envelope schema must be rejected")
	}
	env, _ = Sign(priv, testPayload())
	env.PublicKey = base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := env.Open(); err == nil {
		t.Fatal("a public key of the wrong size must be rejected")
	}
	env, _ = Sign(priv, testPayload())
	env.Payload = "!!! not base64 !!!"
	if _, err := env.Open(); err == nil {
		t.Fatal("non-base64 payload must be rejected")
	}
}

func TestDomainSeparationSignatureOverBarePayloadFails(t *testing.T) {
	// A signature over the raw payload bytes WITHOUT the domain prefix —
	// i.e. produced by some other protocol using the same key — must not
	// be accepted as a signbooth envelope.
	pub, priv := testKey(t)
	p := testPayload()
	p.Schema = PayloadSchema
	p.KeyFP = Fingerprint(pub)
	raw, _ := json.Marshal(p)
	env := Envelope{
		Schema:    EnvelopeSchema,
		Payload:   base64.StdEncoding.EncodeToString(raw),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)),
	}
	if _, err := env.Open(); err == nil {
		t.Fatal("signature missing the domain separator must not verify")
	}
}

func TestPinSemantics(t *testing.T) {
	pub, priv := testKey(t)
	otherPub, _ := testKey(t)
	env, _ := Sign(priv, testPayload())
	if err := env.Pin(Fingerprint(pub)); err != nil {
		t.Fatalf("pin against the actual signing key failed: %v", err)
	}
	if err := env.Pin(Fingerprint(otherPub)); err == nil {
		t.Fatal("pin against a different key must fail")
	}
}

func TestFingerprintFormat(t *testing.T) {
	pub, _ := testKey(t)
	fp := Fingerprint(pub)
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("fingerprint should use the OpenSSH prefix, got %q", fp)
	}
	if strings.HasSuffix(fp, "=") {
		t.Fatalf("fingerprint base64 must be unpadded, got %q", fp)
	}
	if len(fp) != len("SHA256:")+43 { // 32 bytes → 43 unpadded base64 chars
		t.Fatalf("unexpected fingerprint length: %q", fp)
	}
}

func TestValidDigest(t *testing.T) {
	if !ValidDigest("sha256:" + strings.Repeat("0f", 32)) {
		t.Fatal("canonical digest rejected")
	}
	bad := []string{
		"",
		strings.Repeat("ab", 32),             // missing prefix
		"sha256:" + strings.Repeat("AB", 32), // uppercase hex
		"sha256:" + strings.Repeat("ab", 31), // too short
		"sha256:" + strings.Repeat("ab", 33), // too long
		"sha512:" + strings.Repeat("ab", 32), // wrong algorithm
		"sha256:" + strings.Repeat("g", 64),  // non-hex
	}
	for _, s := range bad {
		if ValidDigest(s) {
			t.Fatalf("ValidDigest(%q) = true, want false", s)
		}
	}
}

func TestHashReaderAndHashFile(t *testing.T) {
	// SHA-256 of "abc" is a published NIST test vector.
	digest, n, err := HashReader(strings.NewReader("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if digest != want || n != 3 {
		t.Fatalf("HashReader = %s/%d, want %s/3", digest, n, want)
	}
	path := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	fromFile, sizeFile, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fromFile != want || sizeFile != 3 {
		t.Fatalf("HashFile = %s/%d, want %s/3", fromFile, sizeFile, want)
	}
}

func TestCheckFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.bin")
	os.WriteFile(path, []byte("payload"), 0o644)
	digest, size, _ := HashFile(path)

	p := Payload{Digest: digest, Size: size}
	if err := p.CheckFile(path); err != nil {
		t.Fatalf("unchanged artifact failed check: %v", err)
	}

	// Same size, new bytes: only the digest can catch this.
	os.WriteFile(path, []byte("PAYLOAD"), 0o644)
	if err := p.CheckFile(path); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("want a digest mismatch error, got: %v", err)
	}

	os.WriteFile(path, []byte("payload"), 0o644)
	p.Size = 9999
	if err := p.CheckFile(path); err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Fatalf("want a size mismatch error, got: %v", err)
	}
}

func TestMarshalParseRoundTripAndStrictness(t *testing.T) {
	_, priv := testKey(t)
	env, _ := Sign(priv, testPayload())
	b := Marshal(env)
	if !strings.HasSuffix(string(b), "}\n") || strings.HasSuffix(string(b), "\n\n") {
		t.Fatal(".sbsig files end with exactly one trailing newline")
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got != env {
		t.Fatal("Marshal → Parse must be the identity")
	}
	if _, err := got.Open(); err != nil {
		t.Fatalf("round-tripped envelope no longer verifies: %v", err)
	}
	// A foreign or extended file must fail loudly, not half-verify.
	doc := strings.Replace(string(b), "{", `{"extraField":"x",`, 1)
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("unknown top-level fields must be rejected")
	}
}

func TestOpenRejectsUnknownPayloadFields(t *testing.T) {
	_, priv := testKey(t)
	env, _ := Sign(priv, testPayload())
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	tampered := strings.Replace(string(raw), "{", `{"note":"injected",`, 1)
	// Re-sign so the math passes and only strict decoding can catch it.
	sig := ed25519.Sign(priv, append([]byte(EnvelopeSchema+"\x00"), []byte(tampered)...))
	env.Payload = base64.StdEncoding.EncodeToString([]byte(tampered))
	env.Signature = base64.StdEncoding.EncodeToString(sig)
	if _, err := env.Open(); err == nil {
		t.Fatal("unknown payload fields must be rejected")
	}
}
