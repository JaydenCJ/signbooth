// Tests for the on-disk keystore: PEM round trips, permission modes, and
// the metadata cross-check that stops the daemon from signing with a key
// its records lie about.
package keystore

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/signbooth/internal/envelope"
)

var now = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

func TestCreateThenLoadRoundTrip(t *testing.T) {
	s := Open(t.TempDir())
	rec, err := s.Create("release", now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint format wrong: %q", rec.Fingerprint)
	}
	if rec.CreatedAt != "2026-07-01T12:00:00Z" {
		t.Fatalf("CreatedAt = %q, want the injected clock", rec.CreatedAt)
	}
	priv, got, err := s.Load("release")
	if err != nil {
		t.Fatal(err)
	}
	if got != rec {
		t.Fatalf("Load record %+v != Create record %+v", got, rec)
	}
	// The loaded key must actually be able to sign.
	msg := []byte("probe")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("loaded key cannot produce a valid signature")
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	s := Open(t.TempDir())
	if _, err := s.Create("release", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("release", now); err == nil {
		t.Fatal("re-creating an existing key must fail — rotation means a new name")
	}
}

func TestCreateRejectsInvalidNames(t *testing.T) {
	s := Open(t.TempDir())
	for _, name := range []string{"", "../escape", "UPPER", ".dot"} {
		if _, err := s.Create(name, now); err == nil {
			t.Fatalf("Create(%q) should have been rejected", name)
		}
	}
}

func TestPrivateKeyFileModeIs0600(t *testing.T) {
	dir := t.TempDir()
	Open(dir).Create("release", now)
	fi, err := os.Stat(filepath.Join(dir, "release.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestLoadFailuresAreDetectedAndActionable(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)

	// Missing key: the error names it.
	if _, _, err := s.Load("ghost"); err == nil || !strings.Contains(err.Error(), `"ghost"`) {
		t.Fatalf("want an error naming the missing key, got: %v", err)
	}

	// Corrupt key file.
	s.Create("corrupt", now)
	os.WriteFile(filepath.Join(dir, "corrupt.key"), []byte("garbage"), 0o600)
	if _, _, err := s.Load("corrupt"); err == nil {
		t.Fatal("corrupt key file must fail to load")
	}

	// Metadata swapped in from a different key: the daemon would announce
	// fingerprint A while signing with key B. Load must refuse.
	s.Create("a", now)
	s.Create("b", now)
	metaB, _ := os.ReadFile(filepath.Join(dir, "b.json"))
	doctored := strings.Replace(string(metaB), `"name": "b"`, `"name": "a"`, 1)
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(doctored), 0o600)
	if _, _, err := s.Load("a"); err == nil {
		t.Fatal("metadata/key fingerprint mismatch must refuse to load")
	}
}

func TestListSortedAndMissingDirIsEmpty(t *testing.T) {
	s := Open(t.TempDir())
	for _, n := range []string{"zeta", "alpha", "mid"} {
		s.Create(n, now)
	}
	recs, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[0].Name != "alpha" || recs[1].Name != "mid" || recs[2].Name != "zeta" {
		t.Fatalf("list not sorted: %+v", recs)
	}
	empty := Open(filepath.Join(t.TempDir(), "never-created"))
	if recs, err := empty.List(); err != nil || len(recs) != 0 {
		t.Fatalf("missing dir should list empty, got %d, %v", len(recs), err)
	}
}

func TestExportedPublicPEMRoundTrip(t *testing.T) {
	s := Open(t.TempDir())
	rec, _ := s.Create("release", now)
	pemBytes, err := s.ExportPublicPEM("release")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Fingerprint(pub) != rec.Fingerprint {
		t.Fatal("exported public key does not match the recorded fingerprint")
	}
	// And garbage must not parse.
	if _, err := ParsePublicPEM([]byte("not pem at all")); err == nil {
		t.Fatal("garbage must not parse as a public key")
	}
	if _, err := ParsePublicPEM([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Fatal("a private-key block must not parse as a public key")
	}
}

func TestDeletedKeyIsRevokedImmediately(t *testing.T) {
	// The store caches nothing: removing the file kills the key for the
	// very next Load, which is how operators revoke in an emergency.
	dir := t.TempDir()
	s := Open(dir)
	s.Create("release", now)
	if _, _, err := s.Load("release"); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "release.key"))
	if _, _, err := s.Load("release"); err == nil {
		t.Fatal("a deleted key file must fail to load immediately")
	}
}
