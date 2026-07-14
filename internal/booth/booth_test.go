// Tests for booth home lifecycle and caller-record management, including
// the properties operators rely on: tokens are hashed at rest, saves are
// atomic, and removals take effect on the next read.
package booth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/signbooth/internal/policy"
)

var now = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

func newBooth(t *testing.T) *Booth {
	t.Helper()
	b, err := Init(filepath.Join(t.TempDir(), "home"), now)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ciCaller() policy.Caller {
	return policy.Caller{Name: "ci", Keys: []string{"release"}, Artifacts: []string{"dist/**"}}
}

func TestInitCreatesLockedDownLayout(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if _, err := Init(home, now); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(home); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("home dir should be 0700, got %v %v", fi.Mode().Perm(), err)
	}
	if _, err := os.Stat(filepath.Join(home, "keys")); err != nil {
		t.Fatal("keys/ directory missing after init")
	}
	if fi, err := os.Stat(callersPath(home)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("callers.json should be 0600, got %v %v", fi.Mode().Perm(), err)
	}
	if _, err := os.Stat(AuditPath(home)); err != nil {
		t.Fatal("init must write the genesis audit entry")
	}
}

func TestInitRefusesToRunTwice(t *testing.T) {
	b := newBooth(t)
	if _, err := Init(b.Home, now); err == nil {
		t.Fatal("double init must fail rather than reset state")
	}
}

func TestOpenRequiresInit(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "nope"))
	if err == nil || !strings.Contains(err.Error(), "signbooth init") {
		t.Fatalf("Open on a bare directory should point at init, got: %v", err)
	}
}

func TestAddCallerReturnsTokenOnceAndStoresOnlyHash(t *testing.T) {
	b := newBooth(t)
	token, err := b.AddCaller(ciCaller())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "sbt_") || len(token) != 4+48 {
		t.Fatalf("token format wrong: %q", token)
	}
	raw, _ := os.ReadFile(callersPath(b.Home))
	if strings.Contains(string(raw), token) {
		t.Fatal("plaintext token must never be persisted")
	}
	callers, _ := b.LoadCallers()
	if callers["ci"].TokenSHA256 != HashToken(token) {
		t.Fatal("stored hash does not match the issued token")
	}
}

func TestAddCallerRejectsDuplicateAndInvalidNames(t *testing.T) {
	b := newBooth(t)
	if _, err := b.AddCaller(ciCaller()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AddCaller(ciCaller()); err == nil {
		t.Fatal("duplicate caller must be rejected — token rotation is rm + add")
	}
	c := ciCaller()
	c.Name = "../etc"
	if _, err := b.AddCaller(c); err == nil {
		t.Fatal("path-traversal caller names must be rejected")
	}
}

func TestRemoveCallerSemantics(t *testing.T) {
	b := newBooth(t)
	b.AddCaller(ciCaller())
	if err := b.RemoveCaller("ci"); err != nil {
		t.Fatal(err)
	}
	callers, _ := b.LoadCallers()
	if _, ok := callers["ci"]; ok {
		t.Fatal("removed caller still present")
	}
	if err := b.RemoveCaller("ghost"); err == nil {
		t.Fatal("removing an unknown caller should error, not silently succeed")
	}
}

func TestLoadCallersRejectsUnsupportedVersion(t *testing.T) {
	b := newBooth(t)
	raw, _ := os.ReadFile(callersPath(b.Home))
	os.WriteFile(callersPath(b.Home),
		[]byte(strings.Replace(string(raw), `"version": 1`, `"version": 99`, 1)), 0o600)
	if _, err := b.LoadCallers(); err == nil {
		t.Fatal("future file versions must fail closed")
	}
}

func TestSaveCallersLeavesNoTempFileBehind(t *testing.T) {
	b := newBooth(t)
	b.AddCaller(ciCaller())
	if _, err := os.Stat(callersPath(b.Home) + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("atomic save must clean up its temp file via rename")
	}
}

func TestNewTokenIsUniqueAcrossCalls(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		tok, hash, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatal("token collision — CSPRNG not being used?")
		}
		seen[tok] = true
		if HashToken(tok) != hash {
			t.Fatal("returned hash does not match the token")
		}
	}
}

func TestWellKnownPathsAndEnvHome(t *testing.T) {
	t.Setenv("SIGNBOOTH_HOME", "/custom/booth")
	home, err := DefaultHome()
	if err != nil || home != "/custom/booth" {
		t.Fatalf("DefaultHome = %q, %v; want /custom/booth", home, err)
	}
	if SocketPath("/x") != "/x/booth.sock" || AuditPath("/x") != "/x/audit.log" {
		t.Fatal("well-known paths moved — smoke script and docs depend on them")
	}
}
