// Package booth owns the on-disk layout of a signbooth home directory:
//
//	$SIGNBOOTH_HOME/
//	├── keys/            Ed25519 keypairs (0700 dir, 0600 private keys)
//	├── callers.json     caller records: hashed tokens + policy (0600)
//	├── audit.log        hash-chained JSONL audit trail (0600)
//	└── booth.sock       the daemon's unix socket (created by serve)
//
// Everything the daemon trusts lives under this one directory, protected
// by ordinary unix permissions. Caller records are re-read on every
// request, so `caller add` / `caller rm` take effect without restarting
// the daemon.
package booth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/JaydenCJ/signbooth/internal/audit"
	"github.com/JaydenCJ/signbooth/internal/keystore"
	"github.com/JaydenCJ/signbooth/internal/policy"
)

// callersFile is the serialized form of callers.json.
type callersFile struct {
	Version int                      `json:"version"`
	Callers map[string]policy.Caller `json:"callers"`
}

// Booth is an opened home directory.
type Booth struct {
	Home  string
	Keys  *keystore.Store
	Audit *audit.Log
}

// DefaultHome resolves the booth home: $SIGNBOOTH_HOME if set, otherwise
// <user config dir>/signbooth.
func DefaultHome() (string, error) {
	if h := os.Getenv("SIGNBOOTH_HOME"); h != "" {
		return h, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("booth: cannot resolve a home directory (set SIGNBOOTH_HOME): %w", err)
	}
	return filepath.Join(base, "signbooth"), nil
}

func callersPath(home string) string { return filepath.Join(home, "callers.json") }

// AuditPath returns the audit log location for a home directory.
func AuditPath(home string) string { return filepath.Join(home, "audit.log") }

// SocketPath returns the daemon's default unix socket for a home directory.
func SocketPath(home string) string { return filepath.Join(home, "booth.sock") }

// Init creates a fresh booth home (0700) with an empty caller file and a
// genesis audit entry. It refuses to initialize twice.
func Init(home string, now time.Time) (*Booth, error) {
	if _, err := os.Stat(callersPath(home)); err == nil {
		return nil, fmt.Errorf("booth: %s is already initialized", home)
	}
	if err := os.MkdirAll(filepath.Join(home, "keys"), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(home, 0o700); err != nil {
		return nil, err
	}
	b := &Booth{Home: home, Keys: keystore.Open(filepath.Join(home, "keys"))}
	if err := b.saveCallers(map[string]policy.Caller{}); err != nil {
		return nil, err
	}
	log, err := audit.Open(AuditPath(home))
	if err != nil {
		return nil, err
	}
	b.Audit = log
	_, err = b.Audit.Append(audit.Entry{
		Time:   now.UTC().Format(time.RFC3339),
		Actor:  "-",
		Action: "init",
		Reason: "booth initialized",
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Open loads an existing booth home, failing with an actionable message if
// init has not run there yet.
func Open(home string) (*Booth, error) {
	if _, err := os.Stat(callersPath(home)); err != nil {
		return nil, fmt.Errorf("booth: %s is not initialized — run `signbooth init` first", home)
	}
	log, err := audit.Open(AuditPath(home))
	if err != nil {
		return nil, err
	}
	return &Booth{
		Home:  home,
		Keys:  keystore.Open(filepath.Join(home, "keys")),
		Audit: log,
	}, nil
}

// LoadCallers reads the current caller records from disk.
func (b *Booth) LoadCallers() (map[string]policy.Caller, error) {
	raw, err := os.ReadFile(callersPath(b.Home))
	if err != nil {
		return nil, err
	}
	var f callersFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("booth: parse %s: %w", callersPath(b.Home), err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("booth: %s has unsupported version %d", callersPath(b.Home), f.Version)
	}
	if f.Callers == nil {
		f.Callers = map[string]policy.Caller{}
	}
	return f.Callers, nil
}

// saveCallers writes the caller file atomically (temp file + rename) with
// mode 0600, so a crash mid-write can never leave a truncated policy.
func (b *Booth) saveCallers(callers map[string]policy.Caller) error {
	f := callersFile{Version: 1, Callers: callers}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := callersPath(b.Home) + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, callersPath(b.Home))
}

// AddCaller stores a new caller record and returns the one-time plaintext
// token. Only its SHA-256 lands on disk.
func (b *Booth) AddCaller(c policy.Caller) (string, error) {
	if !policy.ValidName(c.Name) {
		return "", fmt.Errorf("booth: invalid caller name %q (want [a-z0-9][a-z0-9._-]{0,63})", c.Name)
	}
	callers, err := b.LoadCallers()
	if err != nil {
		return "", err
	}
	if _, exists := callers[c.Name]; exists {
		return "", fmt.Errorf("booth: caller %q already exists — remove it first to rotate its token", c.Name)
	}
	token, hash, err := NewToken()
	if err != nil {
		return "", err
	}
	c.TokenSHA256 = hash
	callers[c.Name] = c
	if err := b.saveCallers(callers); err != nil {
		return "", err
	}
	return token, nil
}

// RemoveCaller deletes a caller record; its token stops working on the
// daemon's very next request.
func (b *Booth) RemoveCaller(name string) error {
	callers, err := b.LoadCallers()
	if err != nil {
		return err
	}
	if _, exists := callers[name]; !exists {
		return fmt.Errorf("booth: no such caller %q", name)
	}
	delete(callers, name)
	return b.saveCallers(callers)
}

// NewToken mints a bearer token ("sbt_" + 48 hex chars of CSPRNG output)
// and its SHA-256 hex digest, which is the only form ever persisted.
func NewToken() (token, hash string, err error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = "sbt_" + hex.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken returns the hex SHA-256 of a plaintext token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
