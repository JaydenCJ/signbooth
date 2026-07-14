// Package keystore manages the booth's Ed25519 signing keys on disk.
// Private keys are standard PKCS#8 PEM files with mode 0600 inside a
// 0700 directory; public halves are PKIX PEM, so any stock TLS/JOSE/
// OpenSSL tooling can consume an exported key. A small JSON sidecar
// carries creation metadata and is cross-checked against the key material
// on every load — if the two disagree, loading fails rather than signing
// with a key the metadata lies about.
package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/JaydenCJ/signbooth/internal/envelope"
	"github.com/JaydenCJ/signbooth/internal/policy"
)

// Record is the public description of one key.
type Record struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"createdAt"`
}

// Store is a directory of keys. It performs no caching: deleting a key
// file revokes the key for the very next request.
type Store struct {
	dir string
}

// Open wraps dir as a Store without creating anything.
func Open(dir string) *Store { return &Store{dir: dir} }

// Dir returns the directory backing the store.
func (s *Store) Dir() string { return s.dir }

func (s *Store) keyPath(name string) string  { return filepath.Join(s.dir, name+".key") }
func (s *Store) pubPath(name string) string  { return filepath.Join(s.dir, name+".pub") }
func (s *Store) metaPath(name string) string { return filepath.Join(s.dir, name+".json") }

// Create generates a fresh Ed25519 keypair under name. It refuses to
// overwrite: key rotation means a new name, never silent replacement.
func (s *Store) Create(name string, now time.Time) (Record, error) {
	if !policy.ValidName(name) {
		return Record{}, fmt.Errorf("keystore: invalid key name %q (want [a-z0-9][a-z0-9._-]{0,63})", name)
	}
	if _, err := os.Stat(s.keyPath(name)); err == nil {
		return Record{}, fmt.Errorf("keystore: key %q already exists — rotate by creating a new name", name)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return Record{}, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Record{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Record{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(s.keyPath(name), keyPEM, 0o600); err != nil {
		return Record{}, err
	}
	pubPEM, err := PublicPEM(pub)
	if err != nil {
		return Record{}, err
	}
	if err := os.WriteFile(s.pubPath(name), pubPEM, 0o644); err != nil {
		return Record{}, err
	}

	rec := Record{
		Name:        name,
		Fingerprint: envelope.Fingerprint(pub),
		CreatedAt:   now.UTC().Format(time.RFC3339),
	}
	meta, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return Record{}, err
	}
	if err := os.WriteFile(s.metaPath(name), append(meta, '\n'), 0o600); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Load reads the private key and its metadata, verifying that the
// metadata's fingerprint matches the key material.
func (s *Store) Load(name string) (ed25519.PrivateKey, Record, error) {
	if !policy.ValidName(name) {
		return nil, Record{}, fmt.Errorf("keystore: invalid key name %q", name)
	}
	raw, err := os.ReadFile(s.keyPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, Record{}, fmt.Errorf("keystore: no such key %q", name)
		}
		return nil, Record{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, Record{}, fmt.Errorf("keystore: %s is not a PKCS#8 PEM private key", s.keyPath(name))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, Record{}, fmt.Errorf("keystore: parse %s: %w", s.keyPath(name), err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, Record{}, fmt.Errorf("keystore: key %q is not Ed25519", name)
	}
	rec, err := s.Get(name)
	if err != nil {
		return nil, Record{}, err
	}
	if got := envelope.Fingerprint(priv.Public().(ed25519.PublicKey)); got != rec.Fingerprint {
		return nil, Record{}, fmt.Errorf("keystore: key %q and its metadata disagree (%s vs %s) — refusing to sign", name, got, rec.Fingerprint)
	}
	return priv, rec, nil
}

// Get reads a key's public metadata record.
func (s *Store) Get(name string) (Record, error) {
	raw, err := os.ReadFile(s.metaPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return Record{}, fmt.Errorf("keystore: no such key %q", name)
		}
		return Record{}, err
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Record{}, fmt.Errorf("keystore: parse %s: %w", s.metaPath(name), err)
	}
	return rec, nil
}

// List returns records for every key in the store, sorted by name.
func (s *Store) List() ([]Record, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		rec, err := s.Get(strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ExportPublicPEM returns the PKIX PEM encoding of a key's public half.
func (s *Store) ExportPublicPEM(name string) ([]byte, error) {
	if !policy.ValidName(name) {
		return nil, fmt.Errorf("keystore: invalid key name %q", name)
	}
	b, err := os.ReadFile(s.pubPath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("keystore: no such key %q", name)
		}
		return nil, err
	}
	return b, nil
}

// PublicPEM encodes an Ed25519 public key as PKIX PEM.
func PublicPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicPEM decodes a PKIX PEM public key, as written by
// ExportPublicPEM or `signbooth key export`.
func ParsePublicPEM(b []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("keystore: not a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keystore: public key is not Ed25519")
	}
	return pub, nil
}
