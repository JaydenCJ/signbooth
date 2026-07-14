// In-process integration tests for the CLI: every command is exercised
// through Run with real files in temp directories, and daemon-dependent
// commands run against a real in-process daemon on a unix socket.
package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JaydenCJ/signbooth/internal/api"
	"github.com/JaydenCJ/signbooth/internal/booth"
	"github.com/JaydenCJ/signbooth/internal/server"
)

// run executes one CLI invocation and captures its streams.
func run(args ...string) (code int, stdout, stderr string) {
	var out, errBuf bytes.Buffer
	code = Run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// newHome initializes a booth home under a temp dir.
func newHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if code, _, stderr := run("init", "--home", home); code != exitOK {
		t.Fatalf("init failed (%d): %s", code, stderr)
	}
	return home
}

// addCaller registers a caller via the CLI and returns its plaintext token.
func addCaller(t *testing.T, home, name string, extra ...string) string {
	t.Helper()
	args := append([]string{"caller", "add", name, "--home", home, "--json"}, extra...)
	code, stdout, stderr := run(args...)
	if code != exitOK {
		t.Fatalf("caller add failed (%d): %s", code, stderr)
	}
	var resp struct {
		Caller api.CallerView `json:"caller"`
		Token  string         `json:"token"`
	}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("caller add --json output not JSON: %v\n%s", err, stdout)
	}
	return resp.Token
}

// startDaemon serves the booth on its unix socket, in-process.
func startDaemon(t *testing.T, home string) string {
	t.Helper()
	b, err := booth.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	addr := "unix://" + booth.SocketPath(home)
	ln, _, err := Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: server.New(b, nil).Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return addr
}

// writeArtifact drops a small file to sign.
func writeArtifact(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVersionHelpAndUsageErrors(t *testing.T) {
	code, stdout, _ := run("--version")
	if code != exitOK || stdout != "signbooth 0.1.0\n" {
		t.Fatalf("version: code=%d out=%q", code, stdout)
	}
	code, stdout, _ = run("help")
	if code != exitOK {
		t.Fatalf("help exit = %d", code)
	}
	for _, cmd := range []string{"init", "key new", "caller add", "serve", "sign", "verify", "audit"} {
		if !strings.Contains(stdout, cmd) {
			t.Fatalf("help is missing %q", cmd)
		}
	}
	code, _, stderr := run("frobnicate")
	if code != exitUsage || !strings.Contains(stderr, "frobnicate") {
		t.Fatalf("unknown command: code=%d stderr=%q", code, stderr)
	}
	if code, _, _ := run(); code != exitUsage {
		t.Fatalf("bare invocation should exit %d", exitUsage)
	}
}

func TestInitRefusesToRunTwice(t *testing.T) {
	home := newHome(t)
	code, _, stderr := run("init", "--home", home)
	if code != exitRuntime || !strings.Contains(stderr, "already initialized") {
		t.Fatalf("double init: code=%d stderr=%q", code, stderr)
	}
}

func TestKeyLifecycle(t *testing.T) {
	home := newHome(t)
	// An empty booth points the operator at the next step.
	_, stdout, _ := run("key", "ls", "--home", home)
	if !strings.Contains(stdout, "signbooth key new") {
		t.Fatalf("empty key ls should point at key new, got %q", stdout)
	}
	code, stdout, stderr := run("key", "new", "release", "--home", home)
	if code != exitOK {
		t.Fatalf("key new failed: %s", stderr)
	}
	if !strings.Contains(stdout, "SHA256:") {
		t.Fatalf("key new should print the fingerprint:\n%s", stdout)
	}
	if code, _, _ := run("key", "new", "../evil", "--home", home); code != exitRuntime {
		t.Fatal("invalid key names must be rejected")
	}
	code, stdout, _ = run("key", "ls", "--home", home)
	if code != exitOK || !strings.Contains(stdout, "release") {
		t.Fatalf("key ls: code=%d out=%q", code, stdout)
	}
	code, stdout, _ = run("key", "export", "release", "--home", home)
	if code != exitOK || !strings.Contains(stdout, "BEGIN PUBLIC KEY") {
		t.Fatalf("key export: code=%d out=%q", code, stdout)
	}
}

func TestCallerLifecycle(t *testing.T) {
	home := newHome(t)
	run("key", "new", "release", "--home", home)
	// A caller without any policy would be able to sign nothing; refuse it.
	code, _, stderr := run("caller", "add", "ci", "--home", home)
	if code != exitUsage || !strings.Contains(stderr, "--key and --artifact") {
		t.Fatalf("policy-less caller: code=%d stderr=%q", code, stderr)
	}
	token := addCaller(t, home, "ci", "--key", "release", "--artifact", "dist/**", "--rate", "50")
	if !strings.HasPrefix(token, "sbt_") {
		t.Fatalf("token format: %q", token)
	}
	code, stdout, _ := run("caller", "ls", "--home", home)
	if code != exitOK || !strings.Contains(stdout, "ci") || !strings.Contains(stdout, "50/hour") {
		t.Fatalf("caller ls: %q", stdout)
	}
	if code, _, _ = run("caller", "rm", "ci", "--home", home); code != exitOK {
		t.Fatal("caller rm failed")
	}
	_, stdout, _ = run("caller", "ls", "--home", home)
	if !strings.Contains(stdout, "no callers") {
		t.Fatalf("caller should be gone: %q", stdout)
	}
}

func TestSignVerifyEndToEnd(t *testing.T) {
	home := newHome(t)
	run("key", "new", "release", "--home", home)
	token := addCaller(t, home, "ci", "--key", "release", "--artifact", "*.tar.gz")
	addr := startDaemon(t, home)
	artifact := writeArtifact(t, t.TempDir(), "app.tar.gz", "release payload bytes")

	t.Setenv("SIGNBOOTH_TOKEN", token)
	code, stdout, stderr := run("sign", artifact, "--key", "release", "--addr", addr, "--home", home)
	if code != exitOK {
		t.Fatalf("sign failed (%d): %s", code, stderr)
	}
	if !strings.Contains(stdout, "signed") || !strings.Contains(stdout, artifact+".sbsig") {
		t.Fatalf("sign output: %q", stdout)
	}

	// Verify offline by exported public key…
	pubPath := filepath.Join(home, "release.pem")
	if code, _, _ := run("key", "export", "release", "--home", home, "-o", pubPath); code != exitOK {
		t.Fatal("export failed")
	}
	code, stdout, stderr = run("verify", artifact, "--pub", pubPath)
	if code != exitOK {
		t.Fatalf("verify failed (%d): %s", code, stderr)
	}
	if !strings.Contains(stdout, "verified") || !strings.Contains(stdout, "caller") {
		t.Fatalf("verify output: %q", stdout)
	}

	// …and by pinned fingerprint.
	var recs []struct{ Fingerprint string }
	_, lsOut, _ := run("key", "ls", "--home", home, "--json")
	if err := json.Unmarshal([]byte(lsOut), &recs); err != nil || len(recs) != 1 {
		t.Fatalf("key ls --json: %v %q", err, lsOut)
	}
	if code, _, stderr := run("verify", artifact, "--fingerprint", recs[0].Fingerprint); code != exitOK {
		t.Fatalf("fingerprint verify failed: %s", stderr)
	}
	// The wrong fingerprint must fail even though the signature is valid.
	wrong := "SHA256:" + strings.Repeat("A", 43)
	if code, _, _ := run("verify", artifact, "--fingerprint", wrong); code != exitFail {
		t.Fatal("verify with a foreign fingerprint must exit 1")
	}
}

func TestVerifyFailureModes(t *testing.T) {
	home := newHome(t)
	run("key", "new", "release", "--home", home)
	token := addCaller(t, home, "ci", "--key", "release", "--artifact", "*")
	addr := startDaemon(t, home)
	dir := t.TempDir()
	artifact := writeArtifact(t, dir, "app.bin", "original")

	t.Setenv("SIGNBOOTH_TOKEN", token)
	run("sign", artifact, "--key", "release", "--addr", addr, "--home", home)
	pubPath := filepath.Join(home, "k.pem")
	run("key", "export", "release", "--home", home, "-o", pubPath)

	// Pinning is mandatory: no pin (or two pins) is a usage error.
	if code, _, _ := run("verify", artifact); code != exitUsage {
		t.Fatal("verify without a pin must be a usage error")
	}
	if code, _, _ := run("verify", artifact, "--pub", pubPath, "--fingerprint", "SHA256:x"); code != exitUsage {
		t.Fatal("verify with two pins must be a usage error")
	}

	// A tampered artifact fails with exit 1 and a loud message.
	os.WriteFile(artifact, []byte("tampered"), 0o644)
	code, _, stderr := run("verify", artifact, "--pub", pubPath)
	if code != exitFail || !strings.Contains(stderr, "FAILED") {
		t.Fatalf("tampered artifact: code=%d stderr=%q", code, stderr)
	}
}

func TestSignDeniedAndUnconfiguredExits(t *testing.T) {
	home := newHome(t)
	run("key", "new", "release", "--home", home)
	token := addCaller(t, home, "ci", "--key", "release", "--artifact", "dist/**")
	addr := startDaemon(t, home)
	artifact := writeArtifact(t, t.TempDir(), "outside.bin", "x")

	// Policy denial: the daemon says no → exit 1, no envelope written.
	t.Setenv("SIGNBOOTH_TOKEN", token)
	code, _, stderr := run("sign", artifact, "--key", "release", "--addr", addr, "--home", home)
	if code != exitFail || !strings.Contains(stderr, "denied by policy") {
		t.Fatalf("policy deny: code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(artifact + ".sbsig"); !os.IsNotExist(err) {
		t.Fatal("a denied sign must not leave an envelope behind")
	}

	// No token configured at all: a setup problem → exit 3.
	t.Setenv("SIGNBOOTH_TOKEN", "")
	code, _, stderr = run("sign", artifact, "--key", "release", "--addr", addr, "--home", home)
	if code != exitRuntime || !strings.Contains(stderr, "SIGNBOOTH_TOKEN") {
		t.Fatalf("missing token: code=%d stderr=%q", code, stderr)
	}
}

func TestStatusAndWhoami(t *testing.T) {
	home := newHome(t)
	run("key", "new", "release", "--home", home)
	token := addCaller(t, home, "ci", "--key", "release", "--artifact", "dist/**", "--max-size", "64MB")
	addr := startDaemon(t, home)

	code, stdout, stderr := run("status", "--addr", addr, "--home", home)
	if code != exitOK || !strings.Contains(stdout, "ok") {
		t.Fatalf("status: code=%d out=%q err=%q", code, stdout, stderr)
	}
	t.Setenv("SIGNBOOTH_TOKEN", token)
	code, stdout, _ = run("whoami", "--addr", addr, "--home", home)
	if code != exitOK || !strings.Contains(stdout, "ci") || !strings.Contains(stdout, "64 MB") {
		t.Fatalf("whoami: code=%d out=%q", code, stdout)
	}
	// Revoking the caller kills the token without a daemon restart.
	run("caller", "rm", "ci", "--home", home)
	if code, _, _ := run("whoami", "--addr", addr, "--home", home); code != exitFail {
		t.Fatal("a revoked token must exit 1, and without a daemon restart")
	}
}

func TestAuditShowVerifyAndTamper(t *testing.T) {
	home := newHome(t)
	run("key", "new", "release", "--home", home)
	addCaller(t, home, "ci", "--key", "release", "--artifact", "*")

	code, stdout, _ := run("audit", "show", "--home", home)
	if code != exitOK || !strings.Contains(stdout, "key-new") || !strings.Contains(stdout, "caller-add") {
		t.Fatalf("audit show: %q", stdout)
	}
	_, stdout, _ = run("audit", "show", "--home", home, "-n", "1", "--json")
	lines := strings.Count(strings.TrimSpace(stdout), "\n") + 1
	if lines != 1 || !strings.Contains(stdout, "caller-add") {
		t.Fatalf("-n 1 should print exactly the newest entry, got %q", stdout)
	}
	code, stdout, _ = run("audit", "verify", "--home", home)
	if code != exitOK || !strings.Contains(stdout, "chain intact") {
		t.Fatalf("audit verify: code=%d out=%q", code, stdout)
	}

	// Rewrite one recorded action; the chain must break loudly.
	logPath := booth.AuditPath(home)
	raw, _ := os.ReadFile(logPath)
	os.WriteFile(logPath, []byte(strings.Replace(string(raw), "key-new", "key-old", 1)), 0o600)
	code, _, stderr := run("audit", "verify", "--home", home)
	if code != exitFail || !strings.Contains(stderr, "BROKEN") {
		t.Fatalf("tampered audit: code=%d stderr=%q", code, stderr)
	}
}

func TestListenTCPRules(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.168.1.10:7365", "example.test:80"} {
		if _, _, err := Listen(addr); err == nil {
			t.Fatalf("Listen(%q) must refuse non-loopback binds", addr)
		}
	}
	ln, display, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !strings.HasPrefix(display, "http://127.0.0.1:") {
		t.Fatalf("display = %q", display)
	}
}

func TestListenUnixSocketLifecycle(t *testing.T) {
	// A regular file at the socket path must never be deleted.
	path := filepath.Join(t.TempDir(), "notasocket")
	os.WriteFile(path, []byte("data"), 0o600)
	if _, _, err := Listen("unix://" + path); err == nil {
		t.Fatal("Listen must not delete a regular file at the socket path")
	}

	// A stale socket (crashed daemon) is silently replaced…
	sock := filepath.Join(t.TempDir(), "booth.sock")
	ln1, _, err := Listen("unix://" + sock)
	if err != nil {
		t.Fatal(err)
	}
	ln1.Close() // leaves a stale socket file behind
	ln2, _, err := Listen("unix://" + sock)
	if err != nil {
		t.Fatalf("stale socket must be replaced: %v", err)
	}

	// …but a live daemon is not displaced.
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	defer ln2.Close()
	if _, _, err := Listen("unix://" + sock); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("a live daemon must not be displaced, got: %v", err)
	}
}

func TestResolveAddrPrecedence(t *testing.T) {
	t.Setenv("SIGNBOOTH_ADDR", "127.0.0.1:9999")
	if got := resolveAddr("unix:///flag.sock", "/home"); got != "unix:///flag.sock" {
		t.Fatalf("flag must beat env, got %q", got)
	}
	if got := resolveAddr("", "/home"); got != "127.0.0.1:9999" {
		t.Fatalf("env must beat default, got %q", got)
	}
	t.Setenv("SIGNBOOTH_ADDR", "")
	if got := resolveAddr("", "/home"); got != "unix:///home/booth.sock" {
		t.Fatalf("default must be the home socket, got %q", got)
	}
}

func TestParseAndFormatHelpers(t *testing.T) {
	sizes := map[string]int64{
		"0": 0, "1024": 1024, "64MB": 64 << 20, "512KB": 512 << 10, "2GB": 2 << 30, "10B": 10,
	}
	for in, want := range sizes {
		got, err := parseSize(in)
		if err != nil || got != want {
			t.Fatalf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-1", "MB", "12XB", "1.5MB"} {
		if _, err := parseSize(bad); err == nil {
			t.Fatalf("parseSize(%q) should fail", bad)
		}
	}

	if d, err := parseTTL("30d"); err != nil || d.Hours() != 720 {
		t.Fatalf("30d = %v, %v", d, err)
	}
	if d, err := parseTTL("720h"); err != nil || d.Hours() != 720 {
		t.Fatalf("720h = %v, %v", d, err)
	}
	if d, err := parseTTL("0"); err != nil || d != 0 {
		t.Fatalf("0 = %v, %v", d, err)
	}
	for _, bad := range []string{"-1d", "yesterday", "-5h"} {
		if _, err := parseTTL(bad); err == nil {
			t.Fatalf("parseTTL(%q) should fail", bad)
		}
	}

	rendered := map[int64]string{
		0: "unlimited", 10: "10 B", 512 << 10: "512 KB", 64 << 20: "64 MB", 2 << 30: "2 GB", 1500: "1500 B",
	}
	for in, want := range rendered {
		if got := formatSize(in); got != want {
			t.Fatalf("formatSize(%d) = %q, want %q", in, got, want)
		}
	}
}
