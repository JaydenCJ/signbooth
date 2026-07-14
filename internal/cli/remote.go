// Client-side commands: everything in this file talks to a running daemon
// through internal/client and never touches the keystore directly.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/JaydenCJ/signbooth/internal/api"
	"github.com/JaydenCJ/signbooth/internal/client"
	"github.com/JaydenCJ/signbooth/internal/envelope"
)

// apiExit maps a client error to an exit code: a daemon "no" (denied,
// unauthorized, rate-limited, unknown key) is exit 1; not reaching the
// daemon at all is exit 3.
func apiExit(stderr io.Writer, err error) int {
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		fmt.Fprintf(stderr, "signbooth: %v\n", err)
		return exitFail
	}
	return runtimeErr(stderr, err)
}

func cmdSign(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("sign", stderr)
	homeFlag := fs.String("home", "", "booth home directory (locates the default socket)")
	addrFlag := fs.String("addr", "", "daemon address (unix:///path or 127.0.0.1:PORT)")
	tokenFile := fs.String("token-file", "", "read the caller token from this file")
	key := fs.String("key", "", "signing key name (required)")
	name := fs.String("name", "", "artifact name recorded in the envelope (default: file basename)")
	out := fs.String("o", "", "envelope output path (default: <file>.sbsig)")
	jsonOut := fs.Bool("json", false, "print the envelope JSON to stdout as well")
	pos, ok := parseArgs(fs, argv)
	if !ok || len(pos) != 1 {
		return usageErr(stderr, "usage: signbooth sign <file> --key <name> [flags]")
	}
	if *key == "" {
		return usageErr(stderr, "sign: --key is required (which booth key should sign?)")
	}
	file := pos[0]
	artifact := *name
	if artifact == "" {
		artifact = filepath.Base(file)
	}
	sigPath := *out
	if sigPath == "" {
		sigPath = file + ".sbsig"
	}

	digest, size, err := envelope.HashFile(file)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	token, err := resolveToken(*tokenFile)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	c, err := client.New(resolveAddr(*addrFlag, home), token)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	env, err := c.Sign(api.SignRequest{Key: *key, Artifact: artifact, Digest: digest, Size: size})
	if err != nil {
		return apiExit(stderr, err)
	}
	// Trust nothing blindly, not even our own daemon: re-open the envelope
	// and confirm it covers exactly what we asked to have signed.
	p, err := env.Open()
	if err != nil {
		return runtimeErr(stderr, fmt.Errorf("daemon returned an invalid envelope: %w", err))
	}
	if p.Digest != digest || p.Artifact != artifact || p.Key != *key {
		return runtimeErr(stderr, fmt.Errorf("daemon envelope does not match the request (signed %q %s)", p.Artifact, p.Digest))
	}
	if err := os.WriteFile(sigPath, envelope.Marshal(env), 0o644); err != nil {
		return runtimeErr(stderr, err)
	}
	if *jsonOut {
		_, _ = stdout.Write(envelope.Marshal(env))
		return exitOK
	}
	kv(stdout, "signed", artifact)
	kv(stdout, "digest", digest)
	kv(stdout, "key", fmt.Sprintf("%s (%s)", p.Key, p.KeyFP))
	kv(stdout, "caller", p.Caller)
	kv(stdout, "envelope", sigPath)
	return exitOK
}

func cmdStatus(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("status", stderr)
	homeFlag := fs.String("home", "", "booth home directory (locates the default socket)")
	addrFlag := fs.String("addr", "", "daemon address")
	if pos, ok := parseArgs(fs, argv); !ok || len(pos) != 0 {
		return usageErr(stderr, "usage: signbooth status [--addr ADDR]")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	c, err := client.New(resolveAddr(*addrFlag, home), "")
	if err != nil {
		return runtimeErr(stderr, err)
	}
	h, err := c.Health()
	if err != nil {
		return apiExit(stderr, err)
	}
	if !h.OK || h.Service != "signbooth" {
		fmt.Fprintf(stderr, "signbooth: unexpected health response from %q\n", h.Service)
		return exitFail
	}
	kv(stdout, "daemon", "ok")
	kv(stdout, "version", h.Version)
	kv(stdout, "time", h.Time)
	return exitOK
}

func cmdWhoami(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("whoami", stderr)
	homeFlag := fs.String("home", "", "booth home directory (locates the default socket)")
	addrFlag := fs.String("addr", "", "daemon address")
	tokenFile := fs.String("token-file", "", "read the caller token from this file")
	jsonOut := fs.Bool("json", false, "print the caller view as JSON")
	if pos, ok := parseArgs(fs, argv); !ok || len(pos) != 0 {
		return usageErr(stderr, "usage: signbooth whoami [--addr ADDR]")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	token, err := resolveToken(*tokenFile)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	c, err := client.New(resolveAddr(*addrFlag, home), token)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	v, err := c.Self()
	if err != nil {
		return apiExit(stderr, err)
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return exitOK
	}
	printCallerView(stdout, v)
	return exitOK
}
