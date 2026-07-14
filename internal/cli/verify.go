package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JaydenCJ/signbooth/internal/envelope"
	"github.com/JaydenCJ/signbooth/internal/keystore"
)

// cmdVerify is fully offline: it needs the artifact, the .sbsig envelope,
// and a pinned public key — no daemon, no booth home, no network. Pinning
// is mandatory: an envelope always verifies against its own embedded key,
// so "verify" without saying *which* key would prove nothing.
func cmdVerify(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	sigPath := fs.String("sig", "", "envelope path (default: <file>.sbsig)")
	pubPath := fs.String("pub", "", "pinned public key PEM (as written by `signbooth key export`)")
	fpr := fs.String("fingerprint", "", "pinned key fingerprint (SHA256:…)")
	jsonOut := fs.Bool("json", false, "print the verified payload as JSON")
	pos, ok := parseArgs(fs, argv)
	if !ok || len(pos) != 1 {
		return usageErr(stderr, "usage: signbooth verify <file> (--pub key.pem | --fingerprint SHA256:…) [--sig file.sbsig]")
	}
	if (*pubPath == "") == (*fpr == "") {
		return usageErr(stderr, "verify: pin exactly one of --pub or --fingerprint — the embedded key alone proves nothing")
	}
	file := pos[0]
	sig := *sigPath
	if sig == "" {
		sig = file + ".sbsig"
	}

	pin := *fpr
	if *pubPath != "" {
		raw, err := os.ReadFile(*pubPath)
		if err != nil {
			return runtimeErr(stderr, err)
		}
		pub, err := keystore.ParsePublicPEM(raw)
		if err != nil {
			return runtimeErr(stderr, err)
		}
		pin = envelope.Fingerprint(pub)
	} else if !strings.HasPrefix(pin, "SHA256:") {
		return usageErr(stderr, "verify: --fingerprint must look like SHA256:… (see `signbooth key ls`)")
	}

	raw, err := os.ReadFile(sig)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		return verifyFail(stderr, err)
	}
	p, err := env.Open()
	if err != nil {
		return verifyFail(stderr, err)
	}
	if err := env.Pin(pin); err != nil {
		return verifyFail(stderr, err)
	}
	if err := p.CheckFile(file); err != nil {
		return verifyFail(stderr, err)
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(p)
		return exitOK
	}
	kv(stdout, "verified", p.Artifact)
	kv(stdout, "digest", p.Digest)
	sizeNoun := "bytes"
	if p.Size == 1 {
		sizeNoun = "byte"
	}
	kv(stdout, "size", fmt.Sprintf("%d %s", p.Size, sizeNoun))
	kv(stdout, "key", fmt.Sprintf("%s (%s)", p.Key, p.KeyFP))
	kv(stdout, "caller", p.Caller)
	kv(stdout, "signed", p.SignedAt)
	return exitOK
}

func verifyFail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "signbooth: verification FAILED: %v\n", err)
	return exitFail
}
