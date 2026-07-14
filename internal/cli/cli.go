// Package cli implements the signbooth command-line interface. Exit codes
// follow one convention everywhere: 0 success, 1 a verification / policy /
// audit failure (the answer is "no"), 2 a usage error, 3 a runtime error.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JaydenCJ/signbooth/internal/booth"
	"github.com/JaydenCJ/signbooth/internal/version"
)

const (
	exitOK      = 0
	exitFail    = 1
	exitUsage   = 2
	exitRuntime = 3
)

const usageText = `signbooth — local artifact-signing custody daemon

Usage: signbooth <command> [flags]

Booth (operator, runs on the booth host):
  init                       create the booth home directory
  key new <name>             generate a signing key inside the booth
  key ls                     list keys and fingerprints
  key export <name>          print a key's public half (PKIX PEM)
  caller add <name>          register a caller: token + policy (shown once)
  caller ls                  list callers and their policy
  caller rm <name>           remove a caller (its token dies immediately)
  serve                      run the signing daemon (unix socket / loopback TCP)
  audit [show|verify]        inspect or verify the hash-chained audit log

Caller (any process holding a token):
  sign <file>                hash a file locally, sign via the daemon
  status                     ping the daemon
  whoami                     show the caller's own policy

Anyone (fully offline):
  verify <file>              check a .sbsig envelope against a pinned key

Common flags: --home DIR ($SIGNBOOTH_HOME), --addr ADDR ($SIGNBOOTH_ADDR),
tokens via $SIGNBOOTH_TOKEN or --token-file. Exit codes: 0 ok, 1 fail,
2 usage, 3 runtime. Run 'signbooth <command> -h' for command flags.`

// env is read through a variable so tests could stub it; in production it
// is os.Getenv.
var env = os.Getenv

// Run executes argv and returns the process exit code.
func Run(argv []string, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		fmt.Fprintln(stderr, usageText)
		return exitUsage
	}
	cmd, rest := argv[0], argv[1:]
	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "signbooth %s\n", version.Version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprintln(stdout, usageText)
		return exitOK
	case "init":
		return cmdInit(rest, stdout, stderr)
	case "key":
		return dispatch(rest, stdout, stderr, map[string]func([]string, io.Writer, io.Writer) int{
			"new":    cmdKeyNew,
			"ls":     cmdKeyLs,
			"export": cmdKeyExport,
		}, "key", "new|ls|export")
	case "caller":
		return dispatch(rest, stdout, stderr, map[string]func([]string, io.Writer, io.Writer) int{
			"add": cmdCallerAdd,
			"ls":  cmdCallerLs,
			"rm":  cmdCallerRm,
		}, "caller", "add|ls|rm")
	case "serve":
		return cmdServe(rest, stdout, stderr)
	case "sign":
		return cmdSign(rest, stdout, stderr)
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "status":
		return cmdStatus(rest, stdout, stderr)
	case "whoami":
		return cmdWhoami(rest, stdout, stderr)
	case "audit":
		return cmdAudit(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "signbooth: unknown command %q (run 'signbooth help')\n", cmd)
		return exitUsage
	}
}

func dispatch(argv []string, stdout, stderr io.Writer, subs map[string]func([]string, io.Writer, io.Writer) int, group, choices string) int {
	if len(argv) == 0 {
		fmt.Fprintf(stderr, "signbooth: usage: signbooth %s <%s>\n", group, choices)
		return exitUsage
	}
	fn, ok := subs[argv[0]]
	if !ok {
		fmt.Fprintf(stderr, "signbooth: unknown subcommand %q (want %s)\n", group+" "+argv[0], choices)
		return exitUsage
	}
	return fn(argv[1:], stdout, stderr)
}

// newFlagSet builds a silent flag set; parse errors surface as exit 2.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseArgs parses argv against fs, allowing flags and positional
// arguments to interleave — `signbooth key new release --home X` should
// work, but flag.FlagSet alone stops parsing at the first positional.
func parseArgs(fs *flag.FlagSet, argv []string) ([]string, bool) {
	var pos []string
	for {
		if fs.Parse(argv) != nil {
			return nil, false
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, true
		}
		pos = append(pos, rest[0])
		argv = rest[1:]
	}
}

// resolveHome applies the --home flag, then $SIGNBOOTH_HOME, then the
// user config directory.
func resolveHome(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return booth.DefaultHome()
}

// resolveAddr applies --addr, then $SIGNBOOTH_ADDR, then the home unix socket.
func resolveAddr(flagValue, home string) string {
	if flagValue != "" {
		return flagValue
	}
	if a := env("SIGNBOOTH_ADDR"); a != "" {
		return a
	}
	return "unix://" + booth.SocketPath(home)
}

// resolveToken reads --token-file if given, else $SIGNBOOTH_TOKEN.
func resolveToken(tokenFile string) (string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if t := env("SIGNBOOTH_TOKEN"); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("no token: set SIGNBOOTH_TOKEN or pass --token-file")
}

func runtimeErr(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "signbooth: %v\n", err)
	return exitRuntime
}

func usageErr(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "signbooth: %s\n", fmt.Sprintf(format, args...))
	return exitUsage
}

// kv prints one aligned "label     value" report line.
func kv(w io.Writer, label, value string) {
	fmt.Fprintf(w, "%-9s %s\n", label, value)
}

// stringList collects a repeatable, comma-splittable flag value.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

// parseSize parses a byte size: bare bytes or a KB/MB/GB suffix
// (1024-based). "0" means unlimited.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	upper := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(upper, "GB"):
		mult, s = 1<<30, s[:len(s)-2]
	case strings.HasSuffix(upper, "MB"):
		mult, s = 1<<20, s[:len(s)-2]
	case strings.HasSuffix(upper, "KB"):
		mult, s = 1<<10, s[:len(s)-2]
	case strings.HasSuffix(upper, "B"):
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q (want e.g. 64MB, 512KB, 1048576)", s)
	}
	return n * mult, nil
}

// formatSize renders a byte count with the largest unit that divides it.
func formatSize(n int64) string {
	switch {
	case n == 0:
		return "unlimited"
	case n%(1<<30) == 0:
		return fmt.Sprintf("%d GB", n/(1<<30))
	case n%(1<<20) == 0:
		return fmt.Sprintf("%d MB", n/(1<<20))
	case n%(1<<10) == 0:
		return fmt.Sprintf("%d KB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// parseTTL parses a caller lifetime: any Go duration ("720h") plus a "d"
// day suffix ("30d"). Zero means the token never expires.
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid ttl %q (want e.g. 30d or 720h)", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid ttl %q (want e.g. 30d or 720h)", s)
	}
	return d, nil
}
