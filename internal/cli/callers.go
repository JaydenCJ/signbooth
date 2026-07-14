package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/JaydenCJ/signbooth/internal/api"
	"github.com/JaydenCJ/signbooth/internal/audit"
	"github.com/JaydenCJ/signbooth/internal/booth"
	"github.com/JaydenCJ/signbooth/internal/policy"
	"github.com/JaydenCJ/signbooth/internal/server"
)

func callerView(c policy.Caller) api.CallerView {
	return api.CallerView{
		Name:        c.Name,
		CreatedAt:   c.CreatedAt,
		ExpiresAt:   c.ExpiresAt,
		Keys:        c.Keys,
		Artifacts:   c.Artifacts,
		MaxSize:     c.MaxSize,
		RatePerHour: c.RatePerHour,
	}
}

func printCallerView(w io.Writer, v api.CallerView) {
	kv(w, "caller", v.Name)
	kv(w, "keys", strings.Join(v.Keys, ", "))
	kv(w, "artifacts", strings.Join(v.Artifacts, ", "))
	kv(w, "max size", formatSize(v.MaxSize))
	if v.RatePerHour > 0 {
		kv(w, "rate", fmt.Sprintf("%d/hour", v.RatePerHour))
	} else {
		kv(w, "rate", "unlimited")
	}
	if v.ExpiresAt != "" {
		kv(w, "expires", v.ExpiresAt)
	} else {
		kv(w, "expires", "never")
	}
}

func cmdCallerAdd(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("caller add", stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	jsonOut := fs.Bool("json", false, "print the caller record and token as JSON")
	var keys, artifacts stringList
	fs.Var(&keys, "key", "key name this caller may use (repeatable; \"*\" = any key)")
	fs.Var(&artifacts, "artifact", "artifact glob this caller may sign (repeatable)")
	maxSize := fs.String("max-size", "0", "largest artifact this caller may sign (e.g. 64MB; 0 = unlimited)")
	rate := fs.Int("rate", 0, "signatures per hour (0 = unlimited)")
	ttl := fs.String("ttl", "0", "token lifetime (e.g. 30d, 720h; 0 = never expires)")
	pos, ok := parseArgs(fs, argv)
	if !ok || len(pos) != 1 {
		return usageErr(stderr, "usage: signbooth caller add <name> --key <key> --artifact '<glob>' [flags]")
	}
	if len(keys) == 0 || len(artifacts) == 0 {
		return usageErr(stderr, "caller add: --key and --artifact are required — a caller with no policy can sign nothing")
	}
	sizeLimit, err := parseSize(*maxSize)
	if err != nil {
		return usageErr(stderr, "caller add: %v", err)
	}
	life, err := parseTTL(*ttl)
	if err != nil {
		return usageErr(stderr, "caller add: %v", err)
	}
	if *rate < 0 {
		return usageErr(stderr, "caller add: --rate must be non-negative")
	}

	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	b, err := booth.Open(home)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	now := time.Now()
	c := policy.Caller{
		Name:        pos[0],
		CreatedAt:   now.UTC().Format(time.RFC3339),
		Keys:        keys,
		Artifacts:   artifacts,
		MaxSize:     sizeLimit,
		RatePerHour: *rate,
	}
	if life > 0 {
		c.ExpiresAt = now.Add(life).UTC().Format(time.RFC3339)
	}
	token, err := b.AddCaller(c)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if _, err := b.Audit.Append(audit.Entry{
		Time: now.UTC().Format(time.RFC3339), Actor: "-",
		Action: "caller-add", Reason: fmt.Sprintf("caller %q registered", c.Name),
	}); err != nil {
		return runtimeErr(stderr, err)
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Caller api.CallerView `json:"caller"`
			Token  string         `json:"token"`
		}{callerView(c), token})
		return exitOK
	}
	printCallerView(stdout, callerView(c))
	kv(stdout, "token", token)
	fmt.Fprintln(stdout, "          (shown once — store it in your CI secret store, never on disk)")
	return exitOK
}

func cmdCallerLs(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("caller ls", stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	jsonOut := fs.Bool("json", false, "print caller records as JSON")
	if pos, ok := parseArgs(fs, argv); !ok || len(pos) != 0 {
		return usageErr(stderr, "usage: signbooth caller ls [--json]")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	b, err := booth.Open(home)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	callers, err := b.LoadCallers()
	if err != nil {
		return runtimeErr(stderr, err)
	}
	names := server.SortedCallerNames(callers)
	if *jsonOut {
		views := []api.CallerView{}
		for _, name := range names {
			c := callers[name]
			c.Name = name
			views = append(views, callerView(c))
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(views)
		return exitOK
	}
	if len(names) == 0 {
		fmt.Fprintln(stdout, "no callers — register one with `signbooth caller add <name> --key <key> --artifact '<glob>'`")
		return exitOK
	}
	fmt.Fprintf(stdout, "%-14s  %-18s  %-24s  %-9s  %s\n", "NAME", "KEYS", "ARTIFACTS", "RATE", "EXPIRES")
	for _, name := range names {
		c := callers[name]
		rate := "unlimited"
		if c.RatePerHour > 0 {
			rate = fmt.Sprintf("%d/hour", c.RatePerHour)
		}
		expires := "never"
		if c.ExpiresAt != "" {
			expires = c.ExpiresAt
		}
		fmt.Fprintf(stdout, "%-14s  %-18s  %-24s  %-9s  %s\n",
			name, strings.Join(c.Keys, ","), strings.Join(c.Artifacts, ","), rate, expires)
	}
	return exitOK
}

func cmdCallerRm(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("caller rm", stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	pos, ok := parseArgs(fs, argv)
	if !ok || len(pos) != 1 {
		return usageErr(stderr, "usage: signbooth caller rm <name>")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	b, err := booth.Open(home)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	name := pos[0]
	if err := b.RemoveCaller(name); err != nil {
		return runtimeErr(stderr, err)
	}
	if _, err := b.Audit.Append(audit.Entry{
		Time: time.Now().UTC().Format(time.RFC3339), Actor: "-",
		Action: "caller-rm", Reason: fmt.Sprintf("caller %q removed", name),
	}); err != nil {
		return runtimeErr(stderr, err)
	}
	fmt.Fprintf(stdout, "removed caller %s — its token is dead as of the daemon's next request\n", name)
	return exitOK
}
