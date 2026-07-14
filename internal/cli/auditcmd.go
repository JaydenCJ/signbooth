package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/signbooth/internal/audit"
	"github.com/JaydenCJ/signbooth/internal/booth"
)

func cmdAudit(argv []string, stdout, stderr io.Writer) int {
	sub := "show"
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		switch argv[0] {
		case "show", "verify":
			sub, argv = argv[0], argv[1:]
		default:
			return usageErr(stderr, "usage: signbooth audit [show|verify]")
		}
	}

	fs := newFlagSet("audit "+sub, stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	last := fs.Int("n", 0, "show only the last N entries (show)")
	jsonOut := fs.Bool("json", false, "print entries as JSONL (show)")
	if pos, ok := parseArgs(fs, argv); !ok || len(pos) != 0 {
		return usageErr(stderr, "usage: signbooth audit [show|verify] [flags]")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	path := booth.AuditPath(home)

	if sub == "verify" {
		n, err := audit.Verify(path)
		if err != nil {
			fmt.Fprintf(stderr, "signbooth: audit chain BROKEN: %v\n", err)
			return exitFail
		}
		noun := "entries"
		if n == 1 {
			noun = "entry"
		}
		fmt.Fprintf(stdout, "audit log ok: %d %s, chain intact\n", n, noun)
		return exitOK
	}

	entries, err := audit.Read(path)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if *last > 0 && len(entries) > *last {
		entries = entries[len(entries)-*last:]
	}
	if *jsonOut {
		for _, e := range entries {
			b, _ := json.Marshal(e)
			fmt.Fprintln(stdout, string(b))
		}
		return exitOK
	}
	if len(entries) == 0 {
		fmt.Fprintln(stdout, "audit log is empty")
		return exitOK
	}
	fmt.Fprintf(stdout, "%-5s %-20s  %-10s %-12s %-12s %-20s %s\n",
		"SEQ", "TIME", "ACTOR", "ACTION", "KEY", "ARTIFACT", "REASON")
	for _, e := range entries {
		fmt.Fprintf(stdout, "%-5d %-20s  %-10s %-12s %-12s %-20s %s\n",
			e.Seq, e.Time, e.Actor, e.Action, dash(e.Key), dash(e.Artifact), dash(e.Reason))
	}
	return exitOK
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
