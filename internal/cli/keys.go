package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/JaydenCJ/signbooth/internal/audit"
	"github.com/JaydenCJ/signbooth/internal/booth"
	"github.com/JaydenCJ/signbooth/internal/keystore"
)

func cmdInit(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("init", stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	pos, ok := parseArgs(fs, argv)
	if !ok || len(pos) != 0 {
		return usageErr(stderr, "usage: signbooth init [--home DIR]")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if _, err := booth.Init(home, time.Now()); err != nil {
		return runtimeErr(stderr, err)
	}
	fmt.Fprintf(stdout, "initialized signbooth home at %s\n", home)
	fmt.Fprintln(stdout, "next: signbooth key new <name> → signbooth caller add <name> → signbooth serve")
	return exitOK
}

func cmdKeyNew(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("key new", stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	jsonOut := fs.Bool("json", false, "print the key record as JSON")
	pos, ok := parseArgs(fs, argv)
	if !ok || len(pos) != 1 {
		return usageErr(stderr, "usage: signbooth key new <name>")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	b, err := booth.Open(home)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	rec, err := b.Keys.Create(pos[0], time.Now())
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if _, err := b.Audit.Append(audit.Entry{
		Time: time.Now().UTC().Format(time.RFC3339), Actor: "-",
		Action: "key-new", Key: rec.Name, Reason: rec.Fingerprint,
	}); err != nil {
		return runtimeErr(stderr, err)
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rec)
		return exitOK
	}
	kv(stdout, "key", rec.Name)
	kv(stdout, "fpr", rec.Fingerprint)
	kv(stdout, "created", rec.CreatedAt)
	kv(stdout, "public", filepath.Join(b.Keys.Dir(), rec.Name+".pub"))
	return exitOK
}

func cmdKeyLs(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("key ls", stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	jsonOut := fs.Bool("json", false, "print key records as JSON")
	if pos, ok := parseArgs(fs, argv); !ok || len(pos) != 0 {
		return usageErr(stderr, "usage: signbooth key ls [--json]")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	b, err := booth.Open(home)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	recs, err := b.Keys.List()
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if *jsonOut {
		if recs == nil {
			recs = []keystore.Record{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(recs)
		return exitOK
	}
	if len(recs) == 0 {
		fmt.Fprintln(stdout, "no keys — create one with `signbooth key new <name>`")
		return exitOK
	}
	fmt.Fprintf(stdout, "%-16s  %-50s  %s\n", "NAME", "FINGERPRINT", "CREATED")
	for _, rec := range recs {
		fmt.Fprintf(stdout, "%-16s  %-50s  %s\n", rec.Name, rec.Fingerprint, rec.CreatedAt)
	}
	return exitOK
}

func cmdKeyExport(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("key export", stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	out := fs.String("o", "", "write the public key PEM to this file instead of stdout")
	pos, ok := parseArgs(fs, argv)
	if !ok || len(pos) != 1 {
		return usageErr(stderr, "usage: signbooth key export <name> [-o file]")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	b, err := booth.Open(home)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	pemBytes, err := b.Keys.ExportPublicPEM(pos[0])
	if err != nil {
		return runtimeErr(stderr, err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, pemBytes, 0o644); err != nil {
			return runtimeErr(stderr, err)
		}
		fmt.Fprintf(stdout, "wrote %s\n", *out)
		return exitOK
	}
	_, _ = stdout.Write(pemBytes)
	return exitOK
}
