// Tests for the hash-chained audit log. The threat model: someone with
// write access to the log file edits, deletes, or reorders lines to hide
// a signature. Each of those must be caught by Verify.
package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func logPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit.log")
}

func appendN(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := l.Append(Entry{
			Time: "2026-07-01T12:00:00Z", Actor: "ci", Action: "sign",
			Key: "release", Artifact: "dist/app.tar.gz",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppendAssignsSequenceAndChains(t *testing.T) {
	l, err := Open(logPath(t))
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := l.Append(Entry{Time: "t", Actor: "-", Action: "init"})
	e2, _ := l.Append(Entry{Time: "t", Actor: "a", Action: "sign"})
	if e1.Seq != 1 || e2.Seq != 2 {
		t.Fatalf("sequence = %d, %d; want 1, 2", e1.Seq, e2.Seq)
	}
	if e1.Prev != Genesis {
		t.Fatalf("first entry Prev = %q, want genesis", e1.Prev)
	}
	if e2.Prev != e1.Hash {
		t.Fatalf("entry 2 Prev = %q, want entry 1 hash %q", e2.Prev, e1.Hash)
	}
}

func TestVerifyPassesOnIntactAndEmptyLogs(t *testing.T) {
	path := logPath(t)
	if n, err := Verify(path); err != nil || n != 0 {
		t.Fatalf("missing log should verify as empty, got n=%d err=%v", n, err)
	}
	l, _ := Open(path)
	appendN(t, l, 5)
	n, err := Verify(path)
	if err != nil {
		t.Fatalf("intact log failed verification: %v", err)
	}
	if n != 5 {
		t.Fatalf("verified %d entries, want 5", n)
	}
}

func TestVerifyDetectsEditedLine(t *testing.T) {
	path := logPath(t)
	l, _ := Open(path)
	appendN(t, l, 3)
	raw, _ := os.ReadFile(path)
	// Rewrite history: change which artifact entry 2 says was signed.
	doctored := strings.Replace(string(raw), "dist/app.tar.gz", "dist/innocent.txt", 1)
	os.WriteFile(path, []byte(doctored), 0o600)
	if _, err := Verify(path); err == nil {
		t.Fatal("an edited line must break verification")
	}
}

func TestVerifyDetectsDeletedLine(t *testing.T) {
	path := logPath(t)
	l, _ := Open(path)
	appendN(t, l, 3)
	raw, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(raw), "\n")
	// Drop the middle entry — the classic "make the bad signature vanish".
	os.WriteFile(path, []byte(lines[0]+lines[2]), 0o600)
	if _, err := Verify(path); err == nil {
		t.Fatal("a deleted line must break verification")
	}
}

func TestVerifyDetectsReorderedLines(t *testing.T) {
	path := logPath(t)
	l, _ := Open(path)
	appendN(t, l, 2)
	raw, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(raw), "\n")
	os.WriteFile(path, []byte(lines[1]+lines[0]), 0o600)
	if _, err := Verify(path); err == nil {
		t.Fatal("reordered lines must break verification")
	}
}

func TestInterleavedWritersShareOneChain(t *testing.T) {
	// The daemon and CLI commands hold separate Log instances on the same
	// file (different processes in production). Alternating appends must
	// still produce one linear chain — this is why Append re-reads the
	// tail under a file lock instead of trusting in-memory state.
	path := logPath(t)
	l1, _ := Open(path)
	appendN(t, l1, 2)
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := l2.Append(Entry{Time: "t", Actor: "a", Action: "sign"})
	if e.Seq != 3 {
		t.Fatalf("second writer continued at seq %d, want 3", e.Seq)
	}
	appendN(t, l1, 1) // first writer again, after the file moved under it
	appendN(t, l2, 1)
	n, err := Verify(path)
	if err != nil || n != 5 {
		t.Fatalf("interleaved writers broke the chain: n=%d err=%v", n, err)
	}
}

func TestOpenRejectsCorruptFiles(t *testing.T) {
	// Garbage line.
	path := logPath(t)
	os.WriteFile(path, []byte("this is not json\n"), 0o600)
	if _, err := Open(path); err == nil {
		t.Fatal("non-JSON lines must fail Open")
	}
	// Sequence gap: entry 2 missing from an otherwise valid file.
	path2 := logPath(t)
	l, _ := Open(path2)
	appendN(t, l, 3)
	raw, _ := os.ReadFile(path2)
	lines := strings.SplitAfter(string(raw), "\n")
	os.WriteFile(path2, []byte(lines[0]+lines[2]), 0o600)
	if _, err := Open(path2); err == nil {
		t.Fatal("a sequence gap must fail Open, not silently continue")
	}
}

func TestLogToleratesBlankAndLongLines(t *testing.T) {
	// Deny reasons quote caller input; a very long artifact name must
	// survive the scanner's buffer, and stray blank lines are ignored.
	path := logPath(t)
	l, _ := Open(path)
	long := strings.Repeat("x", 100_000)
	if _, err := l.Append(Entry{Time: "t", Actor: "a", Action: "deny", Reason: long}); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("\n\n")
	f.Close()
	if _, err := Open(path); err != nil {
		t.Fatalf("reopen with a 100 KB line failed: %v", err)
	}
	entries, err := Read(path)
	if err != nil || len(entries) != 1 {
		t.Fatalf("blank lines should be ignored: n=%d err=%v", len(entries), err)
	}
	if n, err := Verify(path); err != nil || n != 1 {
		t.Fatalf("long-line log failed verify: n=%d err=%v", n, err)
	}
}

func TestHashCoversEveryField(t *testing.T) {
	base := Entry{Seq: 1, Time: "t", Actor: "a", Action: "sign",
		Key: "k", Artifact: "art", Digest: "d", Reason: "r", Prev: Genesis}
	baseHash := hashOf(base)
	mutations := []func(*Entry){
		func(e *Entry) { e.Seq = 2 },
		func(e *Entry) { e.Time = "u" },
		func(e *Entry) { e.Actor = "b" },
		func(e *Entry) { e.Action = "deny" },
		func(e *Entry) { e.Key = "k2" },
		func(e *Entry) { e.Artifact = "art2" },
		func(e *Entry) { e.Digest = "d2" },
		func(e *Entry) { e.Reason = "r2" },
		func(e *Entry) { e.Prev = "p" },
	}
	for i, mutate := range mutations {
		e := base
		mutate(&e)
		if hashOf(e) == baseHash {
			t.Fatalf("mutation %d did not change the entry hash — field not covered", i)
		}
	}
}
