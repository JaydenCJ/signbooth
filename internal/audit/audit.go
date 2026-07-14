// Package audit implements the booth's append-only, hash-chained audit
// log. Every entry embeds the hash of its predecessor, so deleting,
// editing, or reordering any line breaks the chain from that point on —
// `signbooth audit verify` walks the file and reports the first bad line.
// The log is plain JSONL: greppable, diffable, no custom tooling needed.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Genesis anchors the chain: the Prev of the first entry.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one audit record. Field order is fixed; the entry's Hash is
// computed over its canonical JSON with the Hash field empty, which covers
// Prev and therefore chains entries together.
type Entry struct {
	Seq      int64  `json:"seq"`
	Time     string `json:"time"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Key      string `json:"key,omitempty"`
	Artifact string `json:"artifact,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Prev     string `json:"prev"`
	Hash     string `json:"hash"`
}

// hashOf computes the chain hash of e: SHA-256 over the canonical JSON of
// the entry with Hash blanked out.
func hashOf(e Entry) string {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		// Entry contains only strings and integers; this cannot happen.
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Log appends entries to a JSONL file. Append is stateless: the chain
// tail (sequence number and head hash) is re-read from the file under an
// exclusive flock on every write, so the daemon and CLI commands in other
// processes can interleave appends without forking the chain.
type Log struct {
	path string
	mu   sync.Mutex // serializes appends within one process
}

// Open validates an existing log's JSON shape and sequence numbers and
// wraps it for appending; a missing file is an empty log. Hashes are not
// checked here — that is Verify's job, and keeping Open cheap means the
// daemon starts instantly even with a large log.
func Open(path string) (*Log, error) {
	l := &Log{path: path}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, err
	}
	defer f.Close()
	if _, _, err := scanTail(f, path); err != nil {
		return nil, err
	}
	return l, nil
}

// scanTail walks the log and returns the last sequence number and hash.
// It validates JSON shape and sequence continuity as it goes.
func scanTail(f *os.File, path string) (seq int64, last string, err error) {
	last = Genesis
	sc := newLineScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return 0, "", fmt.Errorf("audit: %s line %d: %w", path, line, err)
		}
		if e.Seq != seq+1 {
			return 0, "", fmt.Errorf("audit: %s line %d: sequence %d, expected %d", path, line, e.Seq, seq+1)
		}
		seq = e.Seq
		last = e.Hash
	}
	return seq, last, sc.Err()
}

// Append fills in Seq, Prev, and Hash, then writes the entry as one JSONL
// line with mode 0600. Time and the descriptive fields must already be set
// by the caller (the clock is injected upstream for determinism). The file
// is locked (flock) and its tail re-read for the duration of the write, so
// concurrent writers — the daemon plus `key new` / `caller add` in another
// process — always extend one linear chain.
func (l *Log) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return Entry{}, err
	}
	defer unlockFile(f)

	seq, last, err := scanTail(f, l.path)
	if err != nil {
		return Entry{}, err
	}
	e.Seq = seq + 1
	e.Prev = last
	e.Hash = hashOf(e)

	b, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return Entry{}, err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Read parses every entry in the log file. A missing file is an empty log.
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []Entry
	sc := newLineScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			return nil, fmt.Errorf("audit: %s line %d: %w", path, line, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Verify walks the whole chain and returns the entry count. It fails on
// the first broken link: a recomputed hash that differs (edited line), a
// Prev that does not match its predecessor (deleted or reordered line),
// or a sequence gap.
func Verify(path string) (int, error) {
	entries, err := Read(path)
	if err != nil {
		return 0, err
	}
	prev := Genesis
	for i, e := range entries {
		if e.Seq != int64(i)+1 {
			return i, fmt.Errorf("entry %d: sequence %d, expected %d (line removed or reordered)", i+1, e.Seq, i+1)
		}
		if e.Prev != prev {
			return i, fmt.Errorf("entry %d: chain broken — prev %.12s…, expected %.12s…", e.Seq, e.Prev, prev)
		}
		if got := hashOf(e); got != e.Hash {
			return i, fmt.Errorf("entry %d: content was modified after logging (hash mismatch)", e.Seq)
		}
		prev = e.Hash
	}
	return len(entries), nil
}

// newLineScanner returns a bufio.Scanner sized for long audit lines.
func newLineScanner(f *os.File) *bufio.Scanner {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return sc
}
