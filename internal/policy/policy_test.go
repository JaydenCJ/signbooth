// Tests for the pure policy evaluator. Every deny path a caller can hit
// in production is pinned here with its exact ordering, because the deny
// reason is part of the API surface: it lands in the audit log verbatim.
package policy

import (
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

func testCaller() Caller {
	return Caller{
		Name:      "ci",
		CreatedAt: "2026-06-01T00:00:00Z",
		Keys:      []string{"release"},
		Artifacts: []string{"dist/**"},
	}
}

func TestEvaluateAllowsMatchingRequest(t *testing.T) {
	d := Evaluate(testCaller(), Request{Key: "release", Artifact: "dist/app.tar.gz", Size: 100}, testNow)
	if !d.Allow {
		t.Fatalf("expected allow, got deny: %s", d.Reason)
	}
	if d.Reason != "" {
		t.Fatalf("allow decisions must carry no reason, got %q", d.Reason)
	}
}

func TestEvaluateDenyReasonsQuoteTheOffendingInput(t *testing.T) {
	c := testCaller()
	c.MaxSize = 1024
	cases := []struct {
		req    Request
		reason string
	}{
		{Request{Key: "debug", Artifact: "dist/a"}, `key "debug"`},
		{Request{Key: "release", Artifact: "src/secret.go"}, "src/secret.go"},
		{Request{Key: "release", Artifact: "dist/big.bin", Size: 1025}, "1024"},
	}
	for _, tc := range cases {
		d := Evaluate(c, tc.req, testNow)
		if d.Allow {
			t.Fatalf("Evaluate(%+v) allowed, want deny", tc.req)
		}
		if !strings.Contains(d.Reason, tc.reason) {
			t.Fatalf("deny reason %q should contain %q", d.Reason, tc.reason)
		}
	}
}

func TestEvaluateSizeLimitBoundaries(t *testing.T) {
	// The limit is inclusive: "may sign up to 1 KiB" must include 1 KiB.
	c := testCaller()
	c.MaxSize = 1024
	if d := Evaluate(c, Request{Key: "release", Artifact: "dist/a", Size: 1024}, testNow); !d.Allow {
		t.Fatalf("size == limit must be allowed, got %q", d.Reason)
	}
	// And MaxSize 0 means no limit at all.
	if d := Evaluate(testCaller(), Request{Key: "release", Artifact: "dist/huge", Size: 1 << 40}, testNow); !d.Allow {
		t.Fatalf("MaxSize 0 must mean unlimited, got %q", d.Reason)
	}
}

func TestEvaluateDeniesExpiredCallerFirst(t *testing.T) {
	c := testCaller()
	c.ExpiresAt = "2026-06-30T00:00:00Z"
	d := Evaluate(c, Request{Key: "release", Artifact: "dist/a"}, testNow)
	if d.Allow || !strings.Contains(d.Reason, "expired") {
		t.Fatalf("want an expiry deny, got allow=%v reason=%q", d.Allow, d.Reason)
	}
	// Fixed check order means a caller who is both expired AND asking for
	// a forbidden key always gets the expiry reason — deterministic audit.
	d = Evaluate(c, Request{Key: "debug", Artifact: "nope"}, testNow)
	if !strings.Contains(d.Reason, "expired") {
		t.Fatalf("expiry must be checked first, got %q", d.Reason)
	}
}

func TestExpiredSemantics(t *testing.T) {
	c := testCaller()
	c.ExpiresAt = testNow.Format(time.RFC3339)
	if !c.Expired(testNow) {
		t.Fatal("a token is expired at its exact ExpiresAt instant")
	}
	c.ExpiresAt = ""
	if c.Expired(testNow.Add(100 * 365 * 24 * time.Hour)) {
		t.Fatal("empty ExpiresAt must never expire")
	}
	// A corrupted callers.json must never grant eternal access.
	c.ExpiresAt = "not-a-timestamp"
	if !c.Expired(testNow) {
		t.Fatal("malformed ExpiresAt must count as expired (fail closed)")
	}
}

func TestAllowsKeySemantics(t *testing.T) {
	wild := Caller{Keys: []string{"*"}}
	for _, k := range []string{"release", "debug", "anything"} {
		if !wild.AllowsKey(k) {
			t.Fatalf("wildcard key list must allow %q", k)
		}
	}
	exact := Caller{Keys: []string{"release"}}
	if exact.AllowsKey("release-2") || exact.AllowsKey("rel") {
		t.Fatal("key matching must be exact, not prefix or substring")
	}
	if (Caller{}).AllowsKey("release") {
		t.Fatal("a caller with no keys may sign with none")
	}
}

func TestAllowsArtifactAnyPatternSuffices(t *testing.T) {
	c := Caller{Artifacts: []string{"dist/**", "sbom.json"}}
	if !c.AllowsArtifact("sbom.json") {
		t.Fatal("second pattern should match")
	}
	if c.AllowsArtifact("etc/passwd") {
		t.Fatal("no pattern matches; must deny")
	}
}

func TestValidNameAcceptsTypicalNames(t *testing.T) {
	for _, s := range []string{"release", "ci-runner", "team.build_7", "a", "0key", strings.Repeat("x", 64)} {
		if !ValidName(s) {
			t.Fatalf("ValidName(%q) = false, want true", s)
		}
	}
}

func TestValidNameRejectsDangerousNames(t *testing.T) {
	// Names become file paths (<name>.key) and audit fields, so anything
	// enabling traversal, hidden files, or log injection is rejected.
	bad := []string{"", "UPPER", "has space", "../etc", ".hidden", "-flag", "a/b", "名前",
		strings.Repeat("x", 65)}
	for _, s := range bad {
		if ValidName(s) {
			t.Fatalf("ValidName(%q) = true, want false", s)
		}
	}
}
