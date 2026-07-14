// Tests for the artifact glob matcher. The grammar is small on purpose;
// these tables are its spec, including everything it must NOT match.
package policy

import "testing"

func TestMatchLiteralAndCase(t *testing.T) {
	if !Match("dist/app.tar.gz", "dist/app.tar.gz") {
		t.Fatal("identical strings must match")
	}
	if Match("dist/app.tar.gz", "dist/app.tar.GZ") {
		t.Fatal("matching is case-sensitive")
	}
	if Match("a", "") {
		t.Fatal("a literal must not match the empty name")
	}
}

func TestMatchSingleSegmentWildcards(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
		why           string
	}{
		{"dist/*.tar.gz", "dist/app.tar.gz", true, "* matches a run of characters"},
		{"dist/*.tar.gz", "dist/.tar.gz", true, "* matches the empty run too"},
		// The load-bearing security property: "dist/*" must not reach into
		// subdirectories, or a policy for top-level bundles silently widens.
		{"dist/*", "dist/nested/app.tar.gz", false, "* must not cross a path separator"},
		{"*", "dist/app", false, "bare * must not match a multi-segment name"},
		{"*", "", true, "* matches the empty single segment"},
		{"v?.tar", "v1.tar", true, "? matches exactly one character"},
		{"v?.tar", "v12.tar", false, "? must not match two characters"},
		{"v?.tar", "v.tar", false, "? must not match zero characters"},
		{"v?", "v/", false, "? must not match the path separator"},
		// Multiple stars force the matcher to backtrack; a naive greedy
		// scan gets these wrong.
		{"*a*b*", "xxaxxbxx", true, "backtracking star match"},
		{"*a*b*", "xxbxxaxx", false, "order of literals must be preserved"},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v (%s)", c.pattern, c.name, got, c.want, c.why)
		}
	}
}

func TestMatchDoubleStar(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
		why           string
	}{
		{"dist/**", "dist", true, "** matches zero segments"},
		{"dist/**", "dist/a/b/c/app.tar.gz", true, "** matches any depth"},
		{"**/release.bin", "a/b/release.bin", true, "leading ** matches nested files"},
		{"**/release.bin", "release.bin", true, "leading ** also matches the top level"},
		{"dist/**/final.tar", "dist/x/y/final.tar", true, "interior ** bridges segments"},
		{"dist/**/final.tar", "other/x/final.tar", false, "literal prefix still required"},
		// "a**b" is two adjacent stars inside one segment, not a recursive
		// glob — it must not suddenly match across slashes.
		{"dist/a**b", "dist/a/x/b", false, "embedded ** must not cross slashes"},
		{"dist/a**b", "dist/axxxb", true, "a**b collapses to a*b within the segment"},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v (%s)", c.pattern, c.name, got, c.want, c.why)
		}
	}
}

func TestMatchEdgeCases(t *testing.T) {
	if Match("", "") || Match("", "x") {
		t.Fatal("the empty pattern matches nothing — policies must be explicit")
	}
	// "dist/" has an empty final segment; "dist" does not. They differ.
	if Match("dist", "dist/") {
		t.Fatal("trailing slash creates an extra (empty) segment")
	}
	if !Match("dist/*", "dist/") {
		t.Fatal("dist/* should match the empty final segment")
	}
	// [ ] are literal characters in this grammar, by design.
	if Match("dist/[ab].tar", "dist/a.tar") {
		t.Fatal("character classes are not part of the grammar")
	}
	if !Match("dist/[ab].tar", "dist/[ab].tar") {
		t.Fatal("brackets must match themselves literally")
	}
}
