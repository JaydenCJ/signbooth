package policy

import "strings"

// Match reports whether an artifact name matches a glob pattern.
//
// Names and patterns are slash-separated. Within one segment, `*` matches
// any run of characters (including none) and `?` matches exactly one
// character; neither crosses a `/`. A pattern segment that is exactly `**`
// matches zero or more whole segments. There are no character classes —
// the grammar is deliberately small enough to reason about in a security
// policy. Matching is case-sensitive and never touches the filesystem.
func Match(pattern, name string) bool {
	if pattern == "" {
		return false
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegments(pat, name []string) bool {
	if len(pat) == 0 {
		return len(name) == 0
	}
	if pat[0] == "**" {
		// `**` swallows zero segments…
		if matchSegments(pat[1:], name) {
			return true
		}
		// …or one segment, then tries again.
		if len(name) == 0 {
			return false
		}
		return matchSegments(pat, name[1:])
	}
	if len(name) == 0 {
		return false
	}
	if !matchSegment(pat[0], name[0]) {
		return false
	}
	return matchSegments(pat[1:], name[1:])
}

// matchSegment implements `*` / `?` globbing within a single path segment
// using classic backtracking. Segment lengths are bounded by request
// validation, so the worst case stays trivial.
func matchSegment(pat, s string) bool {
	for len(pat) > 0 {
		switch pat[0] {
		case '*':
			for len(pat) > 0 && pat[0] == '*' {
				pat = pat[1:]
			}
			if pat == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchSegment(pat, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
			pat, s = pat[1:], s[1:]
		default:
			if s == "" || s[0] != pat[0] {
				return false
			}
			pat, s = pat[1:], s[1:]
		}
	}
	return s == ""
}
