// Package policy defines caller records and the pure authorization
// function the daemon runs before every signature. Nothing here touches
// the filesystem, the clock, or the network: Evaluate is a function of
// (caller record, request, now), which is what makes every deny reason
// reproducible in a unit test and quotable in the audit log.
package policy

import (
	"fmt"
	"time"
)

// Caller is one client identity: a hashed bearer token plus the policy
// that constrains what the holder of that token may sign. The plaintext
// token is shown once at creation and never stored.
type Caller struct {
	Name        string   `json:"name"`
	TokenSHA256 string   `json:"tokenSHA256"`
	CreatedAt   string   `json:"createdAt"`
	ExpiresAt   string   `json:"expiresAt,omitempty"`    // RFC 3339; empty = never
	Keys        []string `json:"keys"`                   // key names; "*" = any key
	Artifacts   []string `json:"artifacts"`              // glob patterns, see Match
	MaxSize     int64    `json:"maxSizeBytes,omitempty"` // 0 = unlimited
	RatePerHour int      `json:"ratePerHour,omitempty"`  // 0 = unlimited
}

// Request is the policy-relevant slice of one sign request.
type Request struct {
	Key      string
	Artifact string
	Size     int64
}

// Decision is the result of evaluating a request against a caller's
// policy. Reason is empty when allowed and human-quotable when denied —
// it is returned to the caller verbatim and written to the audit log.
type Decision struct {
	Allow  bool
	Reason string
}

func deny(format string, args ...any) Decision {
	return Decision{Allow: false, Reason: fmt.Sprintf(format, args...)}
}

// AllowsKey reports whether the caller's key list permits key name. The
// single entry "*" grants every key; anything else is an exact match.
func (c Caller) AllowsKey(name string) bool {
	for _, k := range c.Keys {
		if k == "*" || k == name {
			return true
		}
	}
	return false
}

// AllowsArtifact reports whether any of the caller's patterns matches name.
func (c Caller) AllowsArtifact(name string) bool {
	for _, p := range c.Artifacts {
		if Match(p, name) {
			return true
		}
	}
	return false
}

// Expired reports whether the caller's token has expired as of now.
// A malformed ExpiresAt counts as expired: fail closed, never open.
func (c Caller) Expired(now time.Time) bool {
	if c.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return true
	}
	return !now.Before(t)
}

// Evaluate runs the full policy check for one request. Checks run in a
// fixed order (expiry, key, artifact, size) so a given request always
// produces the same deny reason.
func Evaluate(c Caller, req Request, now time.Time) Decision {
	if c.Expired(now) {
		return deny("caller %q expired %s", c.Name, c.ExpiresAt)
	}
	if !c.AllowsKey(req.Key) {
		return deny("key %q is not in caller %q's key list", req.Key, c.Name)
	}
	if !c.AllowsArtifact(req.Artifact) {
		return deny("artifact %q matches no allowed pattern", req.Artifact)
	}
	if c.MaxSize > 0 && req.Size > c.MaxSize {
		return deny("size %d exceeds the caller's %d-byte limit", req.Size, c.MaxSize)
	}
	return Decision{Allow: true}
}

// ValidName reports whether s is acceptable as a key or caller name:
// 1–64 characters of lowercase letters, digits, '.', '_' or '-', starting
// with a letter or digit. Names become filenames and audit fields, so the
// alphabet is intentionally strict.
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '.' || c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}
