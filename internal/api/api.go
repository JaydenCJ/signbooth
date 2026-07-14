// Package api defines the wire types shared by the daemon (internal/server)
// and the CLI client (internal/client). The full protocol is documented in
// docs/protocol.md; this package is types only, no behavior.
package api

// SignRequest is the body of POST /v1/sign. The caller hashes the artifact
// locally and sends only its digest — artifact bytes never cross the API.
type SignRequest struct {
	Key      string `json:"key"`
	Artifact string `json:"artifact"`
	Digest   string `json:"digest"` // "sha256:<64 lowercase hex>"
	Size     int64  `json:"size"`
}

// Health is the body of GET /v1/health (the only unauthenticated route).
type Health struct {
	OK      bool   `json:"ok"`
	Service string `json:"service"`
	Version string `json:"version"`
	Time    string `json:"time"`
}

// KeyInfo describes one signing key in GET /v1/keys.
type KeyInfo struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"createdAt"`
}

// KeyList is the body of GET /v1/keys, filtered to the caller's policy.
type KeyList struct {
	Keys []KeyInfo `json:"keys"`
}

// CallerView is the body of GET /v1/self: the authenticated caller's own
// policy, minus anything secret.
type CallerView struct {
	Name        string   `json:"name"`
	CreatedAt   string   `json:"createdAt"`
	ExpiresAt   string   `json:"expiresAt,omitempty"`
	Keys        []string `json:"keys"`
	Artifacts   []string `json:"artifacts"`
	MaxSize     int64    `json:"maxSizeBytes,omitempty"`
	RatePerHour int      `json:"ratePerHour,omitempty"`
}

// ErrorBody is the JSON shape of every non-2xx response.
type ErrorBody struct {
	Error string `json:"error"`
}
