// Package server implements the daemon's loopback HTTP API. The design
// constraints, in order:
//
//  1. Private keys never leave this process. The API accepts digests and
//     returns envelopes; artifact bytes and key bytes never cross it.
//  2. Every decision is auditable. Grants, policy denials, and rejected
//     tokens all land in the hash-chained audit log with their reason.
//  3. Policy edits apply immediately. Caller records are re-read from
//     disk on every request, so add/remove needs no daemon restart.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/JaydenCJ/signbooth/internal/api"
	"github.com/JaydenCJ/signbooth/internal/audit"
	"github.com/JaydenCJ/signbooth/internal/booth"
	"github.com/JaydenCJ/signbooth/internal/envelope"
	"github.com/JaydenCJ/signbooth/internal/policy"
	"github.com/JaydenCJ/signbooth/internal/version"
)

// maxBodyBytes bounds request bodies; sign requests are a few hundred
// bytes, so 64 KiB leaves generous headroom without inviting abuse.
const maxBodyBytes = 64 * 1024

// maxArtifactName bounds the artifact label length accepted by /v1/sign.
const maxArtifactName = 512

// Server holds the daemon state: the booth, an injectable clock (tests
// pin it), and the per-caller rate windows.
type Server struct {
	booth *booth.Booth
	clock func() time.Time

	mu      sync.Mutex
	windows map[string]*rateWindow
}

type rateWindow struct {
	hour  int64
	count int
}

// New builds a Server around an opened booth. A nil clock means time.Now.
func New(b *booth.Booth, clock func() time.Time) *Server {
	if clock == nil {
		clock = time.Now
	}
	return &Server{booth: b, clock: clock, windows: map[string]*rateWindow{}}
}

// Handler returns the HTTP handler for the daemon's API surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/keys", s.authed(s.handleKeys))
	mux.HandleFunc("/v1/self", s.authed(s.handleSelf))
	mux.HandleFunc("/v1/sign", s.authed(s.handleSign))
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, api.ErrorBody{Error: fmt.Sprintf(format, args...)})
}

// log appends an audit entry, stamping the injected clock's time.
func (s *Server) log(e audit.Entry) {
	e.Time = s.clock().UTC().Format(time.RFC3339)
	// An unwritable audit log must not take signing down mid-flight; the
	// next `signbooth audit verify` will surface the gap loudly.
	_, _ = s.booth.Audit.Append(e)
}

// authenticate resolves the bearer token to a caller record. Token hashes
// are compared in constant time against every stored caller, so response
// timing does not leak which token prefixes exist.
func (s *Server) authenticate(r *http.Request) (policy.Caller, bool) {
	header := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || tok == "" {
		return policy.Caller{}, false
	}
	callers, err := s.booth.LoadCallers()
	if err != nil {
		return policy.Caller{}, false
	}
	presented := []byte(booth.HashToken(tok))
	var matched policy.Caller
	found := 0
	for name, c := range callers {
		if subtle.ConstantTimeCompare(presented, []byte(c.TokenSHA256)) == 1 {
			c.Name = name
			matched = c
			found++
		}
	}
	if found != 1 {
		return policy.Caller{}, false
	}
	return matched, true
}

// authed wraps a handler with bearer authentication; failures are audited.
func (s *Server) authed(next func(http.ResponseWriter, *http.Request, policy.Caller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := s.authenticate(r)
		if !ok {
			s.log(audit.Entry{Actor: "-", Action: "auth-reject", Reason: "unknown or malformed bearer token"})
			writeError(w, http.StatusUnauthorized, "unknown or malformed bearer token")
			return
		}
		next(w, r, caller)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed", r.Method)
		return
	}
	writeJSON(w, http.StatusOK, api.Health{
		OK:      true,
		Service: "signbooth",
		Version: version.Version,
		Time:    s.clock().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request, caller policy.Caller) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed", r.Method)
		return
	}
	all, err := s.booth.Keys.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing keys: %v", err)
		return
	}
	list := api.KeyList{Keys: []api.KeyInfo{}}
	for _, rec := range all {
		if !caller.AllowsKey(rec.Name) {
			continue // callers only see the keys their policy grants
		}
		list.Keys = append(list.Keys, api.KeyInfo{
			Name:        rec.Name,
			Fingerprint: rec.Fingerprint,
			CreatedAt:   rec.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleSelf(w http.ResponseWriter, r *http.Request, caller policy.Caller) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed", r.Method)
		return
	}
	writeJSON(w, http.StatusOK, api.CallerView{
		Name:        caller.Name,
		CreatedAt:   caller.CreatedAt,
		ExpiresAt:   caller.ExpiresAt,
		Keys:        caller.Keys,
		Artifacts:   caller.Artifacts,
		MaxSize:     caller.MaxSize,
		RatePerHour: caller.RatePerHour,
	})
}

// validateSignRequest rejects malformed requests before policy ever runs;
// these are 400s, not policy denials, and are not audited as denies.
func validateSignRequest(req api.SignRequest) error {
	if !policy.ValidName(req.Key) {
		return fmt.Errorf("key: invalid name %q", req.Key)
	}
	if req.Artifact == "" || len(req.Artifact) > maxArtifactName {
		return fmt.Errorf("artifact: must be 1-%d characters", maxArtifactName)
	}
	for _, c := range req.Artifact {
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("artifact: control characters are not allowed")
		}
	}
	if !envelope.ValidDigest(req.Digest) {
		return fmt.Errorf("digest: want %q + 64 lowercase hex characters", envelope.DigestPrefix)
	}
	if req.Size < 0 {
		return fmt.Errorf("size: must be non-negative")
	}
	return nil
}

// allowRate consumes one slot in the caller's fixed hourly window.
// limit <= 0 means unlimited.
func (s *Server) allowRate(caller string, limit int) bool {
	if limit <= 0 {
		return true
	}
	hour := s.clock().Unix() / 3600
	s.mu.Lock()
	defer s.mu.Unlock()
	win := s.windows[caller]
	if win == nil || win.hour != hour {
		win = &rateWindow{hour: hour}
		s.windows[caller] = win
	}
	if win.count >= limit {
		return false
	}
	win.count++
	return true
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request, caller policy.Caller) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed", r.Method)
		return
	}
	var req api.SignRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: %v", err)
		return
	}
	if err := validateSignRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: %v", err)
		return
	}

	now := s.clock()
	decision := policy.Evaluate(caller, policy.Request{
		Key:      req.Key,
		Artifact: req.Artifact,
		Size:     req.Size,
	}, now)
	if !decision.Allow {
		s.log(audit.Entry{
			Actor: caller.Name, Action: "deny",
			Key: req.Key, Artifact: req.Artifact, Digest: req.Digest,
			Reason: decision.Reason,
		})
		writeError(w, http.StatusForbidden, "denied by policy: %s", decision.Reason)
		return
	}
	if !s.allowRate(caller.Name, caller.RatePerHour) {
		reason := fmt.Sprintf("rate limit reached (%d/hour)", caller.RatePerHour)
		s.log(audit.Entry{
			Actor: caller.Name, Action: "deny",
			Key: req.Key, Artifact: req.Artifact, Digest: req.Digest,
			Reason: reason,
		})
		writeError(w, http.StatusTooManyRequests, "denied by policy: %s", reason)
		return
	}

	priv, _, err := s.booth.Keys.Load(req.Key)
	if err != nil {
		// Policy allowed the name (e.g. via "*") but the key is gone or
		// corrupt: a server-side condition, distinct from a policy deny.
		s.log(audit.Entry{
			Actor: caller.Name, Action: "deny",
			Key: req.Key, Artifact: req.Artifact, Digest: req.Digest,
			Reason: err.Error(),
		})
		writeError(w, http.StatusNotFound, "key unavailable: %v", err)
		return
	}
	env, err := envelope.Sign(priv, envelope.Payload{
		Artifact: req.Artifact,
		Digest:   req.Digest,
		Size:     req.Size,
		Key:      req.Key,
		Caller:   caller.Name,
		SignedAt: now.UTC().Format(time.RFC3339),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed: %v", err)
		return
	}
	s.log(audit.Entry{
		Actor: caller.Name, Action: "sign",
		Key: req.Key, Artifact: req.Artifact, Digest: req.Digest,
	})
	writeJSON(w, http.StatusOK, env)
}

// SortedCallerNames is a small helper for deterministic listings in the
// CLI; it lives here so list order is defined once for every consumer.
func SortedCallerNames(callers map[string]policy.Caller) []string {
	names := make([]string, 0, len(callers))
	for name := range callers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
