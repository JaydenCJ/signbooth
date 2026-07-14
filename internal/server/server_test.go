// End-to-end tests for the daemon's HTTP surface, run in-process against
// the handler with an injected clock. These are the contract tests for
// everything a caller can observe: status codes, envelope validity, audit
// entries, and the immediacy of policy edits.
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/signbooth/internal/api"
	"github.com/JaydenCJ/signbooth/internal/audit"
	"github.com/JaydenCJ/signbooth/internal/booth"
	"github.com/JaydenCJ/signbooth/internal/envelope"
	"github.com/JaydenCJ/signbooth/internal/policy"
)

var t0 = time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

// fixture is a booth with one key ("release"), one caller, and a server
// whose clock the test controls.
type fixture struct {
	b     *booth.Booth
	srv   *Server
	token string
	now   time.Time
}

func newFixture(t *testing.T, c policy.Caller) *fixture {
	t.Helper()
	b, err := booth.Init(filepath.Join(t.TempDir(), "home"), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Keys.Create("release", t0); err != nil {
		t.Fatal(err)
	}
	token, err := b.AddCaller(c)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{b: b, token: token, now: t0}
	f.srv = New(b, func() time.Time { return f.now })
	return f
}

func ciCaller() policy.Caller {
	return policy.Caller{Name: "ci", Keys: []string{"release"}, Artifacts: []string{"dist/**"}}
}

// call performs one request against the in-process handler.
func (f *fixture) call(t *testing.T, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, req)
	return w
}

func signReq() api.SignRequest {
	return api.SignRequest{
		Key:      "release",
		Artifact: "dist/app.tar.gz",
		Digest:   "sha256:" + strings.Repeat("ab", 32),
		Size:     1234,
	}
}

func lastAudit(t *testing.T, f *fixture) audit.Entry {
	t.Helper()
	entries, err := audit.Read(booth.AuditPath(f.b.Home))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no audit entries: %v", err)
	}
	return entries[len(entries)-1]
}

func TestHealthNeedsNoToken(t *testing.T) {
	f := newFixture(t, ciCaller())
	w := f.call(t, http.MethodGet, "/v1/health", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200", w.Code)
	}
	var h api.Health
	json.Unmarshal(w.Body.Bytes(), &h)
	if !h.OK || h.Service != "signbooth" || h.Version != "0.1.0" {
		t.Fatalf("unexpected health body: %+v", h)
	}
	if h.Time != "2026-07-01T12:00:00Z" {
		t.Fatalf("health must report the injected clock, got %q", h.Time)
	}
}

func TestSignHappyPathReturnsVerifiableEnvelope(t *testing.T) {
	f := newFixture(t, ciCaller())
	w := f.call(t, http.MethodPost, "/v1/sign", f.token, signReq())
	if w.Code != http.StatusOK {
		t.Fatalf("sign = %d, body %s", w.Code, w.Body)
	}
	env, err := envelope.Parse(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	p, err := env.Open()
	if err != nil {
		t.Fatalf("returned envelope does not verify: %v", err)
	}
	if p.Caller != "ci" || p.Key != "release" || p.SignedAt != "2026-07-01T12:00:00Z" {
		t.Fatalf("payload wrong: %+v", p)
	}
	// The envelope must pin to the booth's actual key.
	rec, _ := f.b.Keys.Get("release")
	if err := env.Pin(rec.Fingerprint); err != nil {
		t.Fatalf("envelope not signed by the booth key: %v", err)
	}
}

func TestSignIsAudited(t *testing.T) {
	f := newFixture(t, ciCaller())
	f.call(t, http.MethodPost, "/v1/sign", f.token, signReq())
	e := lastAudit(t, f)
	if e.Action != "sign" || e.Actor != "ci" || e.Artifact != "dist/app.tar.gz" {
		t.Fatalf("sign audit entry wrong: %+v", e)
	}
	if _, err := audit.Verify(booth.AuditPath(f.b.Home)); err != nil {
		t.Fatalf("audit chain broken after a grant: %v", err)
	}
}

func TestSignRejectsBadTokens(t *testing.T) {
	f := newFixture(t, ciCaller())
	if w := f.call(t, http.MethodPost, "/v1/sign", "", signReq()); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", w.Code)
	}
	if e := lastAudit(t, f); e.Action != "auth-reject" {
		t.Fatalf("auth failures must be audited, got %+v", e)
	}
	wrong := "sbt_" + strings.Repeat("0", 48)
	if w := f.call(t, http.MethodPost, "/v1/sign", wrong, signReq()); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token = %d, want 401", w.Code)
	}
}

func TestSignDeniesKeyOutsidePolicy(t *testing.T) {
	f := newFixture(t, ciCaller())
	if _, err := f.b.Keys.Create("debug", t0); err != nil {
		t.Fatal(err)
	}
	req := signReq()
	req.Key = "debug"
	w := f.call(t, http.MethodPost, "/v1/sign", f.token, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign key = %d, want 403", w.Code)
	}
	e := lastAudit(t, f)
	if e.Action != "deny" || !strings.Contains(e.Reason, `"debug"`) {
		t.Fatalf("deny must be audited with its reason, got %+v", e)
	}
}

func TestSignDeniesArtifactAndSizeOutsidePolicy(t *testing.T) {
	c := ciCaller()
	c.MaxSize = 1000
	f := newFixture(t, c)

	req := signReq()
	req.Artifact = "src/anything.go"
	w := f.call(t, http.MethodPost, "/v1/sign", f.token, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign artifact = %d, want 403", w.Code)
	}
	var eb api.ErrorBody
	json.Unmarshal(w.Body.Bytes(), &eb)
	if !strings.Contains(eb.Error, "denied by policy") {
		t.Fatalf("error should say denied by policy, got %q", eb.Error)
	}

	req = signReq()
	req.Size = 1001
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, req); w.Code != http.StatusForbidden {
		t.Fatalf("oversize = %d, want 403", w.Code)
	}
}

func TestSignDeniesExpiredCaller(t *testing.T) {
	c := ciCaller()
	c.ExpiresAt = "2026-07-01T13:00:00Z"
	f := newFixture(t, c)
	f.now = t0.Add(2 * time.Hour) // move the clock past expiry
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, signReq()); w.Code != http.StatusForbidden {
		t.Fatalf("expired caller = %d, want 403", w.Code)
	}
}

func TestSignRateLimitAndWindowReset(t *testing.T) {
	c := ciCaller()
	c.RatePerHour = 2
	f := newFixture(t, c)
	for i := 0; i < 2; i++ {
		if w := f.call(t, http.MethodPost, "/v1/sign", f.token, signReq()); w.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i+1, w.Code)
		}
	}
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, signReq()); w.Code != http.StatusTooManyRequests {
		t.Fatalf("third request = %d, want 429", w.Code)
	}
	// The next hour opens a fresh window — advance the injected clock.
	f.now = t0.Add(time.Hour)
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, signReq()); w.Code != http.StatusOK {
		t.Fatalf("after window reset = %d, want 200", w.Code)
	}
}

func TestSignRejectsMalformedRequests(t *testing.T) {
	f := newFixture(t, ciCaller())

	req := signReq()
	req.Digest = "sha256:short"
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, req); w.Code != http.StatusBadRequest {
		t.Fatalf("bad digest = %d, want 400", w.Code)
	}

	// Artifact names land in audit log lines; a newline would let a caller
	// forge log entries.
	req = signReq()
	req.Artifact = "dist/app\n{\"seq\":999}"
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, req); w.Code != http.StatusBadRequest {
		t.Fatalf("control chars = %d, want 400", w.Code)
	}

	// Unknown fields are rejected so future options cannot be silently
	// ignored by an older daemon.
	body := map[string]any{
		"key": "release", "artifact": "dist/a",
		"digest": "sha256:" + strings.Repeat("ab", 32), "size": 1,
		"privileged": true,
	}
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, body); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", w.Code)
	}
}

func TestSignMissingKeyFileIs404NotCrash(t *testing.T) {
	c := ciCaller()
	c.Keys = []string{"*"} // policy allows any name, even one with no key
	f := newFixture(t, c)
	req := signReq()
	req.Key = "ghost"
	w := f.call(t, http.MethodPost, "/v1/sign", f.token, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing key = %d, want 404", w.Code)
	}
}

func TestMethodDiscipline(t *testing.T) {
	f := newFixture(t, ciCaller())
	if w := f.call(t, http.MethodGet, "/v1/sign", f.token, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/sign = %d, want 405", w.Code)
	}
	if w := f.call(t, http.MethodPost, "/v1/keys", f.token, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/keys = %d, want 405", w.Code)
	}
	if w := f.call(t, http.MethodPost, "/v1/health", "", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/health = %d, want 405", w.Code)
	}
}

func TestCallerRemovalTakesEffectWithoutRestart(t *testing.T) {
	f := newFixture(t, ciCaller())
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, signReq()); w.Code != http.StatusOK {
		t.Fatalf("pre-removal sign = %d", w.Code)
	}
	if err := f.b.RemoveCaller("ci"); err != nil {
		t.Fatal(err)
	}
	if w := f.call(t, http.MethodPost, "/v1/sign", f.token, signReq()); w.Code != http.StatusUnauthorized {
		t.Fatalf("post-removal sign = %d, want 401 — records must be re-read per request", w.Code)
	}
}

func TestKeysListsOnlyGrantedKeys(t *testing.T) {
	f := newFixture(t, ciCaller())
	f.b.Keys.Create("debug", t0) // exists, but ci's policy grants only "release"
	w := f.call(t, http.MethodGet, "/v1/keys", f.token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("keys = %d", w.Code)
	}
	var list api.KeyList
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Keys) != 1 || list.Keys[0].Name != "release" {
		t.Fatalf("caller should see exactly its granted keys, got %+v", list.Keys)
	}
	// And the CLI's shared list-ordering helper stays deterministic.
	names := SortedCallerNames(map[string]policy.Caller{"zeta": {}, "alpha": {}, "mid": {}})
	if strings.Join(names, ",") != "alpha,mid,zeta" {
		t.Fatalf("SortedCallerNames = %v", names)
	}
}

func TestSelfReturnsPolicyWithoutSecrets(t *testing.T) {
	c := ciCaller()
	c.MaxSize = 64 << 20
	c.RatePerHour = 100
	f := newFixture(t, c)
	w := f.call(t, http.MethodGet, "/v1/self", f.token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("self = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "tokenSHA256") {
		t.Fatal("/v1/self must not expose the stored token hash")
	}
	var v api.CallerView
	json.Unmarshal(w.Body.Bytes(), &v)
	if v.Name != "ci" || v.MaxSize != 64<<20 || v.RatePerHour != 100 {
		t.Fatalf("unexpected self view: %+v", v)
	}
}

func TestDuplicateTokenHashesRefuseToAuthenticate(t *testing.T) {
	// If two caller records somehow carry the same token hash (hand-edited
	// callers.json), the identity is ambiguous and must not authenticate.
	f := newFixture(t, ciCaller())
	callers, _ := f.b.LoadCallers()
	dup := callers["ci"]
	dup.Name = "ci2"
	callers["ci2"] = dup
	raw, _ := json.MarshalIndent(map[string]any{"version": 1, "callers": callers}, "", "  ")
	if err := os.WriteFile(filepath.Join(f.b.Home, "callers.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if w := f.call(t, http.MethodGet, "/v1/self", f.token, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("ambiguous token = %d, want 401", w.Code)
	}
}
