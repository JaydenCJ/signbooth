// Tests for the CLI's HTTP client: address parsing, both transports
// (unix socket and loopback TCP), auth header wiring, and error surfacing.
package client

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/JaydenCJ/signbooth/internal/api"
)

func TestNewAddressForms(t *testing.T) {
	// TLS to yourself over loopback is theater; refusing it early keeps
	// people from pointing the client at remote hosts.
	if _, err := New("https://example.test:443", ""); err == nil {
		t.Fatal("https addresses must be refused")
	}
	if _, err := New("", ""); err == nil {
		t.Fatal("empty address must be refused")
	}
	if _, err := New("unix://", ""); err == nil {
		t.Fatal("empty unix socket path must be refused")
	}
	c, err := New("127.0.0.1:7365", "tok")
	if err != nil || c.base != "http://127.0.0.1:7365" {
		t.Fatalf("bare hostport: base = %q, err = %v", c.base, err)
	}
	c, _ = New("http://127.0.0.1:7365/", "")
	if c.base != "http://127.0.0.1:7365" {
		t.Fatalf("trailing slash not stripped: %q", c.base)
	}
}

func TestHealthOverLoopbackTCP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"service":"signbooth","version":"0.1.0","time":"t"}`))
	}))
	defer ts.Close()
	c, err := New(ts.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.Health()
	if err != nil {
		t.Fatal(err)
	}
	if !h.OK || h.Service != "signbooth" {
		t.Fatalf("unexpected health: %+v", h)
	}
}

func TestBearerTokenHeaderWiring(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer ts.Close()

	c, _ := New(ts.URL, "sbt_secret")
	if _, err := c.Keys(); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer sbt_secret" {
		t.Fatalf("Authorization = %q", got)
	}

	// And with no token configured, no header is sent at all.
	c, _ = New(ts.URL, "")
	c.Keys()
	if got != "" {
		t.Fatalf("no token was configured but Authorization = %q was sent", got)
	}
}

func TestAPIErrorCarriesStatusAndServerMessage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"denied by policy: key \"debug\" is not in caller \"ci\"'s key list"}`))
	}))
	defer ts.Close()
	c, _ := New(ts.URL, "tok")
	_, err := c.Sign(api.SignRequest{})
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("want *APIError, got %T: %v", err, err)
	}
	if apiErr.Status != http.StatusForbidden {
		t.Fatalf("status = %d", apiErr.Status)
	}
	if apiErr.Message == "" || apiErr.Error() == "" {
		t.Fatal("server message must be surfaced")
	}
}

func TestNonJSONErrorBodyStillSurfaces(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("some proxy page"))
	}))
	defer ts.Close()
	c, _ := New(ts.URL, "")
	_, err := c.Health()
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Message != "some proxy page" {
		t.Fatalf("plain-text errors must pass through, got %v", err)
	}
}

func TestUnixSocketTransport(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "booth.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true,"service":"signbooth","version":"0.1.0","time":"t"}`))
	})}
	go srv.Serve(ln)
	defer srv.Close()

	c, err := New("unix://"+sock, "")
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.Health()
	if err != nil {
		t.Fatalf("health over unix socket: %v", err)
	}
	if h.Service != "signbooth" {
		t.Fatalf("unexpected response: %+v", h)
	}
}

func TestConnectionErrorIsNotAPIError(t *testing.T) {
	// A dead socket path must produce a transport error the CLI maps to
	// exit 3, not a policy-style failure.
	c, _ := New("unix://"+filepath.Join(t.TempDir(), "absent.sock"), "")
	_, err := c.Health()
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, ok := err.(*APIError); ok {
		t.Fatal("transport failures must not be APIErrors")
	}
}

func TestMalformedSuccessBodyErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{truncated"))
	}))
	defer ts.Close()
	c, _ := New(ts.URL, "")
	if _, err := c.Health(); err == nil {
		t.Fatal("malformed 200 bodies must error, not zero-fill")
	}
}
