// Package client is the CLI's HTTP client for the daemon API. It speaks
// plain HTTP over either a unix domain socket (the default transport,
// permission-guarded by the booth directory) or loopback TCP. It never
// dials anything but the address it is given.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/JaydenCJ/signbooth/internal/api"
	"github.com/JaydenCJ/signbooth/internal/envelope"
)

// APIError carries a non-2xx response's status and server-provided message.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("daemon replied %d: %s", e.Status, e.Message)
}

// Client talks to one signbooth daemon.
type Client struct {
	base  string
	token string
	hc    *http.Client
}

// New builds a client for addr. Accepted forms:
//
//	unix:///path/to/booth.sock   unix domain socket
//	http://127.0.0.1:7365        loopback TCP
//	127.0.0.1:7365               shorthand for the above
//
// token may be empty for unauthenticated routes (health).
func New(addr, token string) (*Client, error) {
	hc := &http.Client{Timeout: 10 * time.Second}
	base := ""
	switch {
	case strings.HasPrefix(addr, "unix://"):
		path := strings.TrimPrefix(addr, "unix://")
		if path == "" {
			return nil, fmt.Errorf("client: empty unix socket path in %q", addr)
		}
		dialer := &net.Dialer{}
		hc.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", path)
			},
		}
		// The host is a placeholder; the transport ignores it.
		base = "http://signbooth"
	case strings.HasPrefix(addr, "http://"):
		base = strings.TrimSuffix(addr, "/")
	case strings.HasPrefix(addr, "https://"):
		return nil, fmt.Errorf("client: signbooth is loopback-only; https addresses are not supported")
	case addr == "":
		return nil, fmt.Errorf("client: empty daemon address")
	default:
		base = "http://" + strings.TrimSuffix(addr, "/")
	}
	return &Client{base: base, token: token, hc: hc}, nil
}

func (c *Client) do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("client: cannot reach the daemon at %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var eb api.ErrorBody
		if json.Unmarshal(raw, &eb) == nil && eb.Error != "" {
			return &APIError{Status: resp.StatusCode, Message: eb.Error}
		}
		return &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("client: malformed daemon response: %w", err)
		}
	}
	return nil
}

// Health pings GET /v1/health (no authentication required).
func (c *Client) Health() (api.Health, error) {
	var h api.Health
	err := c.do(http.MethodGet, "/v1/health", nil, &h)
	return h, err
}

// Keys fetches GET /v1/keys — the keys this caller's policy grants.
func (c *Client) Keys() (api.KeyList, error) {
	var l api.KeyList
	err := c.do(http.MethodGet, "/v1/keys", nil, &l)
	return l, err
}

// Self fetches GET /v1/self — the authenticated caller's own policy.
func (c *Client) Self() (api.CallerView, error) {
	var v api.CallerView
	err := c.do(http.MethodGet, "/v1/self", nil, &v)
	return v, err
}

// Sign posts a sign request and returns the daemon's signature envelope.
func (c *Client) Sign(req api.SignRequest) (envelope.Envelope, error) {
	var env envelope.Envelope
	err := c.do(http.MethodPost, "/v1/sign", req, &env)
	return env, err
}
