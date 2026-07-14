package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/JaydenCJ/signbooth/internal/booth"
	"github.com/JaydenCJ/signbooth/internal/server"
	"github.com/JaydenCJ/signbooth/internal/version"
)

func cmdServe(argv []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("serve", stderr)
	homeFlag := fs.String("home", "", "booth home directory")
	addrFlag := fs.String("addr", "", "listen address: unix:///path/to.sock or 127.0.0.1:PORT")
	if pos, ok := parseArgs(fs, argv); !ok || len(pos) != 0 {
		return usageErr(stderr, "usage: signbooth serve [--addr ADDR]")
	}
	home, err := resolveHome(*homeFlag)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	b, err := booth.Open(home)
	if err != nil {
		return runtimeErr(stderr, err)
	}
	addr := resolveAddr(*addrFlag, home)
	ln, display, err := Listen(addr)
	if err != nil {
		return runtimeErr(stderr, err)
	}

	srv := &http.Server{
		Handler:           server.New(b, nil).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Fprintf(stdout, "signbooth %s listening on %s\n", version.Version, display)
	fmt.Fprintf(stdout, "home %s — stop with Ctrl-C\n", home)

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case s := <-sig:
		fmt.Fprintf(stdout, "received %s, shutting down\n", s)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		return exitOK
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return runtimeErr(stderr, err)
		}
		return exitOK
	}
}

// Listen opens the daemon's listener. Two transports are supported:
//
//	unix:///path/to/booth.sock — a unix domain socket, chmod 0600
//	127.0.0.1:7365 (or http://…) — loopback TCP only
//
// Any TCP host that does not resolve to a loopback IP is refused: keys
// must never be reachable from off the machine.
func Listen(addr string) (net.Listener, string, error) {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		if path == "" {
			return nil, "", fmt.Errorf("serve: empty unix socket path in %q", addr)
		}
		// A stale socket from a crashed daemon would block bind; a live
		// daemon still answers, so probe before removing.
		if fi, err := os.Stat(path); err == nil {
			if fi.Mode()&os.ModeSocket == 0 {
				return nil, "", fmt.Errorf("serve: %s exists and is not a socket — refusing to remove it", path)
			}
			if conn, err := net.DialTimeout("unix", path, 250*time.Millisecond); err == nil {
				conn.Close()
				return nil, "", fmt.Errorf("serve: another daemon is already listening on %s", path)
			}
			if err := os.Remove(path); err != nil {
				return nil, "", err
			}
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, "", err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			ln.Close()
			return nil, "", err
		}
		return ln, "unix://" + path, nil
	}

	hostport := strings.TrimPrefix(addr, "http://")
	hostport = strings.TrimSuffix(hostport, "/")
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, "", fmt.Errorf("serve: invalid address %q (want unix:///path or 127.0.0.1:PORT)", addr)
	}
	if !isLoopbackHost(host) {
		return nil, "", fmt.Errorf("serve: %q is not a loopback address — signbooth never listens off-host", host)
	}
	ln, err := net.Listen("tcp", hostport)
	if err != nil {
		return nil, "", err
	}
	return ln, "http://" + ln.Addr().String(), nil
}

// isLoopbackHost accepts "localhost" and literal loopback IPs. It performs
// no DNS resolution: a name that merely resolves to 127.0.0.1 today could
// resolve elsewhere tomorrow.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
