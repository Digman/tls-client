package tls_client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Digman/tls-client/bandwidth"
	"github.com/Digman/tls-client/profiles"
)

func TestDialTLSClosesConnectionWhenPinFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer func() {
		server.CloseClientConnections()
		server.Close()
	}()

	addr := server.Listener.Addr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	dialer := &closeTrackingDialer{}
	transport, err := newRoundTripper(
		profiles.Chrome_105,
		nil,
		"",
		true,
		false,
		true,
		map[string][]string{host: {"invalid-pin"}},
		nil,
		false,
		false,
		bandwidth.NewNopeTracker(),
		dialer,
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := transport.(*roundTripper).dialTLS(context.Background(), "tcp", addr)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("dialTLS() returned a connection after pin validation failed")
	}
	if !errors.Is(err, ErrBadPinDetected) {
		t.Fatalf("dialTLS() error = %v, want %v", err, ErrBadPinDetected)
	}
	if !dialer.closed.Load() {
		t.Fatal("connection was not closed after pin validation failed")
	}
}

type closeTrackingDialer struct {
	closed atomic.Bool
}

func (d *closeTrackingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *closeTrackingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &closeTrackingConn{Conn: conn, closed: &d.closed}, nil
}

type closeTrackingConn struct {
	net.Conn
	closed *atomic.Bool
}

func (c *closeTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}
