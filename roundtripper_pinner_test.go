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
	fhttp "github.com/bogdanfinn/fhttp"
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
	var reported PinMismatchInfo
	transport, err := newRoundTripper(
		profiles.Chrome_105,
		nil,
		"",
		true,
		false,
		true,
		map[string][]string{host: {"invalid-pin"}},
		func(req *fhttp.Request) {
			var ok bool
			reported, ok = PinMismatchInfoFromRequest(req)
			if !ok {
				t.Fatalf("pin mismatch diagnostics missing from callback request")
			}
		},
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
	var mismatchErr *pinMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatal("dialTLS() error did not retain pin mismatch details")
	}
	if mismatchErr.Info.Host != host {
		t.Fatalf("pin mismatch host = %q, want %q", mismatchErr.Info.Host, host)
	}
	if len(mismatchErr.Info.ExpectedPins) != 1 || mismatchErr.Info.ExpectedPins[0] != "invalid-pin" {
		t.Fatalf("unexpected expected pins: %#v", mismatchErr.Info.ExpectedPins)
	}
	if len(mismatchErr.Info.Certificates) == 0 {
		t.Fatal("pin mismatch details did not include observed certificates")
	}
	if !dialer.closed.Load() {
		t.Fatal("connection was not closed after pin validation failed")
	}

	request, err := fhttp.NewRequest("GET", "https://"+addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, roundTripErr := transport.RoundTrip(request)
	if roundTripErr != ErrBadPinDetected {
		t.Fatalf("RoundTrip() error = %v, want sentinel %v", roundTripErr, ErrBadPinDetected)
	}
	if reported.Host != host || len(reported.Certificates) == 0 {
		t.Fatal("RoundTrip did not invoke detailed pin mismatch handler")
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
