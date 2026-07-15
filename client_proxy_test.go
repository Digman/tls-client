package tls_client

import (
	"context"
	"net"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/proxy"
)

func TestSetProxyFailureKeepsCurrentState(t *testing.T) {
	client, err := NewHttpClient(NewNoopLogger())
	if err != nil {
		t.Fatalf("NewHttpClient() error = %v", err)
	}
	originalTransport := client.(*httpClient).Transport
	originalDialer := client.GetDialer()
	if err := client.SetProxy("http://[::1"); err == nil {
		t.Fatal("SetProxy() error = nil")
	}
	if client.GetProxy() != "" {
		t.Fatalf("GetProxy() = %q, want direct", client.GetProxy())
	}
	if client.(*httpClient).Transport != originalTransport {
		t.Fatal("Transport changed after failed SetProxy")
	}
	if client.GetDialer() != originalDialer {
		t.Fatal("dialer changed after failed SetProxy")
	}
}

func TestSetProxySameURLRebuildsState(t *testing.T) {
	const proxyURL = "http://rotating-proxy.example:8080"
	factoryCalls := 0
	factory := func(string, time.Duration, *net.TCPAddr, http.Header, Logger) (proxy.ContextDialer, error) {
		factoryCalls++
		return &directTestDialer{id: factoryCalls}, nil
	}
	client, err := NewHttpClient(NewNoopLogger(), WithProxyUrl(proxyURL), WithProxyDialerFactory(factory), WithForceHttp1())
	if err != nil {
		t.Fatal(err)
	}
	originalTransport := client.(*httpClient).Transport
	originalDialer := client.GetDialer()

	if err := client.SetProxy(proxyURL); err != nil {
		t.Fatalf("SetProxy() error = %v", err)
	}
	if factoryCalls != 2 {
		t.Fatalf("proxy dialer factory calls = %d, want 2", factoryCalls)
	}
	if client.(*httpClient).Transport == originalTransport {
		t.Fatal("Transport was not rebuilt for rotating proxy")
	}
	if client.GetDialer() == originalDialer {
		t.Fatal("dialer was not rebuilt for rotating proxy")
	}
}

type directTestDialer struct {
	id int
}

func (directTestDialer) Dial(network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

func (directTestDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}
