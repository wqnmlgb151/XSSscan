package ssrfguard

import (
	"context"
	"errors"
	"net"
	"testing"
)

type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

func TestSameOrigin(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"https://EXAMPLE.com/a", "https://example.com:443/b", true},
		{"http://example.com", "http://example.com:80/b", true},
		{"http://example.com", "https://example.com", false},
		{"http://example.com:8080", "http://example.com:8081", false},
		{"http://example.com", "http://sub.example.com", false},
		{"http://example.com", "http://user:pass@example.com", false},
		{"file:///a", "file:///b", false},
		{"", "", false},
	} {
		if got := SameOrigin(tt.a, tt.b); got != tt.want {
			t.Errorf("SameOrigin(%q,%q)=%v", tt.a, tt.b, got)
		}
	}
}

func TestDialResolvedPinsValidatedAddress(t *testing.T) {
	old := AllowPrivate
	AllowPrivate = false
	defer func() { AllowPrivate = old }()
	calls := 0
	resolver := resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		if calls > 1 {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	left, right := net.Pipe()
	defer right.Close()
	conn, err := dialResolved(context.Background(), "tcp", "changing.test:443", resolver, func(_ context.Context, network, address string) (net.Conn, error) {
		if address != "93.184.216.34:443" || network != "tcp" {
			t.Fatalf("unexpected dial %s %s", network, address)
		}
		return left, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if calls != 1 {
		t.Fatalf("resolved %d times", calls)
	}
}

func TestDialResolvedRejectsMixedAndULA(t *testing.T) {
	old := AllowPrivate
	AllowPrivate = false
	defer func() { AllowPrivate = old }()
	for _, restricted := range []string{"127.0.0.1", "fc00::1", "fd00::1", "::ffff:127.0.0.1"} {
		resolver := resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP(restricted)}}, nil
		})
		_, err := dialResolved(context.Background(), "tcp", "mixed.test:80", resolver, func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dialed rejected answer")
			return nil, nil
		})
		if err == nil {
			t.Errorf("allowed %s", restricted)
		}
	}
}

func TestDialResolvedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := resolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) { return nil, ctx.Err() })
	_, err := dialResolved(ctx, "tcp", "cancel.test:80", resolver, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialed after cancellation")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
