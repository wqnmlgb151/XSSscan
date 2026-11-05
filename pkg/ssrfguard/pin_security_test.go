package ssrfguard

import (
	"context"
	"net"
	"net/netip"
	"testing"
)

func TestPinnedPolicyRetainsValidatedAnswers(t *testing.T) {
	calls := 0
	resolver := resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		return []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.2")}}, nil
	})
	policy, rule, err := (Policy{AllowPrivate: true}).pinURL(context.Background(), "http://localhost:18080/", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || rule != "MAP localhost 127.0.0.2" {
		t.Fatalf("pin result %q calls%d", rule, calls)
	}
	answers, err := policy.resolve(context.Background(), "localhost")
	if err != nil || answers[0].IP.String() != "127.0.0.2" {
		t.Fatalf("validated answer lost: %v %v", answers, err)
	}
	answers[0].IP[0] = 0
	again, err := policy.resolve(context.Background(), "localhost")
	if err != nil || again[0].IP.String() != "127.0.0.2" {
		t.Fatal("caller mutated pin snapshot")
	}
	strict := Policy{}
	_, _, err = strict.pinURL(context.Background(), "http://localhost/", resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}))
	if err == nil {
		t.Fatal("mixed DNS answer accepted")
	}
}

func TestEmbeddedIPv4AddressDecoding(t *testing.T) {
	for _, row := range []struct{ input, want string }{
		{"64:ff9b::c000:201", "192.0.2.1"},
		{"2002:c000:201::", "192.0.2.1"},
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", "192.0.2.45"},
	} {
		got, ok := embeddedIPv4(netip.MustParseAddr(row.input))
		if !ok || got.String() != row.want {
			t.Errorf("decode %s => %v %v", row.input, got, ok)
		}
	}
	if err := (Policy{}).CheckIP(net.ParseIP("::ffff:192.0.2.1")); err == nil {
		t.Fatal("mapped reserved IPv4 accepted")
	}
	if err := (Policy{}).CheckIP(net.ParseIP("::ffff:93.184.216.34")); err != nil {
		t.Fatal("mapped public IPv4 rejected")
	}
}
