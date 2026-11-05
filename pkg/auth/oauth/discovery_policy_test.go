package oauth

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"testing"
)

func TestOIDCIssuerAndEndpointPolicy(t *testing.T) {
	var issuer, documentIssuer, tokenURL string
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q}`, documentIssuer, tokenURL)
	}))
	defer server.Close()
	issuer = server.URL + "/realm"
	documentIssuer = issuer
	tokenURL = server.URL + "/token"
	if _, err := DiscoverOIDC(context.Background(), server.Client(), issuer); err != nil {
		t.Fatal(err)
	}

	issuer = server.URL + "/realm/"
	documentIssuer = issuer
	if _, err := DiscoverOIDC(context.Background(), server.Client(), issuer); err != nil {
		t.Fatalf("valid trailing slash rejected: %v", err)
	}
	documentIssuer = server.URL + "/realm"
	if _, err := DiscoverOIDC(context.Background(), server.Client(), issuer); err == nil {
		t.Fatal("issuer spelling mismatch accepted")
	}
	documentIssuer = server.URL
	if _, err := DiscoverOIDC(context.Background(), server.Client(), issuer); err == nil {
		t.Fatal("accepted issuer from another realm")
	}
	documentIssuer = issuer
	foreign := testenv.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("discovery must not fetch token endpoint") }))
	defer foreign.Close()
	tokenURL = foreign.URL + "/token"
	if _, err := DiscoverOIDC(context.Background(), server.Client(), issuer); err == nil {
		t.Fatal("accepted unapproved credential destination")
	}
	if _, err := DiscoverOIDCWithOrigins(context.Background(), server.Client(), issuer, []string{foreign.URL}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"example.test", "https://user:secret@example.test/realm", "https://example.test/realm?query=x", "javascript:alert(1)"} {
		if _, err := ExtractIssuer(raw); err == nil {
			t.Fatalf("bad issuer %q", raw)
		}
	}
	if got, err := ExtractIssuer("https://example.test/tenant/v2/.well-known/openid-configuration"); err != nil || got != "https://example.test/tenant/v2" {
		t.Fatalf("issuer path lost: %s %v", got, err)
	}
}

func TestOAuthPrivateEndpointBlockedBeforeCredentials(t *testing.T) {
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = false
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("blocked token endpoint received credentials") }))
	defer server.Close()
	if _, err := NewFlow(server.Client(), FlowConfig{TokenURL: server.URL, Username: "worker", Password: "secret"}).Authenticate(context.Background()); err == nil {
		t.Fatal("private endpoint bypassed")
	}
}
