package auth

import (
	"context"
	"errors"
	"github.com/wqnmlgb151/XSSscan/pkg/httpclient"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLoginForm200IsFailureWithOriginalEvidence(t *testing.T) {
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "token"})
		w.Write([]byte(`<form><input type="password"></form>`))
	}))
	defer server.Close()
	err := AuthenticateContext(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), httpclient.NewClient(time.Second, nil, ssrfguard.Policy{AllowPrivate: true}), LoginConfig{LoginURL: server.URL, Username: "worker", Password: "original-secret", Headers: map[string]string{"Authorization": "Bearer raw-token"}})
	var diagnostic *httpclient.ExchangeError
	if !errors.As(err, &diagnostic) || !strings.Contains(diagnostic.HTTP.Request, "password=original-secret") || !strings.Contains(diagnostic.HTTP.Request, "Authorization: Bearer raw-token") || !strings.Contains(diagnostic.HTTP.Response, `type="password"`) {
		t.Fatalf("login failed silently or lost evidence: %v %+v", err, diagnostic)
	}
}

func TestLoginExplicitSuccessAndCancellation(t *testing.T) {
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("authenticated fixture")) }))
	defer server.Close()
	if err := AuthenticateContext(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), httpclient.NewClient(time.Second, nil, ssrfguard.Policy{AllowPrivate: true}), LoginConfig{LoginURL: server.URL, SuccessContains: "authenticated fixture"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	cancel()
	if err := AuthenticateContext(ctx, httpclient.NewClient(time.Second, nil, ssrfguard.Policy{AllowPrivate: true}), LoginConfig{LoginURL: server.URL}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel lost: %v", err)
	}
}
