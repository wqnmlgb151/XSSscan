package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestROPCFlow_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		if r.FormValue("grant_type") != "password" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		if r.FormValue("username") != "admin" {
			http.Error(w, "wrong username", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "test-access-token",
			"refresh_token": "test-refresh-token",
			"id_token": "test-id-token",
			"expires_in": 3600,
			"token_type": "Bearer"
		}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	flow := NewFlow(client, FlowConfig{
		TokenURL: server.URL + "/token",
		ClientID: "test-client",
		Username: "admin",
		Password: "secret",
	})

	tokenPair, err := flow.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if tokenPair.AccessToken != "test-access-token" {
		t.Errorf("AccessToken = %q, want %q", tokenPair.AccessToken, "test-access-token")
	}
	if tokenPair.RefreshToken != "test-refresh-token" {
		t.Errorf("RefreshToken = %q, want %q", tokenPair.RefreshToken, "test-refresh-token")
	}
	if tokenPair.IDToken != "test-id-token" {
		t.Errorf("IDToken = %q, want %q", tokenPair.IDToken, "test-id-token")
	}
	if tokenPair.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", tokenPair.ExpiresIn)
	}
	if tokenPair.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", tokenPair.TokenType, "Bearer")
	}
	if tokenPair.IsExpired() {
		t.Error("fresh token should not be expired")
	}
	if tokenPair.AuthorizationHeader() != "Bearer test-access-token" {
		t.Errorf("AuthorizationHeader = %q", tokenPair.AuthorizationHeader())
	}
}

func TestROPCFlow_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid credentials"}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	flow := NewFlow(client, FlowConfig{
		TokenURL: server.URL + "/token",
		ClientID: "test-client",
		Username: "admin",
		Password: "wrong",
	})

	_, err := flow.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for failed auth")
	}
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("expected error to contain 'invalid_grant', got: %v", err)
	}
}

func TestROPCFlow_NoCredentials(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	flow := NewFlow(client, FlowConfig{
		TokenURL: "http://localhost/token",
		ClientID: "test-client",
	})

	_, err := flow.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error when no credentials provided")
	}
}

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if verifier == "" {
		t.Error("verifier is empty")
	}
	if challenge == "" {
		t.Error("challenge is empty")
	}
	if verifier == challenge {
		t.Error("verifier and challenge should be different")
	}

	// Verify S256 relationship
	// (the actual verification is internal, just check they're URL-safe)
	if strings.ContainsAny(verifier, "+/=") {
		t.Error("verifier should be URL-safe base64")
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Error("challenge should be URL-safe base64")
	}
}

func TestBuildAuthorizationURL(t *testing.T) {
	flow := NewFlow(&http.Client{}, FlowConfig{
		AuthURL:     "https://auth.example.com/authorize",
		ClientID:    "my-app",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid profile",
	})

	authURL, err := flow.BuildAuthorizationURL("random-state-123")
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}

	if !strings.HasPrefix(authURL, "https://auth.example.com/authorize?") {
		t.Errorf("unexpected URL prefix: %s", authURL)
	}
	if !strings.Contains(authURL, "response_type=code") {
		t.Errorf("missing response_type: %s", authURL)
	}
	if !strings.Contains(authURL, "client_id=my-app") {
		t.Errorf("missing client_id: %s", authURL)
	}
	if !strings.Contains(authURL, "state=random-state-123") {
		t.Errorf("missing state: %s", authURL)
	}
}

func TestBuildAuthorizationURL_WithPKCE(t *testing.T) {
	flow := NewFlow(&http.Client{}, FlowConfig{
		AuthURL:     "https://auth.example.com/authorize",
		ClientID:    "my-app",
		RedirectURI: "http://localhost:8080/callback",
		UsePKCE:     true,
	})

	authURL, err := flow.BuildAuthorizationURL("state")
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}

	if !strings.Contains(authURL, "code_challenge=") {
		t.Errorf("missing code_challenge: %s", authURL)
	}
	if !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Errorf("missing code_challenge_method: %s", authURL)
	}
}

func TestRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("grant_type") != "refresh_token" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		if r.FormValue("refresh_token") != "old-refresh-token" {
			http.Error(w, "wrong refresh_token", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"access_token": "new-access-token",
			"expires_in": 1800,
			"token_type": "Bearer"
		}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	flow := NewFlow(client, FlowConfig{
		TokenURL: server.URL,
		ClientID: "test-client",
	})

	tokenPair, err := flow.Refresh(context.Background(), "old-refresh-token")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if tokenPair.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q, want %q", tokenPair.AccessToken, "new-access-token")
	}
}

func TestDiscoverOIDC(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"issuer": "https://auth.example.com",
			"authorization_endpoint": "https://auth.example.com/authorize",
			"token_endpoint": "https://auth.example.com/token",
			"userinfo_endpoint": "https://auth.example.com/userinfo"
		}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	doc, err := DiscoverOIDC(context.Background(), client, server.URL)
	if err != nil {
		t.Fatalf("DiscoverOIDC: %v", err)
	}

	if doc.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", doc.Issuer, "https://auth.example.com")
	}
	if doc.AuthorizationEndpoint != "https://auth.example.com/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != "https://auth.example.com/token" {
		t.Errorf("TokenEndpoint = %q", doc.TokenEndpoint)
	}
}

func TestParseTokenResponse(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
		wantToken string
	}{
		{
			name:      "valid response",
			body:      `{"access_token":"abc","token_type":"Bearer","expires_in":3600}`,
			wantErr:   false,
			wantToken: "abc",
		},
		{
			name:    "error response",
			body:    `{"error":"invalid_client","error_description":"Bad client"}`,
			wantErr: true,
		},
		{
			name:    "missing access_token",
			body:    `{"token_type":"Bearer"}`,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			body:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair, err := parseTokenResponse([]byte(tt.body))
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pair.AccessToken != tt.wantToken {
				t.Errorf("AccessToken = %q, want %q", pair.AccessToken, tt.wantToken)
			}
		})
	}
}

func TestParseAzureAD(t *testing.T) {
	cfg := ParseAzureAD("mytenant")
	if cfg.AuthURL != "https://login.microsoftonline.com/mytenant/oauth2/v2.0/authorize" {
		t.Errorf("AuthURL = %q", cfg.AuthURL)
	}
	if cfg.TokenURL != "https://login.microsoftonline.com/mytenant/oauth2/v2.0/token" {
		t.Errorf("TokenURL = %q", cfg.TokenURL)
	}
}

func TestParseGoogle(t *testing.T) {
	cfg := ParseGoogle()
	if cfg.AuthURL != "https://accounts.google.com/o/oauth2/v2/auth" {
		t.Errorf("AuthURL = %q", cfg.AuthURL)
	}
}

func TestParseOkta(t *testing.T) {
	cfg := ParseOkta("mycompany")
	if cfg.AuthURL != "https://mycompany.okta.com/oauth2/default/v1/authorize" {
		t.Errorf("AuthURL = %q", cfg.AuthURL)
	}
}

func TestTokenPair_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		expires time.Time
		want    bool
	}{
		{"future", time.Now().Add(1 * time.Hour), false},
		{"past", time.Now().Add(-1 * time.Hour), true},
		{"near future (within buffer)", time.Now().Add(30 * time.Second), true},
		{"just outside buffer", time.Now().Add(120 * time.Second), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &TokenPair{ExpiresAt: tt.expires}
			if got := tp.IsExpired(); got != tt.want {
				t.Errorf("IsExpired = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractIssuer(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"https://auth.example.com", "https://auth.example.com", false},
		{"https://auth.example.com/", "https://auth.example.com", false},
	}

	for _, tt := range tests {
		got, err := ExtractIssuer(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ExtractIssuer(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ExtractIssuer(%q): %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ExtractIssuer(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
