// Package oauth provides OAuth 2.0 / OpenID Connect authentication flows
// for scanning authenticated endpoints behind modern identity providers.
package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FlowConfig defines parameters for OAuth authentication flows.
type FlowConfig struct {
	AuthURL      string            // Authorization endpoint
	TokenURL     string            // Token endpoint
	ClientID     string            // OAuth client ID
	ClientSecret string            // OAuth client secret (optional for public clients)
	RedirectURI  string            // Callback URL
	Scope        string            // Requested scopes
	Username     string            // Resource owner username (for ROPC)
	Password     string            // Resource owner password (for ROPC)
	UsePKCE      bool              // Enable PKCE (recommended for public clients)
	ExtraParams  map[string]string // Additional parameters for the token request
}

// TokenPair holds the result of a successful authentication.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	IDToken      string // OIDC
	ExpiresIn    int
	TokenType    string
	ExpiresAt    time.Time
}

// OAuthFlow handles OAuth 2.0 authentication flows.
type OAuthFlow struct {
	client *http.Client
	config FlowConfig
}

// NewFlow creates a new OAuth flow handler.
func NewFlow(client *http.Client, config FlowConfig) *OAuthFlow {
	return &OAuthFlow{
		client: client,
		config: config,
	}
}

// Authenticate performs the configured OAuth flow and returns tokens.
func (f *OAuthFlow) Authenticate(ctx context.Context) (*TokenPair, error) {
	if f.config.Username != "" && f.config.Password != "" {
		return f.ropcFlow(ctx)
	}
	return nil, fmt.Errorf("no supported flow configured: provide username/password for ROPC, or use Discover() for authorization code flow")
}

// ropcFlow implements the Resource Owner Password Credentials (ROPC) flow.
// This is the simplest flow but least secure — only recommended for legacy systems.
func (f *OAuthFlow) ropcFlow(ctx context.Context) (*TokenPair, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", f.config.Username)
	form.Set("password", f.config.Password)
	form.Set("client_id", f.config.ClientID)
	if f.config.ClientSecret != "" {
		form.Set("client_secret", f.config.ClientSecret)
	}
	if f.config.Scope != "" {
		form.Set("scope", f.config.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", f.config.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return parseTokenResponse(body)
}

// Refresh uses a refresh token to obtain a new access token.
func (f *OAuthFlow) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", f.config.ClientID)
	if f.config.ClientSecret != "" {
		form.Set("client_secret", f.config.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", f.config.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return parseTokenResponse(body)
}

// GeneratePKCE generates a PKCE code verifier and S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate random: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)

	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])

	return verifier, challenge, nil
}

// BuildAuthorizationURL builds the authorization URL for the Authorization Code flow.
func (f *OAuthFlow) BuildAuthorizationURL(state string) (string, error) {
	u, err := url.Parse(f.config.AuthURL)
	if err != nil {
		return "", fmt.Errorf("parse auth URL: %w", err)
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", f.config.ClientID)
	q.Set("redirect_uri", f.config.RedirectURI)
	if f.config.Scope != "" {
		q.Set("scope", f.config.Scope)
	}
	if state != "" {
		q.Set("state", state)
	}

	if f.config.UsePKCE {
		verifier, challenge, err := GeneratePKCE()
		if err != nil {
			return "", fmt.Errorf("generate PKCE: %w", err)
		}
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
		_ = verifier // caller must store this for token exchange
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ExchangeCode exchanges an authorization code for tokens (Authorization Code flow).
func (f *OAuthFlow) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenPair, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", f.config.RedirectURI)
	form.Set("client_id", f.config.ClientID)
	if f.config.ClientSecret != "" {
		form.Set("client_secret", f.config.ClientSecret)
	}
	if f.config.UsePKCE && codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", f.config.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exchange failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return parseTokenResponse(body)
}

// parseTokenResponse parses a standard OAuth token response.
func parseTokenResponse(body []byte) (*TokenPair, error) {
	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if raw.Error != "" {
		return nil, fmt.Errorf("OAuth error: %s (%s)", raw.Error, raw.ErrorDesc)
	}

	if raw.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in response")
	}

	tokenType := raw.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	return &TokenPair{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		IDToken:      raw.IDToken,
		ExpiresIn:    raw.ExpiresIn,
		TokenType:    tokenType,
		ExpiresAt:    time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second),
	}, nil
}

// IsExpired reports whether the token has expired (with 60s buffer).
func (t *TokenPair) IsExpired() bool {
	return time.Now().After(t.ExpiresAt.Add(-60 * time.Second))
}

// AuthorizationHeader returns the value for the Authorization header.
func (t *TokenPair) AuthorizationHeader() string {
	return t.TokenType + " " + t.AccessToken
}
