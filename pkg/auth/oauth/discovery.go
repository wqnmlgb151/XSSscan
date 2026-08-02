package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// OIDCConfiguration represents the standard OpenID Connect discovery document.
type OIDCConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// DiscoverOIDC fetches the OpenID Connect discovery document from the well-known URL.
func DiscoverOIDC(ctx context.Context, client *http.Client, issuer string) (*OIDCConfiguration, error) {
	// Ensure issuer doesn't have trailing slash
	issuer = strings.TrimRight(issuer, "/")
	wellKnownURL := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create discovery request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery failed (HTTP %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read discovery response: %w", err)
	}

	var config OIDCConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}

	return &config, nil
}

// Discover auto-configures a FlowConfig from an OIDC issuer URL.
func Discover(ctx context.Context, client *http.Client, issuer string) (*FlowConfig, error) {
	doc, err := DiscoverOIDC(ctx, client, issuer)
	if err != nil {
		return nil, err
	}

	return &FlowConfig{
		AuthURL:  doc.AuthorizationEndpoint,
		TokenURL: doc.TokenEndpoint,
	}, nil
}

// ParseAzureAD returns a FlowConfig pre-configured for Azure AD.
func ParseAzureAD(tenant string) *FlowConfig {
	if tenant == "" {
		tenant = "common"
	}
	baseURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0", tenant)
	return &FlowConfig{
		AuthURL:     baseURL + "/authorize",
		TokenURL:    baseURL + "/token",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid profile email",
	}
}

// ParseGoogle returns a FlowConfig pre-configured for Google OAuth.
func ParseGoogle() *FlowConfig {
	return &FlowConfig{
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid profile email",
	}
}

// ParseOkta returns a FlowConfig pre-configured for Okta.
func ParseOkta(domain string) *FlowConfig {
	baseURL := fmt.Sprintf("https://%s.okta.com/oauth2/default", domain)
	return &FlowConfig{
		AuthURL:     baseURL + "/v1/authorize",
		TokenURL:    baseURL + "/v1/token",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid profile email",
	}
}

// ExtractIssuer extracts the issuer URL from a full URL or returns it as-is.
func ExtractIssuer(input string) (string, error) {
	u, err := url.Parse(input)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}

	// If it's just a domain, return as-is
	if u.Path == "" || u.Path == "/" {
		return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
	}

	// Try to extract the base issuer URL
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}
