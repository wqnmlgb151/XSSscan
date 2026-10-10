package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
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
	return DiscoverOIDCWithOrigins(ctx, client, issuer, nil)
}

func DiscoverOIDCWithOrigins(ctx context.Context, client *http.Client, issuer string, allowedOrigins []string) (*OIDCConfiguration, error) {
	var err error
	issuer, err = ExtractIssuer(issuer)
	if err != nil {
		return nil, err
	}
	if err := ssrfguard.IsURLTargetAllowedContext(ctx, issuer); err != nil {
		return nil, err
	}
	client = httpclient.WithRedirectPolicy(httpclient.WithCapture(client))
	// Ensure issuer doesn't have trailing slash
	wellKnownURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return nil, fmt.Errorf("read discovery response: %w", err)
	}

	if len(body) > 64*1024 {
		return nil, fmt.Errorf("OIDC document exceeds size limit")
	}
	var config OIDCConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}

	if config.Issuer != issuer {
		return nil, fmt.Errorf("OIDC issuer mismatch: requested %q, received %q", issuer, config.Issuer)
	}
	if config.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC token_endpoint is missing")
	}
	for _, endpoint := range []string{config.TokenEndpoint, config.AuthorizationEndpoint, config.UserInfoEndpoint, config.RevocationEndpoint, config.EndSessionEndpoint} {
		if endpoint == "" {
			continue
		}
		if err := validateEndpoint(ctx, issuer, endpoint, allowedOrigins); err != nil {
			return nil, err
		}
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
		return "", fmt.Errorf("parse issuer: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("issuer must be an absolute HTTP(S) URL without credentials, query or fragment")
	}
	// Preserve tenant/realm paths. Only strip the documented discovery suffix.
	u.Path = strings.TrimSuffix(u.Path, "/.well-known/openid-configuration")
	u.RawPath = strings.TrimSuffix(u.RawPath, "/.well-known/openid-configuration")
	return u.String(), nil
}
func validateEndpoint(ctx context.Context, issuer, endpoint string, allowed []string) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid OIDC endpoint %q", endpoint)
	}
	allowedOrigin := ssrfguard.SameOrigin(issuer, endpoint)
	for _, origin := range allowed {
		v, e := url.Parse(origin)
		if e != nil || v.Host == "" || v.User != nil || v.RawQuery != "" || v.Fragment != "" || (v.Path != "" && v.Path != "/") {
			return fmt.Errorf("invalid allowed OAuth origin %q", origin)
		}
		if ssrfguard.SameOrigin(origin, endpoint) {
			allowedOrigin = true
		}
	}
	if !allowedOrigin {
		return fmt.Errorf("OIDC endpoint outside approved origins: %s", endpoint)
	}
	if err := ssrfguard.IsURLTargetAllowedContext(ctx, endpoint); err != nil {
		return fmt.Errorf("OIDC endpoint blocked: %w", err)
	}
	return nil
}
