package identity

// OIDC login (scenarios 5 & 6, the #314 compliance demo) via the STANDARD Go OIDC stack:
// github.com/coreos/go-oidc/v3/oidc (discovery + id_token verification) over golang.org/x/oauth2
// (auth-code + PKCE + token exchange). This is deliberately NOT the allme SDK — the point of the OIDC
// scenarios is to prove a real, third-party OIDC client interoperates with the platform.
//
// The library is configured for:
//   - issuer override — discovery runs off the config file's api_url, so a non-prod issuer works;
//   - client_secret_post — the token endpoint's only client-auth method (Endpoint.AuthStyle);
//   - sessionless operation — state (== runId), nonce and PKCE verifier live in the run file, so no
//     server session is needed.

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oidcSetup is a discovered provider + configured oauth2 config for one scenario run.
type oidcSetup struct {
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	clientID     string
}

// newOIDCSetup discovers the issuer and builds the oauth2 config for client_secret_post.
func newOIDCSetup(ctx context.Context, issuer, clientID, clientSecret, redirectURI string) (*oidcSetup, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed for %q: %w", issuer, err)
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams // client_secret_post
	return &oidcSetup{
		provider: provider,
		clientID: clientID,
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURI,
			Endpoint:     endpoint,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
	}, nil
}

// authCodeURL builds the authorization-request URL with state, nonce and an S256 PKCE challenge.
func (s *oidcSetup) authCodeURL(state, nonce, challenge string) string {
	return s.oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// exchangeAndVerify exchanges the code (with the PKCE verifier), then verifies the id_token and its
// nonce, returning the verified claims.
func (s *oidcSetup) exchangeAndVerify(ctx context.Context, code, verifier, nonce string) (map[string]any, error) {
	token, err := s.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange failed: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("oidc token response carried no id_token")
	}
	idToken, err := s.provider.Verifier(&oidc.Config{ClientID: s.clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc id_token verification failed: %w", err)
	}
	if idToken.Nonce != nonce {
		return nil, fmt.Errorf("oidc id_token nonce mismatch")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc claim decode failed: %w", err)
	}
	return claims, nil
}

// oidcContext bounds the OIDC discovery / token network calls so the single worker is never pinned.
func oidcContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}
