package companydata

// "Sign in with allme" — the RP-side OAuth client (#195).
//
// A third-party site embeds a *Sign in with allme* button, sends the person to the hosted consent
// screen, and — once they approve — receives an authorization code at its redirect URI. This file
// wraps the RP half: build the button URL, exchange the code, read the identity, and (for one_time)
// decrypt the shared values. Config-only key handling still holds: the app private key + passphrase
// come from Config (the idw role), never a method argument.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultAuthorizeURL is the hosted consent surface. Native apps claim this https link; web is the fallback.
const DefaultAuthorizeURL = "https://web.allme.fyi/auth"

var nonClaimable = map[string]bool{"photo": true, "document": true, "legal_document": true}

const maxClaims = 15

// Claim is a one_time claim the RP asks for: a field TYPE + an advisory suggestion.
type Claim struct {
	Type     string
	Suggest  string
	Required bool
	Label    string
}

// SignInResult is the decrypted conclusion of CompleteSignIn.
type SignInResult struct {
	User      map[string]string
	Mode      string
	TwoFactor bool
	Values    map[string]string
}

// OAuthClient is the RP-side "Sign in with allme" client.
type OAuthClient struct {
	config       *Config
	doer         Doer
	authorizeURL string
	sleep        func(time.Duration)
}

// OAuthOption configures an OAuthClient.
type OAuthOption func(*OAuthClient)

// WithOAuthDoer injects an HTTP Doer (the standard *http.Client satisfies it) — used in tests.
func WithOAuthDoer(d Doer) OAuthOption { return func(c *OAuthClient) { c.doer = d } }

// WithAuthorizeURL overrides the hosted consent base (non-prod hosts).
func WithAuthorizeURL(u string) OAuthOption { return func(c *OAuthClient) { c.authorizeURL = u } }

// WithOAuthSleep injects the poll sleeper (tests use a no-op).
func WithOAuthSleep(f func(time.Duration)) OAuthOption { return func(c *OAuthClient) { c.sleep = f } }

// NewOAuthClient builds an OAuthClient from an idw-role config.
func NewOAuthClient(config *Config, opts ...OAuthOption) (*OAuthClient, error) {
	if config.OAuthClientID == "" || config.OAuthRedirectURI == "" {
		return nil, newConfigError("OAuthClient requires oauth_client_id + oauth_redirect_uri (idw role)")
	}
	c := &OAuthClient{
		config:       config,
		authorizeURL: DefaultAuthorizeURL,
		sleep:        time.Sleep,
	}
	for _, o := range opts {
		o(c)
	}
	if c.doer == nil {
		c.doer = &http.Client{Timeout: 60 * time.Second}
	}
	return c, nil
}

// OAuthClientFromConfig builds from an idw-role JSON config file.
func OAuthClientFromConfig(path string, opts ...OAuthOption) (*OAuthClient, error) {
	cfg, err := ConfigFromIdwFile(path)
	if err != nil {
		return nil, err
	}
	return NewOAuthClient(cfg, opts...)
}

// OAuthClientFromEnv builds from ALLUS_OAUTH_* env vars.
func OAuthClientFromEnv(opts ...OAuthOption) (*OAuthClient, error) {
	cfg, err := ConfigFromIdwEnv()
	if err != nil {
		return nil, err
	}
	return NewOAuthClient(cfg, opts...)
}

// AuthorizeURLOptions are the optional parameters for AuthorizeURL.
type AuthorizeURLOptions struct {
	Claims        []Claim
	State         string
	ResponseMode  string // "redirect" (default) | "detached"
	CodeChallenge string
	RedirectURI   string
}

// AuthorizeURL builds the consent-screen URL — the "Sign in with allme" button target.
func (c *OAuthClient) AuthorizeURL(mode string, opts *AuthorizeURLOptions) (string, error) {
	if mode != "signin" && mode != "one_time" && mode != "connect" {
		return "", newConfigError("invalid mode %q (expected signin | one_time | connect)", mode)
	}
	if opts == nil {
		opts = &AuthorizeURLOptions{}
	}
	responseMode := opts.ResponseMode
	if responseMode == "" {
		responseMode = "redirect"
	}
	if responseMode != "redirect" && responseMode != "detached" {
		return "", newConfigError("invalid response_mode %q (expected redirect | detached)", responseMode)
	}
	redirect := opts.RedirectURI
	if redirect == "" {
		redirect = c.config.OAuthRedirectURI
	}
	q := url.Values{}
	q.Set("client_id", c.config.OAuthClientID)
	q.Set("redirect_uri", redirect)
	q.Set("mode", mode)
	q.Set("response_mode", responseMode)
	if opts.State != "" {
		q.Set("state", opts.State)
	}
	if opts.CodeChallenge != "" {
		q.Set("code_challenge", opts.CodeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	if cleaned := cleanClaims(opts.Claims); len(cleaned) > 0 {
		b, err := json.Marshal(cleaned)
		if err != nil {
			return "", err
		}
		q.Set("claims", string(b))
	}
	return c.authorizeURL + "?" + q.Encode(), nil
}

func cleanClaims(claims []Claim) []map[string]any {
	out := []map[string]any{}
	for _, c := range claims {
		if c.Type == "" || nonClaimable[c.Type] {
			continue
		}
		entry := map[string]any{"type": c.Type}
		if c.Suggest != "" {
			entry["suggest"] = c.Suggest
		}
		if c.Required {
			entry["required"] = true
		}
		if c.Label != "" {
			entry["label"] = c.Label
		}
		out = append(out, entry)
		if len(out) >= maxClaims {
			break
		}
	}
	return out
}

// ExchangeCode swaps the authorization code for a token (POST /oauth2/token).
func (c *OAuthClient) ExchangeCode(code, codeVerifier string) (map[string]any, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", c.config.OAuthClientID)
	form.Set("code", code)
	form.Set("redirect_uri", c.config.OAuthRedirectURI)
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}
	if c.config.OAuthClientSecret != "" {
		form.Set("client_secret", c.config.OAuthClientSecret)
	}
	return c.postForm(c.apiURL()+"/oauth2/token", form, "token exchange")
}

// Userinfo reads the signed-in identity (GET /api/oauth/userinfo) with the RP token.
func (c *OAuthClient) Userinfo(accessToken string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, c.apiURL()+"/api/oauth/userinfo", nil)
	if err != nil {
		return nil, NewApiError(0, "", fmt.Sprintf("userinfo request build failed: %v", err))
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, NewApiError(0, "", fmt.Sprintf("userinfo request failed: %v", err))
	}
	return c.parse(resp, "userinfo")
}

// CompleteSignIn chains exchange + userinfo, decrypting one_time values via the configured app key.
func (c *OAuthClient) CompleteSignIn(code, codeVerifier string) (*SignInResult, error) {
	token, err := c.ExchangeCode(code, codeVerifier)
	if err != nil {
		return nil, err
	}
	accessToken, _ := token["access_token"].(string)
	if accessToken == "" {
		return nil, newAuthError("token exchange returned no access_token")
	}
	info, err := c.Userinfo(accessToken)
	if err != nil {
		return nil, err
	}
	mode, _ := info["mode"].(string)
	if mode == "" {
		mode, _ = token["mode"].(string)
	}
	res := &SignInResult{
		User: map[string]string{
			"sub":          asString(info["sub"]),
			"share_code":   asString(info["share_code"]),
			"display_name": asString(info["display_name"]),
		},
		Mode:      mode,
		TwoFactor: asBool(info["two_factor"]),
		Values:    map[string]string{},
	}
	if raw, ok := info["values"].(map[string]any); ok && len(raw) > 0 {
		vals, err := c.decryptValues(raw)
		if err != nil {
			return nil, err
		}
		res.Values = vals
	}
	return res, nil
}

func (c *OAuthClient) decryptValues(raw map[string]any) (map[string]string, error) {
	if c.config.OAuthPrivateKey == "" || c.config.OAuthKeyPassphrase == "" {
		return nil, newConfigError("one_time values present but oauth_private_key / oauth_key_passphrase not configured")
	}
	pem, err := os.ReadFile(c.config.OAuthPrivateKey)
	if err != nil {
		return nil, newConfigError("could not read oauth_private_key: %v", err)
	}
	key, err := LoadPrivateKey(pem, c.config.OAuthKeyPassphrase)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for slug, wrapper := range raw {
		pt, err := Decrypt(wrapper, key)
		if err != nil {
			return nil, err
		}
		out[slug] = pt
	}
	return out, nil
}

// PollResult polls /oauth2/result for a detached sign-in (single-delivery).
func (c *OAuthClient) PollResult(state string, timeout, interval time.Duration) (map[string]any, error) {
	if timeout <= 0 {
		timeout = 600 * time.Second
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	form := url.Values{}
	form.Set("client_id", c.config.OAuthClientID)
	form.Set("state", state)
	if c.config.OAuthClientSecret != "" {
		form.Set("client_secret", c.config.OAuthClientSecret)
	}
	deadline := time.Now().Add(timeout)
	for {
		resp, err := c.postRaw(c.apiURL()+"/oauth2/result", form)
		if err != nil {
			return nil, NewApiError(0, "", fmt.Sprintf("result poll failed: %v", err))
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case 200:
			m := parseJSONObject(body)
			if _, ok := m["code"]; ok {
				return m, nil
			}
		case 410:
			return nil, NewApiError(410, "oauth.result_expired", "detached sign-in expired before completion")
		case 202:
			// pending
		default:
			key, msg := errFromBody(body)
			if msg == "" {
				msg = fmt.Sprintf("result poll rejected (HTTP %d)", resp.StatusCode)
			}
			return nil, NewApiError(resp.StatusCode, key, msg)
		}
		if time.Now().After(deadline) {
			return nil, NewApiError(0, "", fmt.Sprintf("detached sign-in not completed within %s", timeout))
		}
		c.sleep(interval)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func (c *OAuthClient) apiURL() string { return strings.TrimRight(c.config.APIURL, "/") }

func (c *OAuthClient) postRaw(u string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return c.doer.Do(req)
}

func (c *OAuthClient) postForm(u string, form url.Values, what string) (map[string]any, error) {
	resp, err := c.postRaw(u, form)
	if err != nil {
		return nil, NewApiError(0, "", fmt.Sprintf("%s request failed: %v", what, err))
	}
	return c.parse(resp, what)
}

func (c *OAuthClient) parse(resp *http.Response, what string) (map[string]any, error) {
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return parseJSONObject(body), nil
	}
	key, msg := errFromBody(body)
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, newAuthError("%s rejected (HTTP %d) %s %s", what, resp.StatusCode, key, msg)
	}
	if msg == "" {
		msg = fmt.Sprintf("%s rejected (HTTP %d)", what, resp.StatusCode)
	}
	return nil, NewApiError(resp.StatusCode, key, msg)
}

func parseJSONObject(body []byte) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return map[string]any{}
	}
	return m
}

func errFromBody(body []byte) (string, string) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "", ""
	}
	key, _ := m["error_key"].(string)
	msg, _ := m["error"].(string)
	return key, msg
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}
