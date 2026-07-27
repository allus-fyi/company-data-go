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

// Claim is a claim the relying party asks for — a REQUEST FIELD (#498).
//
// You describe what you need: a Name (the claim's identity on the wire), a field Type, an advisory
// Suggest-ion, whether it is Required, and whether only a #311-Verified answer will do. You never
// name one of the person's fields — THEY decide which of theirs answers it.
//
// Name is MANDATORY and must be unique within one request: everything downstream is keyed by it (the
// stored mapping, the consent outcome, and the Values/Attestations maps CompleteSignIn returns). Two
// claims sharing a name are rejected rather than silently coalesced.
//
// Verified is accepted only where it can be honoured (#498 §3.1b): on the OIDC flow, and only for a
// type #311 can attest (v1: email). Sending it on a one_time request is refused with
// invalid_request — that leg carries no source row id, so the server could neither enforce the
// requirement nor attest it, and an unhonourable requirement is refused rather than quietly dropped.
type Claim struct {
	// Name is REQUIRED — the claim's identity on the wire; Values/Attestations are keyed by it.
	Name     string
	Type     string
	Suggest  string
	Required bool
	// Verified: only a #311-verified answer satisfies this claim. OIDC flow + verifiable types only.
	Verified bool
	Label    string
}

// Attestation is proof that a delivered value is the #311-verified one (#498 §3.1a).
//
// Present only for a Verified claim under ENCRYPTED delivery. The server builds and seals it against
// your app key — a client-supplied attestation is never accepted — so it attests the server's own
// record of the row the person chose, which is the only thing that makes it evidence.
//
// Verified is computed BY THIS SDK, in constant time, over the plaintext it just decrypted; it is
// never passed through from the server. A Verified==false entry means MISMATCH and the RP MUST
// reject the value. A claim ABSENT from Attestations means "not attested" — never "wrong" — and must
// be treated as unverified.
//
// VerifiedAt carries the snapshot caveat: it attests the value as verified AT THAT MOMENT, not
// verified today. A field loses its verification whenever the person re-saves it.
type Attestation struct {
	// Verified is recomputed here: sha256(salt ‖ plaintext) == hash, constant-time.
	Verified bool
	// Hash is lowercase hex.
	Hash string
	// Salt is lowercase hex.
	Salt       string
	VerifiedAt string
}

// SignInResult is the decrypted conclusion of CompleteSignIn.
//
// #498 §5: User["sub"] IS the person's SHARE CODE and is byte-identical to the id_token's sub;
// "share_code" is retained beside it and now simply equals it. "display_name" is GONE — it is a
// consented name claim now, or nothing: ask for Claim{Name: "name", Type: "text"} and read
// Values["name"].
type SignInResult struct {
	User      map[string]string
	Mode      string
	TwoFactor bool
	// Values maps claim name → plaintext. Unchanged by #498.
	Values map[string]string
	// Attestations maps claim name → Attestation, keyed by the SAME slug as Values (#498 §3.1a).
	// Additive: an integration that never reads it behaves exactly as before. ABSENT = not attested.
	Attestations map[string]Attestation
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
	if mode != "signin" && mode != "one_time" && mode != "connect" && mode != "2fa_enroll" {
		return "", newConfigError("invalid mode %q (expected signin | one_time | connect | 2fa_enroll)", mode)
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
	cleaned, err := cleanClaims(opts.Claims)
	if err != nil {
		return "", err
	}
	if len(cleaned) > 0 {
		b, err := json.Marshal(cleaned)
		if err != nil {
			return "", err
		}
		q.Set("claims", string(b))
	}
	return c.authorizeURL + "?" + q.Encode(), nil
}

func cleanClaims(claims []Claim) ([]map[string]any, error) {
	out := []map[string]any{}
	seen := map[string]bool{}
	for _, c := range claims {
		if c.Type == "" || nonClaimable[c.Type] {
			continue
		}
		// #498 §2: Name is the claim's identity and it is mandatory. Refused HERE rather than left
		// to the API, so the integration error surfaces at the call that made it.
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return nil, newConfigError("every claim must carry a `Name` (#498)")
		}
		if seen[name] {
			return nil, newConfigError("duplicate claim name %q (#498)", name)
		}
		seen[name] = true
		entry := map[string]any{"name": name, "type": c.Type}
		if c.Suggest != "" {
			entry["suggest"] = c.Suggest
		}
		if c.Required {
			entry["required"] = true
		}
		if c.Verified {
			entry["verified"] = true
		}
		if c.Label != "" {
			entry["label"] = c.Label
		}
		out = append(out, entry)
		if len(out) >= maxClaims {
			break
		}
	}
	return out, nil
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
			"sub":        asString(info["sub"]),
			"share_code": asString(info["share_code"]),
		},
		Mode:         mode,
		TwoFactor:    asBool(info["two_factor"]),
		Values:       map[string]string{},
		Attestations: map[string]Attestation{},
	}
	if raw, ok := info["values"].(map[string]any); ok && len(raw) > 0 {
		vals, err := c.decryptValues(raw)
		if err != nil {
			return nil, err
		}
		res.Values = vals
		if rawAttest, ok := info["values_attestation"].(map[string]any); ok && len(rawAttest) > 0 {
			att, err := c.decryptAttestations(rawAttest, vals)
			if err != nil {
				return nil, err
			}
			res.Attestations = att
		}
	}
	return res, nil
}

// decryptAttestations opens the app-key-sealed attestations and attests each value itself (#498 §3.1a).
//
// A SECOND decrypt per verified claim: Values is byte-identical to before, but each attestation is
// its own {"_enc":1,...} object. A passthrough accessor handing back an undecrypted blob would not be
// an implementation of this.
//
// An attestation that cannot be opened or parsed is DROPPED, not surfaced as Verified==false —
// absence means "not attested" and a mismatch means "reject the value", and conflating the two would
// turn a key or transport problem into an accusation that the data was tampered with.
func (c *OAuthClient) decryptAttestations(raw map[string]any, values map[string]string) (map[string]Attestation, error) {
	pem, err := os.ReadFile(c.config.OAuthPrivateKey)
	if err != nil {
		return nil, newConfigError("could not read oauth_private_key: %v", err)
	}
	key, err := LoadPrivateKey(pem, c.config.OAuthKeyPassphrase)
	if err != nil {
		return nil, err
	}
	out := map[string]Attestation{}
	for slug, wrapper := range raw {
		plaintext, ok := values[slug]
		if !ok {
			continue
		}
		opened, err := Decrypt(wrapper, key)
		if err != nil {
			continue
		}
		var parsed struct {
			Hash       string `json:"hash"`
			Salt       string `json:"salt"`
			VerifiedAt string `json:"verified_at"`
		}
		if err := json.Unmarshal([]byte(opened), &parsed); err != nil {
			continue
		}
		if parsed.Hash == "" || parsed.Salt == "" {
			continue
		}
		out[slug] = Attestation{
			// Recomputed here, constant-time, over the plaintext just decrypted — never trusted
			// from the server. false = the delivered value is NOT the verified one; reject it.
			Verified:   HashMatches(parsed.Salt, parsed.Hash, plaintext),
			Hash:       parsed.Hash,
			Salt:       parsed.Salt,
			VerifiedAt: parsed.VerifiedAt,
		}
	}
	return out, nil
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

// PollResult polls /oauth2/result for a detached sign-in or enrollment (single-delivery). A detached
// sign-in returns {code, state}; a detached 2fa_enroll returns {enrolled: true, state} (#481). It
// returns on the first delivered shape (code OR enrolled) and never polls past it, so a one-shot
// enrollment result is not consumed and lost.
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
			// #481: return on the first delivered terminal shape — a sign-in `code` OR a
			// 2fa_enroll `enrolled` sentinel ({enrolled: true, state}). Both are one-shot;
			// returning here (rather than looping) keeps a one-shot enrollment result from
			// being consumed and lost to a timeout.
			if asString(m["code"]) != "" || asBool(m["enrolled"]) {
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
