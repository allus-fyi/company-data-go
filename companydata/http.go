package companydata

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OAuth token + HTTP layer.
//
// HTTPClient is the thin transport every higher layer goes through. It owns:
//
//   - Auth — client_credentials only. On the first call (or when the cached
//     token is near expiry) it POSTs client_id/client_secret to
//     {api_url}/oauth2/token and caches the bearer token + its expiry. Refresh is
//     automatic and transparent; a 401 mid-flight triggers exactly one
//     refresh-and-retry, then surfaces as *AuthError.
//   - Format — sets Accept per Config.Format (application/json or
//     application/xml) and parses the body accordingly (the XML inverse mirrors
//     the platform serializer).
//   - Errors — maps non-2xx to the error taxonomy: 401 → refresh+retry then
//     *AuthError; 429 → read Retry-After and back off + retry a bounded number of
//     times, then *RateLimitError; any other non-2xx → *ApiError carrying the
//     body's error_key when present.
//
// Config-only key handling: the client id/secret come from Config,
// never a method argument.

const (
	// tokenExpirySkew refreshes the token a little before it actually expires so
	// an in-flight call never races the expiry boundary.
	tokenExpirySkew = 30 * time.Second
	// 429 backoff policy: bounded retries with a Retry-After-driven (or default)
	// sleep between attempts.
	defaultMaxRetries429 = 3
	defaultBackoff       = 1 * time.Second
	maxBackoff           = 60 * time.Second
)

// Doer is the minimal HTTP interface HTTPClient needs (so a fake can be injected
// in tests). The standard *http.Client satisfies it.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPClient is the authenticated JSON/XML transport for the company-data API.
type HTTPClient struct {
	config        *Config
	doer          Doer
	apiURL        string
	maxRetries429 int

	// Injectable for tests; default to time.Sleep / time.Now.
	sleep func(time.Duration)
	now   func() time.Time

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// httpOption configures an HTTPClient (test injection of the Doer / clocks).
type httpOption func(*HTTPClient)

// WithDoer injects a custom HTTP Doer (e.g. a fake transport for tests).
func WithDoer(d Doer) httpOption { return func(c *HTTPClient) { c.doer = d } }

// withSleep injects a sleep function (tests use a no-op).
func withSleep(s func(time.Duration)) httpOption { return func(c *HTTPClient) { c.sleep = s } }

// withNow injects a clock (tests advance it to drive token expiry).
func withNow(n func() time.Time) httpOption { return func(c *HTTPClient) { c.now = n } }

// NewHTTPClient builds an HTTPClient for the given config.
func NewHTTPClient(config *Config, opts ...httpOption) *HTTPClient {
	c := &HTTPClient{
		config:        config,
		apiURL:        strings.TrimRight(config.APIURL, "/"),
		maxRetries429: defaultMaxRetries429,
		sleep:         time.Sleep,
		now:           time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	if c.doer == nil {
		c.doer = &http.Client{Timeout: 60 * time.Second}
	}
	return c
}

// ── auth ──────────────────────────────────────────────────────────────────

func (c *HTTPClient) tokenValid() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token != "" && c.now().Before(c.tokenExpiry)
}

// fetchToken POSTs the client credentials to /oauth2/token and caches the result.
func (c *HTTPClient) fetchToken(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.config.ClientID)
	form.Set("client_secret", c.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", &AuthError{msg: "could not build token request: " + err.Error(), err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doer.Do(req)
	if err != nil {
		return "", &AuthError{msg: "token request failed: " + err.Error(), err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errorKey, message := extractError(body, c.config.Format)
		return "", newAuthError("token request rejected (HTTP %d)%s%s", resp.StatusCode,
			bracket(errorKey), colon(message))
	}

	var parsed struct {
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", newAuthError("token response was not valid JSON")
	}
	if parsed.AccessToken == "" {
		return "", newAuthError("token response missing access_token")
	}
	expiresIn := parsed.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	c.mu.Lock()
	c.token = parsed.AccessToken
	ttl := time.Duration(expiresIn)*time.Second - tokenExpirySkew
	if ttl < 0 {
		ttl = 0
	}
	c.tokenExpiry = c.now().Add(ttl)
	tok := c.token
	c.mu.Unlock()
	return tok, nil
}

// bearer returns a valid token, fetching/refreshing when needed.
func (c *HTTPClient) bearer(ctx context.Context, forceRefresh bool) (string, error) {
	if !forceRefresh && c.tokenValid() {
		c.mu.Lock()
		tok := c.token
		c.mu.Unlock()
		return tok, nil
	}
	return c.fetchToken(ctx)
}

// ── requests ────────────────────────────────────────────────────────────────

// Get GETs path (e.g. /api/company-data/connections) → parsed body
// (map[string]any / []any / scalar). Adds the bearer token + an Accept header
// matching Config.Format, parses JSON or XML, and maps non-2xx responses to the
// SDK error types. params may be nil.
func (c *HTTPClient) Get(ctx context.Context, path string, params url.Values) (any, error) {
	wantsXML := c.config.Format == "xml"
	accept := "application/json"
	if wantsXML {
		accept = "application/xml"
	}

	retries429 := 0
	refreshed401 := false
	for {
		token, err := c.bearer(ctx, false)
		if err != nil {
			return nil, err
		}
		reqURL := c.url(path)
		if len(params) > 0 {
			reqURL += "?" + params.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, NewApiError(0, "", "request to "+path+" failed: "+err.Error())
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", accept)

		resp, err := c.doer.Do(req)
		if err != nil {
			return nil, NewApiError(0, "", "request to "+path+" failed: "+err.Error())
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		status := resp.StatusCode

		switch {
		case status >= 200 && status < 300:
			return parseBody(body, wantsXML)

		case status == 401:
			// One refresh-and-retry, then give up as AuthError.
			if !refreshed401 {
				refreshed401 = true
				if _, rerr := c.bearer(ctx, true); rerr != nil {
					return nil, rerr
				}
				continue
			}
			errorKey, message := extractError(body, c.config.Format)
			return nil, newAuthError("unauthorized after token refresh%s%s", bracket(errorKey), colon(message))

		case status == 429:
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			if retries429 < c.maxRetries429 {
				retries429++
				c.sleep(backoffDelay(retryAfter, retries429))
				continue
			}
			errorKey, message := extractError(body, c.config.Format)
			return nil, NewRateLimitError(retryAfter, errorKey, message)

		default:
			errorKey, message := extractError(body, c.config.Format)
			return nil, NewApiError(status, errorKey, message)
		}
	}
}

func (c *HTTPClient) url(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return c.apiURL + path
	}
	return c.apiURL + "/" + path
}

// parseBody parses a 2xx response body as JSON or XML.
func parseBody(body []byte, wantsXML bool) (any, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return map[string]any{}, nil
	}
	if wantsXML {
		return parseXML(text)
	}
	var out any
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, NewApiError(0, "", "response was not valid JSON: "+err.Error())
	}
	return out, nil
}

// ── module helpers ──────────────────────────────────────────────────────────

// extractError pulls error_key + a message out of a non-2xx body (JSON or XML).
func extractError(body []byte, format string) (errorKey, message string) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "", ""
	}
	var parsed any
	if format == "xml" && strings.HasPrefix(text, "<") {
		p, err := parseXML(text)
		if err != nil {
			return "", text
		}
		parsed = p
	} else {
		var j any
		dec := json.NewDecoder(strings.NewReader(text))
		dec.UseNumber()
		if err := dec.Decode(&j); err != nil {
			// Maybe an XML body delivered with a JSON format setting (best effort).
			if strings.HasPrefix(text, "<") {
				if p, perr := parseXML(text); perr == nil {
					parsed = p
				} else {
					return "", text
				}
			} else {
				return "", text
			}
		} else {
			parsed = j
		}
	}
	m, ok := parsed.(map[string]any)
	if !ok {
		return "", ""
	}
	if v, ok := m["error_key"].(string); ok {
		errorKey = v
	}
	if v, ok := m["error"].(string); ok {
		message = v
	} else if v, ok := m["message"].(string); ok {
		message = v
	}
	return errorKey, message
}

// parseRetryAfter parses the Retry-After header (delta-seconds form) → *float64.
// An HTTP-date Retry-After is allowed by spec but the platform sends
// delta-seconds; a date yields nil (default backoff).
func parseRetryAfter(raw string) *float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil
	}
	return &v
}

// backoffDelay is the sleep before the next 429 retry: honor Retry-After when
// present, otherwise exponential backoff capped at maxBackoff.
func backoffDelay(retryAfter *float64, attempt int) time.Duration {
	if retryAfter != nil && *retryAfter >= 0 {
		d := time.Duration(*retryAfter * float64(time.Second))
		if d > maxBackoff {
			d = maxBackoff
		}
		return d
	}
	d := defaultBackoff * (1 << (attempt - 1))
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func bracket(s string) string {
	if s == "" {
		return ""
	}
	return " [" + s + "]"
}

func colon(s string) string {
	if s == "" {
		return ""
	}
	return ": " + s
}
