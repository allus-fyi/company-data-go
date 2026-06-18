package companydata

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// HTTP/auth layer tests. A fake Doer records requests and
// replays scripted responses so we can exercise the client_credentials token
// fetch + caching, 401 → one refresh-and-retry → AuthError, 429 → Retry-After
// backoff → retry / RateLimitError, ApiError mapping (carrying the body
// error_key), and the JSON/XML accept + parse paths. No live API.

type fakeResponse struct {
	status  int
	body    string
	headers map[string]string
}

type fakeDoer struct {
	tokenResponses []fakeResponse // FIFO for POST /oauth2/token
	getResponses   []fakeResponse // FIFO for GET
	posts          []*http.Request
	gets           []*http.Request
}

func (d *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	var queue *[]fakeResponse
	if req.Method == http.MethodPost {
		d.posts = append(d.posts, req)
		queue = &d.tokenResponses
	} else {
		d.gets = append(d.gets, req)
		queue = &d.getResponses
	}
	if len(*queue) == 0 {
		return nil, errors.New("no scripted response")
	}
	fr := (*queue)[0]
	*queue = (*queue)[1:]
	h := http.Header{}
	for k, v := range fr.headers {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: fr.status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(fr.body)),
	}, nil
}

func tokenOK() fakeResponse {
	return fakeResponse{status: 200, body: `{"access_token":"tok-123","token_type":"Bearer","expires_in":3600}`}
}

func newTestHTTP(t *testing.T, d *fakeDoer, format string, sleeps *[]time.Duration) *HTTPClient {
	t.Helper()
	cfg := &Config{
		APIURL:            "https://api.allme.fyi",
		ClientID:          "svc_abc",
		ClientSecret:      "topsecret",
		ServicePrivateKey: "k.pem",
		KeyPassphrase:     "pp",
		Format:            format,
	}
	opts := []httpOption{WithDoer(d)}
	if sleeps != nil {
		opts = append(opts, withSleep(func(dur time.Duration) { *sleeps = append(*sleeps, dur) }))
	}
	return NewHTTPClient(cfg, opts...)
}

func TestTokenFetchedWithClientCredentialsAndAttached(t *testing.T) {
	d := &fakeDoer{tokenResponses: []fakeResponse{tokenOK()}, getResponses: []fakeResponse{{status: 200, body: `{"ok":true}`}}}
	c := newTestHTTP(t, d, "json", nil)
	body, err := c.Get(context.Background(), "/api/company-data/connections", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if m, ok := body.(map[string]any); !ok || m["ok"] != true {
		t.Fatalf("body = %#v", body)
	}
	if len(d.posts) != 1 {
		t.Fatalf("expected 1 token POST, got %d", len(d.posts))
	}
	// The bearer token was attached to the GET.
	if got := d.gets[0].Header.Get("Authorization"); got != "Bearer tok-123" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := d.gets[0].Header.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept = %q", got)
	}
}

func TestTokenCachedAcrossCalls(t *testing.T) {
	d := &fakeDoer{
		tokenResponses: []fakeResponse{tokenOK()},
		getResponses:   []fakeResponse{{status: 200, body: `{}`}, {status: 200, body: `{}`}},
	}
	c := newTestHTTP(t, d, "json", nil)
	_, _ = c.Get(context.Background(), "/a", nil)
	_, _ = c.Get(context.Background(), "/b", nil)
	if len(d.posts) != 1 {
		t.Fatalf("token should be fetched once, got %d POSTs", len(d.posts))
	}
}

func TestTokenRefetchedWhenExpired(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	d := &fakeDoer{
		tokenResponses: []fakeResponse{
			{status: 200, body: `{"access_token":"tok-A","expires_in":60}`},
			{status: 200, body: `{"access_token":"tok-B","expires_in":60}`},
		},
		getResponses: []fakeResponse{{status: 200, body: `{}`}, {status: 200, body: `{}`}},
	}
	cfg := &Config{APIURL: "https://api.allme.fyi", ClientID: "x", ClientSecret: "s", ServicePrivateKey: "k", KeyPassphrase: "p", Format: "json"}
	c := NewHTTPClient(cfg, WithDoer(d), withNow(func() time.Time { return now }))
	_, _ = c.Get(context.Background(), "/a", nil) // fetches tok-A (expiry now+30s with skew)
	if d.gets[0].Header.Get("Authorization") != "Bearer tok-A" {
		t.Fatalf("first call should use tok-A")
	}
	// Advance the clock past expiry → next call refetches.
	now = now.Add(120 * time.Second)
	_, _ = c.Get(context.Background(), "/b", nil)
	if len(d.posts) != 2 {
		t.Fatalf("expected token refetch, got %d POSTs", len(d.posts))
	}
	if d.gets[1].Header.Get("Authorization") != "Bearer tok-B" {
		t.Fatalf("second call should use tok-B, got %q", d.gets[1].Header.Get("Authorization"))
	}
}

func TestTokenFetchFailureRaisesAuthError(t *testing.T) {
	d := &fakeDoer{tokenResponses: []fakeResponse{{status: 401, body: `{"error_key":"oauth.bad_client","error":"nope"}`}}}
	c := newTestHTTP(t, d, "json", nil)
	_, err := c.Get(context.Background(), "/a", nil)
	if err == nil || !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth, got %v", err)
	}
}

func TestSingle401TriggersOneRefreshAndRetryThenSucceeds(t *testing.T) {
	d := &fakeDoer{
		tokenResponses: []fakeResponse{tokenOK(), tokenOK()},
		getResponses:   []fakeResponse{{status: 401, body: `{}`}, {status: 200, body: `{"ok":1}`}},
	}
	c := newTestHTTP(t, d, "json", nil)
	body, err := c.Get(context.Background(), "/a", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if m, ok := body.(map[string]any); !ok || m["ok"] == nil {
		t.Fatalf("body = %#v", body)
	}
	if len(d.posts) != 2 { // initial token + one refresh
		t.Fatalf("expected 2 token POSTs, got %d", len(d.posts))
	}
}

func TestDouble401RaisesAuthError(t *testing.T) {
	d := &fakeDoer{
		tokenResponses: []fakeResponse{tokenOK(), tokenOK()},
		getResponses:   []fakeResponse{{status: 401, body: `{}`}, {status: 401, body: `{"error_key":"expired"}`}},
	}
	c := newTestHTTP(t, d, "json", nil)
	_, err := c.Get(context.Background(), "/a", nil)
	if err == nil || !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth after refresh, got %v", err)
	}
}

func Test429WithRetryAfterBacksOffThenSucceeds(t *testing.T) {
	var sleeps []time.Duration
	d := &fakeDoer{
		tokenResponses: []fakeResponse{tokenOK()},
		getResponses: []fakeResponse{
			{status: 429, headers: map[string]string{"Retry-After": "2"}},
			{status: 200, body: `{"ok":1}`},
		},
	}
	c := newTestHTTP(t, d, "json", &sleeps)
	if _, err := c.Get(context.Background(), "/a", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Fatalf("expected one 2s backoff, got %v", sleeps)
	}
}

func Test429ExhaustsRetriesThenRaisesRateLimitError(t *testing.T) {
	var sleeps []time.Duration
	d := &fakeDoer{
		tokenResponses: []fakeResponse{tokenOK()},
		getResponses: []fakeResponse{
			{status: 429, headers: map[string]string{"Retry-After": "1"}},
			{status: 429, headers: map[string]string{"Retry-After": "1"}},
			{status: 429, headers: map[string]string{"Retry-After": "1"}},
			{status: 429, headers: map[string]string{"Retry-After": "1"}, body: `{"error_key":"rate_limited"}`},
		},
	}
	c := newTestHTTP(t, d, "json", &sleeps)
	_, err := c.Get(context.Background(), "/a", nil)
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("expected *RateLimitError, got %v", err)
	}
	if rl.RetryAfter == nil || *rl.RetryAfter != 1 {
		t.Fatalf("RetryAfter = %v", rl.RetryAfter)
	}
	if !errors.Is(err, ErrRateLimit) || !errors.Is(err, ErrAPI) {
		t.Fatalf("RateLimitError should match ErrRateLimit and ErrAPI")
	}
	if len(sleeps) != 3 { // default max 3 retries
		t.Fatalf("expected 3 backoffs, got %d", len(sleeps))
	}
}

func TestNon2xxMapsToApiErrorWithErrorKey(t *testing.T) {
	d := &fakeDoer{
		tokenResponses: []fakeResponse{tokenOK()},
		getResponses:   []fakeResponse{{status: 403, body: `{"error_key":"company_data.no_client","error":"denied"}`}},
	}
	c := newTestHTTP(t, d, "json", nil)
	_, err := c.Get(context.Background(), "/a", nil)
	var apiErr *ApiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *ApiError, got %v", err)
	}
	if apiErr.Status != 403 || apiErr.ErrorKey != "company_data.no_client" || apiErr.Message != "denied" {
		t.Fatalf("ApiError mismatch: %+v", apiErr)
	}
}

func TestXMLAcceptHeaderAndParsing(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<response><request_fields>` +
		`<item><slug>work_email</slug><label>Work email</label><type>email</type>` +
		`<one_time>false</one_time><mandatory_provide>true</mandatory_provide>` +
		`<mandatory_connected>false</mandatory_connected></item>` +
		`<item><slug>logo</slug><label>Logo</label><type>photo</type>` +
		`<one_time>false</one_time><mandatory_provide>false</mandatory_provide>` +
		`<mandatory_connected>false</mandatory_connected></item>` +
		`</request_fields></response>`
	d := &fakeDoer{tokenResponses: []fakeResponse{tokenOK()}, getResponses: []fakeResponse{{status: 200, body: xml}}}
	c := newTestHTTP(t, d, "xml", nil)
	body, err := c.Get(context.Background(), "/api/company-data/request-fields", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := d.gets[0].Header.Get("Accept"); got != "application/xml" {
		t.Fatalf("Accept = %q", got)
	}
	m := body.(map[string]any)
	fields := m["request_fields"].([]any)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}
	f0 := fields[0].(map[string]any)
	if f0["slug"] != "work_email" || f0["type"] != "email" {
		t.Fatalf("field0 = %#v", f0)
	}
	// Booleans come back as the "true"/"false" strings the API wrote.
	if f0["one_time"] != "false" || f0["mandatory_provide"] != "true" {
		t.Fatalf("xml bool strings = %#v", f0)
	}
}

func TestXMLErrorBodyCarriesErrorKey(t *testing.T) {
	xml := `<?xml version="1.0"?><response><error>nope</error><error_key>company_data.no_client</error_key></response>`
	d := &fakeDoer{tokenResponses: []fakeResponse{tokenOK()}, getResponses: []fakeResponse{{status: 403, body: xml}}}
	c := newTestHTTP(t, d, "xml", nil)
	_, err := c.Get(context.Background(), "/a", nil)
	var apiErr *ApiError
	if !errors.As(err, &apiErr) || apiErr.ErrorKey != "company_data.no_client" {
		t.Fatalf("expected XML error_key, got %v", err)
	}
}

func TestXMLSingleItemListIsStillAList(t *testing.T) {
	xml := `<?xml version="1.0"?><response><changes><item><id>c1</id>` +
		`<event>connection_created</event><person_user_id>u1</person_user_id></item></changes></response>`
	d := &fakeDoer{tokenResponses: []fakeResponse{tokenOK()}, getResponses: []fakeResponse{{status: 200, body: xml}}}
	c := newTestHTTP(t, d, "xml", nil)
	body, err := c.Get(context.Background(), "/api/company-data/changes", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	changes := body.(map[string]any)["changes"]
	lst, ok := changes.([]any)
	if !ok || len(lst) != 1 {
		t.Fatalf("expected single-item list, got %#v", changes)
	}
}
