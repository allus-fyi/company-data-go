package companydata

// "Sign in with allme" RP OAuth client tests (#195). Ports test_oauth.py.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type oauthFake struct {
	postQ []fakeResponse
	getQ  []fakeResponse
	posts []recordedReq
	gets  []recordedReq
}

type recordedReq struct {
	url  string
	form url.Values
}

func (d *oauthFake) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		var form url.Values
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			form, _ = url.ParseQuery(string(b))
		}
		d.posts = append(d.posts, recordedReq{url: req.URL.String(), form: form})
		if len(d.postQ) == 0 {
			return nil, errors.New("no scripted POST response")
		}
		fr := d.postQ[0]
		d.postQ = d.postQ[1:]
		return mkResp(fr), nil
	}
	d.gets = append(d.gets, recordedReq{url: req.URL.String()})
	if len(d.getQ) == 0 {
		return nil, errors.New("no scripted GET response")
	}
	fr := d.getQ[0]
	d.getQ = d.getQ[1:]
	return mkResp(fr), nil
}

func mkResp(fr fakeResponse) *http.Response {
	return &http.Response{StatusCode: fr.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(fr.body))}
}

func idwConfig(t *testing.T, overrides map[string]string) *Config {
	t.Helper()
	cfg := &Config{APIURL: "https://api.allme.fyi", OAuthClientID: "idw_abc123", OAuthRedirectURI: "https://shop.example/cb"}
	if p, ok := overrides["oauth_private_key"]; ok {
		cfg.OAuthPrivateKey = p
	}
	if p, ok := overrides["oauth_key_passphrase"]; ok {
		cfg.OAuthKeyPassphrase = p
	}
	return cfg
}

func TestIdwConfigRequiresFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	os.WriteFile(p, []byte(`{"api_url":"https://api.allme.fyi"}`), 0o600)
	if _, err := ConfigFromIdwFile(p); err == nil {
		t.Fatal("expected ConfigError for missing oauth_client_id")
	}
}

func TestAuthorizeURLSigninGolden(t *testing.T) {
	c, _ := NewOAuthClient(idwConfig(t, nil))
	got, err := c.AuthorizeURL("signin", &AuthorizeURLOptions{State: "st1"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	if u.Scheme+"://"+u.Host+u.Path != "https://web.allme.fyi/auth" {
		t.Fatalf("base = %s", u.Scheme+"://"+u.Host+u.Path)
	}
	q := u.Query()
	if q.Get("client_id") != "idw_abc123" || q.Get("mode") != "signin" || q.Get("response_mode") != "redirect" || q.Get("state") != "st1" {
		t.Fatalf("query = %v", q)
	}
	if q.Has("claims") {
		t.Fatal("no claims expected")
	}
}

func TestAuthorizeURLPKCEAndDetached(t *testing.T) {
	c, _ := NewOAuthClient(idwConfig(t, nil))
	got, _ := c.AuthorizeURL("signin", &AuthorizeURLOptions{ResponseMode: "detached", CodeChallenge: "CH"})
	q, _ := url.Parse(got)
	if q.Query().Get("response_mode") != "detached" || q.Query().Get("code_challenge") != "CH" || q.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("query = %v", q.Query())
	}
}

func TestAuthorizeURLClaimValidation(t *testing.T) {
	c, _ := NewOAuthClient(idwConfig(t, nil))
	got, _ := c.AuthorizeURL("one_time", &AuthorizeURLOptions{Claims: []Claim{
		{Type: "email", Suggest: "email_personal"},
		{Type: "photo"},
		{Type: "phone", Required: true},
		{Type: ""},
	}})
	u, _ := url.Parse(got)
	var parsed []map[string]any
	json.Unmarshal([]byte(u.Query().Get("claims")), &parsed)
	if len(parsed) != 2 || parsed[0]["type"] != "email" || parsed[1]["type"] != "phone" {
		t.Fatalf("claims = %v", parsed)
	}
	if parsed[0]["suggest"] != "email_personal" || parsed[1]["required"] != true {
		t.Fatalf("claim details = %v", parsed)
	}
}

func TestAuthorizeURLCaps15(t *testing.T) {
	c, _ := NewOAuthClient(idwConfig(t, nil))
	var claims []Claim
	for i := 0; i < 30; i++ {
		claims = append(claims, Claim{Type: "text"})
	}
	got, _ := c.AuthorizeURL("one_time", &AuthorizeURLOptions{Claims: claims})
	u, _ := url.Parse(got)
	var parsed []map[string]any
	json.Unmarshal([]byte(u.Query().Get("claims")), &parsed)
	if len(parsed) != 15 {
		t.Fatalf("expected 15 claims, got %d", len(parsed))
	}
}

func TestAuthorizeURLInvalidMode(t *testing.T) {
	c, _ := NewOAuthClient(idwConfig(t, nil))
	if _, err := c.AuthorizeURL("bogus", nil); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestExchangeAndUserinfo(t *testing.T) {
	d := &oauthFake{
		postQ: []fakeResponse{{status: 200, body: `{"access_token":"AT","mode":"signin"}`}},
		getQ:  []fakeResponse{{status: 200, body: `{"sub":"u1","share_code":"AB12CD","display_name":"Alice","mode":"signin","two_factor":false}`}},
	}
	c, _ := NewOAuthClient(idwConfig(t, nil), WithOAuthDoer(d))
	tok, err := c.ExchangeCode("CODE", "V")
	if err != nil || tok["access_token"] != "AT" {
		t.Fatalf("exchange: %v %v", tok, err)
	}
	if d.posts[0].form.Get("grant_type") != "authorization_code" || d.posts[0].form.Get("code_verifier") != "V" {
		t.Fatalf("form = %v", d.posts[0].form)
	}
	info, err := c.Userinfo("AT")
	if err != nil || info["display_name"] != "Alice" {
		t.Fatalf("userinfo: %v %v", info, err)
	}
}

func TestCompleteSignInDecrypts(t *testing.T) {
	vec := loadVector(t)
	dir := t.TempDir()
	pem := filepath.Join(dir, "app.pem")
	os.WriteFile(pem, []byte(vec.EncryptedPrivateKeyPEM), 0o600)
	wrapperJSON, _ := json.Marshal(vec.Text.Wrapper)
	d := &oauthFake{
		postQ: []fakeResponse{{status: 200, body: `{"access_token":"AT","mode":"one_time"}`}},
		getQ: []fakeResponse{{status: 200, body: `{"sub":"u1","display_name":"Alice","mode":"one_time","two_factor":true,"values":{"email_personal":` + string(wrapperJSON) + `}}`}},
	}
	cfg := idwConfig(t, map[string]string{"oauth_private_key": pem, "oauth_key_passphrase": vec.Passphrase})
	c, _ := NewOAuthClient(cfg, WithOAuthDoer(d))
	out, err := c.CompleteSignIn("CODE", "V")
	if err != nil {
		t.Fatal(err)
	}
	if out.Mode != "one_time" || !out.TwoFactor || out.User["display_name"] != "Alice" {
		t.Fatalf("result = %+v", out)
	}
	if out.Values["email_personal"] != vec.Text.Plaintext {
		t.Fatalf("decrypted = %q want %q", out.Values["email_personal"], vec.Text.Plaintext)
	}
}

func TestPollResultPendingThenCode(t *testing.T) {
	d := &oauthFake{postQ: []fakeResponse{{status: 202}, {status: 202}, {status: 200, body: `{"code":"AUTHCODE","state":"DET1"}`}}}
	c, _ := NewOAuthClient(idwConfig(t, nil), WithOAuthDoer(d), WithOAuthSleep(func(time.Duration) {}))
	res, err := c.PollResult("DET1", 5*time.Second, time.Millisecond)
	if err != nil || res["code"] != "AUTHCODE" {
		t.Fatalf("poll: %v %v", res, err)
	}
	if len(d.posts) != 3 {
		t.Fatalf("expected 3 polls, got %d", len(d.posts))
	}
}

func TestPollResultExpired(t *testing.T) {
	d := &oauthFake{postQ: []fakeResponse{{status: 410, body: `{"error_key":"oauth.result_expired"}`}}}
	c, _ := NewOAuthClient(idwConfig(t, nil), WithOAuthDoer(d), WithOAuthSleep(func(time.Duration) {}))
	_, err := c.PollResult("DET1", 5*time.Second, time.Millisecond)
	var ae *ApiError
	if !errors.As(err, &ae) || ae.Status != 410 {
		t.Fatalf("expected ApiError 410, got %v", err)
	}
}
