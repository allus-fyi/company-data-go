package companydata

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/youmark/pkcs8"
)

// Webhook receiver-helper tests. No live API. We build fixture
// webhook requests the way the platform's webhook delivery does:
//
//   - body = the slug-keyed Change shape, JSON or XML;
//   - X-Allus-Signature = lowercase-hex HMAC-SHA256(body, secret);
//   - X-Allus-Webhook-Id selects the secret from config;
//   - for an encrypt_payload webhook the body is REPLACED by a {"_enc":1,...}
//     envelope encrypted to the company ACCOUNT public key with OAEP-SHA1 +
//     AES-256-GCM, and the HMAC is then over that envelope.
//
// The inner field value is a service-key wrapper (SHA-256), reusing the shared
// decryption vector — so a parsed webhook Change decrypts identically to a feed
// Change.

const (
	whSecret    = "wh_secret_abc123"
	whID        = "wh-1"
	acctPassphr = "acctpp"
)

func whConfig(t *testing.T, v *vectorDoc, extra func(*Config)) *Config {
	t.Helper()
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "service-key.pem")
	if err := os.WriteFile(pemPath, []byte(v.EncryptedPrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		APIURL:            "https://api.allme.fyi",
		ClientID:          "svc",
		ClientSecret:      "s",
		ServicePrivateKey: pemPath,
		KeyPassphrase:     v.Passphrase,
		CacheDir:          filepath.Join(dir, "cache"),
		Webhooks:          map[string]string{whID: whSecret},
	}
	if extra != nil {
		extra(cfg)
	}
	return cfg
}

func whTypeForSlug(slug string) string {
	return map[string]string{"work_email": "email", "logo": "photo"}[slug]
}

func sign(body []byte, secret string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func whHeaders(body []byte, secret, webhookID string, doSign bool) map[string]string {
	h := map[string]string{"X-Allus-Webhook-Id": webhookID, "X-Allus-Event": "field_updated"}
	if doSign {
		h["X-Allus-Signature"] = sign(body, secret)
	}
	return h
}

func changeBody(v *vectorDoc) []byte {
	payload := map[string]any{
		"id": "chg-1", "event": "field_updated", "person_user_id": "person-1",
		"slug": "work_email", "at": "2026-06-17T12:00:00Z", "live": true, "value": v.Text.Wrapper,
	}
	b, _ := json.Marshal(payload)
	return b
}

// ── verify ─────────────────────────────────────────────────────────────────

func TestVerifyTrueWithKnownSecret(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	body := changeBody(v)
	if !VerifyWebhook(body, whHeaders(body, whSecret, whID, true), cfg) {
		t.Fatal("expected verify true")
	}
}

func TestVerifyFalseOnTamperedBody(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	body := changeBody(v)
	headers := whHeaders(body, whSecret, whID, true) // signature for the ORIGINAL body
	tampered := append(body, ' ')
	if VerifyWebhook(tampered, headers, cfg) {
		t.Fatal("expected verify false on tampered body")
	}
}

func TestVerifyFalseOnUnknownWebhookID(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	body := changeBody(v)
	if VerifyWebhook(body, whHeaders(body, whSecret, "wh-UNKNOWN", true), cfg) {
		t.Fatal("expected verify false for unknown id")
	}
}

func TestVerifyFalseOnMissingSignature(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	body := changeBody(v)
	if VerifyWebhook(body, whHeaders(body, whSecret, whID, false), cfg) {
		t.Fatal("expected verify false without signature")
	}
}

func TestVerifyAcceptsUppercaseHex(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	body := changeBody(v)
	headers := map[string]string{"X-Allus-Webhook-Id": whID, "X-Allus-Signature": strings.ToUpper(sign(body, whSecret))}
	if !VerifyWebhook(body, headers, cfg) {
		t.Fatal("expected verify true for uppercase hex")
	}
}

func TestVerifySingleWebhookShortcut(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, func(c *Config) { c.Webhooks = map[string]string{singleWebhookKey: whSecret} })
	body := changeBody(v)
	// Header carries an id, but config has only the flat secret → falls back.
	if !VerifyWebhook(body, whHeaders(body, whSecret, whID, true), cfg) {
		t.Fatal("expected verify true via flat secret")
	}
}

func TestVerifyAcceptsHTTPHeader(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	body := changeBody(v)
	// Pass a REAL http.Header — a NAMED type, which a type switch on map[string][]string
	// does NOT match. This is the canonical client.HandleWebhook(body, r.Header) usage; a
	// plain map literal would NOT exercise it (regression: asHeaderMap dropped http.Header,
	// so r.Header yielded no headers → every delivery failed as a bad signature → 401).
	headers := http.Header{}
	headers.Set("X-Allus-Webhook-Id", whID)
	headers.Set("X-Allus-Signature", sign(body, whSecret))
	if !VerifyWebhook(body, headers, cfg) {
		t.Fatal("expected verify true with a real http.Header")
	}
}

// ── parse (plain JSON) ──────────────────────────────────────────────────────

func TestParsePlainJSONBody(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	decryptValue, _ := vectorDecryptValue(t, v)
	body := changeBody(v)
	change, err := ParseWebhook(body, whHeaders(body, whSecret, whID, true), cfg, whTypeForSlug, decryptValue, nil, nil)
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	if change.ID != "chg-1" || change.Event != "field_updated" || change.PersonID != "person-1" {
		t.Fatalf("change = %+v", change)
	}
	if change.Slug != "work_email" || change.Value != v.Text.Plaintext || !change.Live {
		t.Fatalf("change typing = %+v", change)
	}
}

func TestParseXMLBody(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	decryptValue, _ := vectorDecryptValue(t, v)
	w := v.Text.Wrapper
	xml := "<response>" +
		"<id>chg-7</id><event>field_updated</event><person_user_id>person-1</person_user_id>" +
		"<slug>work_email</slug><at>2026-06-17T12:00:00Z</at><live>true</live>" +
		"<value>" +
		"<_enc>1</_enc><k>" + w["k"].(string) + "</k><iv>" + w["iv"].(string) + "</iv><d>" + w["d"].(string) + "</d>" +
		"</value>" +
		"</response>"
	body := []byte(xml)
	change, err := ParseWebhook(body, whHeaders(body, whSecret, whID, true), cfg, whTypeForSlug, decryptValue, nil, nil)
	if err != nil {
		t.Fatalf("ParseWebhook XML: %v", err)
	}
	if change.ID != "chg-7" || change.Slug != "work_email" || change.Value != v.Text.Plaintext {
		t.Fatalf("xml change = %+v", change)
	}
}

// ── parse (account-key encrypt_payload envelope, OAEP-SHA1) ──────────────────

func makeAccountKey(t *testing.T, passphrase string) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pkcs8.MarshalPrivateKey(key, []byte(passphrase), nil) // PBES2 encrypted PKCS#8
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "account.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, &key.PublicKey
}

// wrapToAccountKey mimics the account-key envelope — OAEP-SHA1
// (MGF1-SHA1) + AES-256-GCM.
func wrapToAccountKey(t *testing.T, pub *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	ct := gcm.Seal(nil, iv, plaintext, nil)
	// OpenSSL's default OAEP padding is MGF1-SHA1.
	k, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP SHA1: %v", err)
	}
	envelope := map[string]any{
		"_enc": 1,
		"k":    base64.StdEncoding.EncodeToString(k),
		"iv":   base64.StdEncoding.EncodeToString(iv),
		"d":    base64.StdEncoding.EncodeToString(ct),
	}
	b, _ := json.Marshal(envelope)
	return b
}

func TestParseAccountKeyEnvelope(t *testing.T) {
	v := loadVector(t)
	acctPath, acctPub := makeAccountKey(t, acctPassphr)
	cfg := whConfig(t, v, func(c *Config) {
		c.AccountPrivateKey = acctPath
		c.AccountPassphrase = acctPassphr
	})
	decryptValue, _ := vectorDecryptValue(t, v)

	inner := changeBody(v)                           // the serialized change (JSON)
	body := wrapToAccountKey(t, acctPub, inner)      // the envelope IS the sent body
	headers := whHeaders(body, whSecret, whID, true) // HMAC over the envelope

	if !VerifyWebhook(body, headers, cfg) {
		t.Fatal("verify should pass (HMAC over envelope)")
	}
	change, err := ParseWebhook(body, headers, cfg, whTypeForSlug, decryptValue, nil, nil)
	if err != nil {
		t.Fatalf("ParseWebhook envelope: %v", err)
	}
	if change.ID != "chg-1" || change.Slug != "work_email" {
		t.Fatalf("change = %+v", change)
	}
	// OUTER envelope is account-key (SHA-1); INNER value is service-key (SHA-256).
	if change.Value != v.Text.Plaintext {
		t.Fatalf("inner value = %#v", change.Value)
	}
}

func TestParseAccountEnvelopeWithoutAccountKeyFails(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil) // no account_private_key configured
	decryptValue, _ := vectorDecryptValue(t, v)
	_, acctPub := makeAccountKey(t, "x")
	body := wrapToAccountKey(t, acctPub, changeBody(v))
	_, err := ParseWebhook(body, whHeaders(body, whSecret, whID, true), cfg, whTypeForSlug, decryptValue, nil, nil)
	if err == nil || !errors.Is(err, ErrWebhook) {
		t.Fatalf("expected ErrWebhook, got %v", err)
	}
}

// ── handle = verify + parse ─────────────────────────────────────────────────

func TestHandleVerifyThenParse(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	decryptValue, _ := vectorDecryptValue(t, v)
	body := changeBody(v)
	change, err := HandleWebhook(body, whHeaders(body, whSecret, whID, true), cfg, whTypeForSlug, decryptValue, nil, nil)
	if err != nil {
		t.Fatalf("HandleWebhook: %v", err)
	}
	if change.ID != "chg-1" {
		t.Fatalf("change.ID = %q", change.ID)
	}
}

func TestHandleBadSignatureFails(t *testing.T) {
	v := loadVector(t)
	cfg := whConfig(t, v, nil)
	decryptValue, _ := vectorDecryptValue(t, v)
	body := changeBody(v)
	headers := whHeaders(body, whSecret, whID, true)
	headers["X-Allus-Signature"] = "deadbeef" // wrong
	_, err := HandleWebhook(body, headers, cfg, whTypeForSlug, decryptValue, nil, nil)
	if err == nil || !errors.Is(err, ErrWebhook) {
		t.Fatalf("expected ErrWebhook, got %v", err)
	}
}

// ── alternative webhook auth methods (bearer / basic / header / none) ────────
//
// Mirrors the Python tests at the bottom of test_webhooks.py.

// authCfg builds a minimal Config carrying one alt-auth field. verify never
// reads the PEM here, so the service key path is a throwaway (mirrors the Python
// _auth_cfg, which constructs Config directly to bypass _build validation).
func authCfg(apply func(*Config)) *Config {
	cfg := &Config{
		APIURL:            "https://api.allme.fyi",
		ClientID:          "svc",
		ClientSecret:      "s",
		ServicePrivateKey: "unused.pem",
		KeyPassphrase:     "unused",
	}
	apply(cfg)
	return cfg
}

// fullRaw builds a rawConfig with a real service PEM plus extra overrides, for
// the config-validation tests (mirrors the Python _full_data + Config._build).
func fullRaw(t *testing.T, v *vectorDoc, apply func(*rawConfig)) *rawConfig {
	t.Helper()
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(pemPath, []byte(v.EncryptedPrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := &rawConfig{
		APIURL:            "https://api.allme.fyi",
		ClientID:          "svc",
		ClientSecret:      "s",
		ServicePrivateKey: pemPath,
		KeyPassphrase:     v.Passphrase,
	}
	apply(raw)
	return raw
}

func TestVerifyBearerTrue(t *testing.T) {
	cfg := authCfg(func(c *Config) { c.WebhookBearerToken = "tok123" })
	if !VerifyWebhook([]byte("{}"), map[string]string{"Authorization": "Bearer tok123"}, cfg) {
		t.Fatal("expected bearer verify true")
	}
}

func TestVerifyBearerFalseWrongToken(t *testing.T) {
	cfg := authCfg(func(c *Config) { c.WebhookBearerToken = "tok123" })
	if VerifyWebhook([]byte("{}"), map[string]string{"Authorization": "Bearer nope"}, cfg) {
		t.Fatal("expected bearer verify false for wrong token")
	}
}

func TestVerifyBearerFalseMissingHeader(t *testing.T) {
	cfg := authCfg(func(c *Config) { c.WebhookBearerToken = "tok123" })
	if VerifyWebhook([]byte("{}"), map[string]string{}, cfg) {
		t.Fatal("expected bearer verify false with no Authorization header")
	}
}

func TestVerifyBasicTrue(t *testing.T) {
	cfg := authCfg(func(c *Config) { c.WebhookBasic = &WebhookBasicAuth{Username: "u", Password: "p"} })
	token := base64.StdEncoding.EncodeToString([]byte("u:p"))
	if !VerifyWebhook([]byte("{}"), map[string]string{"Authorization": "Basic " + token}, cfg) {
		t.Fatal("expected basic verify true")
	}
}

func TestVerifyBasicFalseWrongPassword(t *testing.T) {
	cfg := authCfg(func(c *Config) { c.WebhookBasic = &WebhookBasicAuth{Username: "u", Password: "p"} })
	bad := base64.StdEncoding.EncodeToString([]byte("u:wrong"))
	if VerifyWebhook([]byte("{}"), map[string]string{"Authorization": "Basic " + bad}, cfg) {
		t.Fatal("expected basic verify false for wrong password")
	}
}

func TestVerifyHeaderTrueCaseInsensitiveName(t *testing.T) {
	cfg := authCfg(func(c *Config) { c.WebhookHeader = &WebhookHeaderAuth{Name: "X-My-Auth", Value: "sekret"} })
	if !VerifyWebhook([]byte("{}"), map[string]string{"x-my-auth": "sekret"}, cfg) {
		t.Fatal("expected header verify true (case-insensitive name)")
	}
}

func TestVerifyHeaderFalseWrongValue(t *testing.T) {
	cfg := authCfg(func(c *Config) { c.WebhookHeader = &WebhookHeaderAuth{Name: "X-My-Auth", Value: "sekret"} })
	if VerifyWebhook([]byte("{}"), map[string]string{"X-My-Auth": "nope"}, cfg) {
		t.Fatal("expected header verify false for wrong value")
	}
}

func TestVerifyNoneAlwaysTrue(t *testing.T) {
	cfg := authCfg(func(c *Config) { c.WebhookAuthNone = true })
	if !VerifyWebhook([]byte("anything at all"), map[string]string{}, cfg) {
		t.Fatal("expected none verify always true")
	}
}

func TestVerifyNoMethodConfiguredFalse(t *testing.T) {
	cfg := authCfg(func(c *Config) {})
	if VerifyWebhook([]byte("{}"), map[string]string{"Authorization": "Bearer x"}, cfg) {
		t.Fatal("expected verify false with no method configured")
	}
}

func TestConfigRejectsTwoAuthMethods(t *testing.T) {
	v := loadVector(t)
	raw := fullRaw(t, v, func(r *rawConfig) {
		r.WebhookSecret = "h"
		r.WebhookBearerToken = "b"
	})
	if _, err := buildConfig(raw); err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for two methods, got %v", err)
	}
}

func TestConfigRejectsBearerPlusNone(t *testing.T) {
	v := loadVector(t)
	raw := fullRaw(t, v, func(r *rawConfig) {
		r.WebhookBearerToken = "b"
		r.WebhookAuthNone = true
	})
	if _, err := buildConfig(raw); err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for bearer+none, got %v", err)
	}
}

func TestConfigBasicRequiresBothFields(t *testing.T) {
	v := loadVector(t)
	raw := fullRaw(t, v, func(r *rawConfig) { r.WebhookBasic = json.RawMessage(`{"username":"u"}`) })
	if _, err := buildConfig(raw); err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for basic missing password, got %v", err)
	}
}

func TestConfigHeaderRequiresBothFields(t *testing.T) {
	v := loadVector(t)
	raw := fullRaw(t, v, func(r *rawConfig) { r.WebhookHeader = json.RawMessage(`{"name":"X-H"}`) })
	if _, err := buildConfig(raw); err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for header missing value, got %v", err)
	}
}

func TestConfigSingleMethodOKAndMethodName(t *testing.T) {
	v := loadVector(t)

	cfg, err := buildConfig(fullRaw(t, v, func(r *rawConfig) { r.WebhookBearerToken = "b" }))
	if err != nil {
		t.Fatalf("buildConfig bearer: %v", err)
	}
	if cfg.WebhookAuthMethod() != "bearer" {
		t.Fatalf("method = %q, want bearer", cfg.WebhookAuthMethod())
	}

	cfg2, err := buildConfig(fullRaw(t, v, func(r *rawConfig) { r.WebhookSecret = "h" }))
	if err != nil {
		t.Fatalf("buildConfig hmac: %v", err)
	}
	if cfg2.WebhookAuthMethod() != "hmac" {
		t.Fatalf("method = %q, want hmac", cfg2.WebhookAuthMethod())
	}

	cfg3, err := buildConfig(fullRaw(t, v, func(r *rawConfig) { r.WebhookAuthNone = true }))
	if err != nil {
		t.Fatalf("buildConfig none: %v", err)
	}
	if cfg3.WebhookAuthMethod() != "none" {
		t.Fatalf("method = %q, want none", cfg3.WebhookAuthMethod())
	}
}
