package companydata

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"

	"github.com/youmark/pkcs8"
)

// Webhook receiver helpers.
//
// The lower-latency push alternative to polling the changes feed. The platform
// delivers each change event to the company's configured webhook URL with:
//
//   - X-Allus-Webhook-Id  — which webhook this is (selects the HMAC secret).
//   - X-Allus-Signature   — HMAC-SHA256(rawBody, secret) as lowercase hex.
//   - the body — the same slug-keyed Change shape as the pull feed,
//     JSON or XML. If the webhook has
//     encrypt_payload on, the body is REPLACED by a {"_enc":1,...} envelope
//     encrypted to the company ACCOUNT key (and the HMAC is then over that
//     envelope — the final body that was sent).
//
// All secrets/keys come from Config. These helpers take NO key or
// secret arguments — only the raw body, the headers, the config, and (for value
// typing) the same decrypt/type closures the Client already holds.
//
// The account-key envelope is webhook-specific: the platform wraps it with
// OpenSSL's DEFAULT OAEP padding (MGF1-SHA1), NOT the SHA-256 wrapper used for
// person field values (the account-key envelope uses OpenSSL's
// OPENSSL_PKCS1_OAEP_PADDING). So unwrapping the envelope uses an OAEP-SHA1 path
// here, while the inner field value (still a service-key wrapper) decrypts with
// the normal SHA-256 Decrypt.

const (
	hdrWebhookID = "x-allus-webhook-id"
	hdrSignature = "x-allus-signature"
)

// header is a case-insensitive header lookup (frameworks normalize casing
// inconsistently). headers may be a map[string]string or map[string][]string
// (the latter is net/http's http.Header).
func header(headers map[string][]string, name string) string {
	target := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == target && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// asHeaderMap normalizes various header inputs into map[string][]string.
func asHeaderMap(headers any) map[string][]string {
	switch h := headers.(type) {
	case map[string][]string:
		return h
	case map[string]string:
		out := make(map[string][]string, len(h))
		for k, v := range h {
			out[k] = []string{v}
		}
		return out
	default:
		return nil
	}
}

// VerifyWebhook verifies the X-Allus-Signature HMAC over the raw body.
//
// Reads X-Allus-Webhook-Id, looks up that webhook's HMAC secret in config
// (falling back to the single-webhook shortcut), recomputes
// HMAC-SHA256(rawBody, secret) as hex, and constant-time-compares it to the
// X-Allus-Signature header. Returns false on a missing signature,
// unknown/unconfigured webhook id, or mismatch — never returns an error for a
// bad signature (that is HandleWebhook's job).
//
// headers may be a map[string]string or map[string][]string (e.g. http.Header).
func VerifyWebhook(rawBody []byte, headers any, config *Config) bool {
	hmap := asHeaderMap(headers)
	signature := header(hmap, hdrSignature)
	if signature == "" {
		return false
	}
	webhookID := header(hmap, hdrWebhookID)
	secret := config.WebhookSecret(webhookID)
	if secret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(rawBody)
	expected := hex.EncodeToString(mac.Sum(nil))
	// Constant-time compare (case-insensitive hex, like the platform's output).
	got := strings.ToLower(strings.TrimSpace(signature))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}

// ParseWebhook parses a webhook body → a typed Change.
//
// Does NOT verify the signature (use HandleWebhook for verify+parse). Handles
// JSON and XML bodies, and an encrypt_payload account-key envelope: if the
// (JSON) body is a {"_enc":1,...} wrapper, it is first unwrapped with the account
// private key (OAEP-SHA1) into the inner serialized payload, which is then
// parsed. The inner field value (a service-key wrapper) is decrypted by the same
// factory the feed uses, so a webhook Change is byte-identical to a feed Change.
//
// This is the package-level helper; callers usually use the Client methods,
// which supply the decrypt/type closures + the cached account key from config.
func ParseWebhook(rawBody []byte, headers any, config *Config, typeForSlug typeForSlugFn, decryptValue decryptValueFn, binaryFetch binaryFetchFn, accountKey *rsa.PrivateKey) (Change, error) {
	payload, err := decodeWebhookPayload(rawBody, config, accountKey)
	if err != nil {
		return Change{}, err
	}
	m, ok := payload.(map[string]any)
	if !ok {
		return Change{}, newWebhookError("webhook payload is not a JSON/XML object")
	}
	return changeFromAPI(m, typeForSlug, decryptValue, binaryFetch)
}

// HandleWebhook verifies + parses a webhook in one call. Returns a
// *WebhookError on a bad/unknown signature; otherwise the typed Change. The
// typical one-liner inside a webhook route.
func HandleWebhook(rawBody []byte, headers any, config *Config, typeForSlug typeForSlugFn, decryptValue decryptValueFn, binaryFetch binaryFetchFn, accountKey *rsa.PrivateKey) (Change, error) {
	if !VerifyWebhook(rawBody, headers, config) {
		return Change{}, newWebhookError("webhook signature verification failed")
	}
	return ParseWebhook(rawBody, headers, config, typeForSlug, decryptValue, binaryFetch, accountKey)
}

// ── payload decoding (JSON / XML / encrypt_payload envelope) ────────────────

// decodeWebhookPayload decodes the raw body into the change map, unwrapping an
// account envelope first when present.
func decodeWebhookPayload(body []byte, config *Config, accountKey *rsa.PrivateKey) (any, error) {
	text := strings.TrimSpace(string(body))

	// An encrypt_payload envelope is always JSON ({"_enc":1,...}). Detect +
	// unwrap it before anything else (the inner payload is then JSON or XML).
	if strings.HasPrefix(text, "{") {
		var obj map[string]any
		dec := json.NewDecoder(strings.NewReader(text))
		dec.UseNumber()
		if err := dec.Decode(&obj); err != nil {
			return nil, newWebhookError("webhook body is not valid JSON: %v", err)
		}
		if isEnvelope(obj) {
			inner, err := unwrapAccountEnvelope(obj, config, accountKey)
			if err != nil {
				return nil, err
			}
			return decodeInner(inner)
		}
		return obj, nil
	}

	// Otherwise an XML body (the platform's <response> serialization).
	if strings.HasPrefix(text, "<") {
		parsed, err := parseXML(text)
		if err != nil {
			return nil, newWebhookError("webhook body is not valid XML: %v", err)
		}
		return parsed, nil
	}

	return nil, newWebhookError("webhook body is neither JSON nor XML")
}

// isEnvelope reports whether obj is a {"_enc":1, k, iv, d} account envelope.
func isEnvelope(obj map[string]any) bool {
	enc, ok := obj["_enc"]
	if !ok {
		return false
	}
	if !numEquals(enc, 1) {
		return false
	}
	for _, f := range []string{"k", "iv", "d"} {
		if _, ok := obj[f]; !ok {
			return false
		}
	}
	return true
}

func numEquals(v any, want int) bool {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return err == nil && int(i) == want
	case float64:
		return int(n) == want
	case int:
		return n == want
	}
	return false
}

// decodeInner parses the decrypted inner payload (JSON or XML).
func decodeInner(innerText string) (any, error) {
	stripped := strings.TrimSpace(innerText)
	if strings.HasPrefix(stripped, "<") {
		parsed, err := parseXML(stripped)
		if err != nil {
			return nil, newWebhookError("decrypted webhook payload is not valid XML: %v", err)
		}
		return parsed, nil
	}
	var out any
	dec := json.NewDecoder(strings.NewReader(stripped))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, newWebhookError("decrypted webhook payload is not valid JSON: %v", err)
	}
	return out, nil
}

// ── account-key envelope unwrap (OAEP-SHA1 — webhook-specific) ──────────────

// LoadAccountKey loads the account private key from config ONCE (or nil if not
// configured). Reused by the Client so an encrypt_payload webhook never re-reads
// the PEM + re-runs PBKDF2 (~100k iters) per request — the account key is loaded
// a single time at client construction, exactly like the service key. Returns
// nil when no AccountPrivateKey is configured. Returns a *WebhookError on a read
// / passphrase / PEM problem.
func LoadAccountKey(config *Config) (*rsa.PrivateKey, error) {
	if config.AccountPrivateKey == "" {
		return nil, nil
	}
	data, err := os.ReadFile(config.AccountPrivateKey)
	if err != nil {
		return nil, newWebhookError("could not read account_private_key PEM: %s: %v", config.AccountPrivateKey, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, newWebhookError("account_private_key PEM has no PEM block")
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(config.AccountPassphrase))
	if err != nil {
		return nil, newWebhookError("could not load account private key: %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, newWebhookError("account PEM did not contain an RSA private key")
	}
	return rsaKey, nil
}

// unwrapAccountEnvelope decrypts an encrypt_payload envelope with the ACCOUNT key.
//
// The platform wraps the serialized payload to the company account PUBLIC key
// using OpenSSL's default OAEP (MGF1-SHA1) + AES-256-GCM. The hash here is SHA-1 (NOT
// the SHA-256 used for person field values) — the account key is webhook-only,
// so the difference is intentional. Config-only key handling: the account
// key/passphrase come from config, never a public-method argument.
//
// accountKey is the pre-loaded key the Client caches; when nil it is loaded from
// config on demand (the standalone-call path).
func unwrapAccountEnvelope(envelope map[string]any, config *Config, accountKey *rsa.PrivateKey) (string, error) {
	key := accountKey
	if key == nil {
		k, err := LoadAccountKey(config)
		if err != nil {
			return "", err
		}
		key = k
	}
	if key == nil {
		return "", newWebhookError("received an encrypt_payload webhook but no account_private_key is configured")
	}
	return decryptOAEPSHA1(envelope, key)
}

// decryptOAEPSHA1 RSA-OAEP(SHA-1, MGF1-SHA1) unwraps + AES-256-GCM decrypts →
// utf-8 string. Mirrors Decrypt but pins SHA-1 for the OAEP/MGF1 hash to match
// the account-key envelope (the only place the platform uses SHA-1 OAEP). Go's
// rsa.DecryptOAEP uses the same hash for the OAEP digest and MGF1, so passing
// sha1.New() is SHA-1/MGF1-SHA1.
func decryptOAEPSHA1(envelope map[string]any, key *rsa.PrivateKey) (string, error) {
	encKey, err := envB64(envelope["k"], "k")
	if err != nil {
		return "", err
	}
	iv, err := envB64(envelope["iv"], "iv")
	if err != nil {
		return "", err
	}
	ciphertextWithTag, err := envB64(envelope["d"], "d")
	if err != nil {
		return "", err
	}
	if len(iv) != gcmIVLen {
		return "", newWebhookError("envelope iv must be %d bytes, got %d", gcmIVLen, len(iv))
	}
	if len(ciphertextWithTag) < gcmTagLen {
		return "", newWebhookError("envelope ciphertext too short to contain a GCM tag")
	}

	aesKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, encKey, nil)
	if err != nil {
		return "", newWebhookError("account-key envelope RSA-OAEP unwrap failed (wrong account key?): %v", err)
	}
	if len(aesKey) != 32 {
		return "", newWebhookError("unwrapped envelope AES key must be 32 bytes, got %d", len(aesKey))
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", newWebhookError("envelope AES cipher init failed: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", newWebhookError("envelope GCM init failed: %v", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return "", newWebhookError("account-key envelope AES-GCM tag mismatch")
	}
	return string(plaintext), nil
}

func envB64(value any, name string) ([]byte, error) {
	s, ok := value.(string)
	if !ok {
		return nil, newWebhookError("envelope field %q must be a base64 string", name)
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, newWebhookError("envelope field %q is not valid base64", name)
	}
	return out, nil
}
