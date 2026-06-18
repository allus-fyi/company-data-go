package companydata

import (
	"encoding/json"
	"os"
	"strings"
)

// Configuration loading.
//
// Config-only key handling is a hard rule: no SDK function or method ever takes
// a key, passphrase, or secret as an argument. Everything cryptographic —
// decrypting the service PEM, decrypting field values, verifying the webhook
// HMAC, unwrapping the account-key envelope — is driven entirely by this
// config. The developer's only key responsibility is putting the right values
// here.
//
// A single JSON file holds everything; any field may be overridden by an
// ALLUS_* env var, so secrets needn't live in the file.

// singleWebhookKey is the reserved Webhooks map key under which a flat
// "webhook_secret" shortcut is stored.
const singleWebhookKey = "__single__"

// Env-var names that override the corresponding Config field.
const (
	envAPIURL            = "ALLUS_API_URL"
	envClientID          = "ALLUS_CLIENT_ID"
	envClientSecret      = "ALLUS_CLIENT_SECRET"
	envServicePrivateKey = "ALLUS_SERVICE_PRIVATE_KEY"
	envKeyPassphrase     = "ALLUS_KEY_PASSPHRASE"
	envAccountPrivateKey = "ALLUS_ACCOUNT_PRIVATE_KEY"
	envAccountPassphrase = "ALLUS_ACCOUNT_PASSPHRASE"
	envCacheDir          = "ALLUS_CACHE_DIR"
	envFormat            = "ALLUS_FORMAT"
	envWebhookSecret     = "ALLUS_WEBHOOK_SECRET"
)

// Config is the whole SDK configuration. Keys live here and
// nowhere else.
type Config struct {
	APIURL            string `json:"api_url"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	ServicePrivateKey string `json:"service_private_key"` // path to the OpenSSL-encrypted PKCS#8 PEM
	KeyPassphrase     string `json:"key_passphrase"`      // decrypts the service PEM in memory

	// Optional — only needed if you receive encrypt_payload webhooks.
	AccountPrivateKey string `json:"account_private_key,omitempty"`
	AccountPassphrase string `json:"account_passphrase,omitempty"`

	// Optional — per-webhook HMAC secrets keyed by webhook id; matched via the
	// X-Allus-Webhook-Id header. A single-webhook service can use the flat
	// "webhook_secret" shortcut, captured under the reserved singleWebhookKey.
	Webhooks map[string]string `json:"webhooks,omitempty"`

	// Optional — alternative webhook auth methods, mirroring the platform's
	// per-webhook delivery auth. Configure AT MOST ONE family among
	// hmac (webhooks/webhook_secret) | bearer | basic | header | none;
	// two or more → ConfigError. See WebhookAuthMethod().
	WebhookBearerToken string             `json:"webhook_bearer_token,omitempty"` // "Authorization: Bearer <token>"
	WebhookBasic       *WebhookBasicAuth  `json:"webhook_basic,omitempty"`        // {"username","password"} → Basic auth
	WebhookHeader      *WebhookHeaderAuth `json:"webhook_header,omitempty"`       // {"name","value"} → custom header
	WebhookAuthNone    bool               `json:"webhook_auth_none,omitempty"`    // explicit opt-out — verify always true

	// Durable local buffer for the changes pump. Defaults to
	// "./allus-cache".
	CacheDir string `json:"cache_dir,omitempty"`

	// Wire format json|xml (default json) — invisible in the output.
	Format string `json:"format,omitempty"`
}

// WebhookBasicAuth is the {"username","password"} shape for HTTP Basic webhook
// delivery auth.
type WebhookBasicAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// WebhookHeaderAuth is the {"name","value"} shape for a custom-header webhook
// delivery auth.
type WebhookHeaderAuth struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// rawConfig is the on-disk JSON shape (it also captures the flat
// "webhook_secret" shortcut, which Config folds into Webhooks). The webhook
// alt-auth objects are captured as raw json.RawMessage so an absent vs.
// present-but-malformed object can be told apart (the Python reference
// distinguishes data.get("webhook_basic") is None from a bad shape).
type rawConfig struct {
	APIURL             string            `json:"api_url"`
	ClientID           string            `json:"client_id"`
	ClientSecret       string            `json:"client_secret"`
	ServicePrivateKey  string            `json:"service_private_key"`
	KeyPassphrase      string            `json:"key_passphrase"`
	AccountPrivateKey  string            `json:"account_private_key"`
	AccountPassphrase  string            `json:"account_passphrase"`
	Webhooks           map[string]string `json:"webhooks"`
	WebhookSecret      string            `json:"webhook_secret"`
	WebhookBearerToken string            `json:"webhook_bearer_token"`
	WebhookBasic       json.RawMessage   `json:"webhook_basic"`
	WebhookHeader      json.RawMessage   `json:"webhook_header"`
	WebhookAuthNone    bool              `json:"webhook_auth_none"`
	CacheDir           string            `json:"cache_dir"`
	Format             string            `json:"format"`
}

// ConfigFromFile loads a Config from a JSON file; env vars override file
// values. A missing/invalid file or a missing required field returns a
// *ConfigError (fail fast).
func ConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newConfigError("config file not found: %s", path)
		}
		return nil, wrapConfigError(err, "could not read config file: %s", path)
	}
	var raw rawConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, newConfigError("config file is not valid JSON: %s: %v", path, err)
	}
	return buildConfig(&raw)
}

// ConfigFromEnv builds a Config entirely from ALLUS_* env vars.
func ConfigFromEnv() (*Config, error) {
	return buildConfig(&rawConfig{})
}

// buildConfig merges file values with env overrides, validates, and constructs.
func buildConfig(raw *rawConfig) (*Config, error) {
	cfg := &Config{
		APIURL:            firstNonEmpty(os.Getenv(envAPIURL), raw.APIURL),
		ClientID:          firstNonEmpty(os.Getenv(envClientID), raw.ClientID),
		ClientSecret:      firstNonEmpty(os.Getenv(envClientSecret), raw.ClientSecret),
		ServicePrivateKey: firstNonEmpty(os.Getenv(envServicePrivateKey), raw.ServicePrivateKey),
		KeyPassphrase:     firstNonEmpty(os.Getenv(envKeyPassphrase), raw.KeyPassphrase),
		AccountPrivateKey: firstNonEmpty(os.Getenv(envAccountPrivateKey), raw.AccountPrivateKey),
		AccountPassphrase: firstNonEmpty(os.Getenv(envAccountPassphrase), raw.AccountPassphrase),
		CacheDir:          firstNonEmpty(os.Getenv(envCacheDir), raw.CacheDir),
		Format:            firstNonEmpty(os.Getenv(envFormat), raw.Format),
	}

	// Webhook secrets: the "webhooks" map plus the flat "webhook_secret"
	// shortcut (and its env override), normalized into a single map.
	webhooks := map[string]string{}
	for k, v := range raw.Webhooks {
		webhooks[k] = v
	}
	flat := firstNonEmpty(os.Getenv(envWebhookSecret), raw.WebhookSecret)
	if flat != "" {
		webhooks[singleWebhookKey] = flat
	}
	if len(webhooks) > 0 {
		cfg.Webhooks = webhooks
	}

	// Alternative webhook auth methods (file-config only — NO env overrides).
	// Validate object shapes, mirroring the Python reference.
	if raw.WebhookBearerToken != "" {
		cfg.WebhookBearerToken = raw.WebhookBearerToken
	}

	if !isJSONNull(raw.WebhookBasic) {
		var basic WebhookBasicAuth
		if err := json.Unmarshal(raw.WebhookBasic, &basic); err != nil || basic.Username == "" || basic.Password == "" {
			return nil, newConfigError(`"webhook_basic" must be an object with non-empty "username" and "password"`)
		}
		cfg.WebhookBasic = &basic
	}

	if !isJSONNull(raw.WebhookHeader) {
		var hdr WebhookHeaderAuth
		if err := json.Unmarshal(raw.WebhookHeader, &hdr); err != nil || hdr.Name == "" || hdr.Value == "" {
			return nil, newConfigError(`"webhook_header" must be an object with non-empty "name" and "value"`)
		}
		cfg.WebhookHeader = &hdr
	}

	if raw.WebhookAuthNone {
		cfg.WebhookAuthNone = true
	}

	// At most one webhook auth method (family) may be configured.
	var present []string
	if len(cfg.Webhooks) > 0 {
		present = append(present, "hmac")
	}
	if cfg.WebhookBearerToken != "" {
		present = append(present, "bearer")
	}
	if cfg.WebhookBasic != nil {
		present = append(present, "basic")
	}
	if cfg.WebhookHeader != nil {
		present = append(present, "header")
	}
	if cfg.WebhookAuthNone {
		present = append(present, "none")
	}
	if len(present) > 1 {
		return nil, newConfigError("configure at most one webhook auth method (found: %s)", strings.Join(present, ", "))
	}

	// Defaults.
	if cfg.CacheDir == "" {
		cfg.CacheDir = "./allus-cache"
	}
	if cfg.Format == "" {
		cfg.Format = "json"
	} else {
		cfg.Format = strings.ToLower(cfg.Format)
		if cfg.Format != "json" && cfg.Format != "xml" {
			return nil, newConfigError("invalid \"format\": %q (expected one of [json xml])", cfg.Format)
		}
	}

	// Required fields (fail fast).
	var missing []string
	for _, f := range []struct {
		name string
		val  string
	}{
		{"api_url", cfg.APIURL},
		{"client_id", cfg.ClientID},
		{"client_secret", cfg.ClientSecret},
		{"service_private_key", cfg.ServicePrivateKey},
		{"key_passphrase", cfg.KeyPassphrase},
	} {
		if f.val == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return nil, newConfigError("missing required config field(s): %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

// WebhookSecret resolves the HMAC secret for a webhook id.
// Falls back to the single-webhook shortcut secret when there is no id or no
// id-specific match. The webhook helpers read this — application code never
// passes a secret in. Returns "" when no secret is configured.
func (c *Config) WebhookSecret(webhookID string) string {
	if webhookID != "" {
		if s, ok := c.Webhooks[webhookID]; ok {
			return s
		}
	}
	return c.Webhooks[singleWebhookKey]
}

// WebhookAuthMethod returns the single configured webhook auth method, or "" if
// none is set. One of "hmac" | "bearer" | "basic" | "header" | "none". Config
// loading guarantees at most one is configured, so the order here is only a
// tie-break that never triggers.
func (c *Config) WebhookAuthMethod() string {
	if c.WebhookAuthNone {
		return "none"
	}
	if c.WebhookBearerToken != "" {
		return "bearer"
	}
	if c.WebhookBasic != nil {
		return "basic"
	}
	if c.WebhookHeader != nil {
		return "header"
	}
	if len(c.Webhooks) > 0 {
		return "hmac"
	}
	return ""
}

// isJSONNull reports whether a json.RawMessage is absent or the JSON literal
// null — both treated as "not configured" (matching the Python reference, where
// data.get("webhook_basic") is None covers an absent key and an explicit null).
func isJSONNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// firstNonEmpty returns the first non-empty string of its arguments, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
