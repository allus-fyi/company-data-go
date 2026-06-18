package companydata

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Config-loading tests. Mirrors the Python reference's test_config.

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestConfigFromFileLoadsAllFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.json", `{
		"api_url": "https://api.allme.fyi",
		"client_id": "svc_abc",
		"client_secret": "topsecret",
		"service_private_key": "./service.pem",
		"key_passphrase": "pp",
		"account_private_key": "./account.pem",
		"account_passphrase": "app",
		"webhooks": {"wh-1": "s1", "wh-2": "s2"},
		"cache_dir": "./cache",
		"format": "xml"
	}`)
	cfg, err := ConfigFromFile(cfgPath)
	if err != nil {
		t.Fatalf("ConfigFromFile: %v", err)
	}
	if cfg.APIURL != "https://api.allme.fyi" || cfg.ClientID != "svc_abc" || cfg.ClientSecret != "topsecret" {
		t.Fatalf("scalar mismatch: %+v", cfg)
	}
	if cfg.ServicePrivateKey != "./service.pem" || cfg.KeyPassphrase != "pp" {
		t.Fatalf("service key mismatch: %+v", cfg)
	}
	if cfg.AccountPrivateKey != "./account.pem" || cfg.AccountPassphrase != "app" {
		t.Fatalf("account key mismatch: %+v", cfg)
	}
	if cfg.Webhooks["wh-1"] != "s1" || cfg.Webhooks["wh-2"] != "s2" {
		t.Fatalf("webhooks mismatch: %+v", cfg.Webhooks)
	}
	if cfg.CacheDir != "./cache" || cfg.Format != "xml" {
		t.Fatalf("cache/format mismatch: %+v", cfg)
	}
}

func TestConfigOptionalFieldsDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.json", `{
		"api_url": "https://api.allme.fyi",
		"client_id": "x", "client_secret": "s",
		"service_private_key": "k.pem", "key_passphrase": "pp"
	}`)
	cfg, err := ConfigFromFile(cfgPath)
	if err != nil {
		t.Fatalf("ConfigFromFile: %v", err)
	}
	if cfg.CacheDir != "./allus-cache" {
		t.Fatalf("default cache_dir = %q", cfg.CacheDir)
	}
	if cfg.Format != "json" {
		t.Fatalf("default format = %q", cfg.Format)
	}
	if cfg.AccountPrivateKey != "" || len(cfg.Webhooks) != 0 {
		t.Fatalf("unexpected optional values set: %+v", cfg)
	}
}

func TestConfigEnvOverridesFileValues(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.json", `{
		"api_url": "https://file.example",
		"client_id": "file-id", "client_secret": "file-secret",
		"service_private_key": "k.pem", "key_passphrase": "file-pp"
	}`)
	t.Setenv(envClientSecret, "env-secret")
	t.Setenv(envKeyPassphrase, "env-pp")
	cfg, err := ConfigFromFile(cfgPath)
	if err != nil {
		t.Fatalf("ConfigFromFile: %v", err)
	}
	if cfg.ClientSecret != "env-secret" {
		t.Fatalf("client_secret not overridden: %q", cfg.ClientSecret)
	}
	if cfg.KeyPassphrase != "env-pp" {
		t.Fatalf("key_passphrase not overridden: %q", cfg.KeyPassphrase)
	}
	if cfg.ClientID != "file-id" {
		t.Fatalf("client_id should remain file value: %q", cfg.ClientID)
	}
}

func TestConfigFromEnvBuildsWithoutAFile(t *testing.T) {
	t.Setenv(envAPIURL, "https://env.example")
	t.Setenv(envClientID, "env-id")
	t.Setenv(envClientSecret, "env-secret")
	t.Setenv(envServicePrivateKey, "env.pem")
	t.Setenv(envKeyPassphrase, "env-pp")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.APIURL != "https://env.example" || cfg.ClientID != "env-id" {
		t.Fatalf("env build mismatch: %+v", cfg)
	}
}

func TestConfigMissingRequiredFieldFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.json", `{
		"api_url": "https://api.allme.fyi", "client_id": "x"
	}`)
	_, err := ConfigFromFile(cfgPath)
	if err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestConfigMissingFileFails(t *testing.T) {
	_, err := ConfigFromFile(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestConfigInvalidJSONFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.json", `{not json`)
	_, err := ConfigFromFile(cfgPath)
	if err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestConfigInvalidFormatFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.json", `{
		"api_url": "https://api.allme.fyi", "client_id": "x", "client_secret": "s",
		"service_private_key": "k.pem", "key_passphrase": "pp", "format": "yaml"
	}`)
	_, err := ConfigFromFile(cfgPath)
	if err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig, got %v", err)
	}
}

func TestConfigFlatWebhookSecretShortcut(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.json", `{
		"api_url": "https://api.allme.fyi", "client_id": "x", "client_secret": "s",
		"service_private_key": "k.pem", "key_passphrase": "pp",
		"webhook_secret": "flat-secret"
	}`)
	cfg, err := ConfigFromFile(cfgPath)
	if err != nil {
		t.Fatalf("ConfigFromFile: %v", err)
	}
	// The flat secret resolves for any (or no) webhook id.
	if cfg.WebhookSecret("") != "flat-secret" {
		t.Fatalf("flat secret not resolved for empty id: %q", cfg.WebhookSecret(""))
	}
	if cfg.WebhookSecret("any-id") != "flat-secret" {
		t.Fatalf("flat secret not resolved for id: %q", cfg.WebhookSecret("any-id"))
	}
}

func TestWebhookSecretIDSpecificThenFallback(t *testing.T) {
	cfg := &Config{Webhooks: map[string]string{"wh-1": "s1", singleWebhookKey: "flat"}}
	if got := cfg.WebhookSecret("wh-1"); got != "s1" {
		t.Fatalf("id-specific secret = %q", got)
	}
	if got := cfg.WebhookSecret("wh-unknown"); got != "flat" {
		t.Fatalf("fallback secret = %q", got)
	}
}
