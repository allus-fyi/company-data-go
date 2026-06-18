# Config

Configuration loading. A single JSON file holds everything; any
field may be overridden by an `ALLUS_*` env var, so secrets needn't live in the
file.

> **Config-only key handling (a hard rule).** No SDK function or method ever
> takes a key, passphrase, or secret as an argument. Everything cryptographic —
> decrypting the service PEM, decrypting field values, verifying the webhook
> HMAC, unwrapping the account-key envelope — is driven entirely by this config.
> Your only key responsibility is putting the right values here. Keys never
> appear in application code.

## Constructors

```go
companydata.ConfigFromFile(path string) (*Config, error)   // load JSON, then apply env overrides
companydata.ConfigFromEnv()             (*Config, error)   // build entirely from ALLUS_* env vars
```

`companydata.FromConfig(path)` / `companydata.FromEnv()` are the usual entry
points — they call these internally and then build a `*Client`.

A missing/invalid config, an unknown `format`, or a missing required field
returns a `*ConfigError` (`errors.Is(err, ErrConfig)`) — fail fast.

## Fields

```go
type Config struct {
    APIURL            string            // required — API base, e.g. https://api.allme.fyi
    ClientID          string            // required — client_credentials id (one service)
    ClientSecret      string            // required
    ServicePrivateKey string            // required — path to the OpenSSL-encrypted PKCS#8 PEM
    KeyPassphrase     string            // required — decrypts the service PEM in memory

    AccountPrivateKey string            // optional — only for encrypt_payload webhooks
    AccountPassphrase string            // optional

    Webhooks map[string]string          // optional — webhook id -> HMAC secret

    CacheDir string                     // default "./allus-cache" — durable pump buffer
    Format   string                     // "json" (default) | "xml"
}
```

Required: `APIURL`, `ClientID`, `ClientSecret`, `ServicePrivateKey`,
`KeyPassphrase`.

## Env overrides

Every field is overridable; secrets are the common overrides. Env var names are
the `ALLUS_` prefix of the JSON field name:

| Field | Env var |
|-------|---------|
| `api_url` | `ALLUS_API_URL` |
| `client_id` | `ALLUS_CLIENT_ID` |
| `client_secret` | `ALLUS_CLIENT_SECRET` |
| `service_private_key` | `ALLUS_SERVICE_PRIVATE_KEY` |
| `key_passphrase` | `ALLUS_KEY_PASSPHRASE` |
| `account_private_key` | `ALLUS_ACCOUNT_PRIVATE_KEY` |
| `account_passphrase` | `ALLUS_ACCOUNT_PASSPHRASE` |
| `cache_dir` | `ALLUS_CACHE_DIR` |
| `format` | `ALLUS_FORMAT` |
| flat single-webhook secret | `ALLUS_WEBHOOK_SECRET` |

An env var, when set, overrides the file value for that field.

## Webhook secrets

Webhook HMAC secrets live in config (not in code). The SDK reads
`X-Allus-Webhook-Id` off an incoming request and looks up the matching secret in
`Webhooks`. A service with a single webhook can use a flat `"webhook_secret":
"…"` in the JSON (or `ALLUS_WEBHOOK_SECRET`) instead of the map — it is stored
under a reserved key and used as a fallback for any webhook id.

```go
secret := cfg.WebhookSecret(webhookID) // id-specific, then the flat fallback; "" if none
```

## The PEM

`ServicePrivateKey` is the OpenSSL-encrypted PKCS#8 PEM you download from the
portal: PBES2 = PBKDF2-HMAC-SHA256 + AES-256-CBC, 100k iterations. The SDK loads
it once at construction (via `github.com/youmark/pkcs8`, since Go's stdlib cannot
decrypt encrypted PKCS#8) into an in-memory RSA key; it is never written back to
disk in plaintext. A wrong passphrase / unreadable PEM is a `*ConfigError`.
