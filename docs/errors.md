# Errors

The §9 error taxonomy, as idiomatic Go error types. Every error type has a
sentinel (`Err*`) for `errors.Is`, and the concrete types extract their carried
fields with `errors.As`. The names + behavior match all six SDKs.

| Error type | Sentinel | Carried fields | When |
|------------|----------|----------------|------|
| `*ConfigError` | `ErrConfig` | — (wraps a cause via `Unwrap`) | Missing/invalid config or key file at construction (fail fast). |
| `*AuthError` | `ErrAuth` | — | Token fetch/refresh failed (bad client_id/secret, revoked client; a 401 that survived one refresh-and-retry). |
| `*ApiError` | `ErrAPI` | `Status int`, `ErrorKey string`, `Message string` | Any non-2xx from the API. |
| `*DecryptError` | `ErrDecrypt` | — | Wrapper malformed, wrong key, or GCM tag mismatch. |
| `*WebhookError` | `ErrWebhook` | — | Signature verification failed or an envelope couldn't be unwrapped. |
| `*RateLimitError` | `ErrRateLimit` (and `ErrAPI`) | embeds `*ApiError` (Status 429) + `RetryAfter *float64` | A 429 from a rate-limited endpoint. |

## Matching with `errors.Is`

```go
if errors.Is(err, companydata.ErrConfig)   { /* fix the config / PEM */ }
if errors.Is(err, companydata.ErrAuth)     { /* check client_id / client_secret */ }
if errors.Is(err, companydata.ErrRateLimit){ /* back off */ }
```

A `*RateLimitError` matches **both** `ErrRateLimit` and `ErrAPI` (it embeds
`*ApiError`), so generic API handling and specific rate-limit handling both work.

## Extracting fields with `errors.As`

```go
var apiErr *companydata.ApiError
if errors.As(err, &apiErr) {
    log.Printf("API %d %s: %s", apiErr.Status, apiErr.ErrorKey, apiErr.Message)
}

var rl *companydata.RateLimitError
if errors.As(err, &rl) {
    if rl.RetryAfter != nil {
        time.Sleep(time.Duration(*rl.RetryAfter) * time.Second)
    }
}
```

## Behavior notes

- **`ConfigError` is fail-fast** — a bad passphrase, an unreadable PEM, a missing
  required field, or an invalid `format` all surface here at construction
  (`FromConfig` / `New`), before any network call. A bad service-key passphrase
  is reported as `*ConfigError` (it wraps the underlying `*DecryptError`).
- **`AuthError`** is returned after the one automatic refresh-and-retry on a 401
  fails, or when `/oauth2/token` rejects the credentials.
- **`RateLimitError`** is surfaced only after the transport's bounded internal
  429 backoff is exhausted; on the changes feed the SDK keeps retrying within
  reason, and the connections iterator backs off per `Retry-After` before
  surfacing it (the connections endpoints are expensive snapshots, not a poll
  target).
- **`DecryptError`** inside the changes pump is contained: a poison (undecryptable)
  buffered event is dead-lettered immediately rather than wedging the stream (see
  [pump](pump.md)).
