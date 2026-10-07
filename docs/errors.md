# Errors

The §9 error taxonomy, as idiomatic Go error types. Every error type has a
sentinel (`Err*`) for `errors.Is`, and the concrete types extract their carried
fields with `errors.As`. The names + behavior match all six SDKs.

| Error type | Sentinel | Carried fields | When |
|------------|----------|----------------|------|
| `*ConfigError` | `ErrConfig` | — (wraps a cause via `Unwrap`) | Missing/invalid config or key file at construction (fail fast). |
| `*AuthError` | `ErrAuth` | — | Token fetch/refresh failed (bad client_id/secret, revoked client; a 401 that survived one refresh-and-retry). |
| `*ApiError` | `ErrAPI` | `Status int`, `ErrorKey string`, `Message string`, `Details map[string]any` | Any non-2xx from the API. |
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

// Details carries whatever the error body held beside the key and the message.
// A 410 company_data.file_expired (a frozen share-once binary answer past its
// 90-day retention) names the file it can no longer serve:
if errors.As(err, &apiErr) && apiErr.ErrorKey == "company_data.file_expired" {
    sum, _ := apiErr.Details["content_sha256"].(string)
    at, _ := apiErr.Details["expired_at"].(string)
    log.Printf("slot file expired at %s; archived copy should hash to %s", at, sum)
}

var rl *companydata.RateLimitError
if errors.As(err, &rl) {
    if rl.RetryAfter != nil {
        time.Sleep(time.Duration(*rl.RetryAfter) * time.Second)
    }
}
```

## Behavior notes

- **`ApiError.Details` is `nil` when the body carried nothing extra**, which reads
  the same as an empty map in Go — no nil check needed. Numbers inside it are
  `json.Number` (the decoder preserves the wire form), so type-assert to
  `json.Number` or `string`, not to `float64`.
- **A 421 `region.rebase_required` never reaches you when the platform is
  reachable**: it is the global front door telling the SDK to send the call to the
  caller's home region, which the SDK does automatically (README, **How it's
  wired** → Regions). It surfaces as `*ApiError` only when the base the refusal
  names is absent or empty — in which case no base was stored and no retry was made.
- **One request waits 45 seconds for the platform's answer.** The SDK's own
  transport — for `Client`, `CustomerClient` and `OAuthClient` alike — waits 45
  seconds for the platform's answer to one request, and the call then fails as it
  does when the connection drops; a `Doer` you pass with `WithDoer` or
  `WithOAuthDoer` keeps its own limit. A request given up may still have completed
  on the platform.
- **A connection closed before the answer is tried once more.** When the platform
  closes a reused connection before any byte of the answer arrives, the SDK sends
  the request once more on another connection and reports only the second failure.
  This also holds for a `Doer` you pass, as long as it sends with `net/http` (the
  SDK learns about reuse and the first byte from `net/http/httptrace`). A request is
  never sent again once any byte of its answer has arrived, after the 45 seconds
  ran out, or when the connection could not be opened. A request the platform acted on
  before its connection died with no answer at all runs twice.
- **A 503 `db.writes_paused` means saving is paused — retry it.** While the
  platform cannot complete a save in every region, a call can answer 503 with
  `ErrorKey` `db.writes_paused` ("Saving data is not possible right now") and the
  header `Retry-After: 30`. **Nothing was written**, so the call is safe to repeat
  exactly as it was; reads keep working. It surfaces as a plain `*ApiError`
  (`Status == 503`); the SDK does not retry it, and `*ApiError` does not carry the
  `Retry-After` header — wait 30 seconds, then repeat the same call. It can come
  from every company-data and customer call that is not a GET (documents, flow-run
  starts, answers, uploads and generation, consent answers, connect requests,
  messages, 2FA challenges, `/api/keys/batch`); from the change-feed drains
  `GET /api/company-data/changes` and `GET /api/customer/changes` (`ProcessChanges`,
  `DrainBatch`), where nothing was drained — the events stay queued on the server
  and arrive on a later run, and the local buffer is untouched; and from
  `OAuthClient.PollResult` (`POST /oauth2/result`), where the result is not
  consumed — poll again. The token request (`POST /oauth2/token`) does not answer
  it: token grants keep working while saving is paused.

  ```go
  var apiErr *companydata.ApiError
  if errors.As(err, &apiErr) && apiErr.Status == 503 && apiErr.ErrorKey == "db.writes_paused" {
      time.Sleep(30 * time.Second)
      // repeat the same call
  }
  ```
- **A 503 `platform.out_of_order` means the platform is out of order — retry
  it.** While the region serving a call is being rebuilt, the call answers 503
  with `ErrorKey` `platform.out_of_order` ("allme is temporarily out of order.
  Please try again later.") and the header `Retry-After: 300`. **The request was
  not processed**, so the call is safe to repeat exactly as it was; the platform
  answers normally again once the region is back in service. It surfaces as a
  plain `*ApiError` (`Status == 503`); the SDK does not retry it, and `*ApiError`
  does not carry the `Retry-After` header — wait 300 seconds, then repeat the same
  call. It can come from every company-data and customer call, reads included
  (connections, request fields, binary fetches, documents, flow runs, consent
  answers, connect requests, messages, 2FA challenges and results, `/api/keys`);
  from the change-feed drains `GET /api/company-data/changes` and
  `GET /api/customer/changes` (`ProcessChanges`, `DrainBatch`), where nothing was
  drained — the events stay queued on the server and arrive on a later run, and
  the local buffer is untouched; and from every `OAuthClient` call
  (`ExchangeCode`, `Userinfo`, `PollResult` — the result is not consumed; poll
  again). The `client_credentials` token request (`POST /oauth2/token`) the
  service and customer clients make does not answer it, so the SDK still holds a
  token and the 503 arrives on the call itself; every other grant at
  `POST /oauth2/token` — the `OAuthClient` code exchange, a refresh-token grant —
  answers it.

  ```go
  var apiErr *companydata.ApiError
  if errors.As(err, &apiErr) && apiErr.Status == 503 && apiErr.ErrorKey == "platform.out_of_order" {
      time.Sleep(300 * time.Second)
      // repeat the same call
  }
  ```
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
