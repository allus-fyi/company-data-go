# Webhooks

The lower-latency push alternative to polling the changes feed. The
platform delivers each change event to your configured webhook URL; these helpers
verify and parse it. **All secrets/keys come from config — the helpers take no
key or secret arguments.**

## Headers the platform sends

- `X-Allus-Webhook-Id` — which webhook this is (selects the HMAC secret from
  config).
- `X-Allus-Signature` — `HMAC-SHA256(rawBody, secret)` as lowercase hex.
- the body — the same slug-keyed `Change` shape as the feed (JSON or XML). If the
  webhook has `encrypt_payload` on, the body is replaced by a `{"_enc":1,…}`
  envelope encrypted to your **account** key (and the HMAC is then over that
  envelope — the final bytes that were sent).

## Methods

```go
client.VerifyWebhook(rawBody []byte, headers any) bool
client.ParseWebhook(rawBody []byte, headers any)  (Change, error)
client.HandleWebhook(rawBody []byte, headers any) (Change, error)  // verify + parse
```

`headers` may be a `map[string]string` or an `http.Header`
(`map[string][]string`). Lookups are case-insensitive.

- **Verify** reads `X-Allus-Webhook-Id`, looks up that webhook's HMAC secret in
  config (falling back to the single-webhook flat secret), recomputes
  `HMAC-SHA256(rawBody, secret)` and constant-time-compares it to
  `X-Allus-Signature` (tolerant of upper/lower-case hex). Returns `false` on a
  missing signature, unknown/unconfigured webhook id, or mismatch — it never
  returns an error for a bad signature (that's `HandleWebhook`'s job).
- **Parse** decodes the body (JSON or XML) → a `Change`. If it's an
  `encrypt_payload` envelope, it's unwrapped with the configured
  `account_private_key` first, then the inner field value (a service-key wrapper)
  is decrypted with the service key. A webhook `Change` is byte-identical to a
  feed `Change`.
- **Handle** = verify + parse in one call; returns a `*WebhookError`
  (`errors.Is(err, ErrWebhook)`) on a bad/unknown signature or an unwrappable
  envelope.

## In an http.HandlerFunc

```go
func webhook(client *companydata.Client) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        body, err := io.ReadAll(r.Body) // RAW bytes — the HMAC is over them
        if err != nil {
            http.Error(w, "read error", http.StatusBadRequest)
            return
        }
        change, err := client.HandleWebhook(body, r.Header)
        if err != nil {
            http.Error(w, "invalid webhook", http.StatusBadRequest)
            return
        }
        switch change.Event {
        case "field_updated":
            upsert(change.PersonID, change.Slug, change.Value)
        case "connection_created", "connection_deleted",
            "field_deleted", "consent_accepted", "consent_declined":
            // handle per your needs
        }
        w.WriteHeader(http.StatusOK)
    }
}
```

> Always read and pass the **raw** request bytes (`io.ReadAll(r.Body)`) — the HMAC
> is computed over the exact bytes that were sent, never the re-serialized parsed
> tree.

## Two OAEP hashes (a cross-language gotcha)

The crypto uses **two** distinct OAEP hashes, and the SDK gets both right:

- **Inner per-field values** (and all pull-API values) use **RSA-OAEP-SHA256**
  (MGF1-SHA256) with the **service** key — matching the platform's Web Crypto
  encryption.
- The optional **account-key webhook envelope** uses **RSA-OAEP-SHA1**
  (MGF1-SHA1) with the **account** key — OpenSSL's default OAEP padding.

You don't configure this — it's automatic. (It's documented here because it's the
non-obvious detail every language port has to pin explicitly.)

## XXE safety

XML webhook bodies are parsed with Go's `encoding/xml`, which is XXE-safe by
default: it does not resolve external entities or DTDs, so there is no entity
resolver to disable. The HMAC is always over the raw bytes, never the parsed
tree.

## Delivery contract — effectively unique, rarely replayed

Each queued event is POSTed **once**, and **only HTTP `200` counts as delivered** — a
`202`, a `204`, a 3xx redirect and every 4xx/5xx are all treated as a failure. On anything
other than `200` (or a timeout or connection error) the event is **not retried in place**:
it and the rest of the webhook's queue move to a durable server-side backlog and the
webhook is marked bad. The backlog is delivered later, either automatically when
the webhook next probes healthy, or when you drain it yourself with
`GET /api/company-data/changes?webhook_id=…` (delete-on-read).

So deliveries are **effectively unique** — with one rare exception. If your endpoint
processed an event but the platform never saw your `200` (your response timed out, or
you crashed after committing but before responding), the event is treated as failed
and replayed on recovery, so you receive it **again**. Nothing caps that at two: a
failed probe leaves its backlog row in place, so every later recovery attempt whose
`200` is likewise lost replays the same event once more. Inside that window the
contract is **at-least-once** — plan for one or more repeats, not for exactly one.

> **Do not use `change.ID` as an idempotency key here.** On the webhook path the id is
> neither reliably stable nor reliably fresh, and a receiver cannot tell which one it is
> holding. A **live** delivery is built with no change row behind it, so its id is minted
> for that single POST — the later replay of the same event is rebuilt from a durable
> backlog row and therefore carries a **different** id. But a replayed delivery carries
> **that row's** id, and the row stays in place until it is delivered successfully, so a
> re-attempted replay arrives with the **same** id — which changes again if the event is
> re-backlogged after a further failure. An id check therefore misses the duplicate you
> are most likely to see and matches only a rarer one; it is not a contract. If you need
> strict idempotency, key on the **content** — event + person + slug/document + payload —
> never on the id.

**Webhooks and the pull feed are alternative integrations — consume one, never both.**
The id-dedup guidance in [pump.md](pump.md) applies to the pump only, where `change.ID`
is the real server change-row id.

## Config

Webhook secrets and the optional account key live in config:

```json
{
  "webhooks": { "wh_abc123": "hmac_secret" },
  "account_private_key": "./account.pem",
  "account_passphrase": "…"
}
```

A single-webhook service can use a flat `"webhook_secret": "…"` instead of the
map. The account key is only needed for `encrypt_payload` webhooks; it is loaded
once at client construction (no per-request PBKDF2).
