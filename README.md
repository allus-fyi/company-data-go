# allus company-data (Go)

The Go SDK for the **allus company-data API**. Point it at a JSON config file and
it hands back typed, plaintext, **your-slug-keyed conclusions**: for each
connected person, a map of *your request-field slug → plaintext value* (plus
whether the value is live and when it last changed).

The SDK hides everything else — the OAuth token, the field catalog, the id
plumbing, the hybrid decryption, binary fetching, the changes-queue mechanics,
JSON-vs-XML. The platform is **zero-knowledge**: the API only ever holds
ciphertext, so all decryption happens inside the SDK with your service private
key. **The person's own field choices are never exposed** — you only ever see the
request slots you configured.

> This SDK is one of six language ports (Python · Go · TypeScript · C# · Java ·
> PHP) that share an identical API surface. This manual is the Go view of it.

**Contents:** [TL;DR](#tldr--fetch-new-updates) · [Quickstart](#quickstart) ·
[Every call](#every-call) ·
[The typed value model](#the-typed-value-model) ·
[Company documents](#company-documents) ·
[The changes pump](#the-changes-pump) · [Webhooks](#webhooks) ·
[Rate limits](#rate-limits) · [Errors](#errors) · [How it's wired](#how-its-wired)

Deeper reference pages live in [`docs/`](docs/):
[config](docs/config.md) · [model](docs/model.md) · [pump](docs/pump.md) ·
[webhooks](docs/webhooks.md) · [errors](docs/errors.md).

---

## TL;DR — fetch new updates

```bash
go get github.com/allus-fyi/company-data-go@latest
```

Point a config.json at your service keys:

```json
{
  "api_url": "https://api.allme.fyi",
  "client_id": "svc_xxx",
  "client_secret": "xxx",
  "service_private_key": "/path/to/service.pem",
  "key_passphrase": "xxx",
  "cache_dir": "./allus-cache"
}
```

Drain everything new, handled one update at a time:

```go
client, err := companydata.FromConfig("config.json")
if err != nil {
    log.Fatal(err)
}

err = client.ProcessChanges(func(c companydata.Change) error {
    // c.Event, c.PersonID, c.ShareCode, c.Slug, c.Value, c.Live, c.At
    apply(c)
    return nil // returning nil ACKS; an error RETRIES → then dead-letters
}, companydata.PumpOptions{})
```

`ProcessChanges` pulls every pending change, decrypts it, and hands them to your
callback ONE BY ONE, acking each only after your code returns. Crash mid-batch?
The next run replays exactly what wasn't acked — nothing is lost, and the API
keeps no backlog of its own. Run it on a schedule (cron / systemd timer); there
is no daemon/follow mode by design. Connections, binary values, and webhooks are
documented below.

---

## Quickstart

Requires **Go ≥ 1.26**.

```bash
go get github.com/allus-fyi/company-data-go@latest
```

```go
import companydata "github.com/allus-fyi/company-data-go/companydata"
```

The module path is `github.com/allus-fyi/company-data-go`; everything is exported
from the single package `companydata`. No manual file includes — `go get` +
`import` just works.

### 1. Write a config file

A single JSON file holds everything. Any field can be overridden by an `ALLUS_*`
env var, so secrets needn't live in the file. **No SDK function or method ever
takes a key, passphrase, or secret as an argument** — they all come from here.

`allus.json`:

```json
{
  "api_url": "https://api.allme.fyi",
  "client_id": "svc_1a2b3c…",
  "client_secret": "…",
  "service_private_key": "./service-CRM.pem",
  "key_passphrase": "…",

  "account_private_key": "./account.pem",
  "account_passphrase": "…",

  "webhooks": {
    "wh_abc123": "hmac_secret_for_that_webhook"
  },

  "cache_dir": "./allus-cache",
  "format": "json"
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `api_url` | yes | API base, e.g. `https://api.allme.fyi`. |
| `client_id` / `client_secret` | yes | The registered `client_credentials` credentials for **one** service. |
| `service_private_key` | yes | Path to the OpenSSL-encrypted PKCS#8 PEM you downloaded from the portal. |
| `key_passphrase` | yes | Decrypts that PEM in memory at startup. |
| `account_private_key` / `account_passphrase` | only for `encrypt_payload` webhooks | The company **account** key, used to unwrap an encrypted webhook envelope. |
| `webhooks` / `webhook_secret` | webhook auth — HMAC (default) | Per-webhook HMAC secrets keyed by webhook id (matched via the `X-Allus-Webhook-Id` header). A single-webhook service can use a flat `"webhook_secret": "…"` instead of the map. |
| `webhook_bearer_token` | webhook auth — bearer | Verify `Authorization: Bearer <token>` deliveries. |
| `webhook_basic` | webhook auth — basic | `{"username","password"}` — verify HTTP Basic deliveries. |
| `webhook_header` | webhook auth — header | `{"name","value"}` — verify a custom-header delivery. |
| `webhook_auth_none` | webhook auth — none | `true` — explicit opt-out; `verifyWebhook` always passes (use only behind your own gateway). **Configure at most one** webhook auth method (two+ → `ConfigError`). |
| `cache_dir` | no (default `./allus-cache`) | Durable local buffer for the changes pump. Must be writable + durable. |
| `format` | no (default `json`) | Wire format `json` or `xml`. Invisible in the output. |

Env overrides use the `ALLUS_` prefix of the field name, e.g.
`ALLUS_CLIENT_SECRET`, `ALLUS_KEY_PASSPHRASE`, `ALLUS_ACCOUNT_PASSPHRASE`,
`ALLUS_WEBHOOK_SECRET`. A missing/invalid config (or an unreadable PEM / wrong
passphrase) returns a `*ConfigError` at construction — fail fast
(`errors.Is(err, ErrConfig)`).

### 2. First call — list a connection's values

```go
client, err := companydata.FromConfig("allus.json")
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()

// Iterate every connected person (lazy, auto-paged).
conns, errc := client.Connections(ctx, 100, 0)
for conn := range conns {
    fmt.Println(conn.DisplayName, conn.PersonID)
    for slug, val := range conn.Values {
        fmt.Printf("  %s = %v  (live=%t, updated=%v)\n", slug, val.Value, val.Live, val.UpdatedAt)
    }
}
if err := <-errc; err != nil {
    log.Fatal(err)
}
```

Or get all of them eagerly into a slice:

```go
conns, err := client.ConnectionsList(ctx, 100, 0)   // initial full sync
```

Or fetch one connection by id:

```go
conn, err := client.Connection(ctx, "019xxxxxxxxxxxxxxxxxxxxxxxxx")
email := conn.Values["work_email"].Value.(string)    // "alice@acme.com"
```

`companydata.FromEnv()` builds the same client entirely from `ALLUS_*` env vars
(no file).

---

## Every call

`Client` is the only object you construct. Build it from config, then:

```go
companydata.FromConfig(path string, opts ...clientOption) (*Client, error)  // from a JSON file (env overrides secrets)
companydata.FromEnv(opts ...clientOption)                  (*Client, error)  // entirely from ALLUS_* env vars
companydata.New(cfg *Config, opts ...clientOption)         (*Client, error)  // from a prebuilt Config
```

Options are advanced/optional: `WithHTTPClient` (inject a custom transport),
`WithLogger` (a `*log.Logger` for the pump's drain/ack/retry/dead-letter logging).

| Method | Returns | What it does |
|--------|---------|--------------|
| `RequestFields(ctx)` | `[]RequestField, error` | Your request-field **definitions** (slug → label/type/flags). Fetched once and cached. Never the person's fields. |
| `Connections(ctx, limit, offset)` | `(<-chan Connection, <-chan error)` | A **lazy** channel of `Connection`, auto-paging the list endpoint (a short page ends iteration). Read the error channel after the connection channel closes. |
| `ConnectionsList(ctx, limit, offset)` | `[]Connection, error` | Eager convenience — drains the iterator into a slice (initial full sync). |
| `Connection(ctx, id)` | `Connection, error` | One connection by id. |
| `Logs(ctx, limit, offset)` | `[]LogEntry, error` | The service's activity log (ops events only — email/purge/webhook). |
| `ProcessChanges(handler, opts)` | `error` | The **crash-safe streaming pump** (one `Change` at a time, durable buffer, retry→dead-letter, until empty then returns). See [the changes pump](#the-changes-pump). |
| `DrainBatch(max)` | `[]Change, error` | A raw, **unbuffered** drain (advanced — you own durability). |
| `DeadLetters()` | `[]DeadLetter, error` | Inspect the local dead-letter store. |
| `RetryDeadLetters(handler, opts)` | `int, error` | Re-drive dead-lettered events; returns how many succeeded. |
| `VerifyWebhook(rawBody, headers)` | `bool` | Verify a webhook's HMAC signature. |
| `ParseWebhook(rawBody, headers)` | `Change, error` | Parse a webhook body → a `Change`. |
| `HandleWebhook(rawBody, headers)` | `Change, error` | Verify + parse in one call. |

`ctx context.Context` lets you cancel/timeout the network calls. `headers` on the
webhook methods may be a `map[string]string` or an `http.Header`
(`map[string][]string`).

> **Usage intent (enforced by the API).** Poll `ProcessChanges` / the changes
> feed **as often as you like** — it's a cheap drain-on-fetch queue, generously
> rate-limited. The **connections endpoints are heavily rate-limited**: use them
> for the initial full sync + occasional reconciliation, never as a polling
> substitute for the changes feed.

---

## The typed value model

Everything you read is one of these. Names are Go-idiomatic; shapes match the
other five SDKs.

```go
type RequestField struct { Slug, Label, Type string; OneTime, Mandatory bool; Raw map[string]any }
type Connection   struct { ID, PersonID, DisplayName string; ConnectedAt *time.Time; Values map[string]Value; Raw map[string]any }
type Value        struct { Value any; Live bool; UpdatedAt *time.Time; Raw map[string]any }
type Change       struct { ID, Event, PersonID, ShareCode, Slug string; Value any; Live, HasLive bool; At *time.Time; Raw map[string]any }
type LogEntry     struct { Type, Message string; Metadata any; At *time.Time; Raw map[string]any }
```

- **Keyed by your slug.** `conn.Values["work_email"].Value` → `"x@y.com"`. The
  slug is the stable, explicit key you set per request field in the portal —
  rename the label freely, the slug is the contract.
- **`Value.Value` is typed** (use a type switch / assertion):

  | Field type | Go type of `Value.Value` |
  |------------|--------------------------|
  | `email` / `phone` / `url` / `text` | `string` |
  | `address` / `bank` / `creditcard` | `map[string]any` (parsed JSON object) |
  | `date` / `date_of_birth` | `time.Time` |
  | `photo` / `document` / `legal_document` | `*BinaryHandle` (lazy) |

  ```go
  email := conn.Values["work_email"].Value.(string)
  addr  := conn.Values["billing_address"].Value.(map[string]any)
  logo  := conn.Values["logo"].Value.(*BinaryHandle)
  bytes, err := logo.Bytes()          // fetches the slot file endpoint + decrypts on demand
  n,     err := logo.Save("./logo.png") // atomic write (temp + fsync + rename)
  ```

- `Value.Live` = the person chose "keep connected" (auto-updates) vs a one-time
  snapshot. `Value.UpdatedAt` = when this answer last changed (`*time.Time`, nil
  if absent). Both ride on the `Value` (per-answer), not the definition.
- **The person's source field is never present** — no source slug, no
  `field_id`, not even via `Raw` (the hardened API doesn't return it).
- `Raw` on any object → the underlying (hardened) API map, for debugging or an
  edge case the SDK didn't model. It still never contains the person's source
  field.

### Binary fields

A binary answer is a `*BinaryHandle`: `Bytes()` GETs the slot-keyed file
endpoint, decrypts the wrapper, parses the envelope (`{"full":…}` /
`{"file":…}`), and base64-decodes the primary data-URI payload into the file
bytes. `Save(path)` writes those bytes atomically. The handle is lazy and caches
the decrypted envelope, so repeated `Bytes()`/`Save()` don't re-fetch.

---

## Company documents

A service can also push **documents** to people — contracts, statements, signed
PDFs, structured JSON payloads. Unlike the request-field values (which the person
fills in for you), documents flow the other way: **you** create them and the
recipient's app shows them.

The one rule to internalise — **encryption is keyed on the target, never on
`IsPrivate`**:

- **Per-person** (set `ConnectionID`, `PersonUserID`, or `ShareCode`): the value
  is **always end-to-end encrypted to that recipient's public key** before it
  leaves the process — for *every* per-person document, `IsPrivate` or not. The
  SDK resolves the recipient's share code, fetches their public key, and encrypts
  with it. **No method takes a key or secret argument.**
- **Broadcast** (no target): the value is sent **plaintext**. You can't
  single-key-encrypt one blob to *all* of a service's connections, so broadcast
  documents are inherently public-to-your-connections. A broadcast therefore
  **must** be non-private — `IsPrivate: true` with no target returns a
  `*ConfigError`.

`IsPrivate` is a **device-display-only** flag: it tells the recipient's app to
show a lock (tap-to-reveal) vs decrypt-and-show-on-load. It does **not** decide
whether the value is encrypted (the target does). It only makes sense per-person.

`PayloadKind` is `"json"` (a structured object) or `"file"` (raw bytes — PDF,
image, …).

### Create

```go
client, err := companydata.FromConfig("allus.json")
if err != nil {
    log.Fatal(err)
}
ctx := context.Background()

// BROADCAST, plaintext JSON — every connection sees it.
notice, err := client.CreateDocument(ctx, companydata.CreateDocumentOptions{
    Name:        "Q3 service notice",
    PayloadKind: "json",
    JSONValue: map[string]any{
        "headline": "Scheduled maintenance",
        "starts":   "2026-07-01T02:00:00Z",
    },
})

// PER-PERSON, JSON — auto-encrypted to this recipient's public key.
// (IsPrivate optional; it only changes how their device displays it.)
contract, err := client.CreateDocument(ctx, companydata.CreateDocumentOptions{
    ConnectionID: "019xxxxxxxxxxxxxxxxxxxxxxxxx", // or PersonUserID / ShareCode
    Name:         "Service agreement",
    PayloadKind:  "json",
    IsPrivate:    true, // recipient's app shows a lock; the bytes are encrypted either way
    JSONValue:    map[string]any{"plan": "pro", "monthly_eur": 49},
    Status:       "offering",
})

// PER-PERSON, FILE — the file bytes are encrypted to the recipient before upload.
pdf, _ := os.ReadFile("./agreement.pdf")
signed, err := client.CreateDocument(ctx, companydata.CreateDocumentOptions{
    PersonUserID: "019yyyyyyyyyyyyyyyyyyyyyyyyy",
    Name:         "Signed agreement",
    PayloadKind:  "file",
    FileBytes:    pdf,
    FileMime:     "application/pdf",
})
```

Setting `ConnectionID` or `PersonUserID` makes a document per-person; `ShareCode`
short-circuits the recipient-share-code lookup if you already have it. The
returned `Document` carries `ID`, `Status`, `PayloadKind`, `IsPrivate`,
`Metadata`, timestamps, and (for per-person JSON) the encrypted `Value` — call
`doc.JSON()` to get the plaintext object back (it decrypts a per-person wrapper
with your own key, or returns a broadcast value as-is).

### List / fetch / update / delete

```go
// List this service's documents (optional person/status filter + paging).
docs, err := client.ListDocuments(ctx, companydata.ListDocumentsOptions{
    PersonUserID: "019yyyy…", // optional
    Status:       "active",   // optional
    Limit:        100, Offset: 0,
})

// One document by id.
doc, err := client.Document(ctx, "019zzzz…")
obj, _ := doc.JSON() // plaintext (decrypts a per-person wrapper transparently)

// Advance the lifecycle status.
// offering | ready_to_sign | active | active_but_ending | ended
doc, err = client.UpdateDocumentStatus(ctx, doc.ID, "active")

// Update metadata / name / description (any one of the three is required).
doc, err = client.UpdateDocumentMetadata(ctx, doc.ID, companydata.UpdateDocumentMetadataOptions{
    Name:        "Service agreement (v2)",
    Description: "Renewed terms",
    Metadata:    map[string]any{"ref": "AC-2026-0007"},
})

// Delete the document (and its on-disk file).
err = client.DeleteDocument(ctx, doc.ID)
```

### React to status changes in the pump

When a recipient acts on a document, the change feed emits a
**`document_status_changed`** event carrying `DocumentID` + `Status` (no slug, no
value) — handle it alongside the field events:

```go
err := client.ProcessChanges(func(c companydata.Change) error {
    switch c.Event {
    case "document_status_changed":
        // e.g. the person moved a contract offering → ready_to_sign → active
        onDocumentStatus(c.PersonID, c.DocumentID, c.Status)
    case "field_updated":
        upsert(c.PersonID, c.Slug, c.Value)
    }
    return nil
}, companydata.PumpOptions{})
```

The same event arrives over [webhooks](#webhooks) with the identical `Change`
shape.

---

## The changes pump

The changes feed is a server-side **drain-on-fetch queue**:
`GET /api/company-data/changes?limit=N` returns up to N events **and deletes
exactly those rows in the same transaction** — no offset/cursor/page. Because the
API keeps no copy after a fetch, the SDK must not lose a drained batch if your
process crashes, and must never materialize a huge backlog. So consumption goes
through a **pump**, not a list.

```go
err := client.ProcessChanges(func(c companydata.Change) error {
    switch c.Event {
    case "field_updated":
        // c.Slug + c.Value (decrypted at delivery; a *BinaryHandle for binaries)
        upsert(c.PersonID, c.Slug, c.Value)
    case "connection_created", "connection_deleted":
        // no slot/value
    case "consent_accepted", "consent_declined":
        // c.Slug, no value
    }
    return nil // returning nil ACKS; returning an error RETRIES → then dead-letters
}, companydata.PumpOptions{}) // defaults: BatchSize 100, MaxRetries 3, OnError deadletter
```

Per cycle:

1. **Replay first** — deliver any un-acked events already in the local buffer
   (from a previous crashed run), oldest-first.
2. **Drain** — when the buffer is empty, fetch one batch (≤ `BatchSize`, ≤500)
   and **persist it to the durable buffer (fsync) BEFORE handing anything out**.
3. **Deliver one-by-one** — decrypt each event at delivery (never on disk), call
   your handler.
4. **Ack / retry / dead-letter** — on `nil` remove the event; on error retry with
   backoff up to `MaxRetries`, then (default) move it to the dead-letter store and
   continue (one poison event never wedges the stream), or — with
   `OnError: companydata.OnErrorHalt` — stop and return the error.
5. **Repeat** until a drain returns empty and the buffer is drained → **return**.

There is **no follow/daemon mode** — `ProcessChanges` returns when the feed is
empty; you schedule re-runs (a ticker, cron, a worker — whatever fits).

**Guarantees:**

- **Crash-safe** — a batch is durably buffered before any delivery; a crash
  mid-batch replays the un-acked events on the next run. Nothing the API deleted
  is lost.
- **Bounded memory** — only one ≤500-event batch is in flight; a 1M backlog
  streams through in chunks.
- **At-least-once + idempotent** — the ack can't be atomic with your side-effects,
  so **your handler must be idempotent**. Each `Change` carries a stable `ID`
  (captured before the server delete) so you can dedupe.
- **Ciphertext at rest** — the local buffer stores the ciphertext event; values
  are decrypted only at delivery. No plaintext PII is written to disk.

`PumpOptions`:

```go
type PumpOptions struct {
    BatchSize  int                              // ≤500, default 100
    MaxRetries int                              // default 3
    OnError    OnError                          // OnErrorDeadLetter (default) | OnErrorHalt
    Backoff    func(attempt int) time.Duration  // default exponential, capped at 30s
}
```

### Dead-letter

Events that exhaust `MaxRetries` — or that can never decrypt (corrupt/rotated
key, dead-lettered **immediately** without burning retries) — land in a
dead-letter store under `cache_dir`, with the error + attempt count. They are
**never silently dropped**, and never re-fetched from the API (the API already
deleted them — the local buffer is their only home).

```go
dls, _ := client.DeadLetters()                  // inspect (ciphertext + error + attempts)
n, _ := client.RetryDeadLetters(handler, companydata.PumpOptions{}) // re-drive; n = how many succeeded
```

A still-failing re-drive is updated **in place** in the dead-letter dir (never
routed back through the pending dir), and the recorded attempt count is monotonic.

---

## Webhooks

The lower-latency push alternative to polling the feed. All secrets/keys come
from config — **these helpers take no key or secret arguments**.

```go
func webhook(client *companydata.Client) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        body, err := io.ReadAll(r.Body)        // the RAW bytes — the HMAC is over them
        if err != nil {
            http.Error(w, "read error", http.StatusBadRequest)
            return
        }
        change, err := client.HandleWebhook(body, r.Header) // verify + parse
        if err != nil {
            // *WebhookError on a bad/unknown signature or an unwrappable envelope
            http.Error(w, "invalid webhook", http.StatusBadRequest)
            return
        }
        process(change) // same Change shape + types as the feed
        w.WriteHeader(http.StatusOK)
    }
}
```

- `VerifyWebhook(rawBody, headers) bool` — reads `X-Allus-Webhook-Id`, looks up
  that webhook's HMAC secret in config, recomputes `HMAC-SHA256(rawBody, secret)`
  and constant-time-compares it to `X-Allus-Signature` (hex). The HMAC is always
  over the **raw bytes**, never the parsed tree.
- `ParseWebhook(rawBody, headers) (Change, error)` — parses the body (JSON or
  XML) → a `Change`. If the body is an `encrypt_payload` envelope (encrypted to
  your **account** key), the SDK unwraps it with the configured
  `account_private_key` first, then decrypts the inner field value with the
  service key.
- `HandleWebhook(rawBody, headers) (Change, error)` — verify + parse in one call;
  returns a `*WebhookError` on a bad/unknown signature.

The 6 event types + fields are identical to the feed (slug-keyed; no person
source field).

---

## Rate limits

The SDK respects `429 + Retry-After` automatically. The **changes feed** is meant
to be polled often (generous limit). The **connections endpoints** are heavily
rate-limited: the connections iterator paces itself and backs off on a surfaced
`429`, retrying a page a bounded number of times before returning a
`*RateLimitError`. Use connections for the initial full sync + occasional
reconciliation, not as a poll target — that's what the changes feed is for.

---

## Errors

Idiomatic Go error types matching the §9 taxonomy. Each has a sentinel for
`errors.Is`; the concrete types extract carried fields with `errors.As`.

| Error type | Sentinel | When |
|------------|----------|------|
| `*ConfigError` | `ErrConfig` | Missing/invalid config or key file at construction (fail fast). |
| `*AuthError` | `ErrAuth` | Token fetch/refresh failed (bad client_id/secret, revoked client). |
| `*ApiError` (`Status`, `ErrorKey`, `Message`) | `ErrAPI` | Any non-2xx from the API. |
| `*DecryptError` | `ErrDecrypt` | Wrapper malformed, wrong key, or GCM tag mismatch. |
| `*WebhookError` | `ErrWebhook` | Signature verification failed or an envelope couldn't be unwrapped. |
| `*RateLimitError` (`RetryAfter`) | `ErrRateLimit` (also `ErrAPI`) | A 429 from a rate-limited endpoint (embeds `*ApiError`). |

```go
if errors.Is(err, companydata.ErrRateLimit) {
    var rl *companydata.RateLimitError
    errors.As(err, &rl)
    // back off rl.RetryAfter (a *float64 of seconds, or nil)
}

var apiErr *companydata.ApiError
if errors.As(err, &apiErr) {
    log.Printf("API %d %s: %s", apiErr.Status, apiErr.ErrorKey, apiErr.Message)
}
```

---

## How it's wired

- **Auth + transport.** An internal `HTTPClient` owns the `client_credentials`
  token (fetched on first call, cached, auto-refreshed near expiry; one
  refresh-and-retry on a 401), the `Accept` header per `format`, the JSON/XML
  parse, and the §9 error mapping (incl. bounded 429 backoff). The token is
  scoped server-side to exactly one service.
- **Decryption.** The service private key is loaded **once** at construction from
  the configured encrypted PEM + passphrase into an in-memory RSA key; a decrypt
  closure over it is handed to every model factory and the pump. The key never
  appears in a method signature (config-only key handling). Algorithm:
  RSA-OAEP-SHA256 (digest + MGF1) unwrap of the AES key, then AES-256-GCM
  (12-byte nonce, 16-byte tag appended). Verified byte-for-byte against the shared
  cross-language test vector.
- **Slug catalog.** `RequestFields` is fetched once and cached; its slug→type
  map types every value.
- **Binary.** A `*BinaryHandle.Bytes()` GETs the slot file endpoint, unwraps the
  API's `{"encrypted":true,"value":<wrapper>}` envelope, and runs the same
  service-key decrypt → the file bytes.
- **Changes feed.** `ProcessChanges` delegates to the durable-buffered `Pump`,
  injecting a drain closure (`GET /changes?limit=`, returning the raw ciphertext
  events) and a decrypt closure that builds a typed `Change`.
- **XML.** Go's `encoding/xml` is XXE-safe by default — it does not resolve
  external entities or DTDs — so there is no entity resolver to disable. The HMAC
  is always computed over the raw bytes, never the parsed tree.

---

## Development

```bash
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

The test suite covers the decryption core (PBES2 PEM load, text decrypt, and
binary decrypt → envelope → inner bytes), the crash-safe pump
(persist-before-deliver, replay, dead-letter, monotonic attempt counts,
never-resurrect), and the webhook helpers (HMAC verify, JSON/XML parse, and the
account-key OAEP-SHA1 envelope).
