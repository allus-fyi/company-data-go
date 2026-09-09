# Output model

The conclusions. The consumer works with these and nothing else.
They are produced from a *hardened* API object (slug-keyed values; **no person
source field**) and the ciphertext is decrypted transparently with the service
private key loaded from config.

## RequestField — your definitions

```go
type RequestField struct {
    Slug      string
    Label     string
    Type      string
    OneTime   bool   // the person answered "share once" (a frozen snapshot)
    Mandatory bool   // mandatory to provide OR mandatory to stay connected (folds the API's two flags)
    Verified  bool   // this row DEMANDS a verified answer (mutually exclusive with OneTime)
    VerifiedMaxAgeDays *int // oldest verification accepted, in days; nil = no age limit
    Raw       map[string]any
}
```

Fetched once and cached via `client.RequestFields(ctx)`. This is **your** request
config (the slots you set up in the portal) — never the person's fields. It also
types every value (slug → type).

## Connection — a connected person

```go
type Connection struct {
    ID          string
    PersonID    string
    DisplayName string
    ConnectedAt *time.Time
    Values      map[string]Value   // keyed by YOUR request-field slug
    Raw         map[string]any
}
```

No source field anywhere — `Values` is keyed by your slug. `Connection(ctx, id)`
returns one; `Connections(ctx, …)` / `ConnectionsList(ctx, …)` iterate the book.

## Value — one answer

```go
type Value struct {
    Value     any        // the TYPED plaintext (see the type table)
    Live      bool       // "keep connected" (auto-updates) vs a one-time snapshot
    UpdatedAt *time.Time // when this answer last changed (nil if absent)
    Verified  bool       // the hash recomputes over the plaintext AND the verification has not lapsed
    VerifiedAt        *time.Time // when the answering field was verified
    VerifiedExpiresAt *time.Time // when that verification lapses; nil = it does not
    VerifiedMethod    string     // HOW allme bound it: email_code|sms_code|sumsub_id|sumsub_address
    VerifiedProvider  string     // WHO established the proof: allme|sumsub
    VerificationID    string     // the proof id to quote back to allme in a dispute
    Raw       map[string]any
}
```

### `value` types — from the type's RESOLVED definition

A contact-field TYPE is a ROW in the served field-type registry (`GET /api/contact-field-types`),
which the client fetches beside the request-field catalog and holds for its life. A value's shape
follows the type's resolved storage LANE and PRIMITIVE, so a type added as a row types itself with
no SDK release.

`Value.Value` is typed from that definition — use a type switch / assertion:

| The type's resolved… | Go type |
|----------------------|---------|
| storage lane `photo` / `document` | `*BinaryHandle` (lazy) |
| primitive `composite` | `map[string]any` (parsed JSON object) |
| primitive `date` | `time.Time` (midnight UTC; falls back to the raw string if unparseable) |
| primitive `multilist` | `[]any` of the chosen option strings |
| anything else, and a type the registry does not carry | `string` |
| unanswered | `nil`, or an empty `*BinaryHandle` for a binary lane |
For the seeded types that is, unchanged: `email`/`phone`/`url`/`text` and the three numeric types →
a string; `country`/`nationality` → an ISO 3166-1 alpha-2 code string; `address`/`bank`/`creditcard`
→ the parsed object; `date`/`date_of_birth` → the date type; `photo`, `document`,
`legal_document`, `passport`, `photo_id` and `drivers_license` → the lazy binary handle. A request
row of a PARENT type MAY be answered by a field of any DESCENDANT, but that matching happens in
the API: the answer still arrives keyed by YOUR slug and shaped by the SLOT's own type, because
the person's source field — and therefore its type — is never exposed. A binary slot's
slot → source → file resolution is likewise the API's.


```go
v := conn.Values["work_email"]
email := v.Value.(string)
fmt.Println(v.Live, v.UpdatedAt)
```

## BinaryHandle — lazy binary

```go
handle := conn.Values["logo"].Value.(*companydata.BinaryHandle)
data, err := handle.Bytes()         // GETs the slot file endpoint → the file bytes
n, err := handle.Save("./logo.png") // atomic write (temp + fsync + rename)
url := handle.ValueURL()            // the slot-keyed file URL (opaque)
ct := handle.ContentType()          // the Content-Type the bytes arrived with
sum := handle.ContentSha256()       // the platform's X-Allus-Content-Sha256 for those bytes
```

The handle is lazy — nothing is fetched until `Bytes()`/`Save()` — and caches what
it fetched so repeated calls don't re-fetch. `Save` is crash-safe: a crash
mid-write never leaves a truncated file.

**Two 200 shapes, absorbed by the handle.** Whether the slot endpoint returns
`application/json` `{"encrypted":true,"value":<wrapper>}` (decrypted with the
service key, envelope parsed, data-URI decoded) or the file's own `Content-Type`
with the raw bytes as the body depends on whether the person's source field is
private — their choice, changeable at any time, unannounced. `Bytes()` returns the
file either way. The shape is decided on `Content-Type`, never by sniffing the
body, and there is no variant selection: one slot has one byte sequence and one
digest.

`ContentSha256()` and `ContentType()` are empty until something has been fetched,
and on a handle built from an envelope directly. A `410`
`company_data.file_expired` (a frozen share-once answer past its 90-day retention)
surfaces as an `*ApiError` whose `Details` carry `content_sha256` and `expired_at`;
see [errors](errors.md).

## Change — a feed / webhook event

```go
type Change struct {
    ID       string     // pull-feed server change-row id (the pump dedupes on it; NOT stable on webhooks)
    Event    string     // see the events table
    PersonID string
    Slug     string     // present on field_updated / field_deleted / consent_* only
    Value    any        // present on field_updated only (decrypted, same typing as Value.Value)
    Live     bool
    HasLive  bool       // distinguishes "live absent" from "live == false"
    ConnectionID    string // message_received only — the connection to reply/ack on
    MessageID       string // message_received only — the ack boundary
    PersonPublicKey string // message_received only — base64 SPKI for the reply
    MessageBody     string // message_received only — the DECRYPTED text
    Verified bool       // field_updated only; hash recomputes AND the verification has not lapsed
    VerifiedAt        *time.Time // when the answering field was verified
    VerifiedExpiresAt *time.Time // when that verification lapses; nil = it does not
    VerifiedMethod    string     // HOW allme bound it: email_code|sms_code|sumsub_id|sumsub_address
    VerifiedProvider  string     // WHO established the proof: allme|sumsub
    VerificationID    string     // the proof id to quote back to allme in a dispute
    At       *time.Time // the change time (no separate UpdatedAt on a change)
    Raw      map[string]any
}
```

> **On the webhook path this id is NOT a dedup key.** A live webhook delivery has no change row behind it, so its id is minted for that single POST; a delivery replayed from the server-side backlog is rebuilt from a durable row and carries that row's id instead — the same id on every re-attempt of that row. The id is therefore sometimes stable across a duplicate and sometimes not, with no way for the receiver to tell, which is what makes it unusable as an idempotency key. Webhooks and the pull feed are alternative integrations; see `webhooks.md` for the webhook delivery contract and what to key on instead (change.ID is not it).

| Event | Carries |
|-------|---------|
| `connection_created` / `connection_deleted` | identity only (no slot/value) |
| `field_updated` | `Slug` + decrypted `Value` + `Live` (binary → a lazy `*BinaryHandle`) |
| `field_deleted` | `Slug` (no value). A binary slot whose file expired may add `content_sha256` + `expired` in `Raw` |
| `consent_accepted` / `consent_declined` | `Slug` |
| `message_received` | `ConnectionID`, `MessageID`, `PersonPublicKey` + `MessageBody` (the DECRYPTED message text); no slot. Person→company only — a broadcast raises no event |

The event's ciphertext is carried under `body`. It is never `value`: on every other
event `value` means field ciphertext, and a message body is not one.

**Answering one.** `SendMessage` answers **201** with the created message carrying
`message_id`, which is what it returns — hand that id, or the inbound event's `MessageID`,
to `MarkMessagesRead` as the acknowledgement boundary.

## LogEntry — ops log

```go
type LogEntry struct {
    Type     string  // email | purge | webhook | …
    Message  string
    Metadata any
    At       *time.Time
    Raw      map[string]any
}
```

`client.Logs(ctx, limit, offset)` — service operations only, never person data.

## Raw

Every model carries `Raw` — the underlying hardened API map — for debugging or an
edge case the SDK didn't model. It still never contains the person's source
field (the hardened API doesn't return it).

## Share codes — what you may send, what you always receive

A profile can carry a second, human-readable **custom share code** assigned by an
allme operator, beside the generated code the person's app displays. Both resolve
to the same person.

- **Both places this SDK takes a share code as input accept either**:
  `client.SendConnectRequest(ctx, shareCode)` (`POST /api/company-data/connect-requests`)
  and `client.TwoFactor().Challenge(ctx, shareCode, idempotencyKey, contextText)`
  (`POST /api/service-2fa/challenges`). Same parameter, same type, same shape —
  nothing in the SDK changes, and a customer who gives you `ACME` instead of
  `2I6UF3` simply works.
- **Every `share_code` the API emits is the GENERATED code** — `Connection.ShareCode`,
  `Change.ShareCode` and every webhook body. So a code handed to you by a customer
  may differ from the one you read back for that same person, and anything you key
  on the emitted value (a public-key cache, your own customer record) stays
  internally consistent.
