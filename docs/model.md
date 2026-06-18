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
    Raw       map[string]any
}
```

`Value.Value` is typed by the request field's type — use a type switch /
assertion:

| Field type | Go type |
|------------|---------|
| `email` / `phone` / `url` / `text` | `string` |
| `address` / `bank` / `creditcard` | `map[string]any` (parsed JSON object) |
| `date` / `date_of_birth` | `time.Time` (midnight UTC; falls back to the raw string if unparseable) |
| `photo` / `document` / `legal_document` | `*BinaryHandle` |
| unanswered | `nil`, or an empty `*BinaryHandle` for binary types |

```go
v := conn.Values["work_email"]
email := v.Value.(string)
fmt.Println(v.Live, v.UpdatedAt)
```

## BinaryHandle — lazy binary

```go
handle := conn.Values["logo"].Value.(*companydata.BinaryHandle)
data, err := handle.Bytes()        // GETs the slot file endpoint, decrypts, decodes
n, err := handle.Save("./logo.png") // atomic write (temp + fsync + rename)
url := handle.ValueURL()            // the slot-keyed file URL (opaque)
```

The handle is lazy — nothing is fetched until `Bytes()`/`Save()` — and caches the
decrypted envelope so repeated calls don't re-fetch. `Save` is crash-safe: a
crash mid-write never leaves a truncated file.

## Change — a feed / webhook event

```go
type Change struct {
    ID       string     // stable server change-row id (the pump dedupes on it)
    Event    string     // see the events table
    PersonID string
    Slug     string     // present on field_updated / field_deleted / consent_* only
    Value    any        // present on field_updated only (decrypted, same typing as Value.Value)
    Live     bool
    HasLive  bool       // distinguishes "live absent" from "live == false"
    At       *time.Time // the change time (no separate UpdatedAt on a change)
    Raw      map[string]any
}
```

| Event | Carries |
|-------|---------|
| `connection_created` / `connection_deleted` | identity only (no slot/value) |
| `field_updated` | `Slug` + decrypted `Value` + `Live` (binary → a lazy `*BinaryHandle`) |
| `field_deleted` | `Slug` (no value) |
| `consent_accepted` / `consent_declined` | `Slug` |

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
