# Company-data example — read / definitions / changes / webhook / documents (Go SDK)

A runnable website that demonstrates the **regular company-data surface** of the
allme platform — reading connected people's live values, your request-field
catalog, the crash-safe changes feed, inbound webhooks, and company documents /
contracts — through the `github.com/allus-fyi/company-data-go` **Go SDK**. It is
the Go port of the [demo-backend contract](https://github.com/allme-sdk/example-test-suite)
(`CONTRACT.md`, company-data family, **contractVersion 3**) that all six SDK
examples implement: ~90 % of the logic is a shared frontend fetched from a pinned
release; this directory is the thin Go backend that serves it and implements the
contract endpoints.

Every scenario uses the **service-role** data `companydata.Client`, built from
the persisted config file. There is **no OAuth leg** (no `/callback`, no
`/enroll`) — company-data has no consent step. Everything the handlers do goes
through the SDK's **intended top-level surface** (`companydata.Client`) — never
internals, never raw platform HTTP.

---

## Run it — one command

```bash
cd sdks/go/examples/company-data
go run .
```

That runs `main.go`, which:

1. wipes `.runtime/` (fresh state every boot),
2. on first run, downloads the **pinned** frontend release named in
   `frontend.lock`, **verifies its sha256**, and unpacks it to `.frontend/<tag>/`
   (a present, verified bundle is a cache hit — nothing is re-fetched),
3. checks the bundle's `contract.json` version against the backend's (`3`),
4. refuses a busy port with a clear message, then
5. serves `http://localhost:8091` — a **single** `net/http` server whose requests
   are serialised behind one mutex (the Go equivalent of the PHP reference's
   single-worker `php -S`).

Open **http://localhost:8091** and pick a scenario. Each setup panel has a
**Save** button: it POSTs your settings to the backend, which writes them to a
canonical SDK **config file** (`.runtime/config/{sid}.json`, any PEM under
`.runtime/config/keys/`) — the same shape a real integrator wires by hand. **Run**
then builds the `Client` from that file (`companydata.FromConfig`) and runs off
it. You never hand-create or edit the file — the backend writes it from your
browser inputs; it is there to be read.

**Port.** `8091` is the default, overridable with `PORT=<n> go run .`. The default
is deliberately the **same across all six SDK examples** (one browser origin ⇒
your localStorage setup carries across SDKs) — so only one example runs at a time.

**Requirements:** Go ≥ 1.26 and network access on first run (to fetch the pinned
frontend release). No system `curl`/`tar` needed — download, checksum, and unpack
are done in-process.

---

## Which SDK call implements each scenario

| Scenario | SDK call(s) the handler makes |
|----------|-------------------------------|
| `companydata:read` | `Client.ConnectionsList` — grouped by connection (one card per connected person) |
| `companydata:definitions` | `Client.RequestFields` — your request-field catalog (folded `mandatory` + `one_time`) |
| `companydata:changes` | `Client.ProcessChanges` — crash-safe pump drain on start, idempotent on `Change.ID` |
| `companydata:webhook` | `Client.VerifyWebhook` + `Client.ParseWebhook` on `POST /webhook`; `Client.DrainBatch` as the per-poll feed fallback |
| `companydata:documents` | `Client.CreateDocument` ×6 — the six document / contract types |

The data scenarios run synchronously on `/start` (`action:{type:"data"}`) and the
outcome is read once via `GET /api/runs/{runId}` (`status:"done"`, `result`). A
build/SDK failure surfaces as a `failed` run (never a 200 without the envelope).

### The webhook scenario (accumulating)

`companydata:webhook` is the one *accumulating* run. `/start` persists a routing
record `webhookId → runId` (superseding any prior one) and returns
`action:{type:"none"}` — there is **no** long-poll (it would wedge the single
worker). Events then arrive two ways, both appended to the same run's `result`:

- **Inbound deliveries** on the **public `POST /webhook`** route. The exact
  call/status sequence (never the combined `HandleWebhook`, which can't split
  401-vs-200): read `X-Allus-Webhook-Id` → unknown/stale id or no active run
  ⇒ **200** discard; `VerifyWebhook` false ⇒ **401**; `ParseWebhook` ok ⇒ append
  `{source:"webhook"}` + **200**; a `*WebhookError` from `ParseWebhook` is a
  verified-but-unparseable delivery ⇒ **200** and `unparseable++`. Every
  accepted-and-dropped case is **200** because the platform delivery worker counts
  exactly 200 as success.
- **The always-works feed fallback**: each `GET /api/runs` poll on the active run
  also does ONE `Client.DrainBatch` fetch, appending `{source:"feed"}` events
  deduped on `Change.ID`. (Not `ProcessChanges`, which loops the pump to empty —
  that is `companydata:changes`' job.) A blackholed feed is swallowed so the
  webhook path still works.

The run stays `pending` while collecting; the frontend keeps polling and renders
`run.result` = `{webhookId, events, unparseable}`.

---

## How dependencies are pinned (and why the SDK stays clean)

This example is its **own Go module** (`go.mod` in this directory) with a
`replace` directive back to the in-tree SDK (`../..`). It needs **no third-party
runtime dependencies** beyond the SDK (no OIDC library — there is no OAuth leg);
`go.mod` + `go.sum` pin only the SDK's own transitive deps so two fresh
`go run .` builds resolve the identical graph. `.runtime/` and `.frontend/` are
transient and git-ignored.
