# Flow example — run a contract flow (Go SDK)

A runnable website that demonstrates a **contract flow** end-to-end through the
`github.com/allus-fyi/company-data-go` **Go SDK**: trigger a flow run, drive the
company party through it with type-checked step filling, hand a turn to the
person's phone, and on completion read the decrypted answers and — for the
contract fixture — download the generated signed document. Like the
[identity example](../identity/), ~90 % of the logic is a shared frontend fetched
from a pinned release; this directory is the thin Go backend that implements the
[demo-backend contract](https://github.com/allme-sdk/example-test-suite)
(`CONTRACT.md`, flow family — contract v2).

Everything the handler does goes through the SDK's **intended top-level flow
surface** — `Identity()`, `TriggerFlowRun()`, `FlowRun()`, `ProcessFlowRun()`,
`FlowRunAnswers()`, `FlowRunDocument()` — never internals, never raw platform HTTP.

---

## Run it — one command

```bash
cd sdks/go/examples/flow
go run .
```

That runs `main.go`, which:

1. wipes `.runtime/` (fresh state every boot),
2. on first run, downloads the **pinned** frontend release named in
   `frontend.lock`, **verifies its sha256**, and unpacks it to `.frontend/<tag>/`
   (a present, verified bundle is a cache hit — nothing is re-fetched),
3. checks the bundle's `contract.json` version against the backend's (flow = v2),
4. refuses a busy port with a clear message, then
5. serves `http://localhost:8091` — a **single** `net/http` server whose requests
   are serialised behind one mutex (the Go equivalent of the PHP reference's
   single-worker `php -S`).

Open **http://localhost:8091** and pick the **Run a contract flow** scenario.
From there the browser and the allus portal are the only surfaces you touch. The
scenario's **Save** button POSTs your settings to the backend, which writes them
to a canonical SDK **config file** (`.runtime/config/{id}.json`, the service PEM
under `.runtime/config/keys/`) — the same shape a real integrator wires by hand.
The panel shows the written path so you can open and read the real config;
**Trigger** then builds the SDK from that file (`companydata.FromConfig`) and runs
off it. You never hand-create or edit the file — the backend writes it from your
browser inputs; it is there to be read.

**Port.** `8091` is the default, overridable with the `PORT` env var (e.g.
`PORT=8092 go run .`). The default is deliberately the **same across all six SDK
examples** (one browser origin ⇒ your localStorage setup carries across SDKs) —
the documented consequence is that only one example runs at a time.

**Requirements:** Go ≥ 1.26 and network access on first run (to fetch the pinned
frontend release). No system `curl`/`tar` needed — the download, checksum, and
unpack are done in-process.

---

## The scenario — set up, then run

A contract flow is a company-authored graph of steps. The demo ships **two
fixtures** you import into the portal (`fixtures/`):

| Fixture zip | Shape |
|---|---|
| `fixtures/info-gathering.zip` | `data_only` — a few company steps (text, an **email** validation-demo step, an address composite) then one person turn. |
| `fixtures/contract.zip` | `document` — a company step, then a signature leaf that generates a document. |

The scenario's setup checklist names the exact portal steps. In short:

1. In the **allus portal**, register a **data client** (client_credentials) for the
   service — its whitelist auto-grants `/api/company-data/*`. Create/reuse the
   **service** and download its **private key (PEM)** (it decrypts the answers +
   document).
2. **Import** the chosen fixture zip (service settings → Flows → Import) and
   **publish** the imported flow.
3. In the browser, enter the data-client id/secret, pick the service PEM + its
   passphrase, enter the **published flow id** and the target **connection id**, and
   pick the same **fixture** you imported. **Save**, then **Trigger the flow run**.

What you then observe:

- The **flow-run log** accumulates one row per company step as the SDK drives it:
  the `email` step is submitted once with a bad value → rejected (the SDK's
  `*companydata.ValidationError`, shown ✗), then re-submitted valid → accepted ✓.
  The other steps submit valid and advance.
- When the flow reaches the person's turn it shows **"waiting — answer on your
  phone"**; polling resumes automatically once the person answers (and, for the
  contract fixture, **signs**) in the allme app.
- On completion the **decrypted answers** appear, and for the contract fixture the
  **document** is downloaded via `FlowRunDocument()`.
- **"What just happened"** lists the exact SDK methods the run called.

> **Phone required.** The person's turn — and the contract fixture's signature — are
> completed on a **physical phone** with the allme app, signed in as the connected
> demo person (project practice: physical devices).

---

## Which SDK call implements each step

| Step | SDK call the handler makes |
|---|---|
| Trigger the run | `Client.Identity` (company binding) → `Client.Connection` (customer personId) → `Client.TriggerFlowRun(flowID, connectionID, bindings)` |
| Each poll (drive/resume) | `Client.FlowRun(runID)`; on the company's turn `Client.ProcessFlowRun(runID, fillNode, nil)` (one step; a bad email raises `*ValidationError`) |
| On completion | `Client.FlowRunAnswers(run)`; for a `document` flow `Client.FlowRunDocument(runID)` |

---

## Default target — the deployed AWS platform

The scenario's advanced input (**API url**) defaults to the deployed platform
(`https://api.allme.fyi`) — **no environment setup**. You register the data client,
create the service, and import + publish the flow in the **allus portal at
`portal.allus.fyi`**.

> **Portal prerequisite / interim (2026-07-24).** `portal.allus.fyi` is **not
> deployed yet**. Until it lands, the documented interim is to run the **local
> portal UI against the cluster API**: set `VITE_API_URL=https://api.allme.fyi` in
> `allus/.env` and start the portal locally (it proxies `/api` to that URL), so
> every portal step still lands on the same deployed platform the run executes
> against. A physical phone with the allme app reaches the deployed platform
> naturally.

---

## Secondary target — a local stack

Running against a **local stack** is a documented secondary option (see
`docs/reference/software.html`). In the browser, switch the advanced **API url** to
`http://localhost:8070`; no file in **this** example changes. The phone must be able
to reach the local API (project practice: `adb reverse tcp:8070 tcp:8070` on
Android, or the machine's LAN address).

---

## How dependencies are pinned (and why the SDK stays clean)

This example is its **own Go module** (`go.mod` in this directory) with a `replace`
directive back to the in-tree SDK (`../..`). `go.mod` + `go.sum` are committed so
two fresh `go run .` builds resolve the identical graph; `.runtime/` and
`.frontend/` are transient and git-ignored.

To point the example at the **published** package instead of the in-tree source,
drop the `replace` directive and pin a released `github.com/allus-fyi/company-data-go`
version, then `go mod tidy`.

---

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the pin lives in `frontend.lock`
(`{tag, sha256}`). This example pins the **flow family bundle (contract v2)**. To
move to a newer release: note the release **tag** and its `dist.tar.gz` checksum
(`shasum -a 256 dist.tar.gz`) from `github.com/allme-sdk/example-test-suite`, set
`tag` + `sha256` in `frontend.lock`, `rm -rf .frontend/`, then `go run .` — it
re-fetches, verifies the checksum, and checks the bundle's `contract.json` version
against the backend (a mismatch refuses loudly). A pin bump is a **per-example
commit**.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **`port 8091 is busy`** at startup | Another example holds the port — one origin is shared across SDK examples, so only one runs at a time. Stop it, or `PORT=<n> go run .`. |
| **`contract mismatch: bundle contractVersion=… backend implements …`** | The pinned bundle's `contract.json` version differs from this backend (flow = v2). Bump `frontend.lock` to a matching release (and re-fetch), or update the backend. |
| **`frontend checksum MISMATCH`** | The downloaded `dist.tar.gz` doesn't match `frontend.lock`'s `sha256`. Fix the `sha256` (from `shasum -a 256 dist.tar.gz` on the real release) or re-download. |
| **`could not download the pinned frontend release`** | The `v0.2.0` release isn't published yet, or no network. If unpublished, seed the bundle into `.frontend/<tag>/` manually (build `example-test-suite`, `tar -xzf dist.tar.gz -C .frontend/<tag>`, `printf %s <sha> > .frontend/<tag>/.sha`). |
| **`start_failed`** naming a key | The service PEM / passphrase is wrong — re-pick the key and re-save. |
| **`connection_error`** naming a missing person | The connection id is wrong or the person isn't connected to the service — check the connection in the portal. |

---

## What's in here

| Path | What it is |
|---|---|
| `go.mod` · `go.sum` | This example's own Go module — the SDK via a `replace` directive to `../..`. Committed so builds are reproducible. |
| `main.go` | The one-command launcher (frontend fetch + checksum + contract guard + serve). |
| `server.go` | The backend: the `flow:run` handler, the drive/resume poll loop, SDK wiring. |
| `runtime.go` | Cross-request on-disk state — config files, run stash, TTL sweep, Clear. |
| `fixtures/` | The two importable flow packages (portal-export zips). |
| `frontend.lock` | The pinned frontend release (`{tag, sha256}`). |
| `.frontend/` · `.runtime/` | Git-ignored — the fetched bundle and the written config/run state (wiped every boot, `0700`). |
