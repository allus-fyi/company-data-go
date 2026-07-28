# allme SDK examples — the example test suite (Go SDK)

One runnable website that demonstrates **every scenario** of the allme platform through the
`github.com/allus-fyi/company-data-go` **Go SDK**, across all three scenario families:

- **Identity** — Sign in with allme, OIDC login, and 2FA by allme (scenarios 1–8).
- **Flow** — run a contract flow end-to-end (`flow:run`).
- **Company-data** — read connected people's live values, your request-field catalog, the crash-safe
  changes feed, inbound webhooks, and company documents / contracts (`companydata:*`).

~90 % of the logic is a shared frontend fetched from a pinned release; this directory is the thin Go
backend that serves it and implements the [demo-backend contract](https://github.com/allme-sdk/example-test-suite)
(`CONTRACT.md`, **contractVersion 3**). Everything the handlers do goes through the SDK's **intended
top-level surface** (`companydata.OAuthClient`, `companydata.Client`, `companydata.TwoFactorClient`) —
never internals, never raw platform HTTP. The OIDC scenarios (5/6) deliberately use the standard
third-party `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2` stack — that is the point of the OIDC
demonstration (#314).

---

## Run it — one command

```bash
git clone https://github.com/allus-fyi/company-data-go
cd company-data-go/examples
go run .
```

`go run .` runs the launcher in `main.go`, which fetches the pinned portal bundle named in
`frontend.lock`, verifies its sha256, and serves the **example test suite — all three scenario families —
on http://localhost:8091**. In detail it:

1. wipes `.runtime/` (fresh state every boot),
2. on first run downloads the **pinned** frontend release named in `frontend.lock`, **verifies its
   sha256**, and unpacks it to `.frontend/<tag>/` (a present, verified bundle is a cache hit — nothing is
   re-fetched),
3. checks the bundle's `contract.json` version against the backend's (**3**),
4. refuses a busy port with a clear message, then
5. serves port `8091` on **all interfaces** and prints every URL it is reachable on — a **single**
   `net/http` server whose requests are serialised behind
   one mutex (the Go equivalent of the PHP reference's single-worker `php -S`).

Open **http://localhost:8091** and pick a scenario. Each scenario's setup panel has a **Save** button:
it POSTs your settings to the backend, which writes them to a canonical SDK **config file**
(`.runtime/config/{id}.json`, any PEM under `.runtime/config/keys/`) — the same shape a real integrator
wires by hand. The panel shows the written path so you can open and read the real config; **Run** then
builds the SDK from that file (`companydata.OAuthClientFromConfig` / `companydata.FromConfig`) and runs
off it. You never hand-create or edit the file — the backend writes it from your browser inputs.

**From a phone or another machine on the same network.** The server binds **all
interfaces**, so any device on your network can reach it — startup prints the exact
`http://<your-lan-ip>:8091` URL to type, alongside the localhost one. Open that URL on
the phone and press **Save** there: the redirect URI written into the config file
follows the origin you used, so register the same `http://<your-lan-ip>:8091/callback`
on your OAuth app. Binding all interfaces also means **anyone on your network can reach
this demo**, and its setup panels accept and store real credentials under
`.runtime/config/` — OAuth and data-client secrets, private-key PEMs and their
passphrases, and webhook signing secrets. It is a local developer example, not a
hardened service: run it only on a network you trust, and only with sandbox
credentials.

**Port.** `8091` is the default, overridable with the `PORT` env var:

```bash
PORT=8092 go run .
```

The default is deliberately the **same across all six SDK examples** (one browser origin ⇒ your
localStorage setup carries across SDKs) — the documented consequence is that **only one example runs at a
time** (a busy port is refused with a clear message).

**Requirements**

- **Go ≥ 1.26** on your `PATH` (`go version`).
- **Network access on first run** — to download the pinned frontend release and, for the OIDC scenarios,
  the `go-oidc` / `oauth2` libraries. No system `curl`/`tar` needed: the download, checksum, and unpack
  are done in-process. Subsequent runs use the verified cache.
- Nothing else to install — `go run .` resolves the module's dependencies itself.

---

## Set up in the portal

Every non-trivial scenario needs a bit of setup in the **allus portal at
[`https://portal.allus.fyi`](https://portal.allus.fyi)**: register a **data client**
(client_credentials) for the service, create/reuse the **service** and download its **private key
(PEM)** (it decrypts values, answers, documents, and webhook payloads), and — for the flow scenario —
import + publish a flow fixture. Each scenario's setup panel names the exact steps; the summary below
covers what is specific to each family. Every scenario's advanced **API url** input defaults to the
deployed platform (`https://api.allme.fyi`), so no environment setup is required.

### Identity (scenarios 1–8)

Register an **OAuth app** (idw client) in the portal and enter its client id (and secret, if
confidential). The redirect URI the backend registers follows the origin your browser used, so
register that same URI on the OAuth app: **`http://localhost:8091/callback`** when you browse from
this machine, **`http://<your-lan-ip>:8091/callback`** when you drive the example from a phone (the
startup output prints the exact address). Adjust the port if you set `PORT`. Scenario 3 (one-time claims) also needs the OAuth app's **private key** to decrypt the returned
claim values; scenarios 4 and 8 additionally use the **service** data client to read live values / run
2FA. Scenario 7 is a **guide** card (no run) — it points you at scenarios 1 & 5 where the 2FA prompt is
observed.

### Flow (`flow:run`)

A contract flow is a company-authored graph of steps. Two importable fixtures ship in `flow/fixtures/`:

| Fixture zip | Shape |
|---|---|
| `flow/fixtures/info-gathering.zip` | `data_only` — a few company steps (text, an **email** validation-demo step, an address composite) then one person turn. |
| `flow/fixtures/contract.zip` | `document` — a company step, then a signature leaf that generates a document. |

In the portal, **import** the chosen fixture (service settings → Flows → Import) and **publish** it, then
in the browser enter the data-client id/secret, the service PEM + passphrase, the **published flow id**,
the target **connection id**, and pick the same **fixture** you imported. **Save**, then **Trigger the
flow run**. The person's turn — and the contract fixture's signature — are completed on a **physical
phone** with the allme app, signed in as the connected demo person; polling resumes automatically once
they answer.

### Company-data (`companydata:*`)

All five scenarios use the **service** data client (client id/secret + service PEM + passphrase); there
is no OAuth leg. `read`, `definitions`, `changes`, and `documents` run synchronously on **Run** and show
the result immediately. `documents` targets a connected person by **share code** for the per-person /
private / contract types.

**The webhook scenario is setup-first.** In the portal, register a **webhook** for the service and note
its **webhook id** and **HMAC secret**; enter both in the scenario's setup and **Save** — the run needs
them (the backend verifies each delivery's HMAC and selects the secret by the `X-Allus-Webhook-Id`
header). Once started, events arrive two ways, both appended to the same accumulating run:

- **The always-works feed fallback** (no extra setup): each poll does one `Client.DrainBatch` fetch,
  appending `{source:"feed"}` events deduped on `Change.ID`. This works against the deployed platform
  with nothing else running.
- **Live inbound deliveries** on the public `POST /webhook` route — **optional**. To receive real-time
  pushes on `http://localhost:8091/webhook`, expose that route to the platform with a **tunnel** of your
  choice (e.g. a localhost tunnelling service) and register the tunnel URL as the webhook's delivery URL
  in the portal. Without a tunnel the scenario still works via the feed fallback.

---

## Which SDK call implements each scenario

### Identity

| # | Scenario | SDK / library calls the handler makes |
|---|----------|----------------------------------------|
| 1 | Sign in — redirect | `OAuthClient.AuthorizeURL("signin", redirect, PKCE)` → callback → `OAuthClient.CompleteSignIn` |
| 2 | Sign in — detached | `OAuthClient.AuthorizeURL("signin", detached)` → poll `OAuthClient.PollResult` → `OAuthClient.CompleteSignIn` |
| 3 | One-time claims | `OAuthClient.AuthorizeURL("one_time", claims)` → `OAuthClient.CompleteSignIn` (decrypts via the config's `oauth_private_key`) |
| 4 | Connect (stay-connected) | `OAuthClient.AuthorizeURL("connect")` → `OAuthClient.CompleteSignIn`, then live values via `Client.ConnectionsList` (matched by share code) |
| 5 | OIDC login | `oidc.NewProvider` (discovery) → `oauth2.Config.AuthCodeURL` (PKCE) → `oauth2.Config.Exchange` → `IDTokenVerifier.Verify` |
| 6 | OIDC — continue on phone | same OIDC stack as 5; completion arrives on the redirect leg |
| 7 | 2FA at consent — **guide** | none — a checklist card with no `/start`; links to scenarios 1 & 5 |
| 8 | Standalone service-2FA + enrollment | `Client.TwoFactor().Challenge` → `TwoFactorClient.WaitForResult`; enrollment via `OAuthClient.AuthorizeURL("2fa_enroll", …)` |

### Flow

| Step | SDK call the handler makes |
|---|---|
| Trigger the run | `Client.Identity` (company binding) → `Client.Connection` (customer personId) → `Client.TriggerFlowRun(flowID, connectionID, bindings)` |
| Each poll (drive/resume) | `Client.FlowRun(runID)`; on the company's turn `Client.ProcessFlowRun(runID, fillNode, nil)` (one step; a bad email raises `*ValidationError`) |
| On completion | `Client.FlowRunAnswers(run)`; for a `document` flow `Client.FlowRunDocument(runID)` |

### Company-data

| Scenario | SDK call(s) the handler makes |
|----------|-------------------------------|
| `companydata:read` | `Client.ConnectionsList` — grouped by connection (one card per connected person) |
| `companydata:definitions` | `Client.RequestFields` — your request-field catalog (folded `mandatory` + `one_time`) |
| `companydata:changes` | `Client.ProcessChanges` — crash-safe pump drain on start, idempotent on `Change.ID` |
| `companydata:webhook` | `Client.VerifyWebhook` + `Client.ParseWebhook` on `POST /webhook`; `Client.DrainBatch` as the per-poll feed fallback |
| `companydata:documents` | `Client.CreateDocument` ×6 — the six document / contract types |

---

## Secondary target — a local stack

Running against a **local stack** is an optional secondary target. In the browser, switch a scenario's
advanced **API url** to your local API (e.g. `http://localhost:8070`); no file in this example changes. A
phone used for the flow/2FA scenarios must be able to reach that local API.

---

## How it fits together (and why the SDK module stays clean)

```
examples/
  main.go              wiring only: hands the shared runtime to each family and serves them
  internal/demo/       shared scaffolding — the launcher (bundle fetch + checksum + contract guard +
                       port guard + serve), the on-disk runtime store, the router/dispatch, and the
                       SDK-agnostic HTTP helpers
  identity/            the identity scenario handlers (+ the third-party OIDC + PKCE helpers)
  flow/                the flow scenario handler
  company-data/        the company-data scenario handlers
  frontend.lock        the single pinned frontend release ({tag, sha256}) for the whole suite
  go.mod · go.sum      one Go module for all the examples
```

The examples are **one nested Go module** (`go.mod` here) with a `replace` directive back to the SDK at
`..`. Keeping the examples in their own module keeps their extra dependencies (the OIDC stack) **out of
the published SDK module** entirely. Each scenario family is a small sub-package; open a family's file and
you see exactly the SDK calls it makes. `go.mod` + `go.sum` are committed so two fresh `go run .` builds
resolve the identical graph; `.runtime/` and `.frontend/` are transient and git-ignored.

To point the examples at the **published** package instead of the in-tree source, drop the `replace`
directive, pin a released `github.com/allus-fyi/company-data-go` version, then `go mod tidy`.

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the single pin lives in `frontend.lock`
(`{tag, sha256}`). To move to a newer release: note the release **tag** and its `dist.tar.gz` checksum
(`shasum -a 256 dist.tar.gz`) from `github.com/allme-sdk/example-test-suite`, set `tag` + `sha256` in
`frontend.lock`, `rm -rf .frontend/`, then `go run .` — it re-fetches, verifies the checksum, and checks
the bundle's `contract.json` version against the backend (a mismatch refuses loudly).

## Troubleshooting

| Symptom | Fix |
|---|---|
| **`port 8091 is busy`** at startup | Another SDK example holds the port — one origin is shared, so only one runs at a time. Stop it, or `PORT=<n> go run .`. |
| **`contract mismatch: bundle contractVersion=… backend implements 3`** | The pinned bundle's `contract.json` version differs from this backend. Bump `frontend.lock` to a matching release (and re-fetch), or update the backend. |
| **`frontend checksum MISMATCH`** | The downloaded `dist.tar.gz` doesn't match `frontend.lock`'s `sha256`. Fix the `sha256` (from `shasum -a 256 dist.tar.gz` on the real release) or re-download. |
| **`could not download the pinned frontend release`** | The pinned release isn't published yet, or no network. If unpublished, seed the bundle into `.frontend/<tag>/` manually (`tar -xzf dist.tar.gz -C .frontend/<tag>`, `printf %s <sha> > .frontend/<tag>/.sha`). |
| **`not_configured`** on Run | Save the scenario's setup first — Run builds the SDK from the saved config file. |
| **`start_failed`** naming a key | The service/OAuth PEM or passphrase is wrong — re-pick the key and re-save. |
