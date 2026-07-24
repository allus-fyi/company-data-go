# Identity example — sign-in / OIDC / 2FA (Go SDK)

A runnable website that demonstrates **every identity scenario** of the allme
platform — Sign in with allme, OIDC login, and 2FA by allme — through the
`github.com/allus-fyi/company-data-go` **Go SDK**. It is the Go port of the
[demo-backend contract](https://github.com/allme-sdk/example-test-suite)
(`CONTRACT.md`) that all six SDK examples implement: ~90 % of the logic is a
shared frontend fetched from a pinned release; this directory is the thin Go
backend that serves it and implements the contract endpoints.

Everything the handlers do goes through the SDK's **intended top-level surface**
(`companydata.OAuthClient`, `companydata.Client`, `companydata.TwoFactorClient`)
— never internals, never raw platform HTTP. The OIDC scenarios use the standard
third-party `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2` stack — that
is the point of the OIDC demonstration (#314).

---

## Run it — one command

```bash
cd sdks/go/examples/identity
go run .
```

That runs `main.go`, which:

1. wipes `.runtime/` (fresh state every boot),
2. on first run, downloads the **pinned** frontend release named in
   `frontend.lock`, **verifies its sha256**, and unpacks it to
   `.frontend/<tag>/` (a present, verified bundle is a cache hit — nothing is
   re-fetched),
3. checks the bundle's `contract.json` version against the backend's,
4. refuses a busy port with a clear message, then
5. serves `http://localhost:8091` — a **single** `net/http` server whose
   requests are serialised behind one mutex (the Go equivalent of the PHP
   reference's single-worker `php -S`).

Open **http://localhost:8091** and pick a scenario. Each scenario's setup panel
has a **Save** button: it POSTs your settings to the backend, which writes them
to a canonical SDK **config file** (`.runtime/config/{id}.json`, any PEM under
`.runtime/config/keys/`) — the same shape a real integrator wires by hand. The
panel shows the written path so you can open and read the real config; **Run**
then builds the SDK from that file (`companydata.OAuthClientFromConfig` /
`companydata.FromConfig`) and runs off it. You never hand-create or edit the
file — the backend writes it from your browser inputs; it is there to be read.

**Port.** `8091` is the default, overridable with the `PORT` env var:

```bash
PORT=8092 go run .
```

The default is deliberately the **same across all six SDK examples** (one browser
origin ⇒ your localStorage setup carries across SDKs) — the documented
consequence is that only one example runs at a time.

**Requirements:** Go ≥ 1.26 and network access on first run (to fetch the pinned
frontend release + the OIDC libraries). No system `curl`/`tar` needed — the
download, checksum, and unpack are done in-process.

---

## Which SDK call implements each scenario

| # | Scenario | SDK / library calls the handler makes |
|---|----------|----------------------------------------|
| 1 | Sign in — redirect | `OAuthClient.AuthorizeURL("signin", redirect, PKCE)` → callback → `OAuthClient.CompleteSignIn` |
| 2 | Sign in — detached | `OAuthClient.AuthorizeURL("signin", detached)` → poll `OAuthClient.PollResult` → `OAuthClient.CompleteSignIn` |
| 3 | One-time claims | `OAuthClient.AuthorizeURL("one_time", claims)` → `OAuthClient.CompleteSignIn` (decrypts via the config's `oauth_private_key`) |
| 4 | Connect (stay-connected) | `OAuthClient.AuthorizeURL("connect")` → `OAuthClient.CompleteSignIn`, then live values via `Client.ConnectionsList` (matched by share code) |
| 5 | OIDC login | `oidc.NewProvider` (discovery) → `oauth2.Config.AuthCodeURL` (PKCE) → `oauth2.Config.Exchange` → `IDTokenVerifier.Verify` |
| 6 | OIDC — continue on phone | same OIDC stack as 5; completion arrives on the redirect leg |
| 7 | 2FA at consent — **guide** | none — a checklist card with no `/start`; links to scenarios 1 & 5 where the 2FA prompt is observed |
| 8 | Standalone service-2FA + enrollment | `Client.TwoFactor().Challenge` → `TwoFactorClient.WaitForResult`; enrollment via `OAuthClient.AuthorizeURL("2fa_enroll", …)` (redirect + detached legs) |

---

## How dependencies are pinned (and why the SDK stays clean)

This example is its **own Go module** (`go.mod` in this directory) with a
`replace` directive back to the in-tree SDK (`../..`). That keeps the third-party
OIDC libraries (`go-oidc`, `oauth2`, `go-jose`) **out of the published SDK
module** entirely — they are dependencies of the example only. `go.mod` + `go.sum`
are committed so two fresh `go run .` builds resolve the identical graph;
`.runtime/` and `.frontend/` are transient and git-ignored.
