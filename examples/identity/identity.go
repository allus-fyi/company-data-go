package identity

// The identity scenario family: Sign in with allme, OIDC login, and 2FA by allme (scenario ids 1–8; 7 is
// a guide card with no /start). Every handler goes through the SDK's intended top-level surface
// (companydata.OAuthClient, companydata.Client, companydata.TwoFactorClient) — never internals, never raw
// platform HTTP — except the OIDC scenarios (5/6), which deliberately use the standard third-party
// go-oidc + x/oauth2 stack to prove real OIDC interop (#314; see oidc.go).
//
// Settings flow: the browser POSTs a scenario's setup values to POST /api/scenarios/{id}/config, which
// writes them to a canonical SDK config FILE. /start and /enroll then build the SDK from that file via
// the role-appropriate file constructor (OAuthClientFromConfig → ConfigFromIdwFile; FromConfig for the
// service reads) and run OFF the config — exactly as a real integrator wires the SDK. The request body of
// /start is ignored; a /start with no saved config → 409 not_configured.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/allus-fyi/company-data-go/companydata"
	"github.com/allus-fyi/company-data-go/examples/internal/demo"
)

const (
	defaultAPIURL      = demo.DefaultAPIURL
	defaultAuthBase    = companydata.DefaultAuthorizeURL // https://web.allme.fyi/auth
	pollTimeout        = 2 * time.Second                 // short-cycled SDK wait per poll (contract §3)
	oidcNetworkTimeout = 15 * time.Second                // bounds OIDC discovery + token exchange
)

// noOrigin is the refusal when the request carries no Host header, so the browser's origin is unknown
// (#574). There is NO default host: substituting one (localhost) silently sends the round-trip to a
// DIFFERENT origin than the browser is on — a different localStorage and a redirect URI the OAuth app
// never registered.
const noOrigin = "no_origin — this request carried no Host header, so the OAuth redirect URI cannot be " +
	"derived from the origin your browser is using. Open the example by its address " +
	"(http://<host>:<port>/) and save the setup again."

// noStoredOrigin is the refusal when the scenario's saved config holds no redirect URI to complete the
// exchange with.
const noStoredOrigin = "no_origin — the saved config has no oauth_redirect_uri. Save the scenario setup " +
	"again from the browser you will complete the sign-in in."

// scenarios maps id → "runnable" | "guide". Scenario 7 is the guide card (no /start).
var scenarios = map[int]string{
	1: "runnable", 2: "runnable", 3: "runnable", 4: "runnable",
	5: "runnable", 6: "runnable", 7: "guide", 8: "runnable",
}

// scenario ids by role.
var (
	serviceScenarios = map[int]bool{4: true, 8: true} // also read live values via the data Client
	oauthURLScenario = map[int]bool{1: true, 2: true, 3: true, 4: true, 8: true}
)

// thin aliases to the shared scaffolding helpers so the handler code below reads cleanly.
var (
	writeJSON = demo.WriteJSON
	readBody  = demo.ReadBody
	newRunID  = demo.NewRunID
	toStr     = demo.ToStr
	asInt     = demo.AsInt
	orDefault = demo.OrDefault
)

// family implements demo.Family (+ demo.Callbacker, demo.Enroller) for the identity scenarios.
type family struct{ rt *demo.Runtime }

// New binds the identity family to the shared runtime.
func New(rt *demo.Runtime) demo.Family { return &family{rt: rt} }

// Scenarios lists identity scenarios 1–8 with numeric ids (7 is the guide card).
func (family) Scenarios() []demo.Scenario {
	list := make([]demo.Scenario, 0, len(scenarios))
	for id := 1; id <= len(scenarios); id++ {
		list = append(list, demo.Scenario{ID: id, Kind: scenarios[id]})
	}
	return list
}

// Owns reports whether id is one of the identity family's numeric scenario ids.
func (family) Owns(id string) bool {
	if id == "" {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return scenarios[asInt(id)] != ""
}

// ── POST /api/scenarios/{id}/config ───────────────────────────────────────────

// Config writes the browser's setup values to a canonical SDK config FILE. Any PEM is written to
// .runtime/config/keys/ and referenced by path; demo-only run parameters (authorize base, one_time
// claims, share code, context) go to a meta sidecar so the config file stays a pure SDK config.
func (h *family) Config(w http.ResponseWriter, r *http.Request, id string) {
	n := asInt(id)
	if scenarios[n] != "runnable" {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	// The redirect URI is derived from THIS request's origin and from nothing else (#574). Refuse
	// rather than store a hostless URI: the suite renders this sentence on Save.
	if strings.TrimSpace(r.Host) == "" {
		writeJSON(w, 400, map[string]any{"error": noOrigin})
		return
	}
	in := readBody(r)

	// Canonical SDK config — the idw role for every OAuth scenario.
	cfg := map[string]any{
		"api_url":            strings.TrimRight(orDefault(toStr(in["apiUrl"]), defaultAPIURL), "/"),
		"oauth_client_id":    toStr(in["oauthClientId"]),
		"oauth_redirect_uri": h.redirectURI(r),
	}
	if secret := toStr(in["oauthClientSecret"]); secret != "" {
		cfg["oauth_client_secret"] = secret
	}

	// Scenario 3 (one_time): the OAuth app private key decrypts the claim values (config-only keys).
	if n == 3 {
		if pem := toStr(in["oauthPrivateKeyPem"]); pem != "" {
			path, err := h.rt.MaterializeConfigKey(pem)
			if err != nil {
				writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
				return
			}
			cfg["oauth_private_key"] = path
		}
		if pass := toStr(in["oauthKeyPassphrase"]); pass != "" {
			cfg["oauth_key_passphrase"] = pass
		}
	}

	// Scenarios 4/8 also read live values via the service data Client — add the service-role keys to the
	// SAME file (role only decides which fields are REQUIRED; Config loads whatever is present).
	if serviceScenarios[n] {
		cfg["client_id"] = toStr(in["clientId"])
		cfg["client_secret"] = toStr(in["clientSecret"])
		if pem := toStr(in["servicePrivateKeyPem"]); pem != "" {
			path, err := h.rt.MaterializeConfigKey(pem)
			if err != nil {
				writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
				return
			}
			cfg["service_private_key"] = path
		}
		cfg["key_passphrase"] = toStr(in["keyPassphrase"])
	}

	configPath, err := h.rt.WriteConfig(id, cfg)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
		return
	}

	// Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
	meta := map[string]any{}
	if oauthURLScenario[n] {
		meta["authorize_base"] = orDefault(toStr(in["authorizeBase"]), defaultAuthBase)
	}
	if n == 3 {
		meta["claims"] = claimTypes(in)
	}
	if n == 8 {
		meta["share_code"] = toStr(in["shareCode"])
		if c := toStr(in["context"]); c != "" {
			meta["context"] = c
		}
	}
	h.rt.WriteConfigMeta(id, meta)

	writeJSON(w, 200, map[string]any{"ok": true, "configPath": configPath})
}

// ── POST /api/scenarios/{id}/start ────────────────────────────────────────────

func (h *family) Start(w http.ResponseWriter, r *http.Request, id string) {
	n := asInt(id)
	if scenarios[n] != "runnable" {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	if !h.rt.HasConfig(id) {
		writeJSON(w, 409, map[string]any{"error": "not_configured"})
		return
	}
	runID := newRunID()
	run := map[string]any{"scenario": id, "status": "pending", "state": runID, "calls": []any{}}

	switch n {
	case 1, 3, 4: // sign in — redirect | one-time claims | connect
		verifier, challenge := generatePKCE()
		run["verifier"] = verifier
		mode := map[int]string{1: "signin", 3: "one_time", 4: "connect"}[n]
		var claims []companydata.Claim
		if n == 3 {
			for _, t := range claimTypes(h.rt.ReadConfigMeta(id)) {
				// #498: a claim carries a mandatory, unique Name — the key Values and Attestations
				// come back under. The demo's config lists claim TYPES, so the type doubles as the
				// name; a real integration usually names them for its own domain ("billing_email").
				claims = append(claims, companydata.Claim{Name: t, Type: t})
			}
		}
		oauth, err := h.oauthClientFor(id, 0)
		if err != nil {
			h.startErr(w, err)
			return
		}
		url, err := oauth.AuthorizeURL(mode, &companydata.AuthorizeURLOptions{
			Claims: claims, State: runID, ResponseMode: "redirect", CodeChallenge: challenge,
		})
		if err != nil {
			h.startErr(w, err)
			return
		}
		run["calls"] = []any{"OAuthClient.AuthorizeURL"}
		h.rt.WriteRun(runID, run)
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "redirect", "url": url}})

	case 2: // sign in — detached
		verifier, challenge := generatePKCE()
		run["verifier"] = verifier
		run["wait"] = "detached_signin"
		oauth, err := h.oauthClientFor(id, 0)
		if err != nil {
			h.startErr(w, err)
			return
		}
		url, err := oauth.AuthorizeURL("signin", &companydata.AuthorizeURLOptions{
			State: runID, ResponseMode: "detached", CodeChallenge: challenge,
		})
		if err != nil {
			h.startErr(w, err)
			return
		}
		run["calls"] = []any{"OAuthClient.AuthorizeURL"}
		h.rt.WriteRun(runID, run)
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "detached", "url": url}})

	case 5, 6: // OIDC login | OIDC — continue on your phone
		verifier, challenge := generatePKCE()
		nonce := newRunID()
		run["verifier"] = verifier
		run["nonce"] = nonce
		ctx, cancel := oidcContext(context.Background(), oidcNetworkTimeout)
		defer cancel()
		setup, err := h.oidcSetupFor(ctx, id)
		if err != nil {
			h.startErr(w, err)
			return
		}
		url := setup.authCodeURL(runID, nonce, challenge)
		run["calls"] = []any{"(oidc) oidc.NewProvider", "(oidc) oauth2.Config.AuthCodeURL"}
		h.rt.WriteRun(runID, run)
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "redirect", "url": url}})

	case 8: // standalone service-2FA — the challenge step
		meta := h.rt.ReadConfigMeta(id)
		shareCode := toStr(meta["share_code"])
		contextText := toStr(meta["context"])
		idemKey := ("demo-" + runID)
		if len(idemKey) > 64 {
			idemKey = idemKey[:64]
		}
		run["wait"] = "challenge"
		client, err := h.serviceClientFor(id, 0)
		if err != nil {
			h.startErr(w, err)
			return
		}
		challenge, err := client.TwoFactor().Challenge(context.Background(), shareCode, idemKey, contextText)
		if err != nil {
			h.startErr(w, err)
			return
		}
		run["challengeId"] = challenge.ChallengeID
		run["calls"] = []any{"Client.TwoFactor", "TwoFactorClient.Challenge"}
		h.rt.WriteRun(runID, run)
		var digits any
		if challenge.MatchingDigits != "" {
			digits = challenge.MatchingDigits
		}
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "challenge", "matchingDigits": digits}})
	}
}

// startErr surfaces a start-time SDK/OIDC/2FA failure as a NON-2xx the shared frontend client raises
// (parity with the other ports' top-level 500 guard). A 200 without {runId,action} looks like a
// successful start to the client, which then clears any prior error and installs no run id — leaving the
// developer with no failure message and no pollable run (#482 review-pass-1). Both /start and /enroll
// route their error paths here.
func (h *family) startErr(w http.ResponseWriter, err error) {
	writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
}

// ── POST /api/scenarios/{id}/enroll (scenario 8) ──────────────────────────────

func (h *family) Enroll(w http.ResponseWriter, r *http.Request, id string) {
	if asInt(id) != 8 {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	if !h.rt.HasConfig(id) {
		writeJSON(w, 409, map[string]any{"error": "not_configured"})
		return
	}
	in := readBody(r)
	responseMode := "redirect"
	if toStr(in["responseMode"]) == "detached" {
		responseMode = "detached"
	}
	runID := newRunID()

	oauth, err := h.oauthClientFor(id, 0)
	if err != nil {
		h.startErr(w, err)
		return
	}
	url, err := oauth.AuthorizeURL("2fa_enroll", &companydata.AuthorizeURLOptions{
		State: runID, ResponseMode: responseMode,
	})
	if err != nil {
		h.startErr(w, err)
		return
	}

	wait := "enroll_redirect"
	if responseMode == "detached" {
		wait = "detached_enroll"
	}
	run := map[string]any{
		"scenario": id, "isEnroll": true, "status": "pending", "state": runID,
		"calls": []any{"OAuthClient.AuthorizeURL"}, "wait": wait,
	}
	h.rt.WriteRun(runID, run)

	action := map[string]any{"type": responseMode, "url": url}
	writeJSON(w, 200, map[string]any{"runId": runID, "action": action})
}

// ── POST /api/scenarios/{id}/clear ────────────────────────────────────────────

func (h *family) Clear(w http.ResponseWriter, r *http.Request, id string) {
	h.rt.ClearScenario(id)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ── GET /callback ─────────────────────────────────────────────────────────────

func (h *family) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	run := h.rt.ReadRun(state)
	if run == nil {
		http.Redirect(w, r, "/?error=unknown_run", http.StatusFound)
		return
	}
	id := toStr(run["scenario"])
	n := asInt(id)

	if q.Get("enrolled") == "true" {
		// Redirect-leg enrollment outcome (#436) — nothing to exchange; record it.
		run["status"] = "done"
		run["result"] = map[string]any{"enrolled": true}
		appendCall(run, "callback(enrolled=true)")
	} else if code := q.Get("code"); code != "" {
		if n == 5 || n == 6 {
			run = h.completeOidc(run, code)
		} else {
			run = h.completeSignin(run, code)
		}
	} else {
		run["status"] = "failed"
		run["error"] = "callback missing code / enrolled"
	}

	h.rt.WriteRun(state, run)
	http.Redirect(w, r, "/?scenario="+id+"&run="+state, http.StatusFound)
}

// ── GET /api/runs/{runId} ─────────────────────────────────────────────────────

func (h *family) Run(w http.ResponseWriter, runID string, run map[string]any) {
	// Idempotent: a terminal outcome is returned on every poll until TTL/Clear.
	if toStr(run["status"]) == "pending" {
		run = h.advance(run)
		h.rt.WriteRun(runID, run)
	}

	out := map[string]any{"status": orDefault(toStr(run["status"]), "pending"), "calls": run["calls"]}
	if run["result"] != nil {
		out["result"] = run["result"]
	}
	if run["error"] != nil {
		out["error"] = run["error"]
	}
	writeJSON(w, 200, out)
}

// advance short-cycles a pending run awaiting a detached / challenge outcome: ONE SDK wait with
// timeout 2s per poll; an SDK logical timeout is treated as still-pending. Clients are rebuilt from the
// run's scenario config file — the run stores no credentials.
func (h *family) advance(run map[string]any) map[string]any {
	id := toStr(run["scenario"])
	switch toStr(run["wait"]) {
	case "detached_signin":
		oauth, err := h.oauthClientFor(id, pollTimeout)
		if err != nil {
			return failRun(run, err)
		}
		body, err := oauth.PollResult(toStr(run["state"]), pollTimeout, pollTimeout)
		if err != nil {
			return pollErr(run, err)
		}
		appendCall(run, "OAuthClient.PollResult")
		if code := toStr(body["code"]); code != "" {
			run = h.completeSignin(run, code)
		}
	case "detached_enroll":
		oauth, err := h.oauthClientFor(id, pollTimeout)
		if err != nil {
			return failRun(run, err)
		}
		body, err := oauth.PollResult(toStr(run["state"]), pollTimeout, pollTimeout)
		if err != nil {
			return pollErr(run, err)
		}
		appendCall(run, "OAuthClient.PollResult")
		if b, _ := body["enrolled"].(bool); b {
			run["status"] = "done"
			run["result"] = map[string]any{"enrolled": true}
		}
	case "challenge":
		client, err := h.serviceClientFor(id, pollTimeout)
		if err != nil {
			return failRun(run, err)
		}
		res, err := client.TwoFactor().WaitForResult(context.Background(), toStr(run["challengeId"]), pollTimeout, pollTimeout)
		if err != nil {
			return pollErr(run, err)
		}
		appendCall(run, "TwoFactorClient.WaitForResult")
		run["status"] = "done"
		run["result"] = map[string]any{"status": res.Status, "completed_at": res.CompletedAt}
	}
	// else (redirect / continue-on-phone flows): completion arrives via /callback — stay pending.
	return run
}

// pollErr distinguishes the SDK's LOGICAL "not completed within Ns" timeout (still pending) from a real
// transport failure (failed run). The SDK poll helpers signal the logical timeout as an *ApiError(0)
// whose message contains that exact sentinel; a transport failure is a different *ApiError(0) message.
func pollErr(run map[string]any, err error) map[string]any {
	if strings.Contains(err.Error(), "not completed within") {
		return run // logical short-cycle timeout → still pending
	}
	return failRun(run, err)
}

// ── SDK / OIDC completion helpers ─────────────────────────────────────────────

// completeSignin completes a redirect / detached SIGN-IN (scenarios 1, 2, 3, 4): exchange + read
// identity via CompleteSignIn, and for connect (4) read the person's LIVE values via the service client.
func (h *family) completeSignin(run map[string]any, code string) map[string]any {
	id := toStr(run["scenario"])
	oauth, err := h.oauthClientFor(id, 0)
	if err != nil {
		return failRun(run, err)
	}
	res, err := oauth.CompleteSignIn(code, toStr(run["verifier"]))
	if err != nil {
		return failRun(run, err)
	}
	appendCall(run, "OAuthClient.CompleteSignIn")
	result := map[string]any{
		"user":       res.User,
		"mode":       res.Mode,
		"two_factor": res.TwoFactor,
		"values":     res.Values,
	}

	if asInt(id) == 4 {
		shareCode := res.User["share_code"]
		client, err := h.serviceClientFor(id, 0)
		if err != nil {
			return failRun(run, err)
		}
		conns, err := client.ConnectionsList(context.Background(), 0, 0)
		if err != nil {
			return failRun(run, err)
		}
		live := map[string]any{}
		for _, conn := range conns {
			if shareCode != "" && conn.ShareCode == shareCode {
				for slug, v := range conn.Values {
					live[slug] = v.Value
				}
				break
			}
		}
		appendCall(run, "Client.ConnectionsList")
		result["live_values"] = live
	}

	run["status"] = "done"
	run["result"] = result
	return run
}

// completeOidc completes an OIDC sign-in (scenarios 5/6) via the third-party OIDC stack — id_token verified.
func (h *family) completeOidc(run map[string]any, code string) map[string]any {
	id := toStr(run["scenario"])
	ctx, cancel := oidcContext(context.Background(), oidcNetworkTimeout)
	defer cancel()
	setup, err := h.oidcSetupFor(ctx, id)
	if err != nil {
		return failRun(run, err)
	}
	appendCall(run, "(oidc) oidc.NewProvider")
	claims, err := setup.exchangeAndVerify(ctx, code, toStr(run["verifier"]), toStr(run["nonce"]))
	if err != nil {
		return failRun(run, err)
	}
	appendCall(run, "(oidc) oauth2.Config.Exchange", "(oidc) IDTokenVerifier.Verify")
	run["status"] = "done"
	run["result"] = map[string]any{"claims": claims}
	return run
}

// ── SDK / OIDC client builders — built from the persisted config FILE ─────────

// oauthClientFor builds the OAuth client OFF the scenario's config file via the idw file constructor
// (OAuthClientFromConfig → ConfigFromIdwFile). A non-default authorize base (local-stack option) is
// supplied via WithAuthorizeURL. timeout > 0 injects a bounded HTTP Doer for the short-cycled polls so
// one blackholed request cannot pin the single worker for the default 60s transport (contract §3).
func (h *family) oauthClientFor(id string, timeout time.Duration) (*companydata.OAuthClient, error) {
	var opts []companydata.OAuthOption
	if timeout > 0 {
		opts = append(opts, companydata.WithOAuthDoer(&http.Client{Timeout: timeout}))
	}
	if base := toStr(h.rt.ReadConfigMeta(id)["authorize_base"]); base != "" && base != defaultAuthBase {
		opts = append(opts, companydata.WithAuthorizeURL(base))
	}
	return companydata.OAuthClientFromConfig(h.rt.ConfigPath(id), opts...)
}

// serviceClientFor builds the service data client OFF the scenario's config file (service role).
// timeout > 0 injects a bounded HTTP Doer for the short-cycled challenge poll (same reason as above).
func (h *family) serviceClientFor(id string, timeout time.Duration) (*companydata.Client, error) {
	path := h.rt.ConfigPath(id)
	if timeout <= 0 {
		return companydata.FromConfig(path)
	}
	cfg, err := companydata.ConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	return companydata.New(cfg, companydata.WithHTTPClient(
		companydata.NewHTTPClient(cfg, companydata.WithDoer(&http.Client{Timeout: timeout})),
	))
}

// oidcSetupFor builds the OIDC discovery + oauth2 config (the #314 compliance surface) from the config file.
func (h *family) oidcSetupFor(ctx context.Context, id string) (*oidcSetup, error) {
	cfg := readJSONMap(h.rt.ConfigPath(id))
	if cfg == nil {
		cfg = map[string]any{}
	}
	// The SAME value the authorize URL carried, so the two legs of the exchange cannot diverge. An
	// absent record is a loud failure, never a substituted host (#574).
	redirectURI := strings.TrimSpace(toStr(cfg["oauth_redirect_uri"]))
	if redirectURI == "" {
		return nil, errors.New(noStoredOrigin)
	}
	return newOIDCSetup(ctx, toStr(cfg["api_url"]), toStr(cfg["oauth_client_id"]),
		toStr(cfg["oauth_client_secret"]), redirectURI)
}

// redirectURI is the registered redirect URI: http://{host}/callback, host = the origin the browser
// actually used. Never falls back to a hardcoded host (#574) — 127.0.0.1 and localhost are DIFFERENT
// origins for redirect matching and for browser storage alike, so a substituted default drops the
// developer on an origin whose localStorage never held the setup and whose URI the OAuth app never
// registered. Callers refuse an empty r.Host before reaching here.
func (h *family) redirectURI(r *http.Request) string {
	return "http://" + strings.TrimSpace(r.Host) + "/callback"
}

// ── small helpers ─────────────────────────────────────────────────────────────

func claimTypes(in map[string]any) []string {
	if raw, ok := in["claims"].([]any); ok && len(raw) > 0 {
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			out = append(out, toStr(v))
		}
		return out
	}
	return []string{"email", "phone"} // a small default claim set (scenario 3)
}

func appendCall(run map[string]any, names ...string) {
	calls, _ := run["calls"].([]any)
	for _, n := range names {
		calls = append(calls, n)
	}
	run["calls"] = calls
}

func failRun(run map[string]any, err error) map[string]any {
	run["status"] = "failed"
	run["error"] = err.Error()
	return run
}

// readJSONMap decodes a JSON object file into a map; nil on any error (the OIDC setup reads the saved
// config file directly, since the SDK's file constructor is not used for the third-party OIDC stack).
func readJSONMap(path string) map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}
