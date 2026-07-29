package identity

// The identity scenario family: Sign in with allme, OIDC login, and 2FA by allme (scenario ids 1–8; 7 is
// a guide card with no /start). Every handler goes through the SDK's intended top-level surface
// (companydata.OAuthClient, companydata.Client, companydata.TwoFactorClient) — never internals, never raw
// platform HTTP — except the OIDC scenarios (5/6), which deliberately use the standard third-party
// go-oidc + x/oauth2 stack to prove real OIDC interop (see oidc.go).
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

// noOrigin is the refusal when the request carries no Host header, so the browser's origin is unknown.
// There is NO default host: substituting one (localhost) silently sends the round-trip to a
// DIFFERENT origin than the browser is on — a different localStorage and a redirect URI the OAuth app
// never registered.
const noOrigin = "no_origin — this request carried no Host header, so the OAuth redirect URI cannot be " +
	"derived from the origin your browser is using. Open the example by its address " +
	"(http://<host>:<port>/) and save the setup again."

// noStoredOrigin is the refusal when the scenario's saved config holds no redirect URI to complete the
// exchange with.
const noStoredOrigin = "no_origin — the saved config has no oauth_redirect_uri. Save the scenario setup " +
	"again from the browser you will complete the sign-in in."

// The "what just happened" trace. Every entry is `<SDK method> — <what that call did in THIS
// scenario>`, appended AT the call site, in the order the calls were made; an entry wrapped in
// parentheses is a step that is deliberately NOT an SDK call. Keep them in step when this file changes: the
// panel is headed "What just happened", and a list that no longer matches the code is worse than a short
// one.
const (
	callIDWBuild           = "companydata.OAuthClientFromConfig — builds the RP client from the saved config file: client id, secret and the registered redirect URI"
	callAuthSignin         = "OAuthClient.AuthorizeURL — the consent URL the person is sent to (mode signin, response_mode redirect, PKCE S256, state = this run id)"
	callAuthSigninDetached = "OAuthClient.AuthorizeURL — the sign-in URL behind the link + QR (mode signin, response_mode detached, PKCE S256, state = this run id)"
	callAuthOneTime        = "OAuthClient.AuthorizeURL — the consent URL the person is sent to (mode one_time, claims email + phone, PKCE S256, state = this run id)"
	callAuthConnect        = "OAuthClient.AuthorizeURL — the consent URL the person is sent to (mode connect, PKCE S256, state = this run id)"
	callAuthEnroll         = "OAuthClient.AuthorizeURL — the enrollment URL the person is sent to (mode 2fa_enroll, response_mode redirect)"
	callAuthEnrollDetached = "OAuthClient.AuthorizeURL — the enrollment URL behind the link + QR (mode 2fa_enroll, response_mode detached)"
	callPollSignin         = "OAuthClient.PollResult — polls POST /oauth2/result until the phone delivers the code (one 2s-bounded call per browser poll)"
	callPollEnroll         = "OAuthClient.PollResult — polls POST /oauth2/result until the phone delivers {enrolled: true} (one 2s-bounded call per browser poll)"
	callCompleteSignin     = "OAuthClient.CompleteSignIn — exchanges the code + PKCE verifier at POST /oauth2/token, then reads GET /api/oauth/userinfo; mode signin returns the identity only, no claim values"
	callCompleteOneTime    = "OAuthClient.CompleteSignIn — exchanges the code + PKCE verifier at POST /oauth2/token, reads GET /api/oauth/userinfo, and decrypts every claim value with the OAuth app private key"
	callCompleteConnect    = "OAuthClient.CompleteSignIn — exchanges the code + PKCE verifier at POST /oauth2/token, then reads GET /api/oauth/userinfo; connect delivers no values here, the live ones come from the data client below"
	callEnrolledCallback   = "(callback ?enrolled=true) — the redirect-leg enrollment outcome; there is nothing to exchange, so no further SDK call"
	callServiceBuild       = "companydata.FromConfig — builds the SERVICE-role data client from the saved config file: client credentials plus the service private key, decrypted with its passphrase"
	callConnectionsLive    = "Client.ConnectionsList — pages GET /api/company-data/connections and decrypts each person's values with the service key; the run keeps the one whose share code just signed in"
	callTwoFactor          = "Client.TwoFactor — the service-2FA sub-client, on the same data-client credentials"
	callChallenge          = "TwoFactorClient.Challenge — POST /api/service-2fa/challenges for the person's share code with a per-run idempotency key; returns the challenge id, plus matching digits when the service has number matching on"
	callWaitResult         = "TwoFactorClient.WaitForResult — polls GET /api/service-2fa/challenges/{id} until the status leaves pending: approved, denied, expired or revoked (one 2s-bounded call per browser poll; the first terminal read burns the result)"
	callOIDCDiscovery      = "(oidc) oidc.NewProvider — discovery: fetches /.well-known/openid-configuration from the configured API base"
	callOIDCAuthURL        = "(oidc) oauth2.Config.AuthCodeURL — the authorization URL (scope openid profile email, PKCE S256, nonce, state = this run id)"
	callOIDCToken          = "(oidc) oauth2.Config.Exchange — exchanges the code at the discovered token endpoint (client_secret_post + PKCE verifier)"
	callOIDCVerify         = "(oidc) IDTokenVerifier.Verify — verifies the id_token against the JWKS: signature, issuer, audience and nonce; the claims shown are that verified token's"
)

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
	writeJSON    = demo.WriteJSON
	writeFailure = demo.WriteFailure
	readBody     = demo.ReadBody
	newRunID     = demo.NewRunID
	toStr        = demo.ToStr
	asInt        = demo.AsInt
	orDefault    = demo.OrDefault
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
	// The redirect URI is derived from THIS request's origin and from nothing else. Refuse
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
				writeFailure(w, 500, "server_error", err)
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
				writeFailure(w, 500, "server_error", err)
				return
			}
			cfg["service_private_key"] = path
		}
		cfg["key_passphrase"] = toStr(in["keyPassphrase"])
	}

	configPath, err := h.rt.WriteConfig(id, cfg)
	if err != nil {
		writeFailure(w, 500, "server_error", err)
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
				// A claim carries a mandatory, unique Name — the key Values and Attestations
				// come back under. The demo's config lists claim TYPES, so the type doubles as the
				// name; a real integration usually names them for its own domain ("billing_email").
				claims = append(claims, companydata.Claim{Name: t, Type: t})
			}
		}
		authCall := callAuthSignin
		if n == 3 {
			authCall = callAuthOneTime
		} else if n == 4 {
			authCall = callAuthConnect
		}
		run["calls"] = []any{callIDWBuild, authCall}
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
		h.rt.WriteRun(runID, run)
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "redirect", "url": url}})

	case 2: // sign in — detached
		verifier, challenge := generatePKCE()
		run["verifier"] = verifier
		run["wait"] = "detached_signin"
		run["calls"] = []any{callIDWBuild, callAuthSigninDetached}
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
		run["calls"] = []any{callOIDCDiscovery, callOIDCAuthURL}
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
		run["calls"] = []any{callServiceBuild, callTwoFactor, callChallenge}
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
		h.rt.WriteRun(runID, run)
		var digits any
		if challenge.MatchingDigits != "" {
			digits = challenge.MatchingDigits
		}
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "challenge", "matchingDigits": digits}})
	}
}

// startErr surfaces a start-time SDK/OIDC/2FA failure as a NON-2xx the consuming client is documented
// to raise. A 200 without {runId,action} looks like a successful start to the client, which then clears
// any prior error and installs no run id — leaving the developer with no failure message and no
// pollable run. Both /start and /enroll
// route their error paths here.
func (h *family) startErr(w http.ResponseWriter, err error) {
	writeFailure(w, 500, "server_error", err)
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

	wait, enrollCall := "enroll_redirect", callAuthEnroll
	if responseMode == "detached" {
		wait, enrollCall = "detached_enroll", callAuthEnrollDetached
	}
	run := map[string]any{
		"scenario": id, "isEnroll": true, "status": "pending", "state": runID,
		"calls": []any{callIDWBuild, enrollCall}, "wait": wait,
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
		// Redirect-leg enrollment outcome — nothing to exchange; record it.
		run["status"] = "done"
		run["result"] = map[string]any{"enrolled": true}
		appendCall(run, callEnrolledCallback)
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
		appendCall(run, callPollSignin)
		oauth, err := h.oauthClientFor(id, pollTimeout)
		if err != nil {
			return failRun(run, err)
		}
		body, err := oauth.PollResult(toStr(run["state"]), pollTimeout, pollTimeout)
		if err != nil {
			return pollErr(run, err)
		}
		if code := toStr(body["code"]); code != "" {
			run = h.completeSignin(run, code)
		}
	case "detached_enroll":
		appendCall(run, callPollEnroll)
		oauth, err := h.oauthClientFor(id, pollTimeout)
		if err != nil {
			return failRun(run, err)
		}
		body, err := oauth.PollResult(toStr(run["state"]), pollTimeout, pollTimeout)
		if err != nil {
			return pollErr(run, err)
		}
		if b, _ := body["enrolled"].(bool); b {
			run["status"] = "done"
			run["result"] = map[string]any{"enrolled": true}
		}
	case "challenge":
		appendCall(run, callWaitResult)
		client, err := h.serviceClientFor(id, pollTimeout)
		if err != nil {
			return failRun(run, err)
		}
		res, err := client.TwoFactor().WaitForResult(context.Background(), toStr(run["challengeId"]), pollTimeout, pollTimeout)
		if err != nil {
			return pollErr(run, err)
		}
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
	completeCall := callCompleteSignin
	if asInt(id) == 3 {
		completeCall = callCompleteOneTime
	} else if asInt(id) == 4 {
		completeCall = callCompleteConnect
	}
	appendCall(run, completeCall)
	oauth, err := h.oauthClientFor(id, 0)
	if err != nil {
		return failRun(run, err)
	}
	res, err := oauth.CompleteSignIn(code, toStr(run["verifier"]))
	if err != nil {
		return failRun(run, err)
	}
	result := map[string]any{
		"user":       res.User,
		"mode":       res.Mode,
		"two_factor": res.TwoFactor,
		"values":     res.Values,
	}

	if asInt(id) == 4 {
		shareCode := res.User["share_code"]
		appendCall(run, callServiceBuild)
		client, err := h.serviceClientFor(id, 0)
		if err != nil {
			return failRun(run, err)
		}
		appendCall(run, callConnectionsLive)
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
	appendCall(run, callOIDCDiscovery)
	setup, err := h.oidcSetupFor(ctx, id)
	if err != nil {
		return failRun(run, err)
	}
	appendCall(run, callOIDCToken, callOIDCVerify)
	claims, err := setup.exchangeAndVerify(ctx, code, toStr(run["verifier"]), toStr(run["nonce"]))
	if err != nil {
		return failRun(run, err)
	}
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

// oidcSetupFor builds the OIDC discovery + oauth2 config (the OIDC compliance surface) from the config file.
func (h *family) oidcSetupFor(ctx context.Context, id string) (*oidcSetup, error) {
	cfg := readJSONMap(h.rt.ConfigPath(id))
	if cfg == nil {
		cfg = map[string]any{}
	}
	// The SAME value the authorize URL carried, so the two legs of the exchange cannot diverge. An
	// absent record is a loud failure, never a substituted host.
	redirectURI := strings.TrimSpace(toStr(cfg["oauth_redirect_uri"]))
	if redirectURI == "" {
		return nil, errors.New(noStoredOrigin)
	}
	return newOIDCSetup(ctx, toStr(cfg["api_url"]), toStr(cfg["oauth_client_id"]),
		toStr(cfg["oauth_client_secret"]), redirectURI)
}

// redirectURI is the registered redirect URI: http://{host}/callback, host = the origin the browser
// actually used. Never falls back to a hardcoded host — 127.0.0.1 and localhost are DIFFERENT
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

// appendCall records call names on a run's "what just happened" trace through the shared, deduping
// implementation (standards §1), deduping repeat calls across a run's polls.
func appendCall(run map[string]any, names ...string) {
	for _, n := range names {
		demo.RecordCall(run, n)
	}
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
