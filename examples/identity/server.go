package main

// The demo-backend contract (v1), config-file model. One Server, one serialising mutex: HTTP dispatch →
// handler → the intended allme SDK surface (or the standard OIDC stack for scenarios 5/6). Handlers
// NEVER perform raw platform HTTP and NEVER block on the SDK's long defaults — detached / challenge
// waits are short-cycled (timeout 2s) inside GET /api/runs.
//
// Settings flow: the browser POSTs a scenario's setup values to POST /api/scenarios/{id}/config, which
// writes them to a canonical SDK config FILE (.runtime/config/{id}.json). /start and /enroll then build
// the SDK from that file via the role-appropriate file constructor (OAuthClientFromConfig →
// ConfigFromIdwFile; FromConfig → ConfigFromFile for the service reads) and run OFF the config — exactly
// as a real integrator wires the SDK. The request body of /start is ignored; a /start with no saved
// config → 409 not_configured.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/allus-fyi/company-data-go/companydata"
)

const (
	contractVersion    = 1
	sdkName            = "go"
	defaultAPIURL      = "https://api.allme.fyi"
	defaultAuthBase    = companydata.DefaultAuthorizeURL // https://web.allme.fyi/auth
	pollTimeout        = 2 * time.Second                 // short-cycled SDK wait per poll (contract §3)
	oidcNetworkTimeout = 15 * time.Second                // bounds OIDC discovery + token exchange
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

var (
	reConfig = regexp.MustCompile(`^/api/scenarios/(\d+)/config$`)
	reStart  = regexp.MustCompile(`^/api/scenarios/(\d+)/start$`)
	reEnroll = regexp.MustCompile(`^/api/scenarios/(\d+)/enroll$`)
	reClear  = regexp.MustCompile(`^/api/scenarios/(\d+)/clear$`)
	reRun    = regexp.MustCompile(`^/api/runs/([0-9a-f]{32})$`)
)

// Server implements the demo-backend contract.
type Server struct {
	rt          *Runtime
	frontendDir string
	sdkVersion  string
	mu          sync.Mutex // serialises requests → single-worker semantics (contract §3)
}

// ServeHTTP dispatches every request (static bundle OR API) behind the serialising mutex.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rt.ensureDirs()
	s.rt.sweep() // lazy TTL sweep on every request (contract §3)

	path := r.URL.Path
	method := r.Method

	defer func() {
		if rec := recover(); rec != nil {
			writeJSON(w, 500, map[string]any{"error": "server_error", "message": toStr(rec)})
		}
	}()

	switch {
	case path == "/api/meta" && method == http.MethodGet:
		s.meta(w)
	case path == "/callback" && method == http.MethodGet:
		s.callback(w, r)
	case path == "/api/clear" && method == http.MethodPost:
		s.rt.clearAll()
		writeJSON(w, 200, map[string]any{"ok": true})
	case reConfig.MatchString(path) && method == http.MethodPost:
		s.config(w, r, atoiFirst(reConfig, path))
	case reStart.MatchString(path) && method == http.MethodPost:
		s.start(w, r, atoiFirst(reStart, path))
	case reEnroll.MatchString(path) && method == http.MethodPost:
		s.enroll(w, r, atoiFirst(reEnroll, path))
	case reClear.MatchString(path) && method == http.MethodPost:
		s.rt.clearScenario(atoiFirst(reClear, path))
		writeJSON(w, 200, map[string]any{"ok": true})
	case reRun.MatchString(path) && method == http.MethodGet:
		s.run(w, reRun.FindStringSubmatch(path)[1])
	case strings.HasPrefix(path, "/api/"):
		writeJSON(w, 404, map[string]any{"error": "not_found"})
	default:
		s.serveStatic(w, r, path)
	}
}

// ── GET /api/meta ───────────────────────────────────────────────────────────

func (s *Server) meta(w http.ResponseWriter) {
	list := make([]map[string]any, 0, len(scenarios))
	for id := 1; id <= len(scenarios); id++ {
		list = append(list, map[string]any{"id": id, "kind": scenarios[id]})
	}
	writeJSON(w, 200, map[string]any{
		"sdk":             sdkName,
		"sdkVersion":      s.sdkVersion,
		"contractVersion": contractVersion,
		"scenarios":       list,
	})
}

// ── POST /api/scenarios/{id}/config ───────────────────────────────────────────

// config writes the browser's setup values to a canonical SDK config FILE. Any PEM is written to
// .runtime/config/keys/ and referenced by path; demo-only run parameters (authorize base, one_time
// claims, share code, context) go to a meta sidecar so the config file stays a pure SDK config.
func (s *Server) config(w http.ResponseWriter, r *http.Request, id int) {
	if scenarios[id] != "runnable" {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	in := readBody(r)

	// Canonical SDK config — the idw role for every OAuth scenario.
	cfg := map[string]any{
		"api_url":            strings.TrimRight(orDefault(toStr(in["apiUrl"]), defaultAPIURL), "/"),
		"oauth_client_id":    toStr(in["oauthClientId"]),
		"oauth_redirect_uri": s.redirectURI(r),
	}
	if secret := toStr(in["oauthClientSecret"]); secret != "" {
		cfg["oauth_client_secret"] = secret
	}

	// Scenario 3 (one_time): the OAuth app private key decrypts the claim values (config-only keys).
	if id == 3 {
		if pem := toStr(in["oauthPrivateKeyPem"]); pem != "" {
			path, err := s.rt.materializeConfigKey(pem)
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
	if serviceScenarios[id] {
		cfg["client_id"] = toStr(in["clientId"])
		cfg["client_secret"] = toStr(in["clientSecret"])
		if pem := toStr(in["servicePrivateKeyPem"]); pem != "" {
			path, err := s.rt.materializeConfigKey(pem)
			if err != nil {
				writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
				return
			}
			cfg["service_private_key"] = path
		}
		cfg["key_passphrase"] = toStr(in["keyPassphrase"])
	}

	configPath, err := s.rt.writeConfig(id, cfg)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
		return
	}

	// Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
	meta := map[string]any{}
	if oauthURLScenario[id] {
		meta["authorize_base"] = orDefault(toStr(in["authorizeBase"]), defaultAuthBase)
	}
	if id == 3 {
		meta["claims"] = claimTypes(in)
	}
	if id == 8 {
		meta["share_code"] = toStr(in["shareCode"])
		if c := toStr(in["context"]); c != "" {
			meta["context"] = c
		}
	}
	s.rt.writeConfigMeta(id, meta)

	writeJSON(w, 200, map[string]any{"ok": true, "configPath": configPath})
}

// ── POST /api/scenarios/{id}/start ────────────────────────────────────────────

func (s *Server) start(w http.ResponseWriter, r *http.Request, id int) {
	if scenarios[id] != "runnable" {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	if !s.rt.hasConfig(id) {
		writeJSON(w, 409, map[string]any{"error": "not_configured"})
		return
	}
	runID := newRunID()
	run := map[string]any{"scenario": id, "status": "pending", "state": runID, "calls": []any{}}

	switch id {
	case 1, 3, 4: // sign in — redirect | one-time claims | connect
		verifier, challenge := generatePKCE()
		run["verifier"] = verifier
		mode := map[int]string{1: "signin", 3: "one_time", 4: "connect"}[id]
		var claims []companydata.Claim
		if id == 3 {
			for _, t := range claimTypes(s.rt.readConfigMeta(id)) {
				claims = append(claims, companydata.Claim{Type: t})
			}
		}
		oauth, err := s.oauthClientFor(id, 0)
		if err != nil {
			s.startErr(w, err)
			return
		}
		url, err := oauth.AuthorizeURL(mode, &companydata.AuthorizeURLOptions{
			Claims: claims, State: runID, ResponseMode: "redirect", CodeChallenge: challenge,
		})
		if err != nil {
			s.startErr(w, err)
			return
		}
		run["calls"] = []any{"OAuthClient.AuthorizeURL"}
		s.rt.writeRun(runID, run)
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "redirect", "url": url}})

	case 2: // sign in — detached
		verifier, challenge := generatePKCE()
		run["verifier"] = verifier
		run["wait"] = "detached_signin"
		oauth, err := s.oauthClientFor(id, 0)
		if err != nil {
			s.startErr(w, err)
			return
		}
		url, err := oauth.AuthorizeURL("signin", &companydata.AuthorizeURLOptions{
			State: runID, ResponseMode: "detached", CodeChallenge: challenge,
		})
		if err != nil {
			s.startErr(w, err)
			return
		}
		run["calls"] = []any{"OAuthClient.AuthorizeURL"}
		s.rt.writeRun(runID, run)
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "detached", "url": url}})

	case 5, 6: // OIDC login | OIDC — continue on your phone
		verifier, challenge := generatePKCE()
		nonce := newRunID()
		run["verifier"] = verifier
		run["nonce"] = nonce
		ctx, cancel := oidcContext(context.Background(), oidcNetworkTimeout)
		defer cancel()
		setup, err := s.oidcSetupFor(ctx, id)
		if err != nil {
			s.startErr(w, err)
			return
		}
		url := setup.authCodeURL(runID, nonce, challenge)
		run["calls"] = []any{"(oidc) oidc.NewProvider", "(oidc) oauth2.Config.AuthCodeURL"}
		s.rt.writeRun(runID, run)
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "redirect", "url": url}})

	case 8: // standalone service-2FA — the challenge step
		meta := s.rt.readConfigMeta(id)
		shareCode := toStr(meta["share_code"])
		contextText := toStr(meta["context"])
		idemKey := ("demo-" + runID)
		if len(idemKey) > 64 {
			idemKey = idemKey[:64]
		}
		run["wait"] = "challenge"
		client, err := s.serviceClientFor(id, 0)
		if err != nil {
			s.startErr(w, err)
			return
		}
		challenge, err := client.TwoFactor().Challenge(context.Background(), shareCode, idemKey, contextText)
		if err != nil {
			s.startErr(w, err)
			return
		}
		run["challengeId"] = challenge.ChallengeID
		run["calls"] = []any{"Client.TwoFactor", "TwoFactorClient.Challenge"}
		s.rt.writeRun(runID, run)
		var digits any
		if challenge.MatchingDigits != "" {
			digits = challenge.MatchingDigits
		}
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "challenge", "matchingDigits": digits}})
	}
}

// startErr surfaces a start-time SDK/OIDC/2FA failure as a NON-2xx the shared frontend client raises
// (parity with the PHP/Python/TS ports' top-level 500 guard). A 200 without {runId,action} looks like a
// successful start to the client, which then clears any prior error and installs no run id — leaving the
// developer with no failure message and no pollable run (#482 review-pass-1). Both /start and /enroll
// route their error paths here.
func (s *Server) startErr(w http.ResponseWriter, err error) {
	writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
}

// ── POST /api/scenarios/{id}/enroll (scenario 8) ──────────────────────────────

func (s *Server) enroll(w http.ResponseWriter, r *http.Request, id int) {
	if id != 8 {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	if !s.rt.hasConfig(id) {
		writeJSON(w, 409, map[string]any{"error": "not_configured"})
		return
	}
	in := readBody(r)
	responseMode := "redirect"
	if toStr(in["responseMode"]) == "detached" {
		responseMode = "detached"
	}
	runID := newRunID()

	oauth, err := s.oauthClientFor(id, 0)
	if err != nil {
		s.startErr(w, err)
		return
	}
	url, err := oauth.AuthorizeURL("2fa_enroll", &companydata.AuthorizeURLOptions{
		State: runID, ResponseMode: responseMode,
	})
	if err != nil {
		s.startErr(w, err)
		return
	}

	wait := "enroll_redirect"
	if responseMode == "detached" {
		wait = "detached_enroll"
	}
	run := map[string]any{
		"scenario": 8, "isEnroll": true, "status": "pending", "state": runID,
		"calls": []any{"OAuthClient.AuthorizeURL"}, "wait": wait,
	}
	s.rt.writeRun(runID, run)

	action := map[string]any{"type": responseMode, "url": url}
	writeJSON(w, 200, map[string]any{"runId": runID, "action": action})
}

// ── GET /callback ─────────────────────────────────────────────────────────────

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	run := s.rt.readRun(state)
	if run == nil {
		http.Redirect(w, r, "/?error=unknown_run", http.StatusFound)
		return
	}
	id := asInt(run["scenario"])

	if q.Get("enrolled") == "true" {
		// Redirect-leg enrollment outcome (#436) — nothing to exchange; record it.
		run["status"] = "done"
		run["result"] = map[string]any{"enrolled": true}
		appendCall(run, "callback(enrolled=true)")
	} else if code := q.Get("code"); code != "" {
		if id == 5 || id == 6 {
			run = s.completeOidc(run, code)
		} else {
			run = s.completeSignin(run, code)
		}
	} else {
		run["status"] = "failed"
		run["error"] = "callback missing code / enrolled"
	}

	s.rt.writeRun(state, run)
	http.Redirect(w, r, "/?scenario="+strconv.Itoa(id)+"&run="+state, http.StatusFound)
}

// ── GET /api/runs/{runId} ─────────────────────────────────────────────────────

func (s *Server) run(w http.ResponseWriter, runID string) {
	run := s.rt.readRun(runID)
	if run == nil {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}

	// Idempotent: a terminal outcome is returned on every poll until TTL/Clear.
	if toStr(run["status"]) == "pending" {
		run = s.advance(run)
		s.rt.writeRun(runID, run)
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
func (s *Server) advance(run map[string]any) map[string]any {
	id := asInt(run["scenario"])
	switch toStr(run["wait"]) {
	case "detached_signin":
		oauth, err := s.oauthClientFor(id, pollTimeout)
		if err != nil {
			return failRun(run, err)
		}
		body, err := oauth.PollResult(toStr(run["state"]), pollTimeout, pollTimeout)
		if err != nil {
			return pollErr(run, err)
		}
		appendCall(run, "OAuthClient.PollResult")
		if code := toStr(body["code"]); code != "" {
			run = s.completeSignin(run, code)
		}
	case "detached_enroll":
		oauth, err := s.oauthClientFor(id, pollTimeout)
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
		client, err := s.serviceClientFor(id, pollTimeout)
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
func (s *Server) completeSignin(run map[string]any, code string) map[string]any {
	id := asInt(run["scenario"])
	oauth, err := s.oauthClientFor(id, 0)
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

	if id == 4 {
		shareCode := res.User["share_code"]
		client, err := s.serviceClientFor(id, 0)
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
func (s *Server) completeOidc(run map[string]any, code string) map[string]any {
	id := asInt(run["scenario"])
	ctx, cancel := oidcContext(context.Background(), oidcNetworkTimeout)
	defer cancel()
	setup, err := s.oidcSetupFor(ctx, id)
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
func (s *Server) oauthClientFor(id int, timeout time.Duration) (*companydata.OAuthClient, error) {
	var opts []companydata.OAuthOption
	if timeout > 0 {
		opts = append(opts, companydata.WithOAuthDoer(&http.Client{Timeout: timeout}))
	}
	if base := toStr(s.rt.readConfigMeta(id)["authorize_base"]); base != "" && base != defaultAuthBase {
		opts = append(opts, companydata.WithAuthorizeURL(base))
	}
	return companydata.OAuthClientFromConfig(s.rt.configPathFor(id), opts...)
}

// serviceClientFor builds the service data client OFF the scenario's config file (service role).
// timeout > 0 injects a bounded HTTP Doer for the short-cycled challenge poll (same reason as above).
func (s *Server) serviceClientFor(id int, timeout time.Duration) (*companydata.Client, error) {
	path := s.rt.configPathFor(id)
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
func (s *Server) oidcSetupFor(ctx context.Context, id int) (*oidcSetup, error) {
	cfg := readJSONMap(s.rt.configPathFor(id))
	if cfg == nil {
		cfg = map[string]any{}
	}
	return newOIDCSetup(ctx, toStr(cfg["api_url"]), toStr(cfg["oauth_client_id"]),
		toStr(cfg["oauth_client_secret"]), toStr(cfg["oauth_redirect_uri"]))
}

// redirectURI is the registered redirect URI: http://{host}/callback (host = the serving origin).
func (s *Server) redirectURI(r *http.Request) string {
	return "http://" + r.Host + "/callback"
}

// ── static bundle (SPA fallback to index.html) ────────────────────────────────

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request, path string) {
	rel := path
	if rel == "/" {
		rel = "/index.html"
	}
	root, _ := filepath.Abs(s.frontendDir)
	full, _ := filepath.Abs(filepath.Join(s.frontendDir, filepath.Clean(rel)))
	if strings.HasPrefix(full, root+string(filepath.Separator)) || full == root {
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			http.ServeFile(w, r, full)
			return
		}
	}
	// SPA fallback.
	index := filepath.Join(s.frontendDir, "index.html")
	if fi, err := os.Stat(index); err == nil && !fi.IsDir() {
		http.ServeFile(w, r, index)
		return
	}
	http.Error(w, "bundle not found", 404)
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

func atoiFirst(re *regexp.Regexp, path string) int {
	m := re.FindStringSubmatch(path)
	n, _ := strconv.Atoi(m[1])
	return n
}

func readBody(r *http.Request) map[string]any {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return map[string]any{}
	}
	return m
}

func writeJSON(w http.ResponseWriter, status int, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(data)
}

func toStr(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
