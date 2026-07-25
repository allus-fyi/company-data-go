package main

// The demo-backend contract (v3), company-data family, config-file model. One Server, one serialising
// mutex: HTTP dispatch → handler → the intended allme SDK surface (companydata.Client) ONLY — no raw
// platform HTTP, no SDK internals. Every company-data scenario uses the SERVICE-role data Client, built
// from the persisted config file; there is NO OAuth leg (no /callback, no /enroll).
//
// The five scenarios, all namespaced companydata:* (contract §"Company-data family"):
//   read        — Client.ConnectionsList()          → connection-grouped decrypted values
//   definitions — Client.RequestFields()            → your request-field catalog
//   changes     — Client.ProcessChanges()           → a crash-safe pump drain (idempotent on Change.ID)
//   webhook     — VerifyWebhook()+ParseWebhook()    → a public POST /webhook receiver + a DrainBatch()
//                                                      feed fallback; ONE accumulating run keyed by id
//   documents   — Client.CreateDocument() ×6        → the six document/contract types
//
// Settings flow: the browser POSTs a scenario's setup values to POST /api/scenarios/{id}/config, which
// writes them to a canonical SDK config FILE (.runtime/config/{sid}.json). /start builds the Client from
// that file (companydata.FromConfig → ConfigFromFile) and runs OFF it — exactly as a real integrator
// wires the SDK. A /start with no saved config → 409 not_configured.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/allus-fyi/company-data-go/companydata"
)

const (
	contractVersion = 3
	sdkName         = "go"
	defaultAPIURL   = "https://api.allme.fyi"
	drainBatchMax   = 500 // the pump clamps to [1,500]; ask for a full batch per feed pull
)

// scenario ids (all namespaced companydata:* and all "runnable").
const (
	scenRead        = "companydata:read"
	scenDefinitions = "companydata:definitions"
	scenChanges     = "companydata:changes"
	scenWebhook     = "companydata:webhook"
	scenDocuments   = "companydata:documents"
)

// scenarios maps id → "runnable". Every company-data scenario runs synchronously (data) or accumulates
// (webhook). The frontend lists these five for this backend's family.
var scenarioOrder = []string{scenRead, scenDefinitions, scenChanges, scenWebhook, scenDocuments}

func isScenario(id string) bool {
	for _, s := range scenarioOrder {
		if s == id {
			return true
		}
	}
	return false
}

// pumpScenarios need a Config.CacheDir (the SDK pump's durable buffer / dead-letters).
var pumpScenarios = map[string]bool{scenChanges: true, scenWebhook: true}

var (
	reConfig = regexp.MustCompile(`^/api/scenarios/([a-z:]+)/config$`)
	reStart  = regexp.MustCompile(`^/api/scenarios/([a-z:]+)/start$`)
	reClear  = regexp.MustCompile(`^/api/scenarios/([a-z:]+)/clear$`)
	reRun    = regexp.MustCompile(`^/api/runs/([0-9a-f]{32})$`)
)

// Server implements the demo-backend contract (company-data family).
type Server struct {
	rt          *Runtime
	frontendDir string
	sdkVersion  string
	mu          sync.Mutex // serialises requests → single-worker semantics (contract §3)
}

// ServeHTTP dispatches every request (static bundle OR API OR the public POST /webhook) behind the
// serialising mutex.
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
	case path == "/webhook" && method == http.MethodPost:
		s.webhook(w, r) // PUBLIC inbound delivery (not under /api/)
	case path == "/api/clear" && method == http.MethodPost:
		s.rt.clearAll()
		writeJSON(w, 200, map[string]any{"ok": true})
	case reConfig.MatchString(path) && method == http.MethodPost:
		s.config(w, r, reConfig.FindStringSubmatch(path)[1])
	case reStart.MatchString(path) && method == http.MethodPost:
		s.start(w, r, reStart.FindStringSubmatch(path)[1])
	case reClear.MatchString(path) && method == http.MethodPost:
		s.rt.clearScenario(reClear.FindStringSubmatch(path)[1])
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
	list := make([]map[string]any, 0, len(scenarioOrder))
	for _, id := range scenarioOrder {
		list = append(list, map[string]any{"id": id, "kind": "runnable"})
	}
	writeJSON(w, 200, map[string]any{
		"sdk":             sdkName,
		"sdkVersion":      s.sdkVersion,
		"contractVersion": contractVersion,
		"scenarios":       list,
	})
}

// ── POST /api/scenarios/{id}/config ───────────────────────────────────────────

// config writes the browser's setup values to a canonical SDK config FILE. Every company-data scenario
// uses the SERVICE-role Client, so the config always carries client_id/secret + the service PEM (by path)
// + passphrase. The webhook scenario adds the webhooks:{id:secret} map (the SDK selects the secret by the
// X-Allus-Webhook-Id header) and records the webhook id in a meta sidecar (the routing key /start needs).
// The documents scenario records the target person share code in the sidecar.
func (s *Server) config(w http.ResponseWriter, r *http.Request, id string) {
	if !isScenario(id) {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	in := readBody(r)

	// Canonical SDK config — the service role for every company-data scenario.
	cfg := map[string]any{
		"api_url":        strings.TrimRight(orDefault(toStr(in["apiUrl"]), defaultAPIURL), "/"),
		"client_id":      toStr(in["clientId"]),
		"client_secret":  toStr(in["clientSecret"]),
		"key_passphrase": toStr(in["keyPassphrase"]),
	}
	if pem := toStr(in["servicePrivateKeyPem"]); pem != "" {
		path, err := s.rt.materializeConfigKey(pem)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
			return
		}
		cfg["service_private_key"] = path
	}

	// Pump scenarios persist their buffer/dead-letters under .runtime/cache (Config.CacheDir).
	if pumpScenarios[id] {
		cfg["cache_dir"] = s.rt.cacheDir
	}

	meta := map[string]any{}
	if id == scenWebhook {
		// The verifier selects the secret by the delivery's X-Allus-Webhook-Id header, so the config's
		// webhooks map must be keyed by the real webhook id.
		webhookID := toStr(in["webhookId"])
		secret := toStr(in["webhookSecret"])
		if webhookID != "" && secret != "" {
			cfg["webhooks"] = map[string]any{webhookID: secret}
		}
		if webhookID != "" {
			meta["webhook_id"] = webhookID // the routing key /start writes into the route record
		}
	}
	if id == scenDocuments {
		meta["share_code"] = toStr(in["shareCode"]) // the per-person/contract target
	}

	configPath, err := s.rt.writeConfig(id, cfg)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
		return
	}
	s.rt.writeConfigMeta(id, meta)

	writeJSON(w, 200, map[string]any{"ok": true, "configPath": configPath})
}

// ── POST /api/scenarios/{id}/start ────────────────────────────────────────────

func (s *Server) start(w http.ResponseWriter, r *http.Request, id string) {
	if !isScenario(id) {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	if !s.rt.hasConfig(id) {
		// The run is built from the persisted config file, not the request body.
		writeJSON(w, 409, map[string]any{"error": "not_configured"})
		return
	}

	switch id {
	case scenRead:
		s.dataRun(w, id, s.doRead)
	case scenDefinitions:
		s.dataRun(w, id, s.doDefinitions)
	case scenChanges:
		s.dataRun(w, id, s.doChanges)
	case scenDocuments:
		s.dataRun(w, id, s.doDocuments)
	case scenWebhook:
		s.startWebhook(w, id)
	}
}

// dataFn runs a synchronous data scenario's SDK call, appending the SDK-call names it made to *calls.
type dataFn func(c *companydata.Client, calls *[]string) (map[string]any, error)

// dataRun builds the Client from the config file, runs the SDK call, and stores the terminal result. The
// immediate outcome is read once via GET /api/runs (action {type:"data"}). A build/SDK failure is stored
// as a "failed" run (still a 200 {runId, action} — the poll surfaces the error), NOT a non-envelope 200.
func (s *Server) dataRun(w http.ResponseWriter, id string, do dataFn) {
	runID := newRunID()
	calls := []string{}
	client, err := companydata.FromConfig(s.rt.configPathFor(id))
	if err != nil {
		s.rt.writeRun(runID, map[string]any{"scenario": id, "status": "failed", "error": err.Error(), "calls": calls})
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "data"}})
		return
	}
	result, err := do(client, &calls)
	if err != nil {
		s.rt.writeRun(runID, map[string]any{"scenario": id, "status": "failed", "error": err.Error(), "calls": toAnySlice(calls)})
		writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "data"}})
		return
	}
	s.rt.writeRun(runID, map[string]any{"scenario": id, "status": "done", "result": result, "calls": toAnySlice(calls)})
	writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "data"}})
}

// doRead — Client.ConnectionsList() grouped BY connection (one card per connected person), so two people
// who both filled the same slug stay distinguishable.
func (s *Server) doRead(client *companydata.Client, calls *[]string) (map[string]any, error) {
	conns, err := client.ConnectionsList(context.Background(), 0, 0)
	*calls = append(*calls, "Client.ConnectionsList")
	if err != nil {
		return nil, err
	}
	connections := make([]map[string]any, 0, len(conns))
	for _, conn := range conns {
		values := make([]map[string]any, 0, len(conn.Values))
		for slug, v := range conn.Values {
			values = append(values, map[string]any{
				"slug":  slug,
				"value": stringifyValue(v.Value),
				"live":  v.Live,
				"at":    isoOrNil(v.UpdatedAt),
			})
		}
		connections = append(connections, map[string]any{
			"connectionId": conn.ID,
			"personId":     conn.PersonID,
			"displayName":  conn.DisplayName,
			"customerType": conn.CustomerType,
			"shareCode":    conn.ShareCode,
			"values":       values,
		})
	}
	return map[string]any{"connections": connections}, nil
}

// doDefinitions — Client.RequestFields() → your request-field catalog (the folded mandatory bool +
// one_time; the raw split flags are debug-only, off the intended surface).
func (s *Server) doDefinitions(client *companydata.Client, calls *[]string) (map[string]any, error) {
	fs, err := client.RequestFields(context.Background())
	*calls = append(*calls, "Client.RequestFields")
	if err != nil {
		return nil, err
	}
	fields := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		fields = append(fields, map[string]any{
			"slug":      f.Slug,
			"label":     f.Label,
			"type":      f.Type,
			"mandatory": f.Mandatory,
			"one_time":  f.OneTime,
		})
	}
	return map[string]any{"fields": fields}, nil
}

// doChanges — Client.ProcessChanges() drains the feed on start through the crash-safe pump
// (handler-before-ack, at-least-once), so the append handler is idempotent on the pull-feed Change.ID.
// Each event is the rendered-column projection PLUS a raw object with the full public Change fields.
func (s *Server) doChanges(client *companydata.Client, calls *[]string) (map[string]any, error) {
	events := []map[string]any{}
	seen := map[string]bool{}
	err := client.ProcessChanges(func(c companydata.Change) error {
		if c.ID != "" {
			if seen[c.ID] {
				return nil // idempotent: the pump may replay after a crash — dedup on Change.ID
			}
			seen[c.ID] = true
		}
		events = append(events, projectChange(c, ""))
		return nil
	}, companydata.PumpOptions{})
	*calls = append(*calls, "Client.ProcessChanges")
	if err != nil {
		return nil, err
	}
	return map[string]any{"events": events, "drained": true}, nil
}

// doDocuments — Client.CreateDocument() for each of the six document/contract types (payloads verbatim
// from apitests/php/documents.php). The per-person / private / contract types target the connected person
// by share code (from the setup sidecar).
func (s *Server) doDocuments(client *companydata.Client, calls *[]string) (map[string]any, error) {
	shareCode := toStr(s.rt.readConfigMeta(scenDocuments)["share_code"])

	type spec struct {
		label     string
		perPerson bool
		opts      companydata.CreateDocumentOptions
	}
	specs := []spec{
		{"Broadcast plaintext JSON (no target)", false, companydata.CreateDocumentOptions{
			Name: "Service notice", PayloadKind: "json",
			JSONValue: map[string]any{"msg": "Scheduled maintenance Sunday"},
		}},
		{"Broadcast PDF file (no target)", false, companydata.CreateDocumentOptions{
			Name: "Price list", PayloadKind: "file",
			FileBytes: minimalPDF("Price list"), FileMime: "application/pdf",
		}},
		{"Per-person NON-private file", true, companydata.CreateDocumentOptions{
			Name: "Your invoice", PayloadKind: "file",
			FileBytes: minimalPDF("Your invoice"), FileMime: "application/pdf",
		}},
		{"Per-person PRIVATE file (lock → reveal)", true, companydata.CreateDocumentOptions{
			Name: "Confidential report", PayloadKind: "file", IsPrivate: true,
			FileBytes: minimalPDF("Confidential report"), FileMime: "application/pdf",
		}},
		{"CONTRACT requiring SIGNATURE", true, companydata.CreateDocumentOptions{
			Name: "Service agreement", Kind: "agreement", PayloadKind: "file",
			RequiresSignature: true,
			FileBytes:         minimalPDF("Service agreement"), FileMime: "application/pdf",
			Metadata: map[string]any{"can_be_cancelled_in_app": true},
		}},
		{"CONTRACT requiring ACCEPTANCE", true, companydata.CreateDocumentOptions{
			Name: "Terms update", Kind: "agreement", PayloadKind: "json",
			RequiresAcceptance: true, JSONValue: map[string]any{"version": "2.0"},
			Metadata: map[string]any{
				"plan_name":               "Pro Plan",
				"price":                   "9.99",
				"currency":                "EUR",
				"renewal_term":            "Monthly",
				"renewal_date":            "2026-07-30",
				"valid_until":             "2027-06-30",
				"can_be_cancelled_in_app": true,
				"management_url":          "https://example.com/manage",
			},
		}},
	}

	docs := make([]map[string]any, 0, len(specs))
	for i, sp := range specs {
		opts := sp.opts
		if sp.perPerson {
			if shareCode == "" {
				return nil, errors.New("this document type targets a connected person — set a target person share code in the setup, then re-run")
			}
			opts.ShareCode = shareCode
		}
		doc, err := client.CreateDocument(context.Background(), opts)
		if err != nil {
			return nil, err
		}
		docs = append(docs, map[string]any{
			"index":       i + 1,
			"label":       sp.label,
			"document_id": doc.ID,
			"status":      doc.Status,
		})
	}
	*calls = append(*calls, "Client.CreateDocument ×6")
	return map[string]any{"docs": docs}, nil
}

// ── companydata:webhook — the accumulating run + public receiver ──────────────

// startWebhook starts the single accumulating webhook run. Persists the routing record webhookId → runId
// (superseding any prior active webhook run) and returns {action:{type:"none"}} — there is NO long-poll
// (it would wedge the single worker). Events arrive via POST /webhook and via a per-poll DrainBatch()
// feed fallback; the frontend reads the growing list through GET /api/runs.
func (s *Server) startWebhook(w http.ResponseWriter, id string) {
	webhookID := toStr(s.rt.readConfigMeta(id)["webhook_id"])
	if webhookID == "" {
		writeJSON(w, 409, map[string]any{"error": "not_configured"})
		return
	}
	runID := newRunID()
	s.rt.writeRun(runID, map[string]any{
		"scenario":    scenWebhook,
		"status":      "pending", // accumulating — the run enum is unchanged
		"webhookId":   webhookID,
		"events":      []any{},
		"seenFeedIds": []any{}, // feed-only dedup set for the DrainBatch() fallback
		"unparseable": 0,
		"calls":       []any{"(webhook run started — POST /webhook receives; each poll also DrainBatch()s the feed)"},
	})
	s.rt.writeRoute(webhookID, runID)
	writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "none"}})
}

// webhook is the PUBLIC inbound delivery (POST /webhook). The exact call/status sequence (never the
// combined HandleWebhook(), which returns one *WebhookError for BOTH a bad-HMAC and a parse failure):
//
//	(1) read X-Allus-Webhook-Id; unknown/stale id or no active run → 200 acknowledge-and-discard.
//	(2) VerifyWebhook(): false → 401 (a genuine signature failure; misconfiguration should be loud).
//	(3) ParseWebhook(): ok → append (source:"webhook") + 200; a *WebhookError here is a VERIFIED-but-
//	    unparseable delivery → 200 acknowledge-and-note (increment unparseable) — NOT 401, the sig was ok.
//
// All accepted-and-dropped cases return 200 because the platform worker counts EXACTLY 200 as success
// (202/401/other = failure → retry + circuit-break).
func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	webhookID := r.Header.Get("X-Allus-Webhook-Id")

	rt := s.rt.readRoute()
	if rt == nil || webhookID == "" || webhookID != rt.WebhookID {
		writeText(w, 200, "discarded: unknown or stale webhook id")
		return
	}
	run := s.rt.readRun(rt.RunID)
	if run == nil {
		writeText(w, 200, "discarded: no active webhook run")
		return
	}

	client, err := companydata.FromConfig(s.rt.configPathFor(scenWebhook))
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
		return
	}

	recordCall(run, "Client.VerifyWebhook")
	if !client.VerifyWebhook(rawBody, r.Header) {
		// A genuine signature failure — persist the attempted verify so the calls trace stays truthful
		// even on the reject path.
		s.rt.writeRun(rt.RunID, run)
		writeText(w, 401, "signature verification failed")
		return
	}

	recordCall(run, "Client.ParseWebhook")
	change, err := client.ParseWebhook(rawBody, r.Header)
	if err != nil {
		var we *companydata.WebhookError
		if !errors.As(err, &we) {
			// Not a webhook parse/decrypt failure (e.g. the request-fields fetch failed) — surface it.
			writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
			return
		}
		// Verified but unparseable/undecryptable — acknowledge (200) and note it in the raw view.
		run["unparseable"] = asInt(run["unparseable"]) + 1
		appendEvent(run, map[string]any{
			"source": "webhook",
			"event":  nil,
			"id":     nil,
			"note":   "received, could not parse",
			"raw":    map[string]any{"error": we.Error()},
		})
		s.rt.writeRun(rt.RunID, run)
		writeText(w, 200, "ok")
		return
	}
	appendEvent(run, projectChange(change, "webhook"))
	s.rt.writeRun(rt.RunID, run)
	writeText(w, 200, "ok")
}

// ── GET /api/runs/{runId} ─────────────────────────────────────────────────────

func (s *Server) run(w http.ResponseWriter, runID string) {
	run := s.rt.readRun(runID)
	if run == nil {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}

	// The accumulating webhook run: each poll also does ONE immediate DrainBatch() raw feed fetch (NOT
	// ProcessChanges(), which loops the pump to empty and could stall the single worker) so events
	// generated AFTER start still appear in deployed-no-tunnel mode.
	if toStr(run["scenario"]) == scenWebhook {
		run = s.webhookFeedFallback(runID, run)
		writeJSON(w, 200, map[string]any{
			"status": orDefault(toStr(run["status"]), "pending"),
			"calls":  run["calls"],
			"result": map[string]any{
				"webhookId":   toStr(run["webhookId"]),
				"events":      run["events"],
				"unparseable": asInt(run["unparseable"]),
			},
		})
		return
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

// webhookFeedFallback does ONE DrainBatch() fetch per poll for the ACTIVE webhook run, appending new
// source:"feed" events deduped on the pull-feed Change.ID (a feed-only seen-id set in run state). Only
// the CURRENT active run pulls (a superseded run stops receiving). A transport/API error is swallowed so
// a blackholed feed never fails the accumulating run — the webhook path still works.
func (s *Server) webhookFeedFallback(runID string, run map[string]any) map[string]any {
	rt := s.rt.readRoute()
	if rt == nil || rt.RunID != runID {
		return run // superseded/cleared — this run no longer pulls
	}
	seen := map[string]bool{}
	seenList := toStringSlice(run["seenFeedIds"])
	for _, sid := range seenList {
		seen[sid] = true
	}

	client, err := companydata.FromConfig(s.rt.configPathFor(scenWebhook))
	if err != nil {
		return run
	}
	// Every poll ATTEMPTS the feed pull — record the call now (deduped), so an empty poll still reports
	// the DrainBatch it performed rather than claiming no call.
	drainNew := recordCall(run, "Client.DrainBatch")
	changes, err := client.DrainBatch(drainBatchMax)
	if err != nil {
		if drainNew {
			s.rt.writeRun(runID, run)
		}
		return run // a blackholed/failed feed fetch must not fail the accumulating webhook run
	}
	appended := false
	for _, ch := range changes {
		if ch.ID != "" {
			if seen[ch.ID] {
				continue
			}
			seen[ch.ID] = true
			seenList = append(seenList, ch.ID)
		}
		appendEvent(run, projectChange(ch, "feed"))
		appended = true
	}
	if appended {
		run["seenFeedIds"] = toAnySlice(seenList)
	}
	if appended || drainNew {
		s.rt.writeRun(runID, run)
	}
	return run
}

// recordCall appends an SDK-call name to a run's "what just happened" trace, deduped so the panel stays
// small no matter how many deliveries/polls a call spans. Returns true when newly added. A call is
// recorded when it is ATTEMPTED — the trace must be truthful on every path.
func recordCall(run map[string]any, name string) bool {
	calls := toStringSlice(run["calls"])
	for _, c := range calls {
		if c == name {
			return false
		}
	}
	run["calls"] = toAnySlice(append(calls, name))
	return true
}

// appendEvent appends one projected event to a run's events list.
func appendEvent(run map[string]any, ev map[string]any) {
	list, _ := run["events"].([]any)
	run["events"] = append(list, ev)
}

// ── Change projection ─────────────────────────────────────────────────────────

// projectChange renders the leading columns of a Change PLUS a raw object holding the full public Change
// fields, so the frontend's JSON.stringify(result) Raw view can show event-specific extras — nothing is
// dropped. source labels a webhook delivery vs a pull-feed row (empty for the changes scenario, where
// every row is a pull-feed drain).
func projectChange(c companydata.Change, source string) map[string]any {
	ev := map[string]any{
		"event":        emptyToNil(c.Event),
		"personId":     emptyToNil(c.PersonID),
		"shareCode":    emptyToNil(c.ShareCode),
		"customerType": emptyToNil(c.CustomerType),
		"slug":         emptyToNil(c.Slug),
		"value":        stringifyValue(c.Value),
		"live":         c.Live,
		"at":           isoOrNil(c.At),
		"documentId":   emptyToNil(c.DocumentID),
		"status":       emptyToNil(c.Status),
		"action":       emptyToNil(c.Action),
		"id":           emptyToNil(c.ID),
		"raw": map[string]any{
			"id":                  emptyToNil(c.ID),
			"event":               emptyToNil(c.Event),
			"personId":            emptyToNil(c.PersonID),
			"shareCode":           emptyToNil(c.ShareCode),
			"customerType":        emptyToNil(c.CustomerType),
			"slug":                emptyToNil(c.Slug),
			"value":               stringifyValue(c.Value),
			"live":                c.Live,
			"documentId":          emptyToNil(c.DocumentID),
			"status":              emptyToNil(c.Status),
			"action":              emptyToNil(c.Action),
			"note":                emptyToNil(c.Note),
			"method":              emptyToNil(c.Method),
			"contentSha256":       emptyToNil(c.ContentSHA256),
			"signedAt":            emptyToNil(c.SignedAt),
			"cancelEffectiveDate": emptyToNil(c.CancelEffectiveDate),
			"requestId":           emptyToNil(c.RequestID),
			"publicKeySha256":     emptyToNil(c.PublicKeySHA256),
			"verified":            c.Verified,
			"at":                  isoOrNil(c.At),
		},
	}
	if source != "" {
		ev["source"] = source
	}
	return ev
}

// stringifyValue renders a decrypted value for JSON. A binary value is a lazy *BinaryHandle — resolve its
// bytes to a short descriptor rather than dumping raw bytes; scalars/arrays/maps pass through unchanged
// (the frontend JSON-stringifies them); a *time.Time renders as an RFC3339 string.
func stringifyValue(v any) any {
	switch t := v.(type) {
	case nil, bool, string, int, int64, float64, []any, map[string]any:
		return t
	case *time.Time:
		if t == nil {
			return nil
		}
		return t.Format(time.RFC3339)
	case time.Time:
		return t.Format(time.RFC3339)
	case *companydata.BinaryHandle:
		if b, err := t.Bytes(); err == nil {
			return "[binary " + itoa(len(b)) + " bytes]"
		}
		return "[binary value]"
	default:
		return v
	}
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

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, body)
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
	}
	return 0
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func emptyToNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isoOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339)
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func toStringSlice(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// minimalPDF returns a tiny valid one-page PDF carrying label (verbatim shape from apitests/php/
// documents.php) — so the broadcast/per-person/contract file docs upload real bytes without a fixture.
func minimalPDF(label string) []byte {
	safe := strings.NewReplacer("(", "[", ")", "]").Replace(label)
	stream := "BT /F1 18 Tf 40 90 Td (" + safe + ") Tj ET"
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 420 160] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		"<< /Length " + itoa(len(stream)) + " >>\nstream\n" + stream + "\nendstream",
	}
	var sb strings.Builder
	sb.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, body := range objs {
		offsets[i] = sb.Len()
		sb.WriteString(itoa(i+1) + " 0 obj\n" + body + "\nendobj\n")
	}
	xrefPos := sb.Len()
	sb.WriteString("xref\n0 " + itoa(len(objs)+1) + "\n0000000000 65535 f \n")
	for _, off := range offsets {
		sb.WriteString(pad10(off) + " 00000 n \n")
	}
	sb.WriteString("trailer\n<< /Size " + itoa(len(objs)+1) + " /Root 1 0 R >>\nstartxref\n" + itoa(xrefPos) + "\n%%EOF")
	return []byte(sb.String())
}

func pad10(n int) string {
	s := itoa(n)
	for len(s) < 10 {
		s = "0" + s
	}
	return s
}
