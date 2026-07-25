package main

// The demo-backend contract (v2, flow family), config-file model. One Server, one serialising mutex:
// HTTP dispatch → handler → the intended top-level allme SDK flow surface only (Identity /
// TriggerFlowRun / FlowRun / ProcessFlowRun / FlowRunAnswers / FlowRunDocument). Handlers NEVER perform
// raw platform HTTP.
//
// A single scenario "flow:run". There is NO cross-card flow-run-id handoff: the platform flow run lives
// entirely INSIDE this one demo run's .runtime file — the demo runId is the backend run and the platform
// flowRunId is stored inside it, never exposed as a separate browser input.
//
// Settings flow (config-file model): the browser POSTs a scenario's setup values to
// POST /api/scenarios/{id}/config, which writes them to a canonical SDK config FILE
// (.runtime/config/{store}.json; the service PEM → .runtime/config/keys/ by path). /start builds the
// service Client from that file via companydata.FromConfig (ConfigFromFile) and runs OFF the config —
// exactly as a real integrator wires the SDK. The request body of /start is ignored; a /start with no
// saved config → 409 not_configured.
//
// The GET /api/runs/{runId} poll IS the drive loop AND the resume: each poll reads the platform run and,
// if it is the company's turn, drives exactly ONE company step; otherwise it reports waiting/running and
// touches nothing (the next poll after the person answers on their phone resumes automatically).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/allus-fyi/company-data-go/companydata"
)

const (
	contractVersion = 2 // flow family lands at the next-available version (identity=1)
	sdkName         = "go"
	defaultAPIURL   = "https://api.allme.fyi"

	// scenarioID is the single public scenario id (the flow family).
	scenarioID = "flow:run"
	// storeID is the internal store key for the config/meta/run files (the public id is not
	// filesystem-shaped).
	storeID = 1

	// invalidEmail is the canned INVALID value the validation-demo submits once for an email field.
	invalidEmail = "not-an-email"

	// The flow party keys the fixtures pin.
	partyCompany  = "company"
	partyCustomer = "customer"
)

var (
	reConfig = regexp.MustCompile(`^/api/scenarios/([\w:.-]+)/config$`)
	reStart  = regexp.MustCompile(`^/api/scenarios/([\w:.-]+)/start$`)
	reClear  = regexp.MustCompile(`^/api/scenarios/([\w:.-]+)/clear$`)
	reRun    = regexp.MustCompile(`^/api/runs/([0-9a-f]{32})$`)
)

// Server implements the demo-backend contract for the flow family.
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
	case path == "/api/clear" && method == http.MethodPost:
		s.rt.clearAll()
		writeJSON(w, 200, map[string]any{"ok": true})
	case reConfig.MatchString(path) && method == http.MethodPost:
		s.config(w, r, reConfig.FindStringSubmatch(path)[1])
	case reStart.MatchString(path) && method == http.MethodPost:
		s.start(w, reStart.FindStringSubmatch(path)[1])
	case reClear.MatchString(path) && method == http.MethodPost:
		id := reClear.FindStringSubmatch(path)[1]
		if !isKnownScenario(id) {
			writeJSON(w, 404, map[string]any{"error": "not_found"})
			return
		}
		s.rt.clearScenario(storeID)
		writeJSON(w, 200, map[string]any{"ok": true})
	case reRun.MatchString(path) && method == http.MethodGet:
		s.run(w, reRun.FindStringSubmatch(path)[1])
	case strings.HasPrefix(path, "/api/"):
		writeJSON(w, 404, map[string]any{"error": "not_found"})
	default:
		s.serveStatic(w, r, path)
	}
}

func isKnownScenario(id string) bool { return id == scenarioID }

// ── GET /api/meta ───────────────────────────────────────────────────────────

func (s *Server) meta(w http.ResponseWriter) {
	writeJSON(w, 200, map[string]any{
		"sdk":             sdkName,
		"sdkVersion":      s.sdkVersion,
		"contractVersion": contractVersion,
		"scenarios": []map[string]any{
			{"id": scenarioID, "kind": "runnable"},
		},
	})
}

// ── POST /api/scenarios/{id}/config ───────────────────────────────────────────

// config writes the browser's setup values to a canonical SDK config FILE (service role). The service
// PEM is written to config/keys/ and referenced by path; the demo-only run parameters (published flow
// id, connection id, fixture choice) go to the meta sidecar so the config file stays a pure SDK config.
func (s *Server) config(w http.ResponseWriter, r *http.Request, id string) {
	if !isKnownScenario(id) {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	in := readBody(r)

	// Canonical SDK config — the service role (client_credentials + service PEM).
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

	configPath, err := s.rt.writeConfig(storeID, cfg)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "server_error", "message": err.Error()})
		return
	}

	// Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
	s.rt.writeConfigMeta(storeID, map[string]any{
		"flow_id":       toStr(in["flowId"]),
		"connection_id": toStr(in["connectionId"]),
		"fixture":       toStr(in["fixture"]),
	})

	writeJSON(w, 200, map[string]any{"ok": true, "configPath": configPath})
}

// ── POST /api/scenarios/{id}/start ────────────────────────────────────────────

// start triggers the flow run. It builds the service Client from the persisted config file, constructs
// the bindings via the intended SDK surface (company → Identity().CompanyUserID; customer →
// Connection.PersonID), calls TriggerFlowRun, and stores the returned platform flow-run id in the demo
// run file. Returns {runId, action:{"type":"none"}} — the drive happens on the GET /api/runs poll.
func (s *Server) start(w http.ResponseWriter, id string) {
	if !isKnownScenario(id) {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	if !s.rt.hasConfig(storeID) {
		// The run is built from the persisted config file, not the request body.
		writeJSON(w, 409, map[string]any{"error": "not_configured"})
		return
	}
	meta := s.rt.readConfigMeta(storeID)
	flowID := toStr(meta["flow_id"])
	connectionID := toStr(meta["connection_id"])
	if flowID == "" || connectionID == "" {
		writeJSON(w, 409, map[string]any{"error": "not_configured", "message": "flow id and connection id are required"})
		return
	}

	ctx := context.Background()
	calls := []any{}

	client, err := s.serviceClient()
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "start_failed", "message": err.Error()})
		return
	}

	// The COMPANY party binds to this service's own company_user_id.
	identity, err := client.Identity(ctx)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "start_failed", "message": err.Error()})
		return
	}
	calls = append(calls, "Client.Identity")
	companyUserID := identity.CompanyUserID
	if companyUserID == "" {
		writeJSON(w, 502, map[string]any{"error": "identity_error", "message": "Identity() returned no company_user_id"})
		return
	}

	// The CUSTOMER party binds to the connected person's public personId (no public user_id).
	connection, err := client.Connection(ctx, connectionID)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "start_failed", "message": err.Error()})
		return
	}
	calls = append(calls, "Client.Connection")
	personID := connection.PersonID
	if personID == "" {
		writeJSON(w, 502, map[string]any{
			"error":   "connection_error",
			"message": "connection " + connectionID + " has no personId (not found or not connected)",
		})
		return
	}

	bindings := map[string]string{
		partyCompany:  companyUserID,
		partyCustomer: personID,
	}
	flowRun, err := client.TriggerFlowRun(ctx, flowID, connectionID, bindings)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": "start_failed", "message": err.Error()})
		return
	}
	calls = append(calls, "Client.TriggerFlowRun")
	if flowRun.ID == "" {
		writeJSON(w, 502, map[string]any{"error": "trigger_error", "message": "TriggerFlowRun returned no run id"})
		return
	}

	runID := newRunID()
	s.rt.writeRun(runID, map[string]any{
		"scenario":      storeID,
		"flowRunId":     flowRun.ID,
		"steps":         []any{},
		"rejectedNodes": []any{},
		"calls":         calls,
		"completed":     false,
	})

	writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "none"}})
}

// ── GET /api/runs/{runId} ─────────────────────────────────────────────────────

// run is the idempotent, short-cycled poll that IS the drive loop and the resume. Reads the platform
// run; if it is the company's turn drives exactly ONE step; on completion fetches the answers and
// (document-mode) downloads the generated contract. A terminal run returns its cached result on every
// poll until TTL/Clear.
func (s *Server) run(w http.ResponseWriter, runID string) {
	run := s.rt.readRun(runID)
	if run == nil {
		writeJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}

	// Idempotent: once terminal (completed OR errored) the outcome is returned unchanged on every
	// subsequent poll — a failed run must stay failed, not re-drive the platform.
	terminal := run["completed"] == true || run["error"] != nil
	if !terminal {
		run = s.advance(run)
		s.rt.writeRun(runID, run)
	}

	writeJSON(w, 200, s.result(run))
}

// advance does one poll's worth of work and returns the (possibly mutated) run map.
func (s *Server) advance(run map[string]any) map[string]any {
	flowRunID := toStr(run["flowRunId"])
	if flowRunID == "" {
		run["status"] = "error"
		run["error"] = "run has no platform flowRunId"
		return run
	}

	ctx := context.Background()
	client, err := s.serviceClient()
	if err != nil {
		return failRun(run, err)
	}
	flowRun, err := client.FlowRun(ctx, flowRunID)
	if err != nil {
		return failRun(run, err)
	}
	run["calls"] = addCall(run["calls"], "Client.FlowRun")

	status := flowRun.Status
	companyParty := flowRun.CompanyPartyKey()
	companyTurn := companyParty != "" && status == "awaiting_"+companyParty

	switch {
	case status == "completed":
		return s.complete(run, client, flowRun, flowRunID)
	case companyTurn:
		return s.driveStep(run, client, flowRun, flowRunID)
	case strings.HasPrefix(status, "awaiting_"):
		// The person's turn (or the phone signature) — wait; the next poll resumes automatically.
		run["status"] = "waiting_person"
		return run
	default:
		// Any transient in-between state (e.g. generating) — keep polling.
		run["status"] = "running"
		return run
	}
}

// driveStep drives ONE company step via ProcessFlowRun. The validation demo: for an email field whose
// node has not yet been rejected once, fillNode returns the canned INVALID value, which ProcessFlowRun
// rejects with a *ValidationError BEFORE any submit — recorded as accepted:false without advancing. The
// next poll (node marked rejected) fills the VALID value → advances → accepted:true. Other fields submit
// one valid value.
func (s *Server) driveStep(run map[string]any, client *companydata.Client, flowRun companydata.FlowRun, flowRunID string) map[string]any {
	ctx := context.Background()
	nodeKey := flowRun.CurrentNode
	rejectedNodes := strSlice(run["rejectedNodes"])
	rejectedNow := contains(rejectedNodes, nodeKey)

	// filled records every field this node fills, in order, for step logging.
	type filledField struct{ slug, ftype, submitted string }
	var filled []filledField

	fillNode := func(node, answers map[string]any) map[string]any {
		fill := map[string]any{}
		for _, raw := range toAnySlice(node["elements"]) {
			el, ok := raw.(map[string]any)
			if !ok || toStr(el["kind"]) != "field" {
				continue
			}
			slug := toStr(el["slug"])
			if slug == "" {
				continue
			}
			ftype := orDefault(toStr(el["field_type"]), "text")
			rejectDemo := ftype == "email" && !rejectedNow
			value := cannedValue(ftype)
			if rejectDemo {
				value = invalidEmail
			}
			fill[slug] = value
			filled = append(filled, filledField{slug: slug, ftype: ftype, submitted: value})
		}
		return fill
	}

	_, err := client.ProcessFlowRun(ctx, flowRunID, fillNode, nil)
	run["calls"] = addCall(run["calls"], "Client.ProcessFlowRun")

	var ve *companydata.ValidationError
	switch {
	case err == nil:
		// Advanced: every field filled for this node was accepted.
		steps := toAnySlice(run["steps"])
		for _, f := range filled {
			steps = append(steps, map[string]any{
				"slug": f.slug, "type": f.ftype, "submitted": f.submitted, "accepted": true,
			})
		}
		run["steps"] = steps
		run["status"] = "running"
		return run
	case errors.As(err, &ve):
		// The canned invalid value was rejected BEFORE submit — record it and mark the node so the next
		// poll submits the valid value. The node did NOT advance.
		submitted := invalidEmail
		for _, f := range filled {
			if f.slug == ve.Slug {
				submitted = f.submitted
				break
			}
		}
		ftype := orDefault(ve.FieldType, "email")
		steps := toAnySlice(run["steps"])
		steps = append(steps, map[string]any{
			"slug": ve.Slug, "type": ftype, "submitted": submitted, "accepted": false, "error": ve.Error(),
		})
		run["steps"] = steps
		if nodeKey != "" && !contains(rejectedNodes, nodeKey) {
			run["rejectedNodes"] = append(toAnySlice(run["rejectedNodes"]), nodeKey)
		}
		run["status"] = "running"
		return run
	default:
		return failRun(run, err)
	}
}

// complete is terminal: fetch the decrypted answers and, for a document-mode run, download the generated
// contract's company copy (the run-scoped, service-key-decryptable surface).
func (s *Server) complete(run map[string]any, client *companydata.Client, flowRun companydata.FlowRun, flowRunID string) map[string]any {
	ctx := context.Background()

	answers, err := client.FlowRunAnswers(flowRun)
	if err != nil {
		return failRun(run, err)
	}
	run["calls"] = addCall(run["calls"], "Client.FlowRunAnswers")
	answersOut := make([]any, 0, len(answers))
	for slug, value := range answers {
		answersOut = append(answersOut, map[string]any{"slug": slug, "value": value})
	}
	run["answers"] = answersOut

	if flowRun.OutputMode == "document" {
		bytes, err := client.FlowRunDocument(ctx, flowRunID)
		if err != nil {
			// The run completed but the document is not retrievable yet — report it, don't fail.
			run["document"] = map[string]any{"status": "unavailable", "downloaded": false, "error": err.Error()}
		} else {
			run["calls"] = addCall(run["calls"], "Client.FlowRunDocument")
			run["document"] = map[string]any{"status": "downloaded", "downloaded": true, "bytes": len(bytes)}
		}
	}

	run["status"] = "completed"
	run["completed"] = true
	return run
}

// result renders the GET /api/runs/{runId} response: the SHARED run envelope (outer
// {status:"pending"|"done"|"failed", result?, error?, calls}) with the pinned FLOW shape nested under
// `result` ({status:"running"|"waiting_person"|"completed", steps, answers?, document?}). The shared
// frontend reads progress ONLY from run.result and keeps polling ONLY while the outer status is
// "pending", so the inner flow status must NOT sit at the top level — it drives under "pending" until
// the platform run completes ("done") or errors ("failed").
func (s *Server) result(run map[string]any) map[string]any {
	flowStatus := orDefault(toStr(run["status"]), "running")
	outer := "pending"
	if run["error"] != nil {
		outer = "failed"
	} else if flowStatus == "completed" {
		outer = "done"
	}

	result := map[string]any{
		"status": flowStatus,
		"steps":  toAnySlice(run["steps"]),
	}
	if run["answers"] != nil {
		result["answers"] = run["answers"]
	}
	if run["document"] != nil {
		result["document"] = run["document"]
	}

	out := map[string]any{
		"status": outer,
		"result": result,
		"calls":  toAnySlice(run["calls"]),
	}
	if run["error"] != nil {
		out["error"] = run["error"]
	}
	return out
}

// ── SDK client builder — built from the persisted config FILE ─────────────────

// serviceClient builds the service data client OFF the scenario's config file (service role).
func (s *Server) serviceClient() (*companydata.Client, error) {
	return companydata.FromConfig(s.rt.configPathFor(storeID))
}

// cannedValue is a canned VALID plaintext for a field type (demo values over already-supported
// answerable types). An unknown / text type accepts anything.
func cannedValue(ftype string) string {
	switch ftype {
	case "email":
		return "billing@acme.example"
	case "number":
		return "42"
	case "boolean":
		return "true"
	case "date":
		return "2024-01-15"
	case "date_of_birth":
		return "1990-05-01"
	case "phone":
		return "+31201234567"
	case "url":
		return "https://acme.example"
	case "address":
		b, _ := json.Marshal(map[string]any{
			"street": "Herengracht 1", "city": "Amsterdam", "postal_code": "1011AB", "country": "NL",
		})
		return string(b)
	default:
		return "Acme Corporation"
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

// addCall appends a call name preserving first-occurrence order (a poll may repeat FlowRun across polls).
func addCall(existing any, name string) []any {
	calls := toAnySlice(existing)
	for _, c := range calls {
		if toStr(c) == name {
			return calls
		}
	}
	return append(calls, name)
}

func failRun(run map[string]any, err error) map[string]any {
	run["status"] = "error"
	run["error"] = err.Error()
	return run
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

// toAnySlice coerces a JSON-decoded value into a []any (nil → empty slice).
func toAnySlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return []any{}
}

// strSlice coerces a JSON-decoded value into a []string.
func strSlice(v any) []string {
	out := []string{}
	for _, e := range toAnySlice(v) {
		out = append(out, toStr(e))
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
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
