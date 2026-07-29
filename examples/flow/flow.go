package flow

// The flow scenario family: a single scenario "flow:run" that runs a contract flow end-to-end through
// the SDK's intended top-level flow surface (Identity / TriggerFlowRun / FlowRun / ProcessFlowRun /
// FlowRunAnswers / FlowRunDocument) — never raw platform HTTP.
//
// There is NO cross-card flow-run-id handoff: the platform flow run lives entirely INSIDE this one demo
// run's .runtime file — the demo runId is the backend run and the platform flowRunId is stored inside it,
// never exposed as a separate browser input.
//
// Settings flow (config-file model): the browser POSTs its setup values to POST /api/scenarios/{id}/config,
// which writes them to a canonical SDK config FILE (the service PEM → .runtime/config/keys/ by path).
// /start builds the service Client from that file via companydata.FromConfig and runs OFF the config —
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
	"net/http"
	"strconv"
	"strings"

	"github.com/allus-fyi/company-data-go/companydata"
	"github.com/allus-fyi/company-data-go/examples/internal/demo"
)

const (
	defaultAPIURL = demo.DefaultAPIURL

	// scenarioID is the single public scenario id (the flow family).
	scenarioID = "flow:run"

	// invalidEmail is the canned INVALID value the validation-demo submits once for an email field.
	invalidEmail = "not-an-email"

	// The flow party keys the fixtures pin.
	partyCompany  = "company"
	partyCustomer = "customer"
)

// The "what just happened" trace. Every entry is `<SDK method> — <what that call did in THIS
// scenario>`, appended AT the call site, in the order the calls were made. Keep them in step when
// this file changes.
const (
	callServiceBuild  = "companydata.FromConfig — builds the SERVICE-role data client from the saved config file: client credentials plus the service private key, decrypted with its passphrase"
	callRequestFields = "Client.RequestFields — resolves the flow name + published version (the only handle the portal ever shows for it) to its flow id"
	callIdentity      = "Client.Identity — GET /api/company-data/whoami: this service's own company_user_id, which the COMPANY party binds to"
	callConnections   = "Client.ConnectionsList — resolves the person's own share code to the connection whose id the CUSTOMER party binds to"
	callTrigger       = "Client.TriggerFlowRun — starts a run of the published flow for that connection, pinning the flow's latest published version"
	callFlowRun       = "Client.FlowRun — re-read on every poll to see whose turn the run is on"
	callProcess       = "Client.ProcessFlowRun — drives ONE company step: decrypts the answers so far, fills the node, type-checks the values, encrypts a copy per party, submits — and generates the document when the submit lands on a document-mode leaf"
	callAnswers       = "Client.FlowRunAnswers — the completed run's answers, decrypted with the service key"
	callDocument      = "Client.FlowRunDocument — downloads the company's own copy of the generated contract and decrypts it with the service key"
)

// thin aliases to the shared scaffolding helpers so the handler code below reads cleanly.
var (
	writeJSON    = demo.WriteJSON
	writeFailure = demo.WriteFailure
	readBody     = demo.ReadBody
	newRunID     = demo.NewRunID
	toStr        = demo.ToStr
	orDefault    = demo.OrDefault
	toAnySlice   = demo.AnySlice
	strSlice     = demo.StringSlice
)

// family implements demo.Family for the flow scenario.
type family struct{ rt *demo.Runtime }

// New binds the flow family to the shared runtime.
func New(rt *demo.Runtime) demo.Family { return &family{rt: rt} }

// Scenarios lists the single flow scenario.
func (family) Scenarios() []demo.Scenario {
	return []demo.Scenario{{ID: scenarioID, Kind: "runnable"}}
}

// Owns reports whether id is the flow scenario id.
func (family) Owns(id string) bool { return id == scenarioID }

// ── POST /api/scenarios/{id}/config ───────────────────────────────────────────

// Config writes the browser's setup values to a canonical SDK config FILE (service role). The service
// PEM is written to config/keys/ and referenced by path; the demo-only run parameters (flow name +
// published version, the person's share code, fixture choice) go to the meta sidecar so the config file
// stays a pure SDK config. Neither the flow id nor the connection id is ever collected here — Start
// resolves both via the SDK instead of taking either as a raw database id.
func (h *family) Config(w http.ResponseWriter, r *http.Request, id string) {
	in := readBody(r)

	// Canonical SDK config — the service role (client_credentials + service PEM).
	cfg := map[string]any{
		"api_url":        strings.TrimRight(orDefault(toStr(in["apiUrl"]), defaultAPIURL), "/"),
		"client_id":      toStr(in["clientId"]),
		"client_secret":  toStr(in["clientSecret"]),
		"key_passphrase": toStr(in["keyPassphrase"]),
	}
	if pem := toStr(in["servicePrivateKeyPem"]); pem != "" {
		path, err := h.rt.MaterializeConfigKey(pem)
		if err != nil {
			writeFailure(w, 500, "server_error", err)
			return
		}
		cfg["service_private_key"] = path
	}

	configPath, err := h.rt.WriteConfig(id, cfg)
	if err != nil {
		writeFailure(w, 500, "server_error", err)
		return
	}

	// Demo-only run parameters (NOT SDK Config fields) → meta sidecar.
	h.rt.WriteConfigMeta(id, map[string]any{
		"flow_name":    toStr(in["flowName"]),
		"flow_version": toStr(in["flowVersion"]),
		"share_code":   toStr(in["shareCode"]),
		"fixture":      toStr(in["fixture"]),
	})

	writeJSON(w, 200, map[string]any{"ok": true, "configPath": configPath})
}

// ── POST /api/scenarios/{id}/start ────────────────────────────────────────────

// Start triggers the flow run. It builds the service Client from the persisted config file, resolves
// the flow name + published version and the person's share code to the ids TriggerFlowRun needs (neither
// is ever collected as a raw id), constructs the bindings via the intended SDK surface (company →
// Identity().CompanyUserID; customer → Connection.PersonID), calls TriggerFlowRun, and stores the
// returned platform flow-run id in the demo run file. Returns {runId, action:{"type":"none"}} — the
// drive happens on the GET /api/runs poll.
func (h *family) Start(w http.ResponseWriter, r *http.Request, id string) {
	if !h.rt.HasConfig(id) {
		// The run is built from the persisted config file, not the request body.
		writeJSON(w, 409, map[string]any{"error": "not_configured"})
		return
	}
	meta := h.rt.ReadConfigMeta(id)
	flowName := strings.TrimSpace(toStr(meta["flow_name"]))
	flowVersionRaw := strings.TrimSpace(toStr(meta["flow_version"]))
	shareCode := strings.TrimSpace(toStr(meta["share_code"]))
	if flowName == "" || flowVersionRaw == "" || shareCode == "" {
		writeJSON(w, 409, map[string]any{
			"error": "not_configured", "message": "flow name, published version and share code are required",
		})
		return
	}
	flowVersion, convErr := strconv.Atoi(flowVersionRaw)
	if convErr != nil || flowVersion < 0 {
		writeFailure(w, 400, "start_failed", "published version \""+flowVersionRaw+"\" is not a number")
		return
	}

	ctx := context.Background()
	calls := []any{}

	calls = append(calls, callServiceBuild)
	client, err := h.serviceClient(id)
	if err != nil {
		writeFailure(w, 502, "start_failed", err)
		return
	}

	// Resolve the flow name + published version to its flow id. The pair is not guaranteed unique
	// (nothing enforces it), so this can return zero, one, or more than one candidate — only exactly
	// one is safe to proceed on; anything else refuses rather than guess.
	calls = append(calls, callRequestFields)
	candidates, err := resolveFlowIDCandidates(ctx, client, flowName, flowVersion)
	if err != nil {
		writeFailure(w, 502, "start_failed", err)
		return
	}
	if len(candidates) == 0 {
		writeFailure(w, 404, "start_failed",
			"no published flow named \""+flowName+"\" at version "+flowVersionRaw+
				" — check the name and the \"Published vN\" the portal shows next to it")
		return
	}
	if len(candidates) > 1 {
		writeFailure(w, 409, "start_failed",
			"more than one flow matches the name \""+flowName+"\" at version "+flowVersionRaw+
				" — rename one of them in the portal (the flow builder's name field, next to "+
				"\"Published vN\") so the pair is unique, then try again")
		return
	}
	flowID := candidates[0]

	// The COMPANY party binds to this service's own company_user_id.
	calls = append(calls, callIdentity)
	identity, err := client.Identity(ctx)
	if err != nil {
		writeFailure(w, 502, "start_failed", err)
		return
	}
	companyUserID := identity.CompanyUserID
	if companyUserID == "" {
		writeFailure(w, 502, "identity_error", "Identity() returned no company_user_id")
		return
	}

	// Resolve the person's own share code to their connection — the CUSTOMER party binds to the
	// connected person's public personId (no public user_id).
	calls = append(calls, callConnections)
	connection, err := resolveConnection(ctx, client, shareCode)
	if err != nil {
		writeFailure(w, 502, "start_failed", err)
		return
	}
	if connection == nil {
		writeFailure(w, 404, "connection_error",
			"no connection found for share code \""+shareCode+"\" — is the person connected to this service?")
		return
	}
	connectionID := connection.ID
	personID := connection.PersonID
	if connectionID == "" || personID == "" {
		writeFailure(w, 502, "connection_error",
			"connection for share code \""+shareCode+"\" has no id/personId (not found or not connected)")
		return
	}

	bindings := map[string]string{
		partyCompany:  companyUserID,
		partyCustomer: personID,
	}
	calls = append(calls, callTrigger)
	flowRun, err := client.TriggerFlowRun(ctx, flowID, connectionID, bindings)
	if err != nil {
		writeFailure(w, 502, "start_failed", err)
		return
	}
	if flowRun.ID == "" {
		writeFailure(w, 502, "trigger_error", "TriggerFlowRun returned no run id")
		return
	}

	runID := newRunID()
	h.rt.WriteRun(runID, map[string]any{
		"scenario":      scenarioID,
		"flowRunId":     flowRun.ID,
		"steps":         []any{},
		"rejectedNodes": []any{},
		"calls":         calls,
		"completed":     false,
	})

	writeJSON(w, 200, map[string]any{"runId": runID, "action": map[string]any{"type": "none"}})
}

// ── POST /api/scenarios/{id}/clear ────────────────────────────────────────────

func (h *family) Clear(w http.ResponseWriter, r *http.Request, id string) {
	h.rt.ClearScenario(id)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ── GET /api/runs/{runId} ─────────────────────────────────────────────────────

// Run is the idempotent, short-cycled poll that IS the drive loop and the resume. Reads the platform
// run; if it is the company's turn drives exactly ONE step; on completion fetches the answers and
// (document-mode) downloads the generated contract. A terminal run returns its cached result on every
// poll until TTL/Clear.
func (h *family) Run(w http.ResponseWriter, runID string, run map[string]any) {
	// Idempotent: once terminal (completed OR errored) the outcome is returned unchanged on every
	// subsequent poll — a failed run must stay failed, not re-drive the platform.
	terminal := run["completed"] == true || run["error"] != nil
	if !terminal {
		run = h.advance(run)
		h.rt.WriteRun(runID, run)
	}

	writeJSON(w, 200, result(run))
}

// advance does one poll's worth of work and returns the (possibly mutated) run map.
func (h *family) advance(run map[string]any) map[string]any {
	flowRunID := toStr(run["flowRunId"])
	if flowRunID == "" {
		run["status"] = "error"
		run["error"] = "run has no platform flowRunId"
		return run
	}

	ctx := context.Background()
	run["calls"] = demo.AddCall(run["calls"], callServiceBuild)
	client, err := h.serviceClient(scenarioID)
	if err != nil {
		return failRun(run, err)
	}
	run["calls"] = demo.AddCall(run["calls"], callFlowRun)
	flowRun, err := client.FlowRun(ctx, flowRunID)
	if err != nil {
		return failRun(run, err)
	}

	status := flowRun.Status
	companyParty := flowRun.CompanyPartyKey()
	companyTurn := companyParty != "" && status == "awaiting_"+companyParty

	switch {
	case status == "completed":
		return h.complete(run, client, flowRun, flowRunID)
	case companyTurn:
		return h.driveStep(run, client, flowRun, flowRunID)
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
func (h *family) driveStep(run map[string]any, client *companydata.Client, flowRun companydata.FlowRun, flowRunID string) map[string]any {
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

	run["calls"] = demo.AddCall(run["calls"], callProcess)
	_, err := client.ProcessFlowRun(ctx, flowRunID, fillNode, nil)

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
func (h *family) complete(run map[string]any, client *companydata.Client, flowRun companydata.FlowRun, flowRunID string) map[string]any {
	ctx := context.Background()

	run["calls"] = demo.AddCall(run["calls"], callAnswers)
	answers, err := client.FlowRunAnswers(flowRun)
	if err != nil {
		return failRun(run, err)
	}
	ciphers := ownCipherBySlug(flowRun)
	answersOut := make([]any, 0, len(answers))
	for slug, value := range answers {
		answersOut = append(answersOut, map[string]any{"slug": slug, "value": value, "cipher": ciphers[slug]})
	}
	run["answers"] = answersOut

	if flowRun.OutputMode == "document" {
		run["calls"] = demo.AddCall(run["calls"], callDocument)
		bytes, err := client.FlowRunDocument(ctx, flowRunID)
		if err != nil {
			// The run completed but the document is not retrievable yet — report it, don't fail.
			run["document"] = map[string]any{"status": "unavailable", "downloaded": false, "error": err.Error()}
		} else {
			run["document"] = map[string]any{"status": "downloaded", "downloaded": true, "bytes": len(bytes)}
		}
	}

	run["status"] = "completed"
	run["completed"] = true
	return run
}

// resolveFlowIDCandidates resolves a flow's name + published version to its CANDIDATE flow ids.
// flow_id/flow_name/flow_version ride the additive Raw map on the flow-tagged rows RequestFields
// returns — they are not typed fields of companydata.RequestField. Returns every DISTINCT flow id
// whose tagged fields match both name and version, deduplicated, in first-seen order — nothing here
// guarantees the pair is unique, so the caller decides what to do with zero, one, or more than one
// candidate.
func resolveFlowIDCandidates(ctx context.Context, client *companydata.Client, flowName string, flowVersion int) ([]string, error) {
	fields, err := client.RequestFields(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		name, _ := f.Raw["flow_name"].(string)
		if name != flowName {
			continue
		}
		version, ok := asInt(f.Raw["flow_version"])
		if !ok || version != flowVersion {
			continue
		}
		flowID, _ := f.Raw["flow_id"].(string)
		if flowID != "" && !seen[flowID] {
			seen[flowID] = true
			out = append(out, flowID)
		}
	}
	return out, nil
}

// resolveConnection resolves a person's own share code to their Connection. ConnectionsList collects
// the whole (auto-paged) service — a demo has too few connections for that to matter, but it is the
// same call a real integrator would make to look a person up by the one identifier they can read off
// their own app.
func resolveConnection(ctx context.Context, client *companydata.Client, shareCode string) (*companydata.Connection, error) {
	conns, err := client.ConnectionsList(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	wanted := strings.ToUpper(shareCode)
	for i := range conns {
		if strings.ToUpper(conns[i].ShareCode) == wanted {
			return &conns[i], nil
		}
	}
	return nil, nil
}

// asInt coerces a decoded-JSON number (float64, int, or a numeric string) to an int; the ok result is
// false for anything else, including a nil/absent value.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case string:
		i, err := strconv.Atoi(n)
		return i, err == nil
	default:
		return 0, false
	}
}

// ownCipherBySlug returns the company's own answer rows, keyed by slug and left as the
// still-encrypted wrapper the API returned — the evidence the "Decrypted answers" panel pairs
// against each cleartext value, so a reader can see the decrypt actually ran on real ciphertext
// rather than take it on faith.
func ownCipherBySlug(flowRun companydata.FlowRun) map[string]any {
	serviceUID := flowRun.ServiceUserID()
	out := make(map[string]any, len(flowRun.Answers))
	for _, row := range flowRun.Answers {
		slug, ok := row["slug"].(string)
		if !ok {
			continue
		}
		if forUser, _ := row["for_user_id"].(string); forUser == serviceUID {
			out[slug] = row["value"]
		}
	}
	return out
}

// result renders the GET /api/runs/{runId} response: the SHARED run envelope (outer
// {status:"pending"|"done"|"failed", result?, error?, calls}) with the pinned FLOW shape nested under
// `result` ({status:"running"|"waiting_person"|"completed", steps, answers?, document?}). Progress is
// meant to be read ONLY from run.result, with polling continuing ONLY while the outer status is
// "pending", so the inner flow status must NOT sit at the top level — it drives under "pending" until
// the platform run completes ("done") or errors ("failed").
func result(run map[string]any) map[string]any {
	flowStatus := orDefault(toStr(run["status"]), "running")
	outer := "pending"
	if run["error"] != nil {
		outer = "failed"
	} else if flowStatus == "completed" {
		outer = "done"
	}

	res := map[string]any{
		"status": flowStatus,
		"steps":  toAnySlice(run["steps"]),
	}
	if run["answers"] != nil {
		res["answers"] = run["answers"]
	}
	if run["document"] != nil {
		res["document"] = run["document"]
	}

	out := map[string]any{
		"status": outer,
		"result": res,
		"calls":  toAnySlice(run["calls"]),
	}
	if run["error"] != nil {
		out["error"] = run["error"]
	}
	return out
}

// ── SDK client builder — built from the persisted config FILE ─────────────────

// serviceClient builds the service data client OFF the scenario's config file (service role).
func (h *family) serviceClient(id string) (*companydata.Client, error) {
	return companydata.FromConfig(h.rt.ConfigPath(id))
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

// ── small helpers ─────────────────────────────────────────────────────────────

func failRun(run map[string]any, err error) map[string]any {
	run["status"] = "error"
	run["error"] = err.Error()
	return run
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
