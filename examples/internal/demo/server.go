package demo

// The SDK-example demo backend: ONE net/http server, ONE serialising mutex, serving the shared static
// bundle + the whole contract API for ALL THREE scenario families (identity, flow, company-data) on ONE
// port. HTTP dispatch → the owning family's handler → the intended allme SDK surface.
//
// The router owns nothing family-specific: it aggregates each family's /api/meta entries, routes a
// scenario request (/config, /start, /clear) to the family that Owns() the id, dispatches a run poll by
// the run's stored scenario id, and forwards the two public OAuth/webhook routes to whichever family
// implements them (identity's GET /callback + POST .../enroll, company-data's POST /webhook). Everything
// runs behind one mutex — the Go equivalent of the PHP reference's single-worker `php -S`.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Shared contract facts (contract §"backend"). The whole example implements a single contract version.
const (
	// ContractVersion is the demo-backend contract this server implements; a bundle whose contract.json
	// version differs is refused at startup (see launcher.go).
	ContractVersion = 3
	// SDKName identifies this SDK in /api/meta.
	SDKName = "go"
	// DefaultAPIURL is the deployed platform — the default target for every scenario's config.
	DefaultAPIURL = "https://api.allme.fyi"
)

// Scenario is one entry in /api/meta. ID is an int for the identity family (ids 1–8) and a string for
// the flow / company-data families ("flow:run", "companydata:*") — the JSON shape each family already
// published on its own.
type Scenario struct {
	ID   any    `json:"id"`
	Kind string `json:"kind"`
}

// Family is one scenario family (identity / flow / company-data). The router discovers a family's
// scenarios via Scenarios(), routes by Owns(), and delegates the four per-scenario verbs. The three
// public non-scenario routes are opt-in via the small interfaces below.
type Family interface {
	Scenarios() []Scenario // this family's /api/meta entries, in display order
	Owns(id string) bool   // whether a scenario id belongs to this family
	Config(w http.ResponseWriter, r *http.Request, id string)
	Start(w http.ResponseWriter, r *http.Request, id string)
	Clear(w http.ResponseWriter, r *http.Request, id string)
	// Run renders GET /api/runs/{runId} for a run this family owns (the run map is already read).
	Run(w http.ResponseWriter, runID string, run map[string]any)
}

// Callbacker is implemented by the family serving GET /callback (identity's OAuth redirect leg).
type Callbacker interface {
	Callback(w http.ResponseWriter, r *http.Request)
}

// Enroller is implemented by the family serving POST /api/scenarios/{id}/enroll (identity's 2FA enroll).
type Enroller interface {
	Enroll(w http.ResponseWriter, r *http.Request, id string)
}

// Webhooker is implemented by the family serving the public POST /webhook (company-data's receiver).
type Webhooker interface {
	Webhook(w http.ResponseWriter, r *http.Request)
}

// FamilyFactory binds a family to the shared Runtime.
type FamilyFactory func(rt *Runtime) Family

var (
	reConfig = regexp.MustCompile(`^/api/scenarios/([^/]+)/config$`)
	reStart  = regexp.MustCompile(`^/api/scenarios/([^/]+)/start$`)
	reEnroll = regexp.MustCompile(`^/api/scenarios/([^/]+)/enroll$`)
	reClear  = regexp.MustCompile(`^/api/scenarios/([^/]+)/clear$`)
	reRun    = regexp.MustCompile(`^/api/runs/([0-9a-f]{32})$`)
)

// Server implements the demo-backend contract for all families.
type Server struct {
	rt          *Runtime
	frontendDir string
	sdkVersion  string
	families    []Family
	mu          sync.Mutex // serialises requests → single-worker semantics (contract §3)
}

// owner returns the family that owns a scenario id, or nil.
func (s *Server) owner(id string) Family {
	for _, f := range s.families {
		if f.Owns(id) {
			return f
		}
	}
	return nil
}

// ServeHTTP dispatches every request (static bundle OR API OR the public OAuth/webhook routes) behind
// the serialising mutex.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The guard is registered FIRST, so any unexpected panic in request preprocessing is covered too
	// (#583 review pass 1). Ordinary runtime-directory creation failures are rejected at startup by
	// WipeAll; this ordering closes the separate panic-before-recover hole.
	defer func() {
		if rec := recover(); rec != nil {
			WriteFailure(w, 500, "server_error", rec)
		}
	}()

	s.rt.EnsureDirs()
	s.rt.Sweep() // lazy TTL sweep on every request (contract §3)

	path := r.URL.Path
	method := r.Method

	switch {
	case path == "/api/meta" && method == http.MethodGet:
		s.meta(w)
	case path == "/callback" && method == http.MethodGet:
		if f := findCallbacker(s.families); f != nil {
			f.Callback(w, r)
			return
		}
		http.NotFound(w, r)
	case path == "/webhook" && method == http.MethodPost:
		if f := findWebhooker(s.families); f != nil {
			f.Webhook(w, r) // PUBLIC inbound delivery (not under /api/)
			return
		}
		WriteText(w, 200, "discarded: no webhook family") // never fail a delivery with a non-200
	case path == "/api/clear" && method == http.MethodPost:
		s.rt.ClearAll()
		WriteJSON(w, 200, map[string]any{"ok": true})
	case reConfig.MatchString(path) && method == http.MethodPost:
		s.dispatchScenario(w, r, reConfig, func(f Family, id string) { f.Config(w, r, id) })
	case reStart.MatchString(path) && method == http.MethodPost:
		s.dispatchScenario(w, r, reStart, func(f Family, id string) { f.Start(w, r, id) })
	case reEnroll.MatchString(path) && method == http.MethodPost:
		id := reEnroll.FindStringSubmatch(path)[1]
		f := s.owner(id)
		en, ok := f.(Enroller)
		if f == nil || !ok {
			WriteJSON(w, 404, map[string]any{"error": "not_found"})
			return
		}
		en.Enroll(w, r, id)
	case reClear.MatchString(path) && method == http.MethodPost:
		s.dispatchScenario(w, r, reClear, func(f Family, id string) { f.Clear(w, r, id) })
	case reRun.MatchString(path) && method == http.MethodGet:
		s.run(w, reRun.FindStringSubmatch(path)[1])
	case strings.HasPrefix(path, "/api/"):
		WriteJSON(w, 404, map[string]any{"error": "not_found"})
	default:
		s.serveStatic(w, r, path)
	}
}

// dispatchScenario routes a /config|/start|/clear request to the family that owns the captured id.
func (s *Server) dispatchScenario(w http.ResponseWriter, r *http.Request, re *regexp.Regexp, call func(Family, string)) {
	id := re.FindStringSubmatch(r.URL.Path)[1]
	f := s.owner(id)
	if f == nil {
		WriteJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	call(f, id)
}

// ── GET /api/meta ───────────────────────────────────────────────────────────

// meta lists ALL scenarios of ALL families, in family-registration order, at the shared contractVersion.
func (s *Server) meta(w http.ResponseWriter) {
	list := []Scenario{}
	for _, f := range s.families {
		list = append(list, f.Scenarios()...)
	}
	WriteJSON(w, 200, map[string]any{
		"sdk":             SDKName,
		"sdkVersion":      s.sdkVersion,
		"contractVersion": ContractVersion,
		"scenarios":       list,
	})
}

// ── GET /api/runs/{runId} ─────────────────────────────────────────────────────

// run reads the run, finds the family that owns its scenario id, and lets that family render (and, for a
// still-pending run, advance) the poll. Unknown/expired ids → 404.
func (s *Server) run(w http.ResponseWriter, runID string) {
	run := s.rt.ReadRun(runID)
	if run == nil {
		WriteJSON(w, 404, map[string]any{"error": "not_found"})
		return
	}
	f := s.owner(ToStr(run["scenario"]))
	if f == nil {
		// A run with no owning family (should not happen) — surface the stored envelope as-is.
		out := map[string]any{"status": OrDefault(ToStr(run["status"]), "pending"), "calls": run["calls"]}
		if run["result"] != nil {
			out["result"] = run["result"]
		}
		if run["error"] != nil {
			out["error"] = run["error"]
		}
		WriteJSON(w, 200, out)
		return
	}
	f.Run(w, runID, run)
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

func findCallbacker(fs []Family) Callbacker {
	for _, f := range fs {
		if c, ok := f.(Callbacker); ok {
			return c
		}
	}
	return nil
}

func findWebhooker(fs []Family) Webhooker {
	for _, f := range fs {
		if wh, ok := f.(Webhooker); ok {
			return wh
		}
	}
	return nil
}

// ── shared HTTP / value helpers (used by the router AND every family handler) ──

// WriteJSON writes a JSON response without HTML-escaping (URLs in payloads stay readable).
func WriteJSON(w http.ResponseWriter, status int, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(data)
}

// WriteFailure writes the contract's FAILURE envelope (#583):
// {"error": "<token> — <reason>", "message": "<reason>"}. reason is the error, the recovered panic
// value, or a sentence.
//
// The suite's shared client raises body.error VERBATIM and ignores every other key (api.js:
// `throw new Error(body.error || "start failed (…)")`), so a bare token in `error` reaches the developer
// as one uninformative word and the REASON — which the backend has right there — is dropped. That is the
// swallowed failure of standards.html §9: a failure converted into something indistinguishable from any
// other failure. The token is kept and the reason appended in the shape this contract already uses for
// exactly this (`no_origin — …`, #574); `message` keeps the bare reason for a programmatic reader.
//
// fmt.Sprint, not ToStr: a recovered panic value is almost never a string (a runtime fault arrives as
// runtime.Error), and a type assertion to string answers "" for every one of them — reporting the panic
// as an empty reason, the very defect this function exists to close.
//
// NOT used for the token-only refusals the suite handles by STATUS rather than body — 409
// not_configured (startScenario maps the 409 before reading the body) and 404 not_found.
func WriteFailure(w http.ResponseWriter, status int, token string, reason any) {
	text := strings.TrimSpace(fmt.Sprint(reason))
	shown := text
	if shown == "" {
		shown = "no reason was reported"
	}
	WriteJSON(w, status, map[string]any{"error": token + " — " + shown, "message": text})
}

// WriteText writes a plain-text response (the webhook receiver's acknowledgements).
func WriteText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

// ReadBody decodes a request body as a JSON object; empty map on any error.
func ReadBody(r *http.Request) map[string]any {
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

// ToStr returns v as a string ("" when it is not one).
func ToStr(v any) string {
	s, _ := v.(string)
	return s
}

// AsInt coerces a JSON-decoded number/string into an int.
func AsInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i := 0
		for _, c := range n {
			if c < '0' || c > '9' {
				return 0
			}
			i = i*10 + int(c-'0')
		}
		return i
	}
	return 0
}

// OrDefault returns v, or def when v is empty.
func OrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// AnySlice coerces a JSON-decoded value into a []any (nil → empty slice).
func AnySlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return []any{}
}

// StringsToAny widens a []string into a []any (for storing call traces in a run map).
func StringsToAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// StringSlice narrows a JSON-decoded value into a []string.
func StringSlice(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
