package demo

// Cross-request state for the SDK-example demo backend (contract §3, config-file model), SHARED by all
// three scenario families (identity, flow, company-data).
//
// The whole example runs as ONE net/http server and every request is serialised behind one mutex in
// server.go, so — exactly like the PHP reference's single-worker `php -S` — there is NO cross-request
// concurrency to guard inside here: no locks, no tombstones, no burn-on-read. Everything lives under
// runtimeDir (git-ignored, wiped at startup):
//
//   - config/{sid}.json        — the canonical SDK config file a scenario runs OFF (written by
//                                POST /api/scenarios/{id}/config from the browser settings; NOT TTL-swept)
//   - config/{sid}.meta.json   — demo-only run parameters that are not SDK Config fields
//   - config/keys/<sha1>.pem   — the private-key file(s) a config references by path (mode 0600)
//   - runs/{runId}.json        — one run's PKCE/verifier/state, accumulated steps/events, and outcome
//   - webhook-route.json       — the SINGLE active company-data webhook run: {webhookId, runId}
//   - cache/                   — the SDK pump's buffer + dead-letter dir (Config.CacheDir), wiped by Clear
//
// {sid} is a filesystem-safe token of the scenario id — the SAME scheme for every family, so identity's
// numeric ids ("3" → "3.json"), the flow id ("flow:run" → "flow_run.json") and the company-data ids
// ("companydata:read" → "companydata_read.json") all key the store uniformly (contract: config is kept
// per scenario id). Config files persist across runs (they are configuration, not runs) and are removed
// only by a Clear or the startup wipe. Run files are written via write-temp + atomic rename (crash
// hygiene only) and removed by their 30-minute TTL (lazy sweep on any request, which also collects
// orphaned *.tmp files), by Clear, or by the startup wipe.

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// runTTL is the 30-minute run TTL. Config files are exempt (they are configuration, not runs).
const runTTL = 30 * time.Minute

// keyFields are every config field that references a materialized private-key PEM by path — used by the
// key garbage collector. The union across families (identity's OAuth-app key + every service key).
var keyFields = []string{"oauth_private_key", "service_private_key"}

var (
	runIDRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	nonTokRe = regexp.MustCompile(`[^a-z0-9]+`)
)

// Runtime is the on-disk state store rooted at a base directory.
type Runtime struct {
	runtimeDir    string
	runsDir       string
	configDir     string
	configKeysDir string
	cacheDir      string
	routePath     string
}

// NewRuntime builds a Runtime whose state lives under baseDir/.runtime.
func NewRuntime(baseDir string) *Runtime {
	rt := &Runtime{runtimeDir: filepath.Join(baseDir, ".runtime")}
	rt.runsDir = filepath.Join(rt.runtimeDir, "runs")
	rt.configDir = filepath.Join(rt.runtimeDir, "config")
	rt.configKeysDir = filepath.Join(rt.configDir, "keys")
	// The SDK pump persists its buffer + dead-letters here (Config.CacheDir → this path), so Clear /
	// the startup wipe removes it and the "writes only under .runtime/" invariant holds.
	rt.cacheDir = filepath.Join(rt.runtimeDir, "cache")
	rt.routePath = filepath.Join(rt.runtimeDir, "webhook-route.json")
	return rt
}

// CacheDir is the SDK pump's durable buffer / dead-letter directory (Config.CacheDir).
func (rt *Runtime) CacheDir() string { return rt.cacheDir }

// EnsureDirs creates the runtime directories (idempotent).
func (rt *Runtime) EnsureDirs() error {
	for _, d := range []string{rt.runtimeDir, rt.runsDir, rt.configDir, rt.configKeysDir, rt.cacheDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// WipeAll removes ALL runtime state (configs + keys + runs + cache + route) and recreates the empty tree.
func (rt *Runtime) WipeAll() error {
	os.RemoveAll(rt.runtimeDir)
	return rt.EnsureDirs()
}

// ── lazy TTL sweep ──────────────────────────────────────────────────────────

// Sweep removes expired run files and orphaned *.tmp files. Called on every request (contract §3). When
// the active webhook run expires, its routing record is dropped too (a stale record never routes to a
// burned run). Config files carry NO TTL — they are wiped only at startup or by Clear.
func (rt *Runtime) Sweep() {
	now := time.Now()
	entries, _ := os.ReadDir(rt.runsDir)
	for _, e := range entries {
		path := filepath.Join(rt.runsDir, e.Name())
		if strings.HasSuffix(e.Name(), ".tmp") {
			os.Remove(path) // orphaned temp from an interrupted write
			continue
		}
		if strings.HasSuffix(e.Name(), ".json") {
			info, err := e.Info()
			if err == nil && now.Sub(info.ModTime()) > runTTL {
				os.Remove(path)
			}
		}
	}
	rt.reconcileRoute()
}

// ── config files ────────────────────────────────────────────────────────────

// sid is a filesystem-safe token for a scenario's id (identity "3" → "3"; "flow:run" → "flow_run";
// "companydata:read" → "companydata_read").
func sid(scenarioID string) string {
	return strings.Trim(nonTokRe.ReplaceAllString(strings.ToLower(scenarioID), "_"), "_")
}

// ConfigPath is the ABSOLUTE path to a scenario's canonical SDK config file (fed to the SDK's
// FromConfig / ConfigFromFile constructors).
func (rt *Runtime) ConfigPath(scenarioID string) string {
	return filepath.Join(rt.configDir, sid(scenarioID)+".json")
}

func (rt *Runtime) metaPath(scenarioID string) string {
	return filepath.Join(rt.configDir, sid(scenarioID)+".meta.json")
}

// HasConfig reports whether a scenario's config file has been saved.
func (rt *Runtime) HasConfig(scenarioID string) bool {
	_, err := os.Stat(rt.ConfigPath(scenarioID))
	return err == nil
}

// WriteConfig writes a scenario's canonical SDK config file (atomic). Returns the RELATIVE path (for
// display/inspection in the setup panel). config is the canonical SDK config shape (snake_case keys).
func (rt *Runtime) WriteConfig(scenarioID string, config map[string]any) (string, error) {
	if err := rt.EnsureDirs(); err != nil {
		return "", err
	}
	blob, _ := json.MarshalIndent(config, "", "  ")
	if err := atomicWrite(rt.ConfigPath(scenarioID), blob, 0o600); err != nil {
		return "", err
	}
	return ".runtime/config/" + sid(scenarioID) + ".json", nil
}

// WriteConfigMeta writes a scenario's demo-only meta sidecar — run parameters that are NOT SDK Config
// fields (authorize base, one-time claims, share codes, flow/connection ids, webhook id), kept out of
// the canonical config file so it stays a pure SDK config.
func (rt *Runtime) WriteConfigMeta(scenarioID string, meta map[string]any) error {
	if err := rt.EnsureDirs(); err != nil {
		return err
	}
	blob, _ := json.MarshalIndent(meta, "", "  ")
	return atomicWrite(rt.metaPath(scenarioID), blob, 0o600)
}

// ReadConfigMeta reads a scenario's meta sidecar; empty map when absent.
func (rt *Runtime) ReadConfigMeta(scenarioID string) map[string]any {
	m := readJSONMap(rt.metaPath(scenarioID))
	if m == nil {
		return map[string]any{}
	}
	return m
}

// MaterializeConfigKey writes a browser-sent PEM to config/keys/<sha1>.pem (0600) and returns its
// ABSOLUTE path — the value recorded in the config file (the SDK reads keys by path). Content-addressed:
// identical PEM reuses the same file. Removed only by Clear or the startup wipe (never TTL).
func (rt *Runtime) MaterializeConfigKey(pem string) (string, error) {
	if err := rt.EnsureDirs(); err != nil {
		return "", err
	}
	sum := sha1.Sum([]byte(pem))
	path := filepath.Join(rt.configKeysDir, hex.EncodeToString(sum[:])+".pem")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := atomicWrite(path, []byte(pem), 0o600); err != nil {
			return "", err
		}
	}
	os.Chmod(path, 0o600)
	return path, nil
}

// ── runs ────────────────────────────────────────────────────────────────────

// NewRunID returns a fresh 128-bit hex run id.
func NewRunID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func isRunID(s string) bool { return runIDRe.MatchString(s) }

// WriteRun writes a run atomically (write-temp + rename). A reader never sees a partial file.
func (rt *Runtime) WriteRun(runID string, data map[string]any) error {
	data["runId"] = runID
	blob, _ := json.MarshalIndent(data, "", "  ")
	return atomicWrite(filepath.Join(rt.runsDir, runID+".json"), blob, 0o600)
}

// ReadRun reads a run, honouring the TTL. Returns nil for unknown/expired ids (idempotent reads — an
// outcome, once written, is returned on every poll until TTL/Clear removes it).
func (rt *Runtime) ReadRun(runID string) map[string]any {
	if !isRunID(runID) {
		return nil
	}
	path := filepath.Join(rt.runsDir, runID+".json")
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if time.Since(info.ModTime()) > runTTL {
		os.Remove(path)
		return nil
	}
	return readJSONMap(path)
}

// ── webhook routing record (contract §3 — single active webhook run) ──────────

// Route is the single active company-data webhook route.
type Route struct {
	WebhookID string `json:"webhookId"`
	RunID     string `json:"runId"`
}

// WriteRoute persists the single active webhook route {webhookId, runId}, superseding any prior one. A
// new companydata:webhook run calls this on /start; the old run stops receiving (its file stays readable
// until TTL/Clear).
func (rt *Runtime) WriteRoute(webhookID, runID string) error {
	if err := rt.EnsureDirs(); err != nil {
		return err
	}
	blob, _ := json.Marshal(Route{WebhookID: webhookID, RunID: runID})
	return atomicWrite(rt.routePath, blob, 0o600)
}

// ReadRoute returns the active webhook route, or nil when none is set.
func (rt *Runtime) ReadRoute() *Route {
	raw, err := os.ReadFile(rt.routePath)
	if err != nil {
		return nil
	}
	var r Route
	if json.Unmarshal(raw, &r) != nil || r.WebhookID == "" || r.RunID == "" {
		return nil
	}
	return &r
}

// ClearRoute drops the active webhook routing record.
func (rt *Runtime) ClearRoute() { os.Remove(rt.routePath) }

// reconcileRoute drops the routing record if its run is gone (expired/swept/cleared).
func (rt *Runtime) reconcileRoute() {
	if route := rt.ReadRoute(); route != nil {
		if _, err := os.Stat(filepath.Join(rt.runsDir, route.RunID+".json")); err != nil {
			os.Remove(rt.routePath)
		}
	}
}

// WipeCache removes the SDK pump's buffer / dead-letter directory (recreated on next EnsureDirs).
func (rt *Runtime) WipeCache() { os.RemoveAll(rt.cacheDir) }

// ── clear ─────────────────────────────────────────────────────────────────

// ClearScenario deletes a scenario's run files AND its config + meta files, then garbage-collects any
// key PEM no surviving config still references (keys are content-addressed and may be shared) and drops
// the routing record if it pointed at a now-removed run. Families layer any extra teardown (the company-
// data family also wipes the pump cache) on top.
func (rt *Runtime) ClearScenario(scenarioID string) {
	entries, _ := os.ReadDir(rt.runsDir)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(rt.runsDir, e.Name())
		m := readJSONMap(path)
		if m != nil && ToStr(m["scenario"]) == scenarioID {
			os.Remove(path)
		}
	}
	os.Remove(rt.ConfigPath(scenarioID))
	os.Remove(rt.metaPath(scenarioID))
	rt.gcConfigKeys()
	rt.reconcileRoute()
}

// ClearAll wipes all run files, the entire config tree (configs, metas, keys), the route + pump cache.
func (rt *Runtime) ClearAll() {
	entries, _ := os.ReadDir(rt.runsDir)
	for _, e := range entries {
		os.Remove(filepath.Join(rt.runsDir, e.Name()))
	}
	os.RemoveAll(rt.configDir)
	os.RemoveAll(rt.cacheDir)
	rt.ClearRoute()
	rt.EnsureDirs()
}

// gcConfigKeys deletes any key PEM in config/keys that no surviving config/{sid}.json references.
func (rt *Runtime) gcConfigKeys() {
	referenced := map[string]bool{}
	cfgs, _ := os.ReadDir(rt.configDir)
	for _, e := range cfgs {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".meta.json") {
			continue
		}
		m := readJSONMap(filepath.Join(rt.configDir, name))
		if m == nil {
			continue
		}
		for _, field := range keyFields {
			if p, ok := m[field].(string); ok && p != "" {
				referenced[p] = true
			}
		}
	}
	keys, _ := os.ReadDir(rt.configKeysDir)
	for _, e := range keys {
		if !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		path := filepath.Join(rt.configKeysDir, e.Name())
		if !referenced[path] {
			os.Remove(path)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

// atomicWrite writes contents to a temp file in the same directory then renames (crash hygiene: no
// partial reads).
func atomicWrite(finalPath string, contents []byte, mode os.FileMode) error {
	b := make([]byte, 4)
	rand.Read(b)
	tmp := finalPath + "." + hex.EncodeToString(b) + ".tmp"
	if err := os.WriteFile(tmp, contents, mode); err != nil {
		return err
	}
	os.Chmod(tmp, mode)
	return os.Rename(tmp, finalPath)
}

// readJSONMap decodes a JSON object file into a map; nil on any error.
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
