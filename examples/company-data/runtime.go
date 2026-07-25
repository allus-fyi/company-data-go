package main

// Cross-request state for the company-data demo backend (contract §3, config-file model).
//
// The example runs as a SINGLE net/http server and every request is serialised behind one mutex in
// server.go, so — exactly like the PHP reference's single-worker `php -S` — there is NO cross-request
// concurrency to guard inside here: no locks, no tombstones, no burn-on-read. Everything lives under
// runtimeDir (git-ignored, wiped at startup):
//
//   - config/{sid}.json        — the canonical SDK config file a scenario runs OFF (written by
//                                POST /api/scenarios/{id}/config from the browser settings; NOT TTL-swept)
//   - config/{sid}.meta.json   — demo-only run parameters that are not SDK Config fields (a documents
//                                target share_code; the webhook id)
//   - config/keys/<sha1>.pem   — the service private-key file(s) a config references by path (mode 0600)
//   - runs/{runId}.json        — one run's accumulated result (events / rows / docs) + calls
//   - webhook-route.json       — the SINGLE active webhook run: {webhookId, runId}. A new
//                                companydata:webhook run supersedes it; TTL/Clear of the run drops it.
//   - cache/                   — the SDK pump's buffer + dead-letter dir (Config.CacheDir), wiped by Clear
//
// {sid} is a filesystem-safe token of the scenario id (e.g. "companydata:read" → "companydata_read").
// Config files persist across runs (they are configuration, not runs) and are removed only by a Clear or
// the startup wipe. Run files are written via write-temp + atomic rename (crash hygiene only) and removed
// by their 30-minute TTL (lazy sweep on any request, which also collects orphaned *.tmp files), by Clear,
// or by the startup wipe.

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

// ensureDirs creates the runtime directories (idempotent).
func (rt *Runtime) ensureDirs() error {
	for _, d := range []string{rt.runtimeDir, rt.runsDir, rt.configDir, rt.configKeysDir, rt.cacheDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// wipeAll removes ALL runtime state (configs + keys + runs + cache + route) and recreates the empty tree.
func (rt *Runtime) wipeAll() error {
	os.RemoveAll(rt.runtimeDir)
	return rt.ensureDirs()
}

// ── lazy TTL sweep ──────────────────────────────────────────────────────────

// sweep removes expired run files and orphaned *.tmp files. Called on every request (contract §3). When
// the active webhook run expires, its routing record is dropped too (a stale record never routes to a
// burned run). Config files carry NO TTL — they are wiped only at startup or by Clear.
func (rt *Runtime) sweep() {
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
	// Drop the routing record if its run is gone (expired/swept above).
	if route := rt.readRoute(); route != nil {
		if _, err := os.Stat(filepath.Join(rt.runsDir, route.RunID+".json")); err != nil {
			os.Remove(rt.routePath)
		}
	}
}

// ── config files ────────────────────────────────────────────────────────────

// sid is a filesystem-safe token for a scenario's string id ("companydata:read" → "companydata_read").
func sid(scenarioID string) string {
	return strings.Trim(nonTokRe.ReplaceAllString(strings.ToLower(scenarioID), "_"), "_")
}

func (rt *Runtime) configPathFor(scenarioID string) string {
	return filepath.Join(rt.configDir, sid(scenarioID)+".json")
}

func (rt *Runtime) metaPathFor(scenarioID string) string {
	return filepath.Join(rt.configDir, sid(scenarioID)+".meta.json")
}

func (rt *Runtime) hasConfig(scenarioID string) bool {
	_, err := os.Stat(rt.configPathFor(scenarioID))
	return err == nil
}

// writeConfig writes a scenario's canonical SDK config file (atomic). Returns the RELATIVE path (for
// display/inspection in the setup panel). config is the canonical SDK config shape (snake_case keys).
func (rt *Runtime) writeConfig(scenarioID string, config map[string]any) (string, error) {
	if err := rt.ensureDirs(); err != nil {
		return "", err
	}
	blob, _ := json.MarshalIndent(config, "", "  ")
	if err := atomicWrite(rt.configPathFor(scenarioID), blob, 0o600); err != nil {
		return "", err
	}
	return ".runtime/config/" + sid(scenarioID) + ".json", nil
}

// writeConfigMeta writes a scenario's demo-only meta sidecar (share_code, webhook id) — run parameters
// that are NOT SDK Config fields, kept out of the canonical config file.
func (rt *Runtime) writeConfigMeta(scenarioID string, meta map[string]any) error {
	if err := rt.ensureDirs(); err != nil {
		return err
	}
	blob, _ := json.MarshalIndent(meta, "", "  ")
	return atomicWrite(rt.metaPathFor(scenarioID), blob, 0o600)
}

// readConfigMeta reads a scenario's meta sidecar; empty map when absent.
func (rt *Runtime) readConfigMeta(scenarioID string) map[string]any {
	m := readJSONMap(rt.metaPathFor(scenarioID))
	if m == nil {
		return map[string]any{}
	}
	return m
}

// materializeConfigKey writes a browser-sent PEM to config/keys/<sha1>.pem (0600) and returns its
// ABSOLUTE path — the value recorded in the config file (the SDK reads keys by path). Content-addressed:
// identical PEM reuses the same file. Removed only by Clear or the startup wipe (never TTL).
func (rt *Runtime) materializeConfigKey(pem string) (string, error) {
	if err := rt.ensureDirs(); err != nil {
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

func newRunID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func isRunID(s string) bool { return runIDRe.MatchString(s) }

// writeRun writes a run atomically (write-temp + rename). A reader never sees a partial file.
func (rt *Runtime) writeRun(runID string, data map[string]any) error {
	data["runId"] = runID
	blob, _ := json.MarshalIndent(data, "", "  ")
	return atomicWrite(filepath.Join(rt.runsDir, runID+".json"), blob, 0o600)
}

// readRun reads a run, honouring the TTL. Returns nil for unknown/expired ids (idempotent reads — an
// outcome, once written, is returned on every poll until TTL/Clear removes it).
func (rt *Runtime) readRun(runID string) map[string]any {
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

// route is the single active webhook route.
type route struct {
	WebhookID string `json:"webhookId"`
	RunID     string `json:"runId"`
}

// writeRoute persists the single active webhook route {webhookId, runId}, superseding any prior one. A
// new companydata:webhook run calls this on /start; the old run stops receiving (its file stays readable
// until TTL/Clear).
func (rt *Runtime) writeRoute(webhookID, runID string) error {
	if err := rt.ensureDirs(); err != nil {
		return err
	}
	blob, _ := json.Marshal(route{WebhookID: webhookID, RunID: runID})
	return atomicWrite(rt.routePath, blob, 0o600)
}

// readRoute returns the active webhook route, or nil when none is set.
func (rt *Runtime) readRoute() *route {
	raw, err := os.ReadFile(rt.routePath)
	if err != nil {
		return nil
	}
	var r route
	if json.Unmarshal(raw, &r) != nil || r.WebhookID == "" || r.RunID == "" {
		return nil
	}
	return &r
}

func (rt *Runtime) clearRoute() { os.Remove(rt.routePath) }

// ── clear ─────────────────────────────────────────────────────────────────

// clearScenario deletes a scenario's run files AND its config + meta files, then garbage-collects any
// key PEM no surviving config still references (keys are content-addressed and may be shared). Clearing
// the webhook scenario also drops the routing record; clearing anything wipes the shared pump cache dir.
func (rt *Runtime) clearScenario(scenarioID string) {
	entries, _ := os.ReadDir(rt.runsDir)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(rt.runsDir, e.Name())
		m := readJSONMap(path)
		if m != nil && toStr(m["scenario"]) == scenarioID {
			os.Remove(path)
		}
	}
	os.Remove(rt.configPathFor(scenarioID))
	os.Remove(rt.metaPathFor(scenarioID))
	if scenarioID == scenWebhook {
		rt.clearRoute()
	}
	os.RemoveAll(rt.cacheDir)
	rt.gcConfigKeys()
	rt.ensureDirs()
}

// clearAll wipes all run files, the entire config tree (configs, metas, keys), the route + pump cache.
func (rt *Runtime) clearAll() {
	entries, _ := os.ReadDir(rt.runsDir)
	for _, e := range entries {
		os.Remove(filepath.Join(rt.runsDir, e.Name()))
	}
	os.RemoveAll(rt.configDir)
	os.RemoveAll(rt.cacheDir)
	rt.clearRoute()
	rt.ensureDirs()
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
		if p, ok := m["service_private_key"].(string); ok && p != "" {
			referenced[p] = true
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
