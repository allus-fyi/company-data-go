package main

// Cross-request state for the demo backend (contract §3, config-file model).
//
// The example runs as a SINGLE net/http server and every request is serialised behind one mutex in
// server.go, so — exactly like the PHP reference's single-worker `php -S` — there is NO cross-request
// concurrency to guard inside here: no locks, no tombstones, no burn-on-read. Everything lives under
// runtimeDir (git-ignored, wiped at startup):
//
//   - config/{id}.json       — the canonical SDK config file a scenario runs OFF (written by
//                              POST /api/scenarios/{id}/config from the browser settings; NOT TTL-swept)
//   - config/{id}.meta.json  — demo-only run parameters that are not SDK Config fields
//                              (authorize_base, one_time claims, share_code, context)
//   - config/keys/<sha1>.pem — the private-key file(s) a config references by path (mode 0600)
//   - runs/{runId}.json      — PKCE verifier / state / nonce / outcome for one run
//
// Config files persist across runs (they are configuration, not runs) and are removed only by a Clear
// or the startup wipe. Run files are written via write-temp + atomic rename (crash hygiene only) and
// removed by their 30-minute TTL (lazy sweep on any request, which also collects orphaned *.tmp files),
// by Clear, or by the startup wipe.

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// runTTL is the 30-minute run TTL. Config files are exempt (they are configuration, not runs).
const runTTL = 30 * time.Minute

var runIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Runtime is the on-disk state store rooted at a base directory.
type Runtime struct {
	runtimeDir    string
	runsDir       string
	configDir     string
	configKeysDir string
}

// NewRuntime builds a Runtime whose state lives under baseDir/.runtime.
func NewRuntime(baseDir string) *Runtime {
	rt := &Runtime{runtimeDir: filepath.Join(baseDir, ".runtime")}
	rt.runsDir = filepath.Join(rt.runtimeDir, "runs")
	rt.configDir = filepath.Join(rt.runtimeDir, "config")
	rt.configKeysDir = filepath.Join(rt.configDir, "keys")
	return rt
}

// ensureDirs creates the runtime directories (idempotent).
func (rt *Runtime) ensureDirs() error {
	for _, d := range []string{rt.runtimeDir, rt.runsDir, rt.configDir, rt.configKeysDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// wipeAll removes ALL runtime state (configs + keys + runs) and recreates the empty tree.
func (rt *Runtime) wipeAll() error {
	os.RemoveAll(rt.runtimeDir)
	return rt.ensureDirs()
}

// ── lazy TTL sweep ──────────────────────────────────────────────────────────

// sweep removes expired run files and orphaned *.tmp files. Called on every request (contract §3).
// Config files carry NO TTL — they are wiped only at startup or by Clear.
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
}

// ── config files ────────────────────────────────────────────────────────────

func (rt *Runtime) configPathFor(id int) string {
	return filepath.Join(rt.configDir, strconv.Itoa(id)+".json")
}

func (rt *Runtime) metaPathFor(id int) string {
	return filepath.Join(rt.configDir, strconv.Itoa(id)+".meta.json")
}

func (rt *Runtime) hasConfig(id int) bool {
	_, err := os.Stat(rt.configPathFor(id))
	return err == nil
}

// writeConfig writes a scenario's canonical SDK config file (atomic). Returns the RELATIVE path (for
// display/inspection in the setup panel). config is the canonical SDK config shape (snake_case keys).
func (rt *Runtime) writeConfig(id int, config map[string]any) (string, error) {
	if err := rt.ensureDirs(); err != nil {
		return "", err
	}
	blob, _ := json.MarshalIndent(config, "", "  ")
	if err := atomicWrite(rt.configPathFor(id), blob, 0o600); err != nil {
		return "", err
	}
	return ".runtime/config/" + strconv.Itoa(id) + ".json", nil
}

// writeConfigMeta writes a scenario's demo-only meta sidecar (authorize_base, claims, share_code,
// context) — run parameters that are NOT SDK Config fields, kept out of the canonical config file.
func (rt *Runtime) writeConfigMeta(id int, meta map[string]any) error {
	if err := rt.ensureDirs(); err != nil {
		return err
	}
	blob, _ := json.MarshalIndent(meta, "", "  ")
	return atomicWrite(rt.metaPathFor(id), blob, 0o600)
}

// readConfigMeta reads a scenario's meta sidecar; empty map when absent.
func (rt *Runtime) readConfigMeta(id int) map[string]any {
	return readJSONMap(rt.metaPathFor(id))
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

// ── clear ─────────────────────────────────────────────────────────────────

// clearScenario deletes a scenario's run files AND its config + meta files, then garbage-collects any
// key PEM no surviving config still references (keys are content-addressed and may be shared).
func (rt *Runtime) clearScenario(id int) {
	entries, _ := os.ReadDir(rt.runsDir)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(rt.runsDir, e.Name())
		m := readJSONMap(path)
		if m != nil && asInt(m["scenario"]) == id {
			os.Remove(path)
		}
	}
	os.Remove(rt.configPathFor(id))
	os.Remove(rt.metaPathFor(id))
	rt.gcConfigKeys()
}

// clearAll wipes all run files and the entire config tree (configs, metas, keys).
func (rt *Runtime) clearAll() {
	entries, _ := os.ReadDir(rt.runsDir)
	for _, e := range entries {
		os.Remove(filepath.Join(rt.runsDir, e.Name()))
	}
	os.RemoveAll(rt.configDir)
	rt.ensureDirs()
}

// gcConfigKeys deletes any key PEM in config/keys that no surviving config/{id}.json references.
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
		for _, field := range []string{"oauth_private_key", "service_private_key"} {
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

// atomicWrite writes contents to a temp file on the same directory then renames (crash hygiene: no
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
