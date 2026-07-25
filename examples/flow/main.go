package main

// One-command launcher for the flow example: `go run .` (from this directory).
//
// Steps (mirroring the PHP reference bin/start.php):
//  1. wipe .runtime/ (fresh state each boot)
//  2. on a missing/unverified bundle: fetch the pinned frontend release (frontend.lock), VERIFY its
//     sha256, unpack to .frontend/<tag>/ (a present, verified bundle is a cache hit — nothing refetched)
//  3. assert the bundle's contract.json version == the backend's implemented contractVersion
//  4. refuse a busy port with a clear message
//  5. serve http://localhost:${PORT:-8091} with a SINGLE serialising net/http server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

const releaseBase = "https://github.com/allme-sdk/example-test-suite/releases/download"

type frontendLock struct {
	Tag    string `json:"tag"`
	Sha256 string `json:"sha256"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	base, err := os.Getwd()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "flow example (go) — starting up")

	// 1. fresh runtime state
	rt := NewRuntime(base)
	if err := rt.wipeAll(); err != nil {
		return fmt.Errorf("could not reset .runtime/: %w", err)
	}

	// 2. frontend bundle (pinned release, checksum-verified, TAG-specific cache)
	lock, err := readLock(filepath.Join(base, "frontend.lock"))
	if err != nil {
		return err
	}
	frontendDir := filepath.Join(base, ".frontend", lock.Tag) // per-tag cache dir
	if err := ensureFrontend(base, frontendDir, lock); err != nil {
		return err
	}

	// 3. contract guard
	if err := checkContract(frontendDir); err != nil {
		return err
	}

	// 4. port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8091"
	}
	addr := "localhost:" + port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port %s is busy (%v). Set PORT=<n> to use another port "+
			"(one browser origin is shared across SDK examples, so only one runs at a time)", port, err)
	}

	// 5. serve — single serialising server
	srv := &Server{rt: rt, frontendDir: frontendDir, sdkVersion: sdkVersion()}
	fmt.Fprintf(os.Stderr, "serving http://%s  (Ctrl-C to stop)\n", addr)
	httpSrv := &http.Server{Handler: srv}
	return httpSrv.Serve(ln)
}

// ── frontend bundle ───────────────────────────────────────────────────────────

func readLock(path string) (*frontendLock, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("frontend.lock missing: %w", err)
	}
	var l frontendLock
	if err := json.Unmarshal(raw, &l); err != nil || l.Tag == "" || l.Sha256 == "" {
		return nil, fmt.Errorf(`frontend.lock malformed (need {"tag","sha256"})`)
	}
	l.Sha256 = strings.ToLower(l.Sha256)
	return &l, nil
}

// ensureFrontend serves a verified cache hit or fetches + verifies + unpacks the pinned release.
func ensureFrontend(base, frontendDir string, lock *frontendLock) error {
	markSha := strings.ToLower(strings.TrimSpace(readFileString(filepath.Join(frontendDir, ".sha"))))
	cacheValid := isFile(filepath.Join(frontendDir, "index.html")) &&
		isFile(filepath.Join(frontendDir, "contract.json")) &&
		markSha != "" && markSha == lock.Sha256
	if cacheValid {
		fmt.Fprintf(os.Stderr, "frontend %s present + checksum-verified (cache hit) — skipping fetch\n", lock.Tag)
		return nil
	}
	return fetchBundle(base, frontendDir, lock)
}

// fetchBundle downloads dist.tar.gz for the pinned tag, verifies its sha256, and unpacks it. A checksum
// mismatch refuses loudly (an unverified bundle is never served).
func fetchBundle(base, frontendDir string, lock *frontendLock) error {
	url := releaseBase + "/" + lock.Tag + "/dist.tar.gz"
	fmt.Fprintf(os.Stderr, "fetching frontend %s → %s\n", lock.Tag, url)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("could not download the pinned frontend release (%s): %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("could not download the pinned frontend release (%s): HTTP %d", url, resp.StatusCode)
	}
	blob, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("download read failed: %w", err)
	}

	got := hex.EncodeToString(sha256Sum(blob))
	if got != lock.Sha256 {
		return fmt.Errorf("frontend checksum MISMATCH.\n  expected %s\n  got      %s\n"+
			"Refusing to serve an unverified bundle. Fix frontend.lock or re-download.", lock.Sha256, got)
	}

	os.RemoveAll(frontendDir)
	if err := os.MkdirAll(frontendDir, 0o755); err != nil {
		return err
	}
	if err := untar(blob, frontendDir); err != nil {
		return fmt.Errorf("failed to unpack the frontend bundle: %w", err)
	}
	if !isFile(filepath.Join(frontendDir, "index.html")) {
		return fmt.Errorf("frontend bundle has no index.html after unpack")
	}
	// Record the verified checksum so the next start recognises THIS tag/sha as a valid cache-hit.
	os.WriteFile(filepath.Join(frontendDir, ".sha"), []byte(lock.Sha256), 0o644)
	fmt.Fprintf(os.Stderr, "frontend %s verified + unpacked → %s\n", lock.Tag, frontendDir)
	return nil
}

func checkContract(frontendDir string) error {
	raw, err := os.ReadFile(filepath.Join(frontendDir, "contract.json"))
	if err != nil {
		return fmt.Errorf("bundle contract.json missing: %w", err)
	}
	var c struct {
		ContractVersion int `json:"contractVersion"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("bundle contract.json invalid: %w", err)
	}
	if c.ContractVersion != contractVersion {
		return fmt.Errorf("contract mismatch: bundle contractVersion=%d, backend implements %d.\n"+
			"Bump the frontend.lock pin to a release whose contract.json matches, or update the backend.",
			c.ContractVersion, contractVersion)
	}
	return nil
}

// untar extracts a gzipped tar archive to dest, guarding against path traversal.
func untar(blob []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return err
	}
	defer gz.Close()
	root, _ := filepath.Abs(dest)
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, filepath.Clean("/"+hdr.Name))
		abs, _ := filepath.Abs(target)
		if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
			continue // skip anything outside dest (path-traversal guard)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
}

// ── small helpers ───────────────────────────────────────────────────────────

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func readFileString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// sdkVersion reports the resolved company-data-go module version (from build info), or "dev" when the
// example is run against a local (replace-directive) checkout.
func sdkVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path != "github.com/allus-fyi/company-data-go" {
				continue
			}
			// A local replace directive (this example runs against the in-tree SDK) reports no real
			// version — surface it as "dev" rather than the placeholder v0.0.0 / (devel).
			if dep.Replace != nil {
				return "dev"
			}
			if v := dep.Version; v != "" && v != "(devel)" && v != "v0.0.0" {
				return v
			}
		}
	}
	return "dev"
}
