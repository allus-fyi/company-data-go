package demo

// The one-command launcher shared by the whole example: `go run .` (from examples/).
//
// Steps:
//  1. wipe .runtime/ (fresh state each boot)
//  2. on a missing/unverified bundle: fetch the pinned frontend release (frontend.lock), VERIFY its
//     sha256, unpack to .frontend/<tag>/ (a present, verified bundle is a cache hit — nothing refetched)
//  3. assert the bundle's contract.json version == the backend's implemented ContractVersion
//  4. refuse a busy port with a clear message
//  5. serve port ${PORT:-8091} on ALL interfaces with a SINGLE serialising net/http server that hosts
//     all three scenario families — so a phone on the same network can reach it — printing every URL
//     it is reachable on.

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

// Main is the process entry point: it wires the shared Runtime into each family factory and runs the
// server, exiting non-zero on a startup error.
func Main(factories ...FamilyFactory) {
	if err := run(factories); err != nil {
		fmt.Fprintf(os.Stderr, "\nERROR: %v\n", err)
		os.Exit(1)
	}
}

func run(factories []FamilyFactory) error {
	base, err := os.Getwd()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "allme SDK example test suite (go) — starting up")

	// 1. fresh runtime state (shared by all three families)
	rt := NewRuntime(base)
	if err := rt.WipeAll(); err != nil {
		return fmt.Errorf("could not reset .runtime/: %w", err)
	}

	// 2. frontend bundle (pinned release, checksum-verified, TAG-specific cache)
	lock, err := readLock(filepath.Join(base, "frontend.lock"))
	if err != nil {
		return err
	}
	frontendDir := filepath.Join(base, ".frontend", lock.Tag) // per-tag cache dir
	if err := ensureFrontend(frontendDir, lock); err != nil {
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
	// An empty host binds ALL interfaces (dual-stack), so a phone on the same network can reach it.
	addr := ":" + port
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port %s is busy (%v). Set PORT=<n> to use another port "+
			"(one browser origin is shared across SDK examples, so only one runs at a time)", port, err)
	}

	// 5. serve — single serialising server hosting every family
	families := make([]Family, 0, len(factories))
	for _, f := range factories {
		families = append(families, f(rt))
	}
	srv := &Server{rt: rt, frontendDir: frontendDir, sdkVersion: sdkVersion(), families: families}
	printReachableURLs(port)
	httpSrv := &http.Server{Handler: srv}
	return httpSrv.Serve(ln)
}

// printReachableURLs announces every URL the server is reachable on.
//
// The server binds all interfaces, so a phone on the same network can reach it — but only if the
// person holding the phone knows which address to type. Print the loopback URL AND every
// non-loopback IPv4 address of this host, plus the plain warning that this is now open to the
// local network.
func printReachableURLs(port string) {
	fmt.Fprintf(os.Stderr, "serving on ALL interfaces, port %s  (all three scenario families; Ctrl-C to stop)\n", port)
	fmt.Fprintf(os.Stderr, "  on this machine:  http://localhost:%s\n", port)
	lan := lanAddresses()
	if len(lan) == 0 {
		fmt.Fprintln(os.Stderr, "  on this network:  (no non-loopback IPv4 address found — is this machine on a network?)")
	} else {
		for i, addr := range lan {
			label := "                    "
			if i == 0 {
				label = "  on this network:  "
			}
			fmt.Fprintf(os.Stderr, "%shttp://%s:%s\n", label, addr, port)
		}
	}
	fmt.Fprintln(os.Stderr, "  NOTE: anyone on your network can now reach this demo, and its setup panels accept and")
	fmt.Fprintln(os.Stderr, "        store real credentials under .runtime/config/ — OAuth and data-client secrets,")
	fmt.Fprintln(os.Stderr, "        private-key PEMs and their passphrases, and webhook signing secrets. It is a local")
	fmt.Fprintln(os.Stderr, "        developer example, not a hardened service: run it only on a network you trust, and")
	fmt.Fprintln(os.Stderr, "        only with sandbox credentials.")
}

// lanAddresses reports every non-loopback, non-link-local IPv4 address of this host. IPv4 only — an
// IPv6 literal is not what anyone types into a phone.
func lanAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			v4 := ip.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, v4.String())
		}
	}
	return out
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
func ensureFrontend(frontendDir string, lock *frontendLock) error {
	markSha := strings.ToLower(strings.TrimSpace(readFileString(filepath.Join(frontendDir, ".sha"))))
	cacheValid := isFile(filepath.Join(frontendDir, "index.html")) &&
		isFile(filepath.Join(frontendDir, "contract.json")) &&
		markSha != "" && markSha == lock.Sha256
	if cacheValid {
		fmt.Fprintf(os.Stderr, "frontend %s present + checksum-verified (cache hit) — skipping fetch\n", lock.Tag)
		return nil
	}
	return fetchBundle(frontendDir, lock)
}

// fetchBundle downloads dist.tar.gz for the pinned tag, verifies its sha256, and unpacks it. A checksum
// mismatch refuses loudly (an unverified bundle is never served).
func fetchBundle(frontendDir string, lock *frontendLock) error {
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
	if c.ContractVersion != ContractVersion {
		return fmt.Errorf("contract mismatch: bundle contractVersion=%d, backend implements %d.\n"+
			"Bump the frontend.lock pin to a release whose contract.json matches, or update the backend.",
			c.ContractVersion, ContractVersion)
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
