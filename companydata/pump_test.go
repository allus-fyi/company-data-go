package companydata

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Crash-safe changes-pump tests. They drive the pump with a fake
// in-memory drain-on-fetch source returning canned CIPHERTEXT events (reusing
// the shared vector's real wrapper as a value) and a decrypt callable that runs
// the real crypto core. Nothing here touches the live API.
//
// Covered (the §6 contract + the four durability caveats):
//   - persist-before-deliver; ack-on-success; retry→dead-letter→continue;
//   - the crash test (replay-on-restart, idempotent Change.ID);
//   - ciphertext-at-rest; returns-when-drained; batch clamp;
//   - poison-decrypt dead-lettered immediately without burning retries (caveat 1);
//   - still-failing re-drive updated in place, never pending (caveat 2);
//   - monotonic attempt count (caveat 3).

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func pumpConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		APIURL:            "https://api.example.test",
		ClientID:          "svc_test",
		ClientSecret:      "secret",
		ServicePrivateKey: "unused.pem",
		KeyPassphrase:     "pp",
		CacheDir:          filepath.Join(t.TempDir(), "allus-cache"),
	}
}

// fakeSource is an in-memory drain-on-fetch queue: fetch deletes exactly what it
// returns.
type fakeSource struct {
	queue      []map[string]any
	fetchCalls []int
}

func (s *fakeSource) fetch(limit int) ([]map[string]any, error) {
	s.fetchCalls = append(s.fetchCalls, limit)
	n := limit
	if n > len(s.queue) {
		n = len(s.queue)
	}
	batch := s.queue[:n]
	s.queue = s.queue[n:]
	return batch, nil
}

func makeEvents(wrapper map[string]any, count, start int) []map[string]any {
	events := make([]map[string]any, 0, count)
	for i := start; i < start+count; i++ {
		events = append(events, map[string]any{
			"id":             fmt.Sprintf("chg-%04d", i),
			"event":          "field_updated",
			"person_user_id": fmt.Sprintf("person-%d", i),
			"slug":           "work_email",
			"value":          wrapper, // ciphertext, exactly as the API serves it
			"live":           true,
			"at":             fmt.Sprintf("2026-06-17T10:0%d:00Z", i),
		})
	}
	return events
}

func makePoisonEvent(id string) map[string]any {
	return map[string]any{
		"id": id, "event": "field_updated", "person_user_id": "person-x", "slug": "work_email",
		"value": map[string]any{"_enc": 1, "k": "@@notbase64@@", "iv": "AAAA", "d": "AAAA"},
		"live":  true, "at": "2026-06-17T10:09:00Z",
	}
}

// vectorDecryptChange builds the decrypt callable a pump uses: a raw event → a
// typed Change, decrypting the value at delivery with the vector key.
func vectorDecryptChange(t *testing.T) (decryptChangeFn, *rsa.PrivateKey) {
	t.Helper()
	v := loadVector(t)
	priv, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	dc := func(event map[string]any) (Change, error) {
		return changeFromAPI(event, func(string) string { return "text" }, func(w any) (string, error) { return Decrypt(w, priv) }, nil)
	}
	return dc, priv
}

func newTestPump(t *testing.T, cfg *Config, fetch fetchChangesFn, decrypt decryptChangeFn) *Pump {
	t.Helper()
	p, err := NewPump(cfg, fetch, decrypt, withPumpLogger(quietLogger()), withPumpSleep(func(_ time.Duration) {}))
	if err != nil {
		t.Fatalf("NewPump: %v", err)
	}
	return p
}

func wrapperFor(t *testing.T) map[string]any { return loadVector(t).Text.Wrapper }
func plaintextFor(t *testing.T) string       { return loadVector(t).Text.Plaintext }

// ── (a) persist-before-deliver ────────────────────────────────────────────────

func TestBatchPersistedBeforeAnyHandlerCall(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 3, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	firstCount := -1
	handler := func(c Change) error {
		if firstCount == -1 {
			buf, _ := NewFileBuffer(cfg.CacheDir)
			p, _ := buf.Pending()
			firstCount = len(p)
		}
		return nil
	}
	if err := pump.ProcessChanges(handler, PumpOptions{}); err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	if firstCount != 3 {
		t.Fatalf("buffer should hold all 3 before first delivery, got %d", firstCount)
	}
}

// ── (b) ack on success ─────────────────────────────────────────────────────────

func TestHandlerSuccessAcksPendingFile(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 3, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	var seen []string
	if err := pump.ProcessChanges(func(c Change) error { seen = append(seen, c.ID); return nil }, PumpOptions{}); err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	if got := fmt.Sprint(seen); got != "[chg-0001 chg-0002 chg-0003]" {
		t.Fatalf("seen = %v", seen)
	}
	buf, _ := NewFileBuffer(cfg.CacheDir)
	pending, _ := buf.Pending()
	dls, _ := buf.DeadLetters()
	if len(pending) != 0 || len(dls) != 0 {
		t.Fatalf("expected empty buffer, pending=%d dl=%d", len(pending), len(dls))
	}
}

func TestDeliveredChangeIsDecryptedPlaintext(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 1, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	var delivered []Change
	if err := pump.ProcessChanges(func(c Change) error { delivered = append(delivered, c); return nil }, PumpOptions{}); err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	if len(delivered) != 1 || delivered[0].Value != plaintextFor(t) {
		t.Fatalf("delivered value = %#v", delivered)
	}
}

// ── (c) retry → dead-letter → continue ────────────────────────────────────────

func TestPoisonEventDeadLetteredOthersProcessed(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 3, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	attempts := 0
	var ok []string
	handler := func(c Change) error {
		if c.ID == "chg-0002" {
			attempts++
			return errors.New("poison")
		}
		ok = append(ok, c.ID)
		return nil
	}
	if err := pump.ProcessChanges(handler, PumpOptions{MaxRetries: 3}); err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	if attempts != 4 { // 1 + 3 retries
		t.Fatalf("attempts = %d, want 4", attempts)
	}
	if fmt.Sprint(ok) != "[chg-0001 chg-0003]" {
		t.Fatalf("ok = %v", ok)
	}
	buf, _ := NewFileBuffer(cfg.CacheDir)
	if pending, _ := buf.Pending(); len(pending) != 0 {
		t.Fatalf("expected nothing pending")
	}
	dls, _ := buf.DeadLetters()
	if len(dls) != 1 || dls[0].ID != "chg-0002" || dls[0].Attempts != 4 {
		t.Fatalf("dead-letters = %+v", dls)
	}
	if !contains(dls[0].Error, "poison") {
		t.Fatalf("dl error = %q", dls[0].Error)
	}
}

func TestOnErrorHaltStopsAndLeavesPending(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 3, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	handler := func(c Change) error {
		if c.ID == "chg-0002" {
			return errors.New("halt-me")
		}
		return nil
	}
	err := pump.ProcessChanges(handler, PumpOptions{MaxRetries: 1, OnError: OnErrorHalt})
	if err == nil || !contains(err.Error(), "halt-me") {
		t.Fatalf("expected halt-me error, got %v", err)
	}
	buf, _ := NewFileBuffer(cfg.CacheDir)
	pending, _ := buf.Pending()
	ids := idsOf(pending)
	// chg-0001 acked; chg-0002 (failed) + chg-0003 (never reached) still pending.
	if fmt.Sprint(ids) != "[chg-0002 chg-0003]" {
		t.Fatalf("pending = %v", ids)
	}
}

// ── (d) crash test ─────────────────────────────────────────────────────────────

func TestCrashAfterOneThenReplayOnRestart(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 3, 1)}
	dc, _ := vectorDecryptChange(t)
	pump1 := newTestPump(t, cfg, src.fetch, dc)

	var run1 []string
	crashing := func(c Change) error {
		run1 = append(run1, c.ID)
		if len(run1) == 1 {
			return nil // #1 succeeds → acked
		}
		return errors.New("crash") // crash on #2 (with halt → stop, #2 stays pending)
	}
	err := pump1.ProcessChanges(crashing, PumpOptions{MaxRetries: 0, OnError: OnErrorHalt})
	if err == nil || !contains(err.Error(), "crash") {
		t.Fatalf("expected crash error, got %v", err)
	}
	if fmt.Sprint(run1) != "[chg-0001 chg-0002]" {
		t.Fatalf("run1 = %v", run1)
	}
	bufMid, _ := NewFileBuffer(cfg.CacheDir)
	pendMid, _ := bufMid.Pending()
	if fmt.Sprint(idsOf(pendMid)) != "[chg-0002 chg-0003]" {
		t.Fatalf("survivors = %v", idsOf(pendMid))
	}

	// Restart: a brand-new pump on the SAME cache_dir with an EMPTY source.
	empty := &fakeSource{}
	pump2 := newTestPump(t, cfg, empty.fetch, dc)
	var run2 []string
	if err := pump2.ProcessChanges(func(c Change) error { run2 = append(run2, c.ID); return nil }, PumpOptions{}); err != nil {
		t.Fatalf("ProcessChanges restart: %v", err)
	}
	if fmt.Sprint(run2) != "[chg-0002 chg-0003]" {
		t.Fatalf("replay = %v", run2)
	}
	bufEnd, _ := NewFileBuffer(cfg.CacheDir)
	if p, _ := bufEnd.Pending(); len(p) != 0 {
		t.Fatalf("buffer not drained after replay")
	}
}

func TestIdempotentChangeIDStableAcrossReplay(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 2, 1)}
	dc, _ := vectorDecryptChange(t)
	pump1 := newTestPump(t, cfg, src.fetch, dc)

	var run1 [][2]any
	crashNow := func(c Change) error {
		run1 = append(run1, [2]any{c.ID, c.Value})
		return errors.New("crash")
	}
	_ = pump1.ProcessChanges(crashNow, PumpOptions{MaxRetries: 0, OnError: OnErrorHalt})

	empty := &fakeSource{}
	pump2 := newTestPump(t, cfg, empty.fetch, dc)
	var run2 [][2]any
	_ = pump2.ProcessChanges(func(c Change) error { run2 = append(run2, [2]any{c.ID, c.Value}); return nil }, PumpOptions{})

	if run1[0][0] != "chg-0001" {
		t.Fatalf("run1 first id = %v", run1[0][0])
	}
	if run2[0][0] != "chg-0001" || run2[0][1] != run1[0][1] {
		t.Fatalf("replay id/value = %v, run1 = %v", run2[0], run1[0])
	}
}

// ── (e) ciphertext at rest ─────────────────────────────────────────────────────

func TestBufferFilesStoreCiphertextNotPlaintext(t *testing.T) {
	cfg := pumpConfig(t)
	wrapper := wrapperFor(t)
	src := &fakeSource{queue: makeEvents(wrapper, 2, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	// Crash immediately so the files stay on disk to inspect.
	_ = pump.ProcessChanges(func(c Change) error { return errors.New("stop") }, PumpOptions{MaxRetries: 0, OnError: OnErrorHalt})

	pendingPath := filepath.Join(cfg.CacheDir, "pending")
	entries, _ := os.ReadDir(pendingPath)
	plaintext := plaintextFor(t)
	found := false
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		found = true
		data, _ := os.ReadFile(filepath.Join(pendingPath, e.Name()))
		if contains(string(data), plaintext) {
			t.Fatalf("plaintext leaked to disk in %s", e.Name())
		}
		if !contains(string(data), `"_enc"`) || !contains(string(data), wrapper["k"].(string)) {
			t.Fatalf("stored value is not the ciphertext wrapper: %s", data)
		}
	}
	if !found {
		t.Fatal("expected pending files on disk")
	}
}

// ── (f) returns when drained ───────────────────────────────────────────────────

func TestProcessChangesReturnsWhenSourceDrained(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 5, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	var delivered []string
	if err := pump.ProcessChanges(func(c Change) error { delivered = append(delivered, c.ID); return nil }, PumpOptions{BatchSize: 2}); err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	if fmt.Sprint(delivered) != "[chg-0001 chg-0002 chg-0003 chg-0004 chg-0005]" {
		t.Fatalf("delivered = %v", delivered)
	}
	if len(src.queue) != 0 {
		t.Fatalf("source not fully drained")
	}
	if src.fetchCalls[len(src.fetchCalls)-1] != 2 {
		t.Fatalf("last fetch limit = %d", src.fetchCalls[len(src.fetchCalls)-1])
	}
}

func TestEmptySourceReturnsImmediately(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	var delivered []Change
	if err := pump.ProcessChanges(func(c Change) error { delivered = append(delivered, c); return nil }, PumpOptions{}); err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	if len(delivered) != 0 {
		t.Fatalf("delivered = %v", delivered)
	}
	if len(src.fetchCalls) != 1 || src.fetchCalls[0] != 100 {
		t.Fatalf("fetchCalls = %v", src.fetchCalls)
	}
}

func TestBatchSizeClampedTo500(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 1, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)
	if err := pump.ProcessChanges(func(c Change) error { return nil }, PumpOptions{BatchSize: 9999}); err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	maxLimit := 0
	for _, l := range src.fetchCalls {
		if l > maxLimit {
			maxLimit = l
		}
	}
	if maxLimit != 500 {
		t.Fatalf("max fetch limit = %d, want 500", maxLimit)
	}
}

// ── drain_batch primitive + dead-letter retry ─────────────────────────────────

func TestDrainBatchIsRawUnbuffered(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 3, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	batch, err := pump.DrainBatch(2)
	if err != nil {
		t.Fatalf("DrainBatch: %v", err)
	}
	if len(batch) != 2 || batch[0].ID != "chg-0001" || batch[1].ID != "chg-0002" {
		t.Fatalf("batch = %+v", batch)
	}
	buf, _ := NewFileBuffer(cfg.CacheDir)
	if p, _ := buf.Pending(); len(p) != 0 {
		t.Fatalf("DrainBatch must not buffer")
	}
}

func TestRetryDeadLettersRedrives(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 2, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	_ = pump.ProcessChanges(func(c Change) error {
		if c.ID == "chg-0002" {
			return errors.New("boom")
		}
		return nil
	}, PumpOptions{MaxRetries: 1})

	buf, _ := NewFileBuffer(cfg.CacheDir)
	if dls, _ := buf.DeadLetters(); len(dls) != 1 || dls[0].ID != "chg-0002" {
		t.Fatalf("dead-letters = %+v", dls)
	}

	var redriven []string
	n, err := pump.RetryDeadLetters(func(c Change) error { redriven = append(redriven, c.ID); return nil }, PumpOptions{})
	if err != nil {
		t.Fatalf("RetryDeadLetters: %v", err)
	}
	if n != 1 || fmt.Sprint(redriven) != "[chg-0002]" {
		t.Fatalf("redriven n=%d ids=%v", n, redriven)
	}
	buf2, _ := NewFileBuffer(cfg.CacheDir)
	if dls, _ := buf2.DeadLetters(); len(dls) != 0 {
		t.Fatalf("dead-letters not cleared: %+v", dls)
	}
}

func TestRetryDeadLettersStillFailingStaysDeadletteredNeverPending(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 2, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	fail2 := func(c Change) error {
		if c.ID == "chg-0002" {
			return errors.New("boom")
		}
		return nil
	}
	_ = pump.ProcessChanges(fail2, PumpOptions{MaxRetries: 1})

	buf, _ := NewFileBuffer(cfg.CacheDir)
	dl0, _ := buf.DeadLetters()
	if len(dl0) != 1 || dl0[0].Attempts != 2 { // 1 + max_retries
		t.Fatalf("dl0 = %+v", dl0)
	}
	pendingPath := filepath.Join(cfg.CacheDir, "pending")
	deadletterPath := filepath.Join(cfg.CacheDir, "deadletter")

	// Re-drive with a handler that STILL fails. OnError deadletter (default).
	n, err := pump.RetryDeadLetters(fail2, PumpOptions{MaxRetries: 2})
	if err != nil {
		t.Fatalf("RetryDeadLetters: %v", err)
	}
	if n != 0 {
		t.Fatalf("redriven = %d, want 0", n)
	}
	buf2, _ := NewFileBuffer(cfg.CacheDir)
	dl1, _ := buf2.DeadLetters()
	if len(dl1) != 1 || dl1[0].ID != "chg-0002" || dl1[0].Attempts != 3 { // 1 + 2 re-drive attempts
		t.Fatalf("dl1 = %+v", dl1)
	}
	if !contains(dl1[0].Error, "boom") {
		t.Fatalf("dl error = %q", dl1[0].Error)
	}
	// Never appeared in pending/ (no remove→append→dead_letter dance).
	if p, _ := buf2.Pending(); len(p) != 0 {
		t.Fatalf("pending should be empty")
	}
	if entries, _ := os.ReadDir(pendingPath); len(entries) != 0 {
		t.Fatalf("pending dir should have no files, got %d", len(entries))
	}
	// Exactly one record on disk in deadletter/.
	dlFiles := 0
	if entries, _ := os.ReadDir(deadletterPath); true {
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".json" {
				dlFiles++
			}
		}
	}
	if dlFiles != 1 {
		t.Fatalf("deadletter files = %d, want 1", dlFiles)
	}

	// A final successful re-drive removes it cleanly.
	var ok []string
	n2, _ := pump.RetryDeadLetters(func(c Change) error { ok = append(ok, c.ID); return nil }, PumpOptions{})
	if n2 != 1 || fmt.Sprint(ok) != "[chg-0002]" {
		t.Fatalf("final re-drive n=%d ok=%v", n2, ok)
	}
	buf3, _ := NewFileBuffer(cfg.CacheDir)
	if dls, _ := buf3.DeadLetters(); len(dls) != 0 {
		t.Fatalf("dead-letters not cleared")
	}
}

func TestRetryDeadLettersAttemptsMonotonicAcrossRuns(t *testing.T) {
	cfg := pumpConfig(t)
	src := &fakeSource{queue: makeEvents(wrapperFor(t), 2, 1)}
	dc, _ := vectorDecryptChange(t)
	pump := newTestPump(t, cfg, src.fetch, dc)

	fail2 := func(c Change) error {
		if c.ID == "chg-0002" {
			return errors.New("boom")
		}
		return nil
	}
	_ = pump.ProcessChanges(fail2, PumpOptions{MaxRetries: 3})
	buf, _ := NewFileBuffer(cfg.CacheDir)
	dl0, _ := buf.DeadLetters()
	if dl0[0].Attempts != 4 { // 1 + 3
		t.Fatalf("dl0 attempts = %d", dl0[0].Attempts)
	}
	// Re-drive with a SMALLER budget (run-local attempts = 1). Must stay clamped at 4.
	if n, _ := pump.RetryDeadLetters(fail2, PumpOptions{MaxRetries: 0}); n != 0 {
		t.Fatalf("redriven = %d", n)
	}
	buf2, _ := NewFileBuffer(cfg.CacheDir)
	dl1, _ := buf2.DeadLetters()
	if dl1[0].Attempts != 4 {
		t.Fatalf("attempts not monotonic: %d (want 4)", dl1[0].Attempts)
	}
}

// ── caveat 1: poison-decrypt must not wedge the stream ──────────────────────────

func TestPoisonDecryptDeadLettersWithoutWedging(t *testing.T) {
	cfg := pumpConfig(t)
	v := loadVector(t)
	priv, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)

	decryptCalls := 0
	dc := func(event map[string]any) (Change, error) {
		if event["id"] == "chg-0002" {
			decryptCalls++
			return Change{}, &DecryptError{msg: "corrupt ciphertext for chg-0002"}
		}
		return changeFromAPI(event, func(string) string { return "text" }, func(w any) (string, error) { return Decrypt(w, priv) }, nil)
	}
	events := makeEvents(v.Text.Wrapper, 1, 1)
	events = append(events, makePoisonEvent("chg-0002"))
	events = append(events, makeEvents(v.Text.Wrapper, 1, 3)...)
	src := &fakeSource{queue: events}
	pump := newTestPump(t, cfg, src.fetch, dc)

	var delivered []string
	if err := pump.ProcessChanges(func(c Change) error { delivered = append(delivered, c.ID); return nil }, PumpOptions{MaxRetries: 3}); err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	if fmt.Sprint(delivered) != "[chg-0001 chg-0003]" {
		t.Fatalf("delivered = %v", delivered)
	}
	if decryptCalls != 1 { // dead-lettered immediately, no retries burned
		t.Fatalf("decryptCalls = %d, want 1", decryptCalls)
	}
	buf, _ := NewFileBuffer(cfg.CacheDir)
	if p, _ := buf.Pending(); len(p) != 0 {
		t.Fatalf("nothing should be wedged in pending")
	}
	dls, _ := buf.DeadLetters()
	if len(dls) != 1 || dls[0].ID != "chg-0002" || dls[0].Attempts != 1 {
		t.Fatalf("dead-letters = %+v", dls)
	}
	if !contains(dls[0].Error, "DecryptError") {
		t.Fatalf("dl error = %q", dls[0].Error)
	}

	// A fresh pump on the SAME cache_dir, empty source: must NOT re-deliver the poison.
	empty := &fakeSource{}
	pump2 := newTestPump(t, cfg, empty.fetch, dc)
	var delivered2 []string
	if err := pump2.ProcessChanges(func(c Change) error { delivered2 = append(delivered2, c.ID); return nil }, PumpOptions{}); err != nil {
		t.Fatalf("ProcessChanges restart: %v", err)
	}
	if len(delivered2) != 0 {
		t.Fatalf("poison should not be replayed, got %v", delivered2)
	}
}

func TestPoisonDecryptWithHaltReraises(t *testing.T) {
	cfg := pumpConfig(t)
	v := loadVector(t)
	priv, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	dc := func(event map[string]any) (Change, error) {
		if event["id"] == "chg-0001" {
			return Change{}, &DecryptError{msg: "undecryptable"}
		}
		return changeFromAPI(event, func(string) string { return "text" }, func(w any) (string, error) { return Decrypt(w, priv) }, nil)
	}
	src := &fakeSource{queue: []map[string]any{makePoisonEvent("chg-0001")}}
	pump := newTestPump(t, cfg, src.fetch, dc)
	err := pump.ProcessChanges(func(c Change) error { return nil }, PumpOptions{OnError: OnErrorHalt})
	if err == nil || !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt on halt, got %v", err)
	}
	buf, _ := NewFileBuffer(cfg.CacheDir)
	pending, _ := buf.Pending()
	if fmt.Sprint(idsOf(pending)) != "[chg-0001]" {
		t.Fatalf("poison should stay pending for inspection, got %v", idsOf(pending))
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func idsOf(events []map[string]any) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, eventID(e))
	}
	return out
}

func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }
