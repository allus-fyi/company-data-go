package companydata

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Durable plain-file buffer for the crash-safe changes pump.
//
// The changes feed is a server-side drain-on-fetch queue: a fetch returns up to
// N events and deletes those rows in the same transaction — the API keeps no
// copy. So a drained batch MUST be persisted locally BEFORE any delivery, or a
// consumer crash mid-batch loses events the API already deleted. This file is
// that persistence: a zero-dependency, plain-file buffer under CacheDir.
//
// Layout:
//
//	<cache_dir>/pending/<seq>_<change_id>.json     # one un-acked event, oldest-first
//	<cache_dir>/deadletter/<seq>_<change_id>.json  # events that exhausted retries
//
//   - The stored event is the raw hardened API event — its value / value_url is
//     CIPHERTEXT, never the decrypted plaintext. No PII is ever written to disk.
//   - <seq> is a zero-padded, monotonically increasing sequence number persisted
//     in <cache_dir>/.seq. Because Append is called in drain order
//     (oldest-first), sorting filenames lexicographically yields oldest-first.
//   - Writes are crash-safe: each file is written to a temp name, fsync'd,
//     atomically renamed into place, and the containing directory is fsync'd.
//   - Ack deletes the pending file; DeadLetter moves it to deadletter/ with the
//     error + attempt count appended. Neither re-fetches from the API (it already
//     deleted the row) — the buffer is the only home.

const (
	pendingDir    = "pending"
	deadletterDir = "deadletter"
	seqFile       = ".seq"
	// seqWidth keeps filenames sorting lexicographically up to ~10^16 appends.
	seqWidth = 16
	// deadletterMetaKey is the reserved field under which the failure context is
	// stored on a dead-lettered event.
	deadletterMetaKey = "_deadletter"
)

// deadletterMeta is the failure context appended to a dead-lettered event.
type deadletterMeta struct {
	Error    string `json:"error"`
	Attempts int    `json:"attempts"`
}

// DeadLetter is a flattened view of a dead-lettered event for inspection
// (DeadLetters / RetryDeadLetters): the stored ciphertext Event plus the
// lifted-out Error and Attempts, and the event's own Id.
type DeadLetter struct {
	ID       string         // the change id
	Event    map[string]any // the stored (ciphertext) event, with _deadletter stripped
	Error    string
	Attempts int
}

// FileBuffer is a durable, ordered, ciphertext-at-rest event buffer under
// CacheDir. Re-instantiating a FileBuffer on the same CacheDir recovers whatever
// is on disk — that recovery is exactly the pump's replay-on-restart.
type FileBuffer struct {
	dir           string
	pendingPath   string
	deadletterPth string
	seqPath       string
	mu            sync.Mutex // guards the seq counter against concurrent appends
}

// NewFileBuffer creates (or recovers) a FileBuffer rooted at cacheDir.
func NewFileBuffer(cacheDir string) (*FileBuffer, error) {
	b := &FileBuffer{
		dir:           cacheDir,
		pendingPath:   filepath.Join(cacheDir, pendingDir),
		deadletterPth: filepath.Join(cacheDir, deadletterDir),
		seqPath:       filepath.Join(cacheDir, seqFile),
	}
	if err := os.MkdirAll(b.pendingPath, 0o755); err != nil {
		return nil, fmt.Errorf("could not create pending dir: %w", err)
	}
	if err := os.MkdirAll(b.deadletterPth, 0o755); err != nil {
		return nil, fmt.Errorf("could not create deadletter dir: %w", err)
	}
	return b, nil
}

// ── sequence ────────────────────────────────────────────────────────────────

// nextSeq returns a monotonic sequence, recovered from disk so it survives a
// restart. On a fresh process it seeds from the highest seq already present in
// either directory, so replayed-then-newly-appended events keep ordering.
func (b *FileBuffer) nextSeq() (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, ok := b.readSeq()
	if !ok {
		cur = b.maxOnDiskSeq()
	}
	next := cur + 1
	if err := atomicWriteInt(b.seqPath, next); err != nil {
		return 0, err
	}
	return next, nil
}

func (b *FileBuffer) readSeq() (int, bool) {
	data, err := os.ReadFile(b.seqPath)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return v, true
}

func (b *FileBuffer) maxOnDiskSeq() int {
	best := 0
	for _, d := range []string{b.pendingPath, b.deadletterPth} {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if seq, ok := seqOf(e.Name()); ok && seq > best {
				best = seq
			}
		}
	}
	return best
}

// ── append / pending / ack ───────────────────────────────────────────────────

// Append persists a drained batch (oldest-first), each in its own fsync'd file.
// Each event is stored verbatim (ciphertext value intact). Returns the list of
// pending filenames written. This is the backup the API no longer holds — it
// MUST complete before the pump delivers anything.
func (b *FileBuffer) Append(events []map[string]any) ([]string, error) {
	written := make([]string, 0, len(events))
	for _, event := range events {
		seq, err := b.nextSeq()
		if err != nil {
			return written, err
		}
		name := fmt.Sprintf("%0*d_%s.json", seqWidth, seq, sanitizeID(eventID(event)))
		path := filepath.Join(b.pendingPath, name)
		if err := atomicWriteJSON(path, event); err != nil {
			return written, err
		}
		written = append(written, name)
	}
	return written, nil
}

// Pending returns all un-acked events, oldest-first (by the sortable filename).
func (b *FileBuffer) Pending() ([]map[string]any, error) {
	names, err := b.pendingFiles()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		event, err := readEvent(b.pendingPath, n)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, nil
}

func (b *FileBuffer) pendingFiles() ([]string, error) {
	return listJSON(b.pendingPath)
}

func (b *FileBuffer) findPendingFile(changeID string) (string, error) {
	target := sanitizeID(changeID)
	names, err := b.pendingFiles()
	if err != nil {
		return "", err
	}
	for _, name := range names {
		if idPart(name) == target+".json" {
			return name, nil
		}
	}
	return "", nil
}

// Ack deletes the pending file for changeID (the per-item ack). Idempotent —
// returns false if there was nothing to ack.
func (b *FileBuffer) Ack(changeID string) (bool, error) {
	name, err := b.findPendingFile(changeID)
	if err != nil {
		return false, err
	}
	if name == "" {
		return false, nil
	}
	if err := os.Remove(filepath.Join(b.pendingPath, name)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	fsyncDir(b.pendingPath)
	return true, nil
}

// ── dead-letter ───────────────────────────────────────────────────────────────

// DeadLetterEvent moves a poison event from pending → deadletter with the error
// + attempts. The event keeps its ciphertext value; the failure context is
// stored under the reserved _deadletter key so it is never silently dropped.
//
// At-least-once safety: the new dead-letter copy is written BEFORE the pending
// copy is unlinked, so a crash between them leaves
// the event in both dirs → harmless re-delivery on replay (the id-dedup handler
// absorbs it). Do NOT "fix" this by deleting first.
func (b *FileBuffer) DeadLetterEvent(changeID, errMsg string, attempts int) (bool, error) {
	name, err := b.findPendingFile(changeID)
	if err != nil {
		return false, err
	}
	if name == "" {
		return false, nil
	}
	event, err := readEvent(b.pendingPath, name)
	if err != nil {
		return false, err
	}
	event[deadletterMetaKey] = deadletterMeta{Error: errMsg, Attempts: attempts}
	dest := filepath.Join(b.deadletterPth, name)
	if err := atomicWriteJSON(dest, event); err != nil { // write the new copy FIRST
		return false, err
	}
	if err := os.Remove(filepath.Join(b.pendingPath, name)); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	fsyncDir(b.pendingPath)
	return true, nil
}

func (b *FileBuffer) deadletterFiles() ([]string, error) {
	return listJSON(b.deadletterPth)
}

// DeadLetters returns all dead-lettered events, oldest-first. Each item carries
// the stored (ciphertext) event with the error + attempts lifted out of the
// reserved _deadletter block, plus the event's own id for convenience.
func (b *FileBuffer) DeadLetters() ([]DeadLetter, error) {
	names, err := b.deadletterFiles()
	if err != nil {
		return nil, err
	}
	out := make([]DeadLetter, 0, len(names))
	for _, name := range names {
		event, err := readEvent(b.deadletterPth, name)
		if err != nil {
			return nil, err
		}
		errMsg, attempts := readDeadletterMeta(event)
		clean := make(map[string]any, len(event))
		for k, v := range event {
			if k == deadletterMetaKey {
				continue
			}
			clean[k] = v
		}
		out = append(out, DeadLetter{
			ID:       eventID(event),
			Event:    clean,
			Error:    errMsg,
			Attempts: attempts,
		})
	}
	return out, nil
}

func (b *FileBuffer) findDeadletterFile(changeID string) (string, error) {
	target := sanitizeID(changeID)
	names, err := b.deadletterFiles()
	if err != nil {
		return "", err
	}
	for _, name := range names {
		if idPart(name) == target+".json" {
			return name, nil
		}
	}
	return "", nil
}

// UpdateDeadLetter rewrites a dead-letter record IN PLACE with a refreshed error
// + attempts. Used by a still-failing re-drive (RetryDeadLetters): the record
// stays in deadletter/ and its failure context is updated atomically (temp file
// inside deadletter/ → fsync → rename over the same path). It is NEVER routed
// back through pending/, so a crash anywhere in this method leaves the record
// either as the old dead-letter or the new one — it can never resurrect as a
// live pending event. Idempotent (returns false if the record is gone).
// Preserves the file's seq prefix so its oldest-first ordering is unchanged.
//
// The stored attempt count is monotonic across separate re-drive runs: clamp to
// max(existing, new) so a later run with a smaller maxRetries never lowers the
// recorded total.
func (b *FileBuffer) UpdateDeadLetter(changeID, errMsg string, attempts int) (bool, error) {
	name, err := b.findDeadletterFile(changeID)
	if err != nil {
		return false, err
	}
	if name == "" {
		return false, nil
	}
	path := filepath.Join(b.deadletterPth, name)
	event, err := readEvent(b.deadletterPth, name)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	_, priorAttempts := readDeadletterMeta(event)
	clean := make(map[string]any, len(event))
	for k, v := range event {
		if k == deadletterMetaKey {
			continue
		}
		clean[k] = v
	}
	clean[deadletterMetaKey] = deadletterMeta{Error: errMsg, Attempts: maxInt(priorAttempts, attempts)}
	if err := atomicWriteJSON(path, clean); err != nil { // temp+fsync+rename, within deadletter/
		return false, err
	}
	return true, nil
}

// RemoveDeadLetter deletes a dead-letter record (after a successful re-drive).
// Idempotent.
func (b *FileBuffer) RemoveDeadLetter(changeID string) (bool, error) {
	name, err := b.findDeadletterFile(changeID)
	if err != nil {
		return false, err
	}
	if name == "" {
		return false, nil
	}
	if err := os.Remove(filepath.Join(b.deadletterPth, name)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	fsyncDir(b.deadletterPth)
	return true, nil
}

// ── module helpers ─────────────────────────────────────────────────────────

// eventID extracts the "id" field of an event as a string ("" if absent).
func eventID(event map[string]any) string {
	if v, ok := event["id"]; ok && v != nil {
		switch s := v.(type) {
		case string:
			return s
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// readDeadletterMeta pulls error + attempts out of the reserved _deadletter
// block, tolerating both the struct form (in-process) and the JSON-decoded map
// form (read back from disk).
func readDeadletterMeta(event map[string]any) (string, int) {
	raw, ok := event[deadletterMetaKey]
	if !ok || raw == nil {
		return "", 0
	}
	switch m := raw.(type) {
	case deadletterMeta:
		return m.Error, m.Attempts
	case map[string]any:
		errMsg, _ := m["error"].(string)
		attempts := 0
		switch a := m["attempts"].(type) {
		case float64:
			attempts = int(a)
		case int:
			attempts = a
		case json.Number:
			if n, err := a.Int64(); err == nil {
				attempts = int(n)
			}
		}
		return errMsg, attempts
	}
	return "", 0
}

// sanitizeID makes a change id safe for a filename (the seq prefix guarantees
// order). Mirrors the Python reference.
func sanitizeID(changeID string) string {
	if changeID == "" {
		return "noid"
	}
	var b strings.Builder
	for _, r := range changeID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "noid"
	}
	return b.String()
}

// seqOf extracts the leading sequence number from a buffer filename.
func seqOf(name string) (int, bool) {
	idx := strings.Index(name, "_")
	if idx < 0 {
		return 0, false
	}
	v, err := strconv.Atoi(name[:idx])
	if err != nil {
		return 0, false
	}
	return v, true
}

// idPart returns the "<id>.json" portion after the seq prefix.
func idPart(name string) string {
	idx := strings.Index(name, "_")
	if idx < 0 {
		return name
	}
	return name[idx+1:]
}

// listJSON returns the sorted .json files in dir (skipping temp files).
func listJSON(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".json") && !strings.HasPrefix(n, ".tmp_") {
			names = append(names, n)
		}
	}
	sort.Strings(names) // zero-padded seq prefix → lexicographic == oldest-first
	return names, nil
}

// readEvent reads + JSON-decodes one stored event. json.Number is used so
// integer fields (e.g. attempts) round-trip without float coercion surprises.
func readEvent(dir, name string) (map[string]any, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	var event map[string]any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&event); err != nil {
		return nil, err
	}
	return event, nil
}

// atomicWriteJSON writes obj as JSON to path crash-safely (temp + fsync +
// rename + dir fsync).
func atomicWriteJSON(path string, obj any) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp_*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	fsyncDir(dir)
	return nil
}

// atomicWriteInt writes a single integer crash-safely.
func atomicWriteInt(path string, value int) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".tmp_seq_")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(strconv.Itoa(value)); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	fsyncDir(dir)
	return nil
}

// fsyncDir fsyncs a directory so a create/rename within it is durably recorded.
// Best-effort: a platform without dir fds (some Windows) is silently tolerated.
func fsyncDir(path string) {
	d, err := os.Open(path)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
