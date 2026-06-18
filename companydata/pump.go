package companydata

import (
	"errors"
	"log"
	"time"
)

// Crash-safe streaming changes pump.
//
// The changes feed is a server-side drain-on-fetch queue: a fetch returns up to
// N events (default 100, max 500) and deletes those rows in the same
// transaction — the API keeps no copy. So consumption cannot be a plain list: a
// consumer crash mid-batch would lose events the API already deleted, and a huge
// backlog must not materialize in memory. The pump solves both:
//
//	ProcessChanges(handler) — one Change at a time, until the feed is empty, then
//	                          RETURNS. No follow/daemon mode (you schedule re-runs).
//
// Per cycle:
//  1. Replay first — deliver any un-acked events already in the local buffer
//     (from a previous crashed run), oldest-first.
//  2. Drain — when the buffer is empty, fetch ONE batch (≤ BatchSize, ≤500) and
//     persist it to the durable buffer (fsync) BEFORE handing anything out.
//  3. Deliver one-by-one — for each buffered event oldest-first: decrypt its
//     value (at delivery — never on disk), build the typed Change, call the handler.
//  4. Ack / retry / dead-letter — on success remove the event from the buffer; on
//     error retry with backoff up to MaxRetries, then (OnError "deadletter") move
//     it to the dead-letter store and continue, or (OnError "halt") stop and return.
//  5. Repeat until a drain returns empty AND the buffer is drained → return.
//
// Crash safety + at-least-once + idempotency: a batch is durably buffered before
// any delivery, and acked per-item only after the handler succeeds. A crash
// between a handler's success and its ack re-delivers that event on restart, so
// the handler MUST be idempotent — every Change carries a stable ID (captured
// before the server delete) for dedup.
//
// Injection (so tests + the real Client share one pump): the pump takes a
// fetchChanges(limit) -> []event source (the raw drain-on-fetch call, returning
// ciphertext event maps) and a decryptChange(event) -> Change callable (closes
// over the loaded service private key — config-only key handling). No
// key/secret is ever a method argument.

const (
	// maxBatch caps a fetch at 500. The pump clamps any
	// requested batch size to this.
	maxBatch     = 500
	defaultBatch = 100

	defaultPumpMaxRetries = 3
	defaultPumpBackoff    = 500 * time.Millisecond
	maxPumpBackoff        = 30 * time.Second
)

// OnError selects the pump's behavior when an event exhausts its retries.
type OnError string

const (
	// OnErrorDeadLetter moves the poison event to the dead-letter store and
	// continues (one poison event never wedges the stream). The default.
	OnErrorDeadLetter OnError = "deadletter"
	// OnErrorHalt stops the pump and returns the error (the event stays pending).
	OnErrorHalt OnError = "halt"
)

// fetchChangesFn is the pump's drain source: given a limit, drain-and-return up
// to that many raw event maps.
type fetchChangesFn func(limit int) ([]map[string]any, error)

// decryptChangeFn turns a raw event map into a typed Change (value decrypted at
// delivery).
type decryptChangeFn func(event map[string]any) (Change, error)

// Handler is the consumer handler: it does the side-effect; success acks, a
// non-nil error retries.
type Handler func(Change) error

// PumpOptions configure ProcessChanges / RetryDeadLetters.
type PumpOptions struct {
	// BatchSize is the per-drain fetch size, clamped to [1, 500] (default 100).
	BatchSize int
	// MaxRetries is the retry budget for a failing handler (default 3).
	MaxRetries int
	// OnError is deadletter (default) or halt.
	OnError OnError
	// Backoff maps a 1-based attempt to a sleep duration (default exponential,
	// capped at 30s).
	Backoff func(attempt int) time.Duration
}

func (o PumpOptions) withDefaults() PumpOptions {
	if o.BatchSize == 0 {
		o.BatchSize = defaultBatch
	}
	o.BatchSize = clampBatch(o.BatchSize)
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	if o.OnError == "" {
		o.OnError = OnErrorDeadLetter
	}
	if o.Backoff == nil {
		o.Backoff = defaultPumpBackoffFn
	}
	return o
}

// Pump is the crash-safe changes pump. It wires a durable
// FileBuffer (under Config.CacheDir) to an injected drain source + decrypt
// callable.
type Pump struct {
	fetchChanges fetchChangesFn
	decrypt      decryptChangeFn
	logger       *log.Logger
	sleep        func(time.Duration)
	buffer       *FileBuffer
}

// pumpOption configures a Pump (test injection of logger/sleep).
type pumpOption func(*Pump)

func withPumpLogger(l *log.Logger) pumpOption { return func(p *Pump) { p.logger = l } }
func withPumpSleep(s func(time.Duration)) pumpOption {
	return func(p *Pump) { p.sleep = s }
}

// NewPump builds a Pump with a durable FileBuffer under config.CacheDir. The
// buffer recovers whatever is already on disk — that recovery IS the
// replay-on-restart in step 1.
func NewPump(config *Config, fetch fetchChangesFn, decrypt decryptChangeFn, opts ...pumpOption) (*Pump, error) {
	buf, err := NewFileBuffer(config.CacheDir)
	if err != nil {
		return nil, err
	}
	p := &Pump{
		fetchChanges: fetch,
		decrypt:      decrypt,
		logger:       log.Default(),
		sleep:        time.Sleep,
		buffer:       buf,
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Buffer returns the pump's durable buffer (for inspection / tests).
func (p *Pump) Buffer() *FileBuffer { return p.buffer }

// ── the pump ──────────────────────────────────────────────────────────────

// ProcessChanges streams events through handler until the feed is empty, then
// returns. handler is called with one typed Change at a time and must be
// idempotent (at-least-once delivery; dedup on Change.ID).
//
// With OnError == OnErrorHalt, a failing event (after retries) or a poison
// decrypt stops the pump and returns the underlying error (the event stays
// pending for inspection). With OnError == OnErrorDeadLetter (default), such an
// event is dead-lettered and the stream continues.
func (p *Pump) ProcessChanges(handler Handler, opts PumpOptions) error {
	opts = opts.withDefaults()

	for {
		// 1. Replay anything already buffered (a previous crashed run), then
		//    deliver it. If the buffer is empty, drain ONE batch first.
		pending, err := p.buffer.Pending()
		if err != nil {
			return err
		}
		if len(pending) > 0 {
			p.logf("pump replay: %d buffered event(s)", len(pending))
		} else {
			drained, err := p.drainIntoBuffer(opts.BatchSize)
			if err != nil {
				return err
			}
			if drained == 0 {
				// A drain returned empty AND the buffer is drained → done.
				return nil
			}
			pending, err = p.buffer.Pending()
			if err != nil {
				return err
			}
		}

		// 3+4. Deliver each buffered event oldest-first; ack/retry/dead-letter.
		for _, event := range pending {
			if err := p.deliverOne(event, handler, opts); err != nil {
				// OnErrorHalt surfaced an error → stop the pump.
				return err
			}
		}
		// Loop: re-check the buffer (now drained) and try another drain.
	}
}

// drainIntoBuffer fetches one batch and PERSISTS it to the buffer before any
// delivery. Returns the number of events drained (0 means the feed is empty).
func (p *Pump) drainIntoBuffer(size int) (int, error) {
	batch, err := p.fetchChanges(size)
	if err != nil {
		return 0, err
	}
	p.logf("pump drain: fetched %d event(s) (limit=%d)", len(batch), size)
	if len(batch) == 0 {
		return 0, nil
	}
	// Persist-before-deliver: the durable backup the API no longer has.
	if _, err := p.buffer.Append(batch); err != nil {
		return 0, err
	}
	return len(batch), nil
}

// deliverOne decrypts at delivery, calls the handler, then acks / retries /
// dead-letters.
//
// Durability note: the decrypt happens INSIDE the delivery
// attempt (not before the loop) so a DecryptError on a persisted poison event
// (corrupt/truncated ciphertext, rotated key) is handled like a failure instead
// of propagating out of ProcessChanges and wedging the stream on replay.
// Re-decrypting can't fix such an event, so a DecryptError is dead-lettered
// IMMEDIATELY — it does not burn MaxRetries (with OnErrorHalt it returns the
// error, as a handler error would).
//
// A returned non-nil error means OnErrorHalt and the event was left pending.
func (p *Pump) deliverOne(event map[string]any, handler Handler, opts PumpOptions) error {
	changeID := eventID(event)
	attempts := 0

	for {
		attempts++
		change, derr := p.decrypt(event)
		if derr != nil {
			// A poison event: re-decrypting won't help, so don't burn retries.
			if errors.Is(derr, ErrDecrypt) {
				if opts.OnError == OnErrorHalt {
					p.logf("pump halt: id=%s undecryptable (%v)", changeID, derr)
					return derr
				}
				if _, err := p.buffer.DeadLetterEvent(changeID, "DecryptError: "+derr.Error(), attempts); err != nil {
					return err
				}
				p.logf("pump dead-letter (undecryptable): id=%s: %v", changeID, derr)
				return nil
			}
			// A non-decrypt error from the decrypt closure is treated like a
			// handler error (retry path below) — rare, but contained.
		}

		var herr error
		if derr == nil {
			herr = handler(change)
		} else {
			herr = derr
		}

		if herr == nil {
			// Success → per-item ack (remove from the buffer).
			if _, err := p.buffer.Ack(changeID); err != nil {
				return err
			}
			p.logf("pump ack: id=%s", changeID)
			return nil
		}

		// Handler (or non-decrypt) error → retry or dead-letter.
		if attempts <= opts.MaxRetries {
			delay := opts.Backoff(attempts)
			if delay < 0 {
				delay = 0
			}
			p.logf("pump retry: id=%s attempt=%d failed (%v); backoff %v", changeID, attempts, herr, delay)
			if delay > 0 {
				p.sleep(delay)
			}
			continue
		}
		// Retries exhausted.
		if opts.OnError == OnErrorHalt {
			p.logf("pump halt: id=%s failed after %d attempt(s)", changeID, attempts)
			return herr
		}
		if _, err := p.buffer.DeadLetterEvent(changeID, herr.Error(), attempts); err != nil {
			return err
		}
		p.logf("pump dead-letter: id=%s after %d attempt(s): %v", changeID, attempts, herr)
		return nil
	}
}

// ── advanced primitive ──────────────────────────────────────────────────────

// DrainBatch is a raw, UNBUFFERED drain → typed Changes (advanced).
//
// Fetches one batch (clamped ≤500) and returns the decrypted Changes directly —
// it does NOT persist anything to the buffer, so YOU own durability if you use
// it. Prefer ProcessChanges for safe consumption.
func (p *Pump) DrainBatch(max int) ([]Change, error) {
	size := clampBatch(max)
	batch, err := p.fetchChanges(size)
	if err != nil {
		return nil, err
	}
	p.logf("drain_batch: fetched %d event(s) (limit=%d)", len(batch), size)
	out := make([]Change, 0, len(batch))
	for _, event := range batch {
		c, err := p.decrypt(event)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// ── dead-letter inspect / re-drive ──────────────────────────────────────────

// DeadLetters returns the local dead-letter store (ciphertext + error + attempt
// count).
func (p *Pump) DeadLetters() ([]DeadLetter, error) {
	return p.buffer.DeadLetters()
}

// RetryDeadLetters re-drives every dead-lettered event through handler. On
// success the dead-letter record is removed; on repeated failure it is
// re-dead-lettered IN PLACE (OnErrorDeadLetter) or the error is returned
// (OnErrorHalt). They are never re-fetched from the API (it already deleted them)
// — the local store is their only home. Returns the count successfully re-driven.
//
// Durability note: a still-failing re-drive updates the record IN PLACE
// (UpdateDeadLetter) and NEVER routes it back through pending/, so there is no
// crash window that could resurrect a dead-letter as a live pending event. The
// stored attempt count is clamped monotonic in UpdateDeadLetter.
func (p *Pump) RetryDeadLetters(handler Handler, opts PumpOptions) (int, error) {
	opts = opts.withDefaults()

	records, err := p.buffer.DeadLetters()
	if err != nil {
		return 0, err
	}
	redriven := 0
	for _, rec := range records {
		changeID := rec.ID
		event := rec.Event // already has _deadletter stripped
		attempts := 0
		for {
			attempts++
			change, derr := p.decrypt(event)
			if derr != nil {
				if errors.Is(derr, ErrDecrypt) {
					if opts.OnError == OnErrorHalt {
						p.logf("retry_dead_letters halt: id=%s undecryptable (%v)", changeID, derr)
						return redriven, derr
					}
					if _, uerr := p.buffer.UpdateDeadLetter(changeID, "DecryptError: "+derr.Error(), attempts); uerr != nil {
						return redriven, uerr
					}
					p.logf("retry_dead_letters: id=%s still undecryptable (%v)", changeID, derr)
					break
				}
			}

			var herr error
			if derr == nil {
				herr = handler(change)
			} else {
				herr = derr
			}

			if herr == nil {
				if _, err := p.buffer.RemoveDeadLetter(changeID); err != nil {
					return redriven, err
				}
				p.logf("retry_dead_letters: id=%s re-driven OK", changeID)
				redriven++
				break
			}

			if attempts <= opts.MaxRetries {
				delay := opts.Backoff(attempts)
				if delay > 0 {
					p.sleep(delay)
				}
				continue
			}
			if opts.OnError == OnErrorHalt {
				p.logf("retry_dead_letters halt: id=%s failed again", changeID)
				return redriven, herr
			}
			// Refresh the stored attempt count + error IN PLACE — never re-enters pending/.
			if _, uerr := p.buffer.UpdateDeadLetter(changeID, herr.Error(), attempts); uerr != nil {
				return redriven, uerr
			}
			p.logf("retry_dead_letters: id=%s still failing (%v)", changeID, herr)
			break
		}
	}
	return redriven, nil
}

// logf logs through the pump's logger (nil-safe).
func (p *Pump) logf(format string, a ...any) {
	if p.logger != nil {
		p.logger.Printf(format, a...)
	}
}

// clampBatch clamps a requested batch size into [1, maxBatch].
func clampBatch(value int) int {
	if value < 1 {
		return 1
	}
	if value > maxBatch {
		return maxBatch
	}
	return value
}

// defaultPumpBackoffFn is exponential backoff (capped) for the attempt-th retry.
func defaultPumpBackoffFn(attempt int) time.Duration {
	d := defaultPumpBackoff * (1 << (attempt - 1))
	if d > maxPumpBackoff {
		d = maxPumpBackoff
	}
	return d
}
