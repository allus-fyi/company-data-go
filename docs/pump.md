# The changes pump

Crash-safe streaming consumption of the changes feed.

## Why a pump

`GET /api/company-data/changes?limit=N` is a **drain-on-fetch queue**: it returns
up to N events **and deletes exactly those rows in the same transaction** — no
offset/cursor/page. The API keeps no copy after a fetch. So consumption cannot be
a plain list: a consumer crash mid-batch would lose events the API already
deleted, and a 1M backlog must not materialize in memory. The pump solves both.

## ProcessChanges

```go
err := client.ProcessChanges(handler, companydata.PumpOptions{})
```

`handler` is `func(companydata.Change) error`. It is called with **one `Change`
at a time**; returning `nil` acks (the event is removed from the durable buffer),
returning an error retries. The pump runs **until the feed is empty, then
returns** — there is **no follow/daemon mode**; you schedule re-runs (a ticker,
cron, a worker — whatever fits).

### Per cycle

1. **Replay first** — deliver any un-acked events already in the local buffer
   (from a previous crashed run), oldest-first.
2. **Drain** — when the buffer is empty, fetch one batch (≤ `BatchSize`, ≤500)
   and persist it to the durable buffer (fsync) **before** handing anything out.
3. **Deliver one-by-one** — decrypt each event at delivery (never on disk), call
   the handler.
4. **Ack / retry / dead-letter** — on `nil` remove the event; on error retry with
   backoff up to `MaxRetries`, then dead-letter (default) and continue, or
   (`OnErrorHalt`) stop and return the error.
5. Repeat until a drain returns empty and the buffer is drained → return.

## Options

```go
type PumpOptions struct {
    BatchSize  int                              // ≤500, default 100
    MaxRetries int                              // default 3
    OnError    OnError                          // OnErrorDeadLetter (default) | OnErrorHalt
    Backoff    func(attempt int) time.Duration  // default exponential, capped at 30s
}
```

## Guarantees

- **Crash-safe.** A batch is durably buffered (temp file + fsync + atomic rename
  + dir fsync) before any delivery, and acked per-item only after the handler
  succeeds. A crash mid-batch replays the un-acked events on the next run.
  Nothing the API deleted is lost.
- **Bounded memory.** Only one ≤500-event batch is in flight at a time.
- **At-least-once + idempotent.** The ack can't be atomic with your side-effects,
  so **your handler must be idempotent** — dedupe on `Change.ID` (a stable id
  captured before the server delete).
- **Ciphertext at rest.** The buffer stores the ciphertext event; values are
  decrypted only at delivery. No plaintext PII is written to disk.

## Durability caveats (preserved from the Python reference)

These are subtle invariants every port replicates:

1. **Decrypt inside the delivery attempt.** A persisted event can be
   undecryptable (corrupt/truncated/rotated key). Decryption happens inside the
   try, so a `*DecryptError` is contained and the event is **dead-lettered
   immediately** (re-decrypt can't help → it does NOT burn the retry budget); it
   never propagates out and wedges replay. (`OnErrorHalt` returns it, like a
   handler error.)
2. **A re-failing dead-letter is updated in place** (atomic temp+fsync+rename
   within the dead-letter dir), never routed back through the pending dir — so no
   crash window can resurrect a dead-letter as a live pending event.
3. **Stored attempt count is monotonic** across separate retry runs:
   `max(existing, new)` — a later run with a smaller `MaxRetries` never lowers the
   recorded total.
4. **At-least-once on dead-letter.** The new dead-letter copy is written **before**
   the pending copy is unlinked, so a crash between them leaves the event in both
   dirs → harmless re-delivery on replay (the id-dedup handler absorbs it).

## Dead-letter

Events that exhaust `MaxRetries`, or that can never decrypt, land in a
dead-letter store under `cache_dir` (ciphertext + the error + attempt count).
They are **never silently dropped**, and never re-fetched from the API (the local
store is their only home).

```go
dls, _ := client.DeadLetters()                  // []DeadLetter — id, Event, Error, Attempts
n, _ := client.RetryDeadLetters(handler, companydata.PumpOptions{}) // re-drive; n = how many succeeded
```

## Advanced primitive

```go
batch, err := client.DrainBatch(max) // raw, UNBUFFERED — you own durability
```

`DrainBatch` fetches one batch (clamped ≤500) and returns the decrypted
`[]Change` directly without buffering. Prefer `ProcessChanges` for safe
consumption.
