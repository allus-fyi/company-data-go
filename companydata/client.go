package companydata

import (
	"context"
	"crypto/rsa"
	"errors"
	"log"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Client facade.
//
// The one object an integrating company touches. Build it from config (the keys
// live there and nowhere else), then call:
//
//	client.RequestFields(ctx)               -> cached []RequestField  (slug -> meta)
//	client.Connections(ctx)                 -> channel of Connection (auto-paged)
//	client.ConnectionsList(ctx, limit, off) -> []Connection (eager, all pages)
//	client.Connection(ctx, id)              -> one Connection
//	client.Logs(ctx, limit, offset)         -> []LogEntry
//	client.ProcessChanges(handler, opts)    -> the crash-safe pump
//	client.DrainBatch(max)                  -> raw unbuffered drain (advanced)
//	client.DeadLetters() / client.RetryDeadLetters(handler, opts)
//
// Plus the webhook receiver helpers, exposed as methods that
// delegate to the package-level functions (all config-driven, no key/secret args):
//
//	client.VerifyWebhook(rawBody, headers) -> bool
//	client.ParseWebhook(rawBody, headers)  -> Change
//	client.HandleWebhook(rawBody, headers) -> Change
//
// How it is wired (the "everything else the SDK hides"):
//
//   - Auth + transport — an HTTPClient owns the client_credentials token, the
//     JSON/XML accept+parse, and the error mapping (incl. 429 backoff).
//   - Decryption — the service private key is loaded ONCE at construction from
//     the configured encrypted PEM + passphrase into an in-memory RSA key; a
//     decrypt closure over it is handed to every model factory and the pump
//     (config-only key handling — the key never appears in a method signature).
//   - Slug catalog — RequestFields is fetched once and cached; its slug→type map
//     types every value (so address parses to a map, photo becomes a lazy binary
//     handle, etc.).
//   - Binary — a value's *BinaryHandle.Bytes() GETs the slot file endpoint,
//     unwraps the API's {"encrypted":true,"value":<wrapper>} envelope, and runs
//     the same service-key decrypt → the file bytes.
//   - Changes feed — ProcessChanges delegates to the Pump, injecting a
//     fetchChanges closure (GET /changes?limit=, returning the raw ciphertext
//     events) and a decrypt closure that builds a typed Change.

const (
	baseEndpoint    = "/api/company-data"
	epConnections   = baseEndpoint + "/connections"
	epChanges       = baseEndpoint + "/changes"
	epRequestFields = baseEndpoint + "/request-fields"
	epLogs          = baseEndpoint + "/logs"

	// defaultConnPage is the connections iterator page size. The endpoint is
	// heavily rate-limited, so pages are reasonably large to
	// minimize requests for a full sync, while the iterator stays lazy.
	defaultConnPage = 100

	// Bounded extra backoff for the connections iterator on a surfaced 429.
	connMax429Backoffs = 5
	connDefaultBackoff = 5 * time.Second
	connMaxBackoff     = 120 * time.Second
)

// Client is the company-data SDK client facade. It is safe for
// sequential use; ProcessChanges runs the pump on the calling goroutine.
type Client struct {
	config     *Config
	http       *HTTPClient
	logger     *log.Logger
	sleep      func(time.Duration)
	privateKey *rsa.PrivateKey
	accountKey *rsa.PrivateKey

	requestFields []RequestField
	typeBySlug    map[string]string
	fieldsLoaded  bool

	pump *Pump
}

// clientOption configures a Client.
type clientOption func(*Client)

// WithHTTPClient injects a custom HTTPClient (e.g. with a fake Doer for tests).
func WithHTTPClient(h *HTTPClient) clientOption { return func(c *Client) { c.http = h } }

// WithLogger sets the logger used by the client + pump.
func WithLogger(l *log.Logger) clientOption { return func(c *Client) { c.logger = l } }

// withClientSleep injects a sleep function (tests use a no-op).
func withClientSleep(s func(time.Duration)) clientOption {
	return func(c *Client) { c.sleep = s }
}

// New builds a Client from a Config. The service private key is loaded ONCE here
// (config-only key handling); a bad passphrase / unreadable PEM is
// a *ConfigError (fail fast).
func New(config *Config, opts ...clientOption) (*Client, error) {
	c := &Client{
		config:     config,
		logger:     log.Default(),
		sleep:      time.Sleep,
		typeBySlug: map[string]string{},
	}
	for _, o := range opts {
		o(c)
	}
	if c.http == nil {
		c.http = NewHTTPClient(config)
	}

	key, err := loadServiceKey(config)
	if err != nil {
		return nil, err
	}
	c.privateKey = key

	// Load the ACCOUNT private key ONCE too (nil unless configured) — reused for
	// every encrypt_payload webhook so we don't re-read the PEM + re-run PBKDF2.
	acct, err := LoadAccountKey(config)
	if err != nil {
		return nil, err
	}
	c.accountKey = acct

	return c, nil
}

// FromConfig builds a Client from a JSON config file (env vars override
// secrets).
func FromConfig(path string, opts ...clientOption) (*Client, error) {
	cfg, err := ConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	return New(cfg, opts...)
}

// FromEnv builds a Client entirely from ALLUS_* env vars.
func FromEnv(opts ...clientOption) (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return New(cfg, opts...)
}

// ── decryption wiring (closures over the loaded key — never a method arg) ───

// decryptValue decrypts a service-key ciphertext wrapper → plaintext.
func (c *Client) decryptValue(wrapper any) (string, error) {
	return Decrypt(wrapper, c.privateKey)
}

// binaryFetch fetches a slot file endpoint and unwraps its
// {"encrypted":true,"value":...} envelope, returning the inner {"_enc":1,...}
// wrapper for the BinaryHandle to decrypt.
func (c *Client) binaryFetch(valueURL string) (any, error) {
	body, err := c.http.Get(context.Background(), valueURL, nil)
	if err != nil {
		return nil, err
	}
	if m, ok := body.(map[string]any); ok {
		if v, ok := m["value"]; ok {
			return v, nil
		}
	}
	// Defensive: some shapes might return the wrapper directly.
	return body, nil
}

// typeForSlug resolves a request slug to its field type (loads the catalog once).
func (c *Client) typeForSlug(slug string) string {
	if !c.fieldsLoaded {
		_, _ = c.RequestFields(context.Background())
	}
	return c.typeBySlug[slug]
}

// ── definitions ──────────────────────────────────────────────────────────────

// RequestFields returns the cached request-field DEFINITIONS.
//
// Fetched once from GET /api/company-data/request-fields and cached for the life
// of the client (it's the company's static config, and it types every value).
// Returns YOUR request config — never the person's fields.
func (c *Client) RequestFields(ctx context.Context) ([]RequestField, error) {
	if c.fieldsLoaded {
		return c.requestFields, nil
	}
	body, err := c.http.Get(ctx, epRequestFields, nil)
	if err != nil {
		return nil, err
	}
	fields := requestFieldsFromAPI(body)
	c.requestFields = fields
	c.typeBySlug = map[string]string{}
	for _, f := range fields {
		if f.Slug != "" {
			c.typeBySlug[f.Slug] = f.Type
		}
	}
	c.fieldsLoaded = true
	return fields, nil
}

// ── connections (heavily rate-limited — initial sync / reconciliation) ──────

// Connections returns a channel that lazily pages the list endpoint, sending one
// Connection at a time, and an error channel that is closed when iteration ends
// (carrying a single error if one occurred). The connection channel is closed
// when the book is exhausted or an error is hit.
//
// The connections endpoints are heavily rate-limited: use this
// for the initial full sync + occasional reconciliation, never as a poll
// substitute for the changes feed. On a surfaced *RateLimitError the iterator
// backs off per Retry-After and retries the page a bounded number of times
// before surfacing the error.
//
// Honor the API's reported total: a short page (fewer rows than the page size)
// ends iteration. Cancel via ctx to stop early.
//
// For a simpler eager API, use ConnectionsList.
func (c *Client) Connections(ctx context.Context, limit, offset int) (<-chan Connection, <-chan error) {
	out := make(chan Connection)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		page := limit
		if page < 1 {
			page = defaultConnPage
		}
		cur := offset
		if cur < 0 {
			cur = 0
		}
		if _, err := c.RequestFields(ctx); err != nil {
			errc <- err
			return
		}

		for {
			body, err := c.getConnectionsPage(ctx, page, cur)
			if err != nil {
				errc <- err
				return
			}
			items := listItems(body)
			if len(items) == 0 {
				return
			}
			for _, obj := range items {
				m, ok := obj.(map[string]any)
				if !ok {
					continue
				}
				conn, err := connectionFromAPI(m, c.typeForSlug, c.decryptValue, c.binaryFetch, m)
				if err != nil {
					errc <- err
					return
				}
				select {
				case out <- conn:
				case <-ctx.Done():
					errc <- ctx.Err()
					return
				}
			}
			// A short page means we reached the end (no more rows than asked for).
			if len(items) < page {
				return
			}
			cur += page
		}
	}()

	return out, errc
}

// ConnectionsList eagerly drains the connections iterator into a slice (the
// initial-full-sync convenience). It auto-pages and honors the rate limit.
func (c *Client) ConnectionsList(ctx context.Context, limit, offset int) ([]Connection, error) {
	conns, errc := c.Connections(ctx, limit, offset)
	var out []Connection
	for conn := range conns {
		out = append(out, conn)
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	return out, nil
}

// getConnectionsPage GETs one connections page, backing off on a surfaced 429.
func (c *Client) getConnectionsPage(ctx context.Context, page, offset int) (any, error) {
	attempts := 0
	for {
		params := url.Values{}
		params.Set("limit", strconv.Itoa(page))
		params.Set("offset", strconv.Itoa(offset))
		body, err := c.http.Get(ctx, epConnections, params)
		if err == nil {
			return body, nil
		}
		var rl *RateLimitError
		if !asRateLimit(err, &rl) {
			return nil, err
		}
		attempts++
		if attempts > connMax429Backoffs {
			return nil, err
		}
		delay := connBackoff(rl.RetryAfter, attempts)
		c.logf("connections rate-limited (offset=%d); backoff %v (attempt %d)", offset, delay, attempts)
		if delay > 0 {
			c.sleep(delay)
		}
	}
}

// Connection fetches a single connection by id → one Connection.
// connectionDetail returns {connection_id, user_id, values} and no
// display_name/connected_at; those identity fields simply stay empty.
func (c *Client) Connection(ctx context.Context, id string) (Connection, error) {
	if _, err := c.RequestFields(ctx); err != nil {
		return Connection{}, err
	}
	body, err := c.http.Get(ctx, epConnections+"/"+id, nil)
	if err != nil {
		return Connection{}, err
	}
	m, ok := body.(map[string]any)
	if !ok {
		return Connection{}, NewApiError(0, "", "connection response was not an object")
	}
	// Defensive: a single-item list shape.
	if _, hasValues := m["values"]; !hasValues {
		if items := listItems(m); len(items) > 0 {
			if first, ok := items[0].(map[string]any); ok {
				m = first
			}
		}
	}
	return connectionFromAPI(m, c.typeForSlug, c.decryptValue, c.binaryFetch, nil)
}

// ── logs (moderate rate-limit) ──────────────────────────────────────────────

// Logs returns the service's activity log → []LogEntry.
// Ops events only (email / purge / webhook) — never person field data.
func (c *Client) Logs(ctx context.Context, limit, offset int) ([]LogEntry, error) {
	if limit < 1 {
		limit = 1
	}
	if offset < 0 {
		offset = 0
	}
	params := url.Values{}
	params.Set("limit", strconv.Itoa(limit))
	params.Set("offset", strconv.Itoa(offset))
	body, err := c.http.Get(ctx, epLogs, params)
	if err != nil {
		return nil, err
	}
	return logEntriesFromAPI(body), nil
}

// ── changes feed — the crash-safe pump ────────────────────────

// Pump returns the crash-safe changes pump (built lazily).
func (c *Client) Pump() (*Pump, error) {
	if c.pump == nil {
		p, err := NewPump(
			c.config,
			c.fetchChanges,
			c.decryptChange,
			withPumpLogger(c.logger),
			withPumpSleep(c.sleep),
		)
		if err != nil {
			return nil, err
		}
		c.pump = p
	}
	return c.pump, nil
}

// fetchChanges is the pump's drain source: GET /changes?limit= → raw ciphertext
// events. The feed is drain-on-fetch — this call deletes exactly
// the returned rows server-side, so the pump persists them durably before
// delivery.
func (c *Client) fetchChanges(limit int) ([]map[string]any, error) {
	params := url.Values{}
	params.Set("limit", strconv.Itoa(limit))
	body, err := c.http.Get(context.Background(), epChanges, params)
	if err != nil {
		return nil, err
	}
	items := extractList(body, "changes")
	out := make([]map[string]any, 0, len(items))
	for _, o := range items {
		if m, ok := o.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// decryptChange is the pump's decrypt: a raw event map → a typed Change (value
// decrypted at delivery).
func (c *Client) decryptChange(event map[string]any) (Change, error) {
	return changeFromAPI(event, c.typeForSlug, c.decryptValue, c.binaryFetch)
}

// ProcessChanges drains the changes feed through handler one at a time,
// crash-safely. Replays the durable buffer, drains ≤500 at a time,
// persist-before-deliver, per-item ack, retry→dead-letter→continue, until the
// feed is empty then returns (no daemon mode — schedule re-runs yourself).
// handler must be idempotent (at-least-once; dedup on Change.ID).
func (c *Client) ProcessChanges(handler Handler, opts PumpOptions) error {
	if _, err := c.RequestFields(context.Background()); err != nil {
		return err
	}
	p, err := c.Pump()
	if err != nil {
		return err
	}
	return p.ProcessChanges(handler, opts)
}

// DrainBatch is a raw, UNBUFFERED drain → []Change (advanced — you own
// durability). Prefer ProcessChanges for safe consumption.
func (c *Client) DrainBatch(max int) ([]Change, error) {
	if _, err := c.RequestFields(context.Background()); err != nil {
		return nil, err
	}
	p, err := c.Pump()
	if err != nil {
		return nil, err
	}
	return p.DrainBatch(max)
}

// DeadLetters returns the local dead-letter store.
func (c *Client) DeadLetters() ([]DeadLetter, error) {
	p, err := c.Pump()
	if err != nil {
		return nil, err
	}
	return p.DeadLetters()
}

// RetryDeadLetters re-drives dead-lettered events through handler.
func (c *Client) RetryDeadLetters(handler Handler, opts PumpOptions) (int, error) {
	if _, err := c.RequestFields(context.Background()); err != nil {
		return 0, err
	}
	p, err := c.Pump()
	if err != nil {
		return 0, err
	}
	return p.RetryDeadLetters(handler, opts)
}

// ── webhook receiver helpers ──────

// VerifyWebhook verifies a webhook's X-Allus-Signature HMAC.
// headers may be a map[string]string or http.Header (map[string][]string).
func (c *Client) VerifyWebhook(rawBody []byte, headers any) bool {
	return VerifyWebhook(rawBody, headers, c.config)
}

// ParseWebhook parses a webhook body → a typed Change. Loads the
// request-fields catalog once for value typing.
func (c *Client) ParseWebhook(rawBody []byte, headers any) (Change, error) {
	if _, err := c.RequestFields(context.Background()); err != nil {
		return Change{}, err
	}
	return ParseWebhook(rawBody, headers, c.config, c.typeForSlug, c.decryptValue, c.binaryFetch, c.accountKey)
}

// HandleWebhook verifies + parses a webhook in one call → Change.
func (c *Client) HandleWebhook(rawBody []byte, headers any) (Change, error) {
	if _, err := c.RequestFields(context.Background()); err != nil {
		return Change{}, err
	}
	return HandleWebhook(rawBody, headers, c.config, c.typeForSlug, c.decryptValue, c.binaryFetch, c.accountKey)
}

func (c *Client) logf(format string, a ...any) {
	if c.logger != nil {
		c.logger.Printf(format, a...)
	}
}

// ── module helpers ──────────────────────────────────────────────────────────

// loadServiceKey reads the configured encrypted PEM and decrypts it with the
// passphrase (once). A bad passphrase / unreadable PEM is a *ConfigError.
func loadServiceKey(config *Config) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(config.ServicePrivateKey)
	if err != nil {
		return nil, wrapConfigError(err, "could not read service_private_key PEM: %s: %v", config.ServicePrivateKey, err)
	}
	key, err := LoadPrivateKey(pemBytes, config.KeyPassphrase)
	if err != nil {
		return nil, wrapConfigError(err, "could not load service private key: %v", err)
	}
	return key, nil
}

// listItems pulls the items array out of a {total, items} list response.
func listItems(body any) []any {
	switch b := body.(type) {
	case map[string]any:
		if v, ok := b["items"]; ok {
			if lst, ok := v.([]any); ok {
				return lst
			}
			if v != nil {
				return []any{v}
			}
		}
		return nil
	case []any:
		return b
	default:
		return nil
	}
}

// connBackoff is the backoff before retrying a rate-limited connections page.
func connBackoff(retryAfter *float64, attempt int) time.Duration {
	if retryAfter != nil && *retryAfter >= 0 {
		d := time.Duration(*retryAfter * float64(time.Second))
		if d > connMaxBackoff {
			d = connMaxBackoff
		}
		return d
	}
	d := connDefaultBackoff * (1 << (attempt - 1))
	if d > connMaxBackoff {
		d = connMaxBackoff
	}
	return d
}

// asRateLimit reports whether err is (or wraps) a *RateLimitError, and if so
// stores it into *target.
func asRateLimit(err error, target **RateLimitError) bool {
	return errors.As(err, target)
}
