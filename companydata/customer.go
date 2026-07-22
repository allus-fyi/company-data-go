package companydata

// CustomerClient (b2b, #168) — the connecting company's client.
//
// A CUSTOMER consumes and answers another company's service over its acct_*
// credentials: list company↔company connections, provide/edit typed consent
// answers, read (and decrypt) issued documents, run contract flows, drain the
// account change feed, and verify account-level webhooks. It reuses the same
// crash-safe Pump, webhook helpers, and hybrid-crypto core as the service Client.
//
// NO sign/accept methods (spec D6): signing/accepting a contract is a deliberate
// human step-up that stays portal-only; a machine acct_* token is rejected by the
// API for those routes.

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	epCustomerConnections = "/api/company-connections"
	epCustomerConsents    = "/api/company-connections/consents"
	epCustomerChanges     = "/api/customer/changes"
)

// CustomerServiceLink is one service inside a CustomerConnection.
type CustomerServiceLink struct {
	ServiceLinkID  string           `json:"service_link_id"`
	ServiceID      string           `json:"service_id"`
	ServiceName    string           `json:"service_name"`
	ServiceCode    string           `json:"service_code"`
	Shared         []map[string]any `json:"shared"`
	Mappings       []map[string]any `json:"mappings"`
	PendingConsent any              `json:"pending_consent"`
	Raw            map[string]any   `json:"-"`
}

// CustomerConnection is one company↔company connection from the customer's side.
type CustomerConnection struct {
	ID             string                `json:"id"`
	CompanyUserID  string                `json:"company_user_id"`
	CompanyName    string                `json:"company_name"`
	CompanyCode    string                `json:"company_code"`
	CustomerType   string                `json:"customer_type"`
	CompanyProfile []map[string]any      `json:"company_profile"`
	Services       []CustomerServiceLink `json:"services"`
	Raw            map[string]any        `json:"-"`
}

// TypedAnswer is a typed answer to a consent/edit request row (before encryption).
type TypedAnswer struct {
	RequestFieldID string
	Value          string
	Kind           string // "typed" (default) | "one_time"
}

// FlowParty identifies a flow party for EncryptFlowAnswer.
type FlowParty struct {
	UserID  string
	Type    string
	IsOwner bool
}

// CustomerClient is the b2b customer-side facade. NO sign/accept (spec D6).
type CustomerClient struct {
	config      *Config
	http        *HTTPClient
	logger      *log.Logger
	sleep       func(time.Duration)
	accountKey  *rsa.PrivateKey
	pubkeyCache map[string]*rsa.PublicKey
	// #344 review pass 2: pubkeyCache is reachable from two goroutines now — batchKey during an
	// encryption, and InvalidatePublicKey which the README tells webhook consumers to call from
	// their own handler. An unsynchronised map under concurrent read+write is a hard crash in Go,
	// not a stale-value bug, so the cache gets a mutex covering lookup, write and invalidation.
	// #344 review pass 3 corrects the pass-2 note that once stood here: serviceKeyCache and
	// requestTypeCache ARE reachable from concurrent encryptions (they sit on the same
	// encryptFor* paths as pubkeyCache), so an unsynchronised map there is the same hard crash.
	// They now share otherMu. Neither has an invalidator, so neither needs a generation counter
	// — but adding one later MUST bring a generation with it, for the reason spelled out below.
	// #344 review pass 3: a per-key GENERATION counter, bumped by every invalidation.
	//
	// Locking the map alone is not enough. The fetch path is check (locked) → unlock → HTTP →
	// store (locked), so an InvalidatePublicKey that lands between the unlock and the store is
	// silently undone: the pre-rotation key is written back AFTER the delete, the key_rotated
	// event has already been consumed, and with no TTL the process encrypts to the dead key for
	// the rest of its life — the exact symptom this issue exists to fix.
	//
	// The fetch snapshots the generation before releasing the mutex and stores only if it is
	// still current; otherwise it discards its result and the next caller refetches. Invalidation
	// therefore dominates every fetch that began before it.
	pubkeyGen       map[string]uint64
	pubkeyMu        sync.Mutex
	// otherMu guards serviceKeyCache and requestTypeCache. Separate from pubkeyMu so a public-key
	// fetch and a service-key fetch never serialise on each other.
	otherMu         sync.Mutex
	serviceKeyCache map[string]*rsa.PublicKey
	// requestTypeCache maps "companyCode/serviceCode" → {request_field_id: field_type},
	// resolved from the connect-screen lookup for typed-answer validation (#302).
	requestTypeCache map[string]map[string]string
	pump             *Pump
}

// NewCustomer builds a CustomerClient. The transport authenticates as the acct_*
// client (config.CustomerClientID/Secret).
func NewCustomer(config *Config, opts ...customerOption) (*CustomerClient, error) {
	if config.CustomerClientID == "" || config.CustomerClientSecret == "" {
		return nil, newConfigError("CustomerClient requires customer_client_id + customer_client_secret")
	}
	c := &CustomerClient{
		config:           config,
		logger:           log.Default(),
		sleep:            time.Sleep,
		pubkeyCache:      map[string]*rsa.PublicKey{},
		pubkeyGen:        map[string]uint64{},
		serviceKeyCache:  map[string]*rsa.PublicKey{},
		requestTypeCache: map[string]map[string]string{},
	}
	for _, o := range opts {
		o(c)
	}
	if c.http == nil {
		// HTTPClient authenticates with config.ClientID/Secret; hand it a copy
		// pointed at the customer acct_* pair.
		httpCfg := *config
		httpCfg.ClientID = config.CustomerClientID
		httpCfg.ClientSecret = config.CustomerClientSecret
		c.http = NewHTTPClient(&httpCfg)
	}
	acct, err := LoadAccountKey(config)
	if err != nil {
		return nil, err
	}
	c.accountKey = acct
	return c, nil
}

type customerOption func(*CustomerClient)

// WithCustomerHTTP injects a transport (for tests).
func WithCustomerHTTP(h *HTTPClient) customerOption { return func(c *CustomerClient) { c.http = h } }

// FromCustomerConfig builds a CustomerClient from a customer-role JSON config file.
func FromCustomerConfig(path string, opts ...customerOption) (*CustomerClient, error) {
	cfg, err := ConfigFromCustomerFile(path)
	if err != nil {
		return nil, err
	}
	return NewCustomer(cfg, opts...)
}

// FromCustomerEnv builds a CustomerClient entirely from ALLUS_* env vars.
func FromCustomerEnv(opts ...customerOption) (*CustomerClient, error) {
	cfg, err := ConfigFromCustomerEnv()
	if err != nil {
		return nil, err
	}
	return NewCustomer(cfg, opts...)
}

// ── connections ──────────────────────────────────────────────────────────────

// Connections lists the customer's company↔company connections.
func (c *CustomerClient) Connections() ([]CustomerConnection, error) {
	body, err := c.http.Get(context.Background(), epCustomerConnections, nil)
	if err != nil {
		return nil, err
	}
	return parseCustomerConnections(body), nil
}

// Connection returns one connection's full structure.
func (c *CustomerClient) Connection(id string) (CustomerConnection, error) {
	body, err := c.http.Get(context.Background(), epCustomerConnections+"/"+id, nil)
	if err != nil {
		return CustomerConnection{}, err
	}
	if m, ok := body.(map[string]any); ok {
		return parseCustomerConnection(m), nil
	}
	return CustomerConnection{}, nil
}

// ── consents (typed answers) ──────────────────────────────────────────────────

// PendingConsents returns the pending consent requests.
func (c *CustomerClient) PendingConsents() ([]map[string]any, error) {
	body, err := c.http.Get(context.Background(), epCustomerConsents, nil)
	if err != nil {
		return nil, err
	}
	items := extractList(body, "consents")
	if len(items) == 0 {
		items = extractList(body, "items")
	}
	out := make([]map[string]any, 0, len(items))
	for _, o := range items {
		if m, ok := o.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// ProvideConsent answers a consent's request rows by TYPING values, encrypted to
// the target SERVICE public key.
func (c *CustomerClient) ProvideConsent(consentID string, answers []TypedAnswer, companyCode, serviceCode string) (any, error) {
	decisions, err := c.encryptTyped(answers, companyCode, serviceCode)
	if err != nil {
		return nil, err
	}
	return c.http.Post(context.Background(), epCustomerConsents+"/"+consentID+"/provide", map[string]any{"decisions": decisions})
}

// DeclineConsent declines a consent (grandfathered — the connection stays active).
func (c *CustomerClient) DeclineConsent(consentID string) (any, error) {
	return c.http.Post(context.Background(), epCustomerConsents+"/"+consentID+"/decline", nil)
}

// EditAnswers re-types + re-encrypts already-answered mappings.
func (c *CustomerClient) EditAnswers(connectionID, serviceLinkID string, answers []TypedAnswer, companyCode, serviceCode string) (any, error) {
	decisions, err := c.encryptTyped(answers, companyCode, serviceCode)
	if err != nil {
		return nil, err
	}
	return c.http.Put(context.Background(), epCustomerConnections+"/"+connectionID+"/services/"+serviceLinkID+"/mappings", map[string]any{"decisions": decisions})
}

// ── documents (account-key decrypt; NO sign/accept — D6) ───────────────────────

// Documents returns the documents issued to this connection (from its payload).
func (c *CustomerClient) Documents(conn CustomerConnection) []Document {
	var out []Document
	add := func(list []any) {
		for _, d := range list {
			if m, ok := d.(map[string]any); ok {
				out = append(out, documentFromAPI(m, c.decryptAccount))
			}
		}
	}
	for _, svc := range conn.Services {
		if docs, ok := svc.Raw["documents"].([]any); ok {
			add(docs)
		}
	}
	if docs, ok := conn.Raw["documents"].([]any); ok {
		add(docs)
	}
	return out
}

// DocumentFile fetches + decrypts a document's file blob with the ACCOUNT key.
func (c *CustomerClient) DocumentFile(connectionID, documentID string) (any, error) {
	body, err := c.http.Get(context.Background(), epCustomerConnections+"/"+connectionID+"/documents/"+documentID+"/file", nil)
	if err != nil {
		return nil, err
	}
	if m, ok := body.(map[string]any); ok {
		if enc, _ := m["encrypted"].(bool); enc {
			if v, ok := m["value"]; ok {
				plain, derr := c.decryptAccount(v)
				if derr != nil {
					return nil, derr
				}
				var out any
				return out, json.Unmarshal([]byte(plain), &out)
			}
		}
		if _, ok := m["_enc"]; ok {
			plain, derr := c.decryptAccount(m)
			if derr != nil {
				return nil, derr
			}
			var out any
			return out, json.Unmarshal([]byte(plain), &out)
		}
	}
	return body, nil
}

// CancelDocument cancels an in-app-cancellable document.
func (c *CustomerClient) CancelDocument(connectionID, documentID, note string) (any, error) {
	var payload any
	if note != "" {
		payload = map[string]any{"note": note}
	}
	return c.http.Post(context.Background(), epCustomerConnections+"/"+connectionID+"/documents/"+documentID+"/cancel", payload)
}

// ── contract flows ─────────────────────────────────────────────────────────────

// FlowRuns lists the flow runs on a connection.
func (c *CustomerClient) FlowRuns(connectionID string) ([]FlowRun, error) {
	body, err := c.http.Get(context.Background(), epCustomerConnections+"/"+connectionID+"/flow-runs", nil)
	if err != nil {
		return nil, err
	}
	items := extractList(body, "runs")
	out := make([]FlowRun, 0, len(items))
	for _, o := range items {
		if m, ok := o.(map[string]any); ok {
			out = append(out, flowRunFromAPI(m))
		}
	}
	return out, nil
}

// FlowRun returns one flow run.
func (c *CustomerClient) FlowRun(connectionID, runID string) (FlowRun, error) {
	body, err := c.http.Get(context.Background(), epCustomerConnections+"/"+connectionID+"/flow-runs/"+runID, nil)
	if err != nil {
		return FlowRun{}, err
	}
	if m, ok := body.(map[string]any); ok {
		return flowRunFromAPI(m), nil
	}
	return FlowRun{}, nil
}

// SubmitFlowAnswers submits this party's turn (body carries the encrypted per-party answers).
func (c *CustomerClient) SubmitFlowAnswers(connectionID, runID string, body map[string]any) (any, error) {
	return c.http.Post(context.Background(), epCustomerConnections+"/"+connectionID+"/flow-runs/"+runID+"/answers", body)
}

// DeclineFlowRun declines a flow run.
func (c *CustomerClient) DeclineFlowRun(connectionID, runID string) (any, error) {
	return c.http.Post(context.Background(), epCustomerConnections+"/"+connectionID+"/flow-runs/"+runID+"/decline", nil)
}

// EncryptFlowAnswer encrypts one answer value for one flow party per the P4 key rule.
func (c *CustomerClient) EncryptFlowAnswer(plaintext string, party FlowParty, companyCode, serviceCode string) (map[string]any, error) {
	var pub *rsa.PublicKey
	var err error
	if party.IsOwner {
		pub, err = c.serviceKey(companyCode, serviceCode)
	} else {
		pub, err = c.batchKey(party.UserID)
	}
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, fmt.Errorf("no public key available for party %s", party.UserID)
	}
	return EncryptForPublicKey(plaintext, pub)
}

// ── change feed (P2 account feed) ──────────────────────────────────────────────

// Pump returns the crash-safe changes pump (built lazily).
func (c *CustomerClient) Pump() (*Pump, error) {
	if c.pump == nil {
		p, err := NewPump(c.config, c.fetchChanges, c.decryptChange, withPumpLogger(c.logger), withPumpSleep(c.sleep))
		if err != nil {
			return nil, err
		}
		c.pump = p
	}
	return c.pump, nil
}

func (c *CustomerClient) fetchChanges(limit int) ([]map[string]any, error) {
	params := url.Values{}
	params.Set("limit", strconv.Itoa(limit))
	body, err := c.http.Get(context.Background(), epCustomerChanges, params)
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

// InvalidatePublicKey drops a person's cached RSA public key, by user id. See the Client method of
// the same name (#344); the changes feed calls this for you, webhook consumers must call it.
func (c *CustomerClient) InvalidatePublicKey(userID string) {
	c.pubkeyMu.Lock()
	delete(c.pubkeyCache, userID)
	c.pubkeyGen[userID]++ // any fetch already in flight must not write its stale result back
	c.pubkeyMu.Unlock()
}

func (c *CustomerClient) decryptChange(event map[string]any) (Change, error) {
	// #344: see Client.decryptChange. Note this cache also stores a negative (nil) result, so
	// without invalidation a person who had no key yet would stay unresolvable for the process
	// lifetime too.
	// #344: the pull feed names it `event`; a raw webhook body names it `action` (and on document
	// rows `action` carries signed|accepted|cancelled instead) — so match either key.
	evType, _ := event["event"].(string)
	act, _ := event["action"].(string)
	if evType == "key_rotated" || act == "key_rotated" {
		if id, _ := event["person_user_id"].(string); id != "" {
			c.InvalidatePublicKey(id)
		}
	}
	return changeFromAPI(event, func(string) string { return "" }, c.decryptAccount, nil)
}

// ProcessChanges drains the customer change feed through handler, crash-safely.
func (c *CustomerClient) ProcessChanges(handler Handler, opts PumpOptions) error {
	p, err := c.Pump()
	if err != nil {
		return err
	}
	return p.ProcessChanges(handler, opts)
}

// DrainBatch is a raw, unbuffered drain → []Change.
func (c *CustomerClient) DrainBatch(max int) ([]Change, error) {
	p, err := c.Pump()
	if err != nil {
		return nil, err
	}
	return p.DrainBatch(max)
}

// DeadLetters returns the local dead-letter store.
func (c *CustomerClient) DeadLetters() ([]DeadLetter, error) {
	p, err := c.Pump()
	if err != nil {
		return nil, err
	}
	return p.DeadLetters()
}

// RetryDeadLetters re-drives dead-lettered events through handler.
func (c *CustomerClient) RetryDeadLetters(handler Handler, opts PumpOptions) (int, error) {
	p, err := c.Pump()
	if err != nil {
		return 0, err
	}
	return p.RetryDeadLetters(handler, opts)
}

// ── account-level webhook receiver helpers (config-driven) ─────────────────────

// VerifyWebhook verifies an account-level webhook delivery.
func (c *CustomerClient) VerifyWebhook(rawBody []byte, headers any) bool {
	return VerifyWebhook(rawBody, headers, c.config)
}

// ParseWebhook parses a webhook body → a typed Change.
func (c *CustomerClient) ParseWebhook(rawBody []byte, headers any) (Change, error) {
	return ParseWebhook(rawBody, headers, c.config, func(string) string { return "" }, c.decryptAccount, nil, c.accountKey)
}

// HandleWebhook verifies + parses a webhook in one call → Change.
func (c *CustomerClient) HandleWebhook(rawBody []byte, headers any) (Change, error) {
	return HandleWebhook(rawBody, headers, c.config, func(string) string { return "" }, c.decryptAccount, nil, c.accountKey)
}

// ── internals ──────────────────────────────────────────────────────────────────

func (c *CustomerClient) decryptAccount(wrapper any) (string, error) {
	if c.accountKey == nil {
		return "", newConfigError("account_private_key is required to decrypt this value")
	}
	return Decrypt(wrapper, c.accountKey)
}

// requestFieldTypes resolves {request_field_id: field_type} for a service from the
// connect-screen lookup, cached per company/service. Best-effort — a lookup failure
// yields an empty map so typed-answer validation is simply skipped (#302).
func (c *CustomerClient) requestFieldTypes(companyCode, serviceCode string) map[string]string {
	key := companyCode + "/" + serviceCode
	c.otherMu.Lock()
	m, ok := c.requestTypeCache[key]
	c.otherMu.Unlock()
	if ok {
		return m
	}
	out := map[string]string{}
	body, err := c.http.Get(context.Background(), epCustomerConnections+"/lookup/"+companyCode+"/"+serviceCode, nil)
	if err == nil {
		for _, r := range extractList(body, "request_fields") {
			if m, ok := r.(map[string]any); ok {
				id := asString(m["id"])
				ft := asString(m["field_type"])
				if ft == "" {
					ft = asString(m["type"])
				}
				if id != "" && ft != "" {
					out[id] = ft
				}
			}
		}
	}
	c.otherMu.Lock()
	c.requestTypeCache[key] = out
	c.otherMu.Unlock()
	return out
}

func (c *CustomerClient) encryptTyped(answers []TypedAnswer, companyCode, serviceCode string) ([]map[string]any, error) {
	pub, err := c.serviceKey(companyCode, serviceCode)
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, fmt.Errorf("no service key for %s/%s", companyCode, serviceCode)
	}
	// #302: validate each typed answer against its request row's field type, BEFORE
	// encryption. Skip an answer whose type can't be resolved (do not invent one).
	types := c.requestFieldTypes(companyCode, serviceCode)
	for _, a := range answers {
		if ft := types[a.RequestFieldID]; ft != "" {
			if !FieldValueValid(ft, a.Value) {
				return nil, newValidationError(a.RequestFieldID, ft)
			}
		}
	}
	out := make([]map[string]any, 0, len(answers))
	for _, a := range answers {
		wrapper, err := EncryptForPublicKey(a.Value, pub)
		if err != nil {
			return nil, err
		}
		kind := a.Kind
		if kind == "" {
			kind = "typed"
		}
		out = append(out, map[string]any{"request_field_id": a.RequestFieldID, "kind": kind, "value": wrapper})
	}
	return out, nil
}

func (c *CustomerClient) serviceKey(companyCode, serviceCode string) (*rsa.PublicKey, error) {
	key := companyCode + "/" + serviceCode
	c.otherMu.Lock()
	k, ok := c.serviceKeyCache[key]
	c.otherMu.Unlock()
	if ok {
		return k, nil
	}
	body, err := c.http.Get(context.Background(), epKeys+"/"+companyCode+"/"+serviceCode, nil)
	if err != nil {
		return nil, err
	}
	var pub *rsa.PublicKey
	if m, ok := body.(map[string]any); ok {
		if spki, ok := m["public_key"].(string); ok && spki != "" {
			pub, err = LoadPublicKey(spki)
			if err != nil {
				return nil, err
			}
		}
	}
	c.otherMu.Lock()
	c.serviceKeyCache[key] = pub
	c.otherMu.Unlock()
	return pub, nil
}

func (c *CustomerClient) batchKey(userID string) (*rsa.PublicKey, error) {
	// Lock only around the map access, never across the HTTP call below — holding it there would
	// serialise every concurrent encryption behind one network round-trip. Same shape as the
	// service client's recipientPublicKey. The comma-ok is load-bearing: a nil value is a CACHED
	// NEGATIVE (person has no key yet) and must still count as a hit.
	c.pubkeyMu.Lock()
	k, ok := c.pubkeyCache[userID]
	gen := c.pubkeyGen[userID]
	c.pubkeyMu.Unlock()
	if ok {
		return k, nil
	}
	body, err := c.http.Post(context.Background(), epKeys+"/batch", map[string]any{"user_ids": []string{userID}})
	if err != nil {
		return nil, err
	}
	var pub *rsa.PublicKey
	if m, ok := body.(map[string]any); ok {
		if keys, ok := m["keys"].(map[string]any); ok {
			if spki, ok := keys[userID].(string); ok && spki != "" {
				pub, err = LoadPublicKey(spki)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	c.pubkeyMu.Lock()
	// Store ONLY if no invalidation happened while the request was in flight.
	if c.pubkeyGen[userID] == gen {
		c.pubkeyCache[userID] = pub
	}
	c.pubkeyMu.Unlock()
	return pub, nil
}

func parseCustomerConnections(body any) []CustomerConnection {
	items := extractList(body, "connections")
	if len(items) == 0 {
		items = extractList(body, "items")
	}
	out := make([]CustomerConnection, 0, len(items))
	for _, o := range items {
		if m, ok := o.(map[string]any); ok {
			out = append(out, parseCustomerConnection(m))
		}
	}
	return out
}

func parseCustomerConnection(obj map[string]any) CustomerConnection {
	company, _ := obj["company"].(map[string]any)
	conn := CustomerConnection{
		ID:            custFirst(obj, "id", "company_connection_id"),
		CompanyUserID: custFirstNested(obj, company, "company_user_id", "user_id"),
		CompanyName:   custFirstNested(obj, company, "company_name", "display_name"),
		CompanyCode:   custFirstNested(obj, company, "company_code", "share_code"),
		CustomerType:  custStr(obj["customer_type"]),
		Raw:           obj,
	}
	if profile, ok := obj["company_profile"].([]any); ok {
		for _, p := range profile {
			if m, ok := p.(map[string]any); ok {
				conn.CompanyProfile = append(conn.CompanyProfile, m)
			}
		}
	}
	if services, ok := obj["services"].([]any); ok {
		for _, s := range services {
			if m, ok := s.(map[string]any); ok {
				conn.Services = append(conn.Services, parseCustomerServiceLink(m))
			}
		}
	}
	return conn
}

func parseCustomerServiceLink(obj map[string]any) CustomerServiceLink {
	link := CustomerServiceLink{
		ServiceLinkID:  custFirst(obj, "service_link_id", "id"),
		ServiceID:      custStr(obj["service_id"]),
		ServiceName:    custFirst(obj, "service_name", "name"),
		ServiceCode:    custFirst(obj, "service_code", "share_code"),
		PendingConsent: obj["pending_consent"],
		Raw:            obj,
	}
	if shared, ok := obj["shared"].([]any); ok {
		for _, s := range shared {
			if m, ok := s.(map[string]any); ok {
				link.Shared = append(link.Shared, m)
			}
		}
	}
	if mappings, ok := obj["mappings"].([]any); ok {
		for _, s := range mappings {
			if m, ok := s.(map[string]any); ok {
				link.Mappings = append(link.Mappings, m)
			}
		}
	}
	return link
}

func custStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func custFirst(obj map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := obj[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func custFirstNested(obj, nested map[string]any, objKey, nestedKey string) string {
	if s, ok := obj[objKey].(string); ok && s != "" {
		return s
	}
	if nested != nil {
		if s, ok := nested[nestedKey].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
