package companydata

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Client-facade tests. Everything is mocked — a router Doer
// replays canned hardened API JSON: the token, the request-fields catalog, the
// connections list, a single connection, the logs, the changes feed, and a slot
// file endpoint. Ciphertext fields reuse the shared decryption vector's real
// wrapper + the vector's key (written to a temp PEM the Client loads at
// construction), so this exercises the whole facade → http → crypto → model
// wiring end-to-end without the network.

// routerDoer dispatches a GET by path to a scripted handler; POST always
// returns the token.
type routerDoer struct {
	route func(path string, params map[string][]string) (int, string)
	gets  []string
	posts int
}

func (d *routerDoer) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		d.posts++
		return jsonResp(200, `{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}`), nil
	}
	d.gets = append(d.gets, req.URL.Path)
	status, body := d.route(req.URL.Path, req.URL.Query())
	return jsonResp(status, body), nil
}

func jsonResp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func clientConfig(t *testing.T, v *vectorDoc) *Config {
	t.Helper()
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "service-key.pem")
	if err := os.WriteFile(pemPath, []byte(v.EncryptedPrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Config{
		APIURL:            "https://api.allme.fyi",
		ClientID:          "svc_abc",
		ClientSecret:      "topsecret",
		ServicePrivateKey: pemPath,
		KeyPassphrase:     v.Passphrase,
		CacheDir:          filepath.Join(dir, "cache"),
	}
}

func newTestClient(t *testing.T, cfg *Config, route func(string, map[string][]string) (int, string)) (*Client, *routerDoer) {
	t.Helper()
	d := &routerDoer{route: route}
	http := NewHTTPClient(cfg, WithDoer(d))
	c, err := New(cfg, WithHTTPClient(http), WithLogger(log.New(io.Discard, "", 0)), withClientSleep(func(_ time.Duration) {}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, d
}

const requestFieldsBody = `{"request_fields":[
	{"slug":"work_email","label":"Work email","type":"email","one_time":false,"mandatory_provide":true,"mandatory_connected":false},
	{"slug":"billing_address","label":"Billing address","type":"address","one_time":false,"mandatory_provide":false,"mandatory_connected":false},
	{"slug":"logo","label":"Logo","type":"photo","one_time":true,"mandatory_provide":false,"mandatory_connected":false}
]}`

func TestRequestFieldsParsedAndCached(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	calls := 0
	c, _ := newTestClient(t, cfg, func(path string, _ map[string][]string) (int, string) {
		if strings.HasSuffix(path, "/request-fields") {
			calls++
			return 200, requestFieldsBody
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	})
	fields, err := c.RequestFields(context.Background())
	if err != nil {
		t.Fatalf("RequestFields: %v", err)
	}
	if len(fields) != 3 || fields[0].Slug != "work_email" || !fields[0].Mandatory {
		t.Fatalf("fields = %+v", fields)
	}
	// Cached: a second call (and internal type lookups) does NOT re-fetch.
	_, _ = c.RequestFields(context.Background())
	_ = c.typeForSlug("work_email")
	if calls != 1 {
		t.Fatalf("request-fields fetched %d times, want 1", calls)
	}
}

func TestConnectionsYieldsTypedDecrypted(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	addrWrapper := encryptForVectorKey(t, v, `{"city":"Utrecht","country":"NL"}`)
	page1 := map[string]any{
		"total": 1,
		"items": []any{
			map[string]any{
				"connection_id": "csc-1", "user_id": "person-1", "display_name": "Anna",
				"connected_at": "2026-06-10T00:00:00Z",
				"values": map[string]any{
					"work_email":      map[string]any{"value": v.Text.Wrapper, "live": true, "updatedAt": "2026-06-17T10:00:00Z"},
					"billing_address": map[string]any{"value": addrWrapper, "live": false},
					"logo":            map[string]any{"value_url": "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file", "live": true},
				},
				"pending_consent": []any{},
			},
		},
	}
	page1JSON, _ := json.Marshal(page1)

	c, d := newTestClient(t, cfg, func(path string, _ map[string][]string) (int, string) {
		switch {
		case strings.HasSuffix(path, "/request-fields"):
			return 200, requestFieldsBody
		case strings.HasSuffix(path, "/connections"):
			return 200, string(page1JSON)
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	})

	conns, err := c.ConnectionsList(context.Background(), 100, 0)
	if err != nil {
		t.Fatalf("ConnectionsList: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	conn := conns[0]
	if conn.ID != "csc-1" || conn.PersonID != "person-1" || conn.DisplayName != "Anna" {
		t.Fatalf("identity = %+v", conn)
	}
	if conn.Values["work_email"].Value != v.Text.Plaintext || !conn.Values["work_email"].Live {
		t.Fatalf("work_email = %#v", conn.Values["work_email"])
	}
	addr := conn.Values["billing_address"].Value.(map[string]any)
	if addr["city"] != "Utrecht" || addr["country"] != "NL" {
		t.Fatalf("billing_address = %#v", addr)
	}
	if _, ok := conn.Values["logo"].Value.(*BinaryHandle); !ok {
		t.Fatalf("logo should be *BinaryHandle")
	}
	// Only the catalog + one connections page were fetched (no slot file yet).
	for _, g := range d.gets {
		if strings.Contains(g, "/file") {
			t.Fatalf("binary should be lazy, but fetched %s", g)
		}
	}
}

func TestConnectionsAutoPages(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	makeItem := func(i string) map[string]any {
		return map[string]any{"connection_id": "c" + i, "user_id": "p" + i, "display_name": "N" + i, "values": map[string]any{}}
	}
	page0, _ := json.Marshal(map[string]any{"total": 3, "items": []any{makeItem("1"), makeItem("2")}})
	page1, _ := json.Marshal(map[string]any{"total": 3, "items": []any{makeItem("3")}})
	pages := []string{string(page0), string(page1)}
	idx := 0
	var offsets []string

	c, _ := newTestClient(t, cfg, func(path string, params map[string][]string) (int, string) {
		if strings.HasSuffix(path, "/request-fields") {
			return 200, `{"request_fields":[]}`
		}
		if strings.HasSuffix(path, "/connections") {
			offsets = append(offsets, params["offset"][0])
			body := pages[idx]
			idx++
			return 200, body
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	})

	conns, err := c.ConnectionsList(context.Background(), 2, 0)
	if err != nil {
		t.Fatalf("ConnectionsList: %v", err)
	}
	var ids []string
	for _, cn := range conns {
		ids = append(ids, cn.ID)
	}
	if strings.Join(ids, ",") != "c1,c2,c3" {
		t.Fatalf("ids = %v", ids)
	}
	if strings.Join(offsets, ",") != "0,2" {
		t.Fatalf("offsets = %v", offsets)
	}
}

func TestBinaryHandleFetchesSlotAndDecrypts(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	page := map[string]any{
		"total": 1,
		"items": []any{
			map[string]any{
				"connection_id": "csc-1", "user_id": "person-1", "display_name": "Anna",
				"values": map[string]any{
					"logo": map[string]any{"value_url": "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file", "live": true},
				},
			},
		},
	}
	pageJSON, _ := json.Marshal(page)
	slotBody, _ := json.Marshal(map[string]any{"encrypted": true, "value": v.Binary.Wrapper})

	c, d := newTestClient(t, cfg, func(path string, _ map[string][]string) (int, string) {
		switch {
		case strings.HasSuffix(path, "/request-fields"):
			return 200, requestFieldsBody
		case strings.HasSuffix(path, "/connections"):
			return 200, string(pageJSON)
		case strings.HasSuffix(path, "/slots/sf-9/file"):
			return 200, string(slotBody)
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	})

	conns, err := c.ConnectionsList(context.Background(), 100, 0)
	if err != nil {
		t.Fatalf("ConnectionsList: %v", err)
	}
	handle := conns[0].Values["logo"].Value.(*BinaryHandle)
	for _, g := range d.gets {
		if strings.Contains(g, "/file") {
			t.Fatalf("should be lazy until Bytes()")
		}
	}
	data, err := handle.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	fetchedFile := false
	for _, g := range d.gets {
		if strings.HasSuffix(g, "/slots/sf-9/file") {
			fetchedFile = true
		}
	}
	if !fetchedFile {
		t.Fatal("expected the slot file to be fetched")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != v.Binary.InnerFullSHA256 {
		t.Fatal("binary bytes sha256 mismatch")
	}
}

func TestConnectionByID(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	detail := map[string]any{
		"connection_id": "csc-7", "user_id": "person-7",
		"values": map[string]any{"work_email": map[string]any{"value": v.Text.Wrapper, "live": true}},
	}
	detailJSON, _ := json.Marshal(detail)
	c, _ := newTestClient(t, cfg, func(path string, _ map[string][]string) (int, string) {
		if strings.HasSuffix(path, "/request-fields") {
			return 200, requestFieldsBody
		}
		if strings.HasSuffix(path, "/connections/csc-7") {
			return 200, string(detailJSON)
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	})
	conn, err := c.Connection(context.Background(), "csc-7")
	if err != nil {
		t.Fatalf("Connection: %v", err)
	}
	if conn.ID != "csc-7" || conn.PersonID != "person-7" || conn.Values["work_email"].Value != v.Text.Plaintext {
		t.Fatalf("conn = %+v", conn)
	}
}

func TestLogsDeserialize(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	body := `{"total":2,"items":[
		{"type":"email","message":"stale-queue alert","metadata":{"days":3},"created_at":"2026-06-17T06:00:00Z"},
		{"type":"purge","message":"purged 4","metadata":{"count":4},"created_at":"2026-06-17T07:00:00Z"}
	]}`
	var seenLimit string
	c, _ := newTestClient(t, cfg, func(path string, params map[string][]string) (int, string) {
		if strings.HasSuffix(path, "/logs") {
			seenLimit = params["limit"][0]
			return 200, body
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	})
	logs, err := c.Logs(context.Background(), 50, 0)
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	if len(logs) != 2 || logs[0].Type != "email" {
		t.Fatalf("logs = %+v", logs)
	}
	md := logs[0].Metadata.(map[string]any)
	// json.Number for the metadata int.
	if asString(md["days"]) != "3" {
		t.Fatalf("metadata days = %#v", md["days"])
	}
	if seenLimit != "50" {
		t.Fatalf("limit param = %q", seenLimit)
	}
}

func TestProcessChangesDrainsThroughPump(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	served := false
	wrapperJSON, _ := json.Marshal(v.Text.Wrapper)
	feed := `{"changes":[
		{"id":"chg-1","event":"field_updated","person_user_id":"person-1","slug":"work_email","value":` + string(wrapperJSON) + `,"live":true,"at":"2026-06-17T12:00:00Z"},
		{"id":"chg-2","event":"connection_created","person_user_id":"person-2","at":"2026-06-17T12:05:00Z"}
	]}`

	c, _ := newTestClient(t, cfg, func(path string, _ map[string][]string) (int, string) {
		if strings.HasSuffix(path, "/request-fields") {
			return 200, requestFieldsBody
		}
		if strings.HasSuffix(path, "/changes") {
			if served {
				return 200, `{"changes":[]}`
			}
			served = true
			return 200, feed
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	})

	type seenItem struct {
		id, event string
		value     any
	}
	var seen []seenItem
	err := c.ProcessChanges(func(ch Change) error {
		seen = append(seen, seenItem{ch.ID, ch.Event, ch.Value})
		return nil
	}, PumpOptions{})
	if err != nil {
		t.Fatalf("ProcessChanges: %v", err)
	}
	if len(seen) != 2 || seen[0].id != "chg-1" || seen[1].id != "chg-2" {
		t.Fatalf("seen = %+v", seen)
	}
	if seen[0].event != "field_updated" || seen[0].value != v.Text.Plaintext {
		t.Fatalf("seen[0] = %+v", seen[0])
	}
	if seen[1].event != "connection_created" || seen[1].value != nil {
		t.Fatalf("seen[1] = %+v", seen[1])
	}
	p, _ := c.Pump()
	if pend, _ := p.Buffer().Pending(); len(pend) != 0 {
		t.Fatalf("buffer not fully drained")
	}
}

func TestFromConfigLoadsKey(t *testing.T) {
	v := loadVector(t)
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(pemPath, []byte(v.EncryptedPrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON, _ := json.Marshal(map[string]any{
		"api_url": "https://api.allme.fyi", "client_id": "svc_abc", "client_secret": "s",
		"service_private_key": pemPath, "key_passphrase": v.Passphrase, "cache_dir": filepath.Join(dir, "cache"),
	})
	if err := os.WriteFile(cfgPath, cfgJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := FromConfig(cfgPath)
	if err != nil {
		t.Fatalf("FromConfig: %v", err)
	}
	// The key is loaded into memory and the decrypt closure works on the vector.
	pt, err := c.decryptValue(v.Text.Wrapper)
	if err != nil || pt != v.Text.Plaintext {
		t.Fatalf("decryptValue = %q, %v", pt, err)
	}
}

// ── company documents (write) ──────────────────────────────────────────────────

// writeReq captures a recorded write-verb request for assertions.
type writeReq struct {
	method      string
	path        string
	jsonBody    map[string]any // decoded JSON body (nil for raw)
	rawBody     []byte         // raw body bytes when Content-Type wasn't application/json
	contentType string
}

// rwDoer routes GET to a get-router, the OAuth token POST to a canned token, and
// every other write verb (POST/PUT/DELETE to non-token paths) to a write-router.
type rwDoer struct {
	getRoute   func(path string, params map[string][]string) (int, string)
	writeRoute func(w writeReq) (int, string)
	gets       []string
	writes     []writeReq
}

func (d *rwDoer) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet {
		d.gets = append(d.gets, req.URL.Path)
		status, body := d.getRoute(req.URL.Path, req.URL.Query())
		return jsonResp(status, body), nil
	}
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/oauth2/token") {
		return jsonResp(200, `{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}`), nil
	}
	wr := writeReq{method: req.Method, path: req.URL.Path, contentType: req.Header.Get("Content-Type")}
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		wr.rawBody = raw
		if wr.contentType == "application/json" {
			_ = json.Unmarshal(raw, &wr.jsonBody)
		}
	}
	d.writes = append(d.writes, wr)
	status, body := d.writeRoute(wr)
	return jsonResp(status, body), nil
}

func newTestClientRW(t *testing.T, cfg *Config,
	getRoute func(string, map[string][]string) (int, string),
	writeRoute func(writeReq) (int, string)) (*Client, *rwDoer) {
	t.Helper()
	d := &rwDoer{getRoute: getRoute, writeRoute: writeRoute}
	httpc := NewHTTPClient(cfg, WithDoer(d))
	c, err := New(cfg, WithHTTPClient(httpc), WithLogger(log.New(io.Discard, "", 0)), withClientSleep(func(_ time.Duration) {}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, d
}

func noGET(t *testing.T) func(string, map[string][]string) (int, string) {
	return func(path string, _ map[string][]string) (int, string) {
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	}
}

// vectorPubSPKIB64 is the vector key's PUBLIC half as base64 SPKI/DER (what
// GET /api/keys returns).
func vectorPubSPKIB64(t *testing.T, v *vectorDoc) string {
	t.Helper()
	priv, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestCreateDocumentBroadcastJSONIsPlaintext(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)

	var posted map[string]any
	c, _ := newTestClientRW(t, cfg, noGET(t), func(w writeReq) (int, string) {
		if w.method != "POST" || !strings.HasSuffix(w.path, "/documents") {
			t.Fatalf("unexpected write %s %s", w.method, w.path)
		}
		posted = w.jsonBody
		valJSON, _ := json.Marshal(w.jsonBody["value"])
		return 201, `{"id":"d1","kind":"document","name":"Terms","description":null,` +
			`"status":"active","payload_kind":"json","is_private":false,"value":` + string(valJSON) +
			`,"metadata":null,"created_at":null,"updated_at":null}`
	})

	doc, err := c.CreateDocument(context.Background(), CreateDocumentOptions{
		Name: "Terms", PayloadKind: "json",
		JSONValue: map[string]any{"url": "x", "v": "1"}, Status: "active",
	})
	if err != nil {
		t.Fatalf("CreateDocument: %v", err)
	}
	if posted["target"] != nil {
		t.Fatalf("broadcast target should be nil, got %#v", posted["target"])
	}
	val, ok := posted["value"].(map[string]any)
	if !ok || val["url"] != "x" || val["v"] != "1" {
		t.Fatalf("broadcast value should be plaintext object, got %#v", posted["value"])
	}
	if _, enc := val["_enc"]; enc {
		t.Fatalf("broadcast value must not be encrypted: %#v", val)
	}
	if posted["is_private"] != false {
		t.Fatalf("is_private = %#v", posted["is_private"])
	}
	if doc.ID != "d1" || doc.Status != "active" {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestCreateDocumentPerPersonEncryptsForBothPrivacy(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	spki := vectorPubSPKIB64(t, v)
	priv, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)

	for _, isPrivate := range []bool{false, true} {
		keysFetched := 0
		getRoute := func(path string, _ map[string][]string) (int, string) {
			if !strings.HasSuffix(path, "/api/keys/ABC123") {
				t.Fatalf("unexpected GET %s", path)
			}
			keysFetched++
			return 200, `{"public_key":"` + spki + `"}`
		}
		var captured map[string]any
		writeRoute := func(w writeReq) (int, string) {
			captured = w.jsonBody
			valJSON, _ := json.Marshal(w.jsonBody["value"])
			ip := "false"
			if isPrivate {
				ip = "true"
			}
			return 201, `{"id":"d2","kind":"document","name":"PP","description":null,` +
				`"status":"active","payload_kind":"json","is_private":` + ip + `,"value":` + string(valJSON) +
				`,"metadata":null,"created_at":null,"updated_at":null}`
		}
		c, _ := newTestClientRW(t, cfg, getRoute, writeRoute)

		doc, err := c.CreateDocument(context.Background(), CreateDocumentOptions{
			Name: "PP", PayloadKind: "json", JSONValue: map[string]any{"plan": "pro"},
			ConnectionID: "conn-1", ShareCode: "ABC123", IsPrivate: isPrivate,
		})
		if err != nil {
			t.Fatalf("CreateDocument(is_private=%v): %v", isPrivate, err)
		}
		if keysFetched != 1 {
			t.Fatalf("expected 1 key fetch, got %d", keysFetched)
		}
		val, ok := captured["value"].(map[string]any)
		if !ok || !isEncWrapper(val) {
			t.Fatalf("per-person value must be ENCRYPTED (any is_private), got %#v", captured["value"])
		}
		for _, f := range []string{"k", "iv", "d"} {
			if _, ok := val[f]; !ok {
				t.Fatalf("wrapper missing %q: %#v", f, val)
			}
		}
		target, ok := captured["target"].(map[string]any)
		if !ok || target["connection_id"] != "conn-1" {
			t.Fatalf("target = %#v", captured["target"])
		}
		if captured["is_private"] != isPrivate {
			t.Fatalf("is_private = %#v, want %v", captured["is_private"], isPrivate)
		}
		// round-trips through the SDK's own decrypt → the original plaintext
		pt, err := Decrypt(val, priv)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(pt), &got); err != nil || got["plan"] != "pro" {
			t.Fatalf("decrypted = %q (%v)", pt, err)
		}
		if doc.ID != "d2" {
			t.Fatalf("doc id = %q", doc.ID)
		}
	}
}

func TestCreateDocumentPrivateBroadcastFails(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	c, _ := newTestClientRW(t, cfg, noGET(t), func(writeReq) (int, string) {
		t.Fatal("should not write for a private broadcast")
		return 0, ""
	})
	_, err := c.CreateDocument(context.Background(), CreateDocumentOptions{
		Name: "x", PayloadKind: "json", JSONValue: map[string]any{"a": 1}, IsPrivate: true,
	})
	if err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ConfigError for private broadcast, got %v", err)
	}
}

func TestCreateDocumentContractWithoutTargetFails(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	c, _ := newTestClientRW(t, cfg, noGET(t), func(writeReq) (int, string) {
		t.Fatal("should not write for a targetless contract")
		return 0, ""
	})
	_, err := c.CreateDocument(context.Background(), CreateDocumentOptions{
		Name: "Agreement", PayloadKind: "json", Kind: "agreement", RequiresSignature: true,
		JSONValue: map[string]any{"a": 1},
	})
	if err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ConfigError for a targetless contract, got %v", err)
	}
}

func TestCreateDocumentInvalidKindFails(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	c, _ := newTestClientRW(t, cfg, noGET(t), func(writeReq) (int, string) {
		t.Fatal("should not write for an invalid kind")
		return 0, ""
	})
	_, err := c.CreateDocument(context.Background(), CreateDocumentOptions{
		Name: "x", PayloadKind: "json", Kind: "invalid", JSONValue: map[string]any{"a": 1},
	})
	if err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ConfigError for an invalid kind, got %v", err)
	}
}

func TestCreateDocumentFileBroadcastUploadsRawBytes(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	c, d := newTestClientRW(t, cfg, noGET(t), func(w writeReq) (int, string) {
		if strings.HasSuffix(w.path, "/documents") {
			return 201, `{"id":"f1","kind":"document","name":"C","description":null,` +
				`"status":"active","payload_kind":"file","is_private":false,"value":{"_pending":true},` +
				`"metadata":null,"created_at":null,"updated_at":null}`
		}
		if !strings.HasSuffix(w.path, "/documents/f1/file") {
			t.Fatalf("unexpected write path %s", w.path)
		}
		return 200, `{"id":"f1"}`
	})

	if _, err := c.CreateDocument(context.Background(), CreateDocumentOptions{
		Name: "C", PayloadKind: "file", FileBytes: []byte("%PDF-1.4 x"), FileMime: "application/pdf",
	}); err != nil {
		t.Fatalf("CreateDocument: %v", err)
	}
	if len(d.writes) != 2 {
		t.Fatalf("expected 2 writes, got %d", len(d.writes))
	}
	if !strings.HasSuffix(d.writes[0].path, "/documents") || d.writes[0].jsonBody["target"] != nil {
		t.Fatalf("create body = %+v", d.writes[0])
	}
	if !strings.HasSuffix(d.writes[1].path, "/documents/f1/file") {
		t.Fatalf("upload path = %s", d.writes[1].path)
	}
	if string(d.writes[1].rawBody) != "%PDF-1.4 x" {
		t.Fatalf("upload body = %q, want raw plaintext bytes", d.writes[1].rawBody)
	}
}

func TestCreateDocumentFilePerPersonUploadsWrapperBytes(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	spki := vectorPubSPKIB64(t, v)
	priv, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)

	c, d := newTestClientRW(t, cfg,
		func(path string, _ map[string][]string) (int, string) {
			return 200, `{"public_key":"` + spki + `"}`
		},
		func(w writeReq) (int, string) {
			if strings.HasSuffix(w.path, "/documents") {
				return 201, `{"id":"f2","kind":"document","name":"C","description":null,` +
					`"status":"active","payload_kind":"file","is_private":true,"value":{"_pending":true},` +
					`"metadata":null,"created_at":null,"updated_at":null}`
			}
			return 200, `{"id":"f2"}`
		})

	if _, err := c.CreateDocument(context.Background(), CreateDocumentOptions{
		Name: "C", PayloadKind: "file", FileBytes: []byte("hello-bytes"),
		FileMime: "application/pdf", PersonUserID: "u1", ShareCode: "ABC123", IsPrivate: true,
	}); err != nil {
		t.Fatalf("CreateDocument: %v", err)
	}
	upload := d.writes[1].rawBody
	if len(upload) == 0 {
		t.Fatal("expected an upload body")
	}
	var wrapper map[string]any
	if err := json.Unmarshal(upload, &wrapper); err != nil {
		t.Fatalf("upload not JSON: %v", err)
	}
	if !isEncWrapper(wrapper) {
		t.Fatalf("upload must be a ciphertext wrapper, got %#v", wrapper)
	}
	// decrypt → the {"file":"data:...base64,..."} envelope holding the original bytes
	envJSON, err := Decrypt(wrapper, priv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		t.Fatalf("envelope not JSON: %v", err)
	}
	fileURI, _ := env["file"].(string)
	if !strings.HasPrefix(fileURI, "data:application/pdf;base64,") {
		t.Fatalf("file envelope = %q", fileURI)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.SplitN(fileURI, ",", 2)[1])
	if err != nil || string(decoded) != "hello-bytes" {
		t.Fatalf("decoded file bytes = %q (%v)", decoded, err)
	}
}

func TestDocumentVerbsHitRightPath(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	getRoute := func(path string, _ map[string][]string) (int, string) {
		if strings.HasSuffix(path, "/documents") {
			return 200, `{"total":0,"items":[]}`
		}
		if strings.Contains(path, "/documents/d9") {
			return 200, `{"id":"d9","payload_kind":"json","is_private":false,"value":{"a":1}}`
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	}
	writeRoute := func(writeReq) (int, string) {
		return 200, `{"id":"d9","payload_kind":"json","is_private":false,"value":{"a":1},"status":"ended"}`
	}
	c, d := newTestClientRW(t, cfg, getRoute, writeRoute)

	docs, err := c.ListDocuments(context.Background(), ListDocumentsOptions{Status: "active"})
	if err != nil {
		t.Fatalf("ListDocuments: %v", err)
	}
	if len(docs) != 0 {
		t.Fatalf("expected 0 docs, got %d", len(docs))
	}
	doc, err := c.Document(context.Background(), "d9")
	if err != nil || doc.ID != "d9" {
		t.Fatalf("Document = %+v, %v", doc, err)
	}
	if _, err := c.UpdateDocumentStatus(context.Background(), "d9", "ended"); err != nil {
		t.Fatalf("UpdateDocumentStatus: %v", err)
	}
	if _, err := c.UpdateDocumentMetadata(context.Background(), "d9", UpdateDocumentMetadataOptions{Name: "renamed"}); err != nil {
		t.Fatalf("UpdateDocumentMetadata: %v", err)
	}
	if err := c.DeleteDocument(context.Background(), "d9"); err != nil {
		t.Fatalf("DeleteDocument: %v", err)
	}

	puts, deletes := 0, 0
	for _, w := range d.writes {
		suffix := w.path
		if i := strings.Index(w.path, "/api/company-data"); i >= 0 {
			suffix = w.path[i+len("/api/company-data"):]
		}
		switch {
		case w.method == "PUT" && suffix == "/documents/d9":
			puts++
		case w.method == "DELETE" && suffix == "/documents/d9":
			deletes++
		}
	}
	if puts != 2 {
		t.Fatalf("expected 2 PUTs to /documents/d9, got %d", puts)
	}
	if deletes != 1 {
		t.Fatalf("expected 1 DELETE to /documents/d9, got %d", deletes)
	}
}

// ── connect requests (service-initiated; idea 2) ────────────────────────────

func TestSendConnectRequest(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)

	var captured map[string]any
	c, _ := newTestClientRW(t, cfg, noGET(t), func(w writeReq) (int, string) {
		if w.method != "POST" || !strings.HasSuffix(w.path, "/company-data/connect-requests") {
			t.Fatalf("unexpected write %s %s", w.method, w.path)
		}
		captured = w.jsonBody
		return 201, `{"request_id":"req-1"}`
	})

	rid, err := c.SendConnectRequest(context.Background(), "  ABC123 ")
	if err != nil {
		t.Fatalf("SendConnectRequest: %v", err)
	}
	if rid != "req-1" {
		t.Fatalf("request_id = %q", rid)
	}
	if captured["share_code"] != "ABC123" {
		t.Fatalf("share_code = %#v (should be trimmed)", captured["share_code"])
	}
}

func TestSendConnectRequestBlankFails(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	c, _ := newTestClientRW(t, cfg, noGET(t), func(writeReq) (int, string) {
		t.Fatal("should not write for a blank share code")
		return 0, ""
	})
	if _, err := c.SendConnectRequest(context.Background(), "   "); err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ConfigError for a blank share code, got %v", err)
	}
}

func TestChangeParsesConnectRequestOutcomeEvents(t *testing.T) {
	noType := func(string) string { return "" }
	echo := func(v any) (string, error) { return "", nil }

	accepted, err := changeFromAPI(map[string]any{
		"id": "c1", "event": "connection_request_accepted", "request_id": "req-9",
		"person_user_id": "person-1", "share_code": "P1CODE", "at": "2026-06-23T10:00:00Z",
	}, noType, echo, nil)
	if err != nil {
		t.Fatalf("changeFromAPI accepted: %v", err)
	}
	if accepted.Event != "connection_request_accepted" || accepted.RequestID != "req-9" {
		t.Fatalf("accepted = %+v", accepted)
	}
	if accepted.PersonID != "person-1" || accepted.ShareCode != "P1CODE" {
		t.Fatalf("accepted identity = %+v", accepted)
	}
	if accepted.Slug != "" || accepted.Value != nil {
		t.Fatalf("accepted should carry no slot/value: %+v", accepted)
	}

	rejected, err := changeFromAPI(map[string]any{
		"id": "c2", "event": "connection_request_rejected", "request_id": "req-8",
		"person_user_id": "person-2",
	}, noType, echo, nil)
	if err != nil {
		t.Fatalf("changeFromAPI rejected: %v", err)
	}
	if rejected.Event != "connection_request_rejected" || rejected.RequestID != "req-8" {
		t.Fatalf("rejected = %+v", rejected)
	}

	created, err := changeFromAPI(map[string]any{
		"id": "c3", "event": "connection_created", "person_user_id": "person-3",
	}, noType, echo, nil)
	if err != nil {
		t.Fatalf("changeFromAPI created: %v", err)
	}
	if created.RequestID != "" {
		t.Fatalf("request_id should be empty for unrelated events, got %q", created.RequestID)
	}
}

func TestFromConfigBadPassphraseIsConfigError(t *testing.T) {
	v := loadVector(t)
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(pemPath, []byte(v.EncryptedPrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	cfgJSON, _ := json.Marshal(map[string]any{
		"api_url": "https://api.allme.fyi", "client_id": "x", "client_secret": "s",
		"service_private_key": pemPath, "key_passphrase": "WRONG", "cache_dir": filepath.Join(dir, "cache"),
	})
	if err := os.WriteFile(cfgPath, cfgJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := FromConfig(cfgPath)
	if err == nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ConfigError, got %v", err)
	}
}
