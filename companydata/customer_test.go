package companydata

// CustomerClient (b2b, #168) — parse + method-shape + key-sourcing tests.
// Reuses the shared decryption vector's key as the customer ACCOUNT key.

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func customerConfig(t *testing.T, v *vectorDoc) *Config {
	t.Helper()
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "account-key.pem")
	if err := os.WriteFile(pemPath, []byte(v.EncryptedPrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Config{
		APIURL:               "https://api.allme.fyi",
		CustomerClientID:     "acct_abc",
		CustomerClientSecret: "topsecret",
		AccountPrivateKey:    pemPath,
		AccountPassphrase:    v.Passphrase,
		CacheDir:             filepath.Join(dir, "cache"),
	}
}

func newTestCustomer(t *testing.T, cfg *Config,
	getRoute func(string, map[string][]string) (int, string),
	writeRoute func(writeReq) (int, string)) (*CustomerClient, *rwDoer) {
	t.Helper()
	d := &rwDoer{getRoute: getRoute, writeRoute: writeRoute}
	httpc := NewHTTPClient(cfg, WithDoer(d))
	c, err := NewCustomer(cfg, WithCustomerHTTP(httpc))
	if err != nil {
		t.Fatalf("NewCustomer: %v", err)
	}
	c.logger = log.New(io.Discard, "", 0)
	c.sleep = func(time.Duration) {}
	return c, d
}

func TestCustomerConfigRequiresAcctPair(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	_ = os.WriteFile(p, []byte(`{"api_url":"https://api.allme.fyi"}`), 0o600)
	if _, err := ConfigFromCustomerFile(p); err == nil {
		t.Fatal("expected ConfigError for a customer config missing the acct_* pair")
	}
}

func TestCustomerConnectionsParse(t *testing.T) {
	v := loadVector(t)
	cfg := customerConfig(t, v)
	body := `{"connections":[{"id":"conn-1","customer_type":"company",` +
		`"company":{"user_id":"co-1","display_name":"Acme BV","share_code":"ACME01"},` +
		`"company_profile":[{"slug":"company_email","value":"hi@acme.example"}],` +
		`"services":[{"service_link_id":"sl-1","service_name":"CRM","shared":[{"slug":"x","value":"y"}]}]}]}`
	c, _ := newTestCustomer(t, cfg,
		func(string, map[string][]string) (int, string) { return 200, body },
		func(writeReq) (int, string) { return 200, "{}" })
	conns, err := c.Connections()
	if err != nil {
		t.Fatalf("Connections: %v", err)
	}
	if len(conns) != 1 || conns[0].CustomerType != "company" || conns[0].CompanyName != "Acme BV" || conns[0].CompanyCode != "ACME01" {
		t.Fatalf("bad parse: %+v", conns)
	}
	if len(conns[0].Services) != 1 || conns[0].Services[0].ServiceName != "CRM" {
		t.Fatalf("bad service parse: %+v", conns[0].Services)
	}
}

func TestCustomerProvideConsentEncryptsToServiceKey(t *testing.T) {
	v := loadVector(t)
	cfg := customerConfig(t, v)
	spki := vectorPubSPKIB64(t, v)
	c, d := newTestCustomer(t, cfg,
		func(path string, _ map[string][]string) (int, string) {
			if path == "/api/keys/ACME01/CRM" {
				return 200, `{"public_key":"` + spki + `"}`
			}
			return 200, "{}"
		},
		func(w writeReq) (int, string) { return 200, `{"ok":true}` })
	if _, err := c.ProvideConsent("consent-1", []TypedAnswer{{RequestFieldID: "rf-1", Value: "billing@me.example"}}, "ACME01", "CRM"); err != nil {
		t.Fatalf("ProvideConsent: %v", err)
	}
	last := d.writes[len(d.writes)-1]
	if last.path != "/api/company-connections/consents/consent-1/provide" {
		t.Fatalf("wrong path: %s", last.path)
	}
	decisions := last.jsonBody["decisions"].([]any)
	dec := decisions[0].(map[string]any)
	if dec["kind"] != "typed" {
		t.Fatalf("wrong kind: %v", dec["kind"])
	}
	priv, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	plain, err := Decrypt(dec["value"], priv)
	if err != nil || plain != "billing@me.example" {
		t.Fatalf("decrypt: %v %q", err, plain)
	}
}

func TestCustomerDocumentFileDecryptsWithAccountKey(t *testing.T) {
	v := loadVector(t)
	cfg := customerConfig(t, v)
	priv, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	wrapper, err := EncryptForPublicKey(`{"file":"data:application/pdf;base64,AAA","name":"contract.pdf"}`, &priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	wjb, _ := json.Marshal(map[string]any{"encrypted": true, "value": wrapper})
	wj := string(wjb)
	c, _ := newTestCustomer(t, cfg,
		func(string, map[string][]string) (int, string) { return 200, wj },
		func(writeReq) (int, string) { return 200, "{}" })
	out, err := c.DocumentFile("conn-1", "doc-1")
	if err != nil {
		t.Fatalf("DocumentFile: %v", err)
	}
	m := out.(map[string]any)
	if m["name"] != "contract.pdf" {
		t.Fatalf("bad doc: %+v", m)
	}
}

func TestCustomerDrainBatchUsesCustomerChanges(t *testing.T) {
	v := loadVector(t)
	cfg := customerConfig(t, v)
	hit := false
	c, _ := newTestCustomer(t, cfg,
		func(path string, _ map[string][]string) (int, string) {
			if path == "/api/customer/changes" {
				hit = true
				return 200, `{"changes":[{"id":"ch-1","event":"share_changed","customer_type":"company"}]}`
			}
			return 200, "{}"
		},
		func(writeReq) (int, string) { return 200, "{}" })
	changes, err := c.DrainBatch(10)
	if err != nil {
		t.Fatalf("DrainBatch: %v", err)
	}
	if !hit || len(changes) != 1 || changes[0].ID != "ch-1" || changes[0].CustomerType != "company" {
		t.Fatalf("bad drain: hit=%v %+v", hit, changes)
	}
}

func TestCustomerNoSignAcceptMethods(t *testing.T) {
	typ := reflect.TypeOf(&CustomerClient{})
	for _, banned := range []string{"Sign", "Accept", "SignDocument", "AcceptDocument", "SignEmailCode"} {
		if _, ok := typ.MethodByName(banned); ok {
			t.Fatalf("CustomerClient must not expose %s (D6)", banned)
		}
	}
}
