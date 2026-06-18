package companydata

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Output-model tests. They build hardened API objects with
// ciphertext fields (using the shared vector's key, encrypting fresh values for
// structured types), and assert the typed, slug-keyed, decrypted output — and
// that the person's source field is never present.

// encryptForVectorKey encrypts plaintext into a platform wrapper with the vector
// key's PUBLIC half (RSA-OAEP-SHA256 + AES-256-GCM).
func encryptForVectorKey(t *testing.T, v *vectorDoc, plaintext string) map[string]any {
	t.Helper()
	priv, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	pub := &priv.PublicKey
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	ct := gcm.Seal(nil, iv, []byte(plaintext), nil)
	k, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}
	return map[string]any{
		"_enc": 1,
		"k":    base64.StdEncoding.EncodeToString(k),
		"iv":   base64.StdEncoding.EncodeToString(iv),
		"d":    base64.StdEncoding.EncodeToString(ct),
	}
}

func vectorDecryptValue(t *testing.T, v *vectorDoc) (decryptValueFn, *rsa.PrivateKey) {
	t.Helper()
	priv, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	return func(w any) (string, error) { return Decrypt(w, priv) }, priv
}

func TestRequestFieldsParsedAndMandatoryFolded(t *testing.T) {
	body := map[string]any{"request_fields": []any{
		map[string]any{"slug": "work_email", "label": "Work email", "type": "email",
			"one_time": false, "mandatory_provide": true, "mandatory_connected": false},
		map[string]any{"slug": "ref", "label": "Ref", "type": "text",
			"one_time": true, "mandatory_provide": false, "mandatory_connected": true},
	}}
	fields := requestFieldsFromAPI(body)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}
	if fields[0].Slug != "work_email" || !fields[0].Mandatory || fields[0].OneTime {
		t.Fatalf("field0 = %+v", fields[0])
	}
	if !fields[1].OneTime || !fields[1].Mandatory { // mandatory_connected folds into Mandatory
		t.Fatalf("field1 = %+v", fields[1])
	}
}

func TestRequestFieldCoercesXMLBoolStrings(t *testing.T) {
	body := map[string]any{"request_fields": []any{
		map[string]any{"slug": "s", "label": "L", "type": "email",
			"one_time": "false", "mandatory_provide": "true", "mandatory_connected": "false"},
	}}
	f := requestFieldsFromAPI(body)[0]
	if f.OneTime || !f.Mandatory {
		t.Fatalf("xml bool coercion: %+v", f)
	}
}

func TestConnectionDetailTypedSlugKeyed(t *testing.T) {
	v := loadVector(t)
	decryptValue, _ := vectorDecryptValue(t, v)
	addrWrapper := encryptForVectorKey(t, v, `{"city":"Utrecht","country":"NL"}`)

	obj := map[string]any{
		"connection_id": "csc-1",
		"user_id":       "person-1",
		"display_name":  "Anna",
		"connected_at":  "2026-06-10T00:00:00Z",
		"values": map[string]any{
			"work_email":      map[string]any{"value": v.Text.Wrapper, "live": true, "updatedAt": "2026-06-17T10:00:00Z"},
			"billing_address": map[string]any{"value": addrWrapper, "live": false},
			"logo":            map[string]any{"value_url": "https://api.allme.fyi/api/company-data/connections/csc-1/slots/sf-9/file", "live": true},
		},
	}
	typeForSlug := func(slug string) string {
		return map[string]string{"work_email": "email", "billing_address": "address", "logo": "photo"}[slug]
	}
	conn, err := connectionFromAPI(obj, typeForSlug, decryptValue, nil, obj)
	if err != nil {
		t.Fatalf("connectionFromAPI: %v", err)
	}
	if conn.ID != "csc-1" || conn.PersonID != "person-1" || conn.DisplayName != "Anna" {
		t.Fatalf("identity mismatch: %+v", conn)
	}
	// text → decrypted string
	if conn.Values["work_email"].Value != v.Text.Plaintext {
		t.Fatalf("work_email = %#v", conn.Values["work_email"].Value)
	}
	if !conn.Values["work_email"].Live {
		t.Fatal("work_email should be live")
	}
	if conn.Values["work_email"].UpdatedAt == nil {
		t.Fatal("work_email should have updatedAt")
	}
	// structured → parsed map
	addr, ok := conn.Values["billing_address"].Value.(map[string]any)
	if !ok || addr["city"] != "Utrecht" || addr["country"] != "NL" {
		t.Fatalf("billing_address = %#v", conn.Values["billing_address"].Value)
	}
	// binary → lazy handle
	if _, ok := conn.Values["logo"].Value.(*BinaryHandle); !ok {
		t.Fatalf("logo should be *BinaryHandle, got %T", conn.Values["logo"].Value)
	}
}

func TestBinaryHandleLazyFetchAndDecrypt(t *testing.T) {
	v := loadVector(t)
	decryptValue, _ := vectorDecryptValue(t, v)

	fetchCalls := 0
	binaryFetch := func(url string) (any, error) {
		fetchCalls++
		// The slot endpoint serves {"encrypted":true,"value":<wrapper>}; here the
		// fetch callback already unwraps to the inner wrapper.
		return v.Binary.Wrapper, nil
	}
	obj := map[string]any{
		"connection_id": "csc-1", "user_id": "person-1", "display_name": "Anna",
		"values": map[string]any{
			"logo": map[string]any{"value_url": "https://api.allme.fyi/.../slots/sf-9/file", "live": true},
		},
	}
	conn, err := connectionFromAPI(obj, func(string) string { return "photo" }, decryptValue, binaryFetch, obj)
	if err != nil {
		t.Fatalf("connectionFromAPI: %v", err)
	}
	handle := conn.Values["logo"].Value.(*BinaryHandle)
	if fetchCalls != 0 {
		t.Fatal("handle should be lazy (no fetch yet)")
	}
	data, err := handle.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if fetchCalls != 1 {
		t.Fatalf("expected 1 fetch, got %d", fetchCalls)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != v.Binary.InnerFullSHA256 {
		t.Fatalf("binary bytes sha256 mismatch")
	}
	// Second call should not re-fetch (cached envelope).
	if _, err := handle.Bytes(); err != nil {
		t.Fatalf("Bytes (2): %v", err)
	}
	if fetchCalls != 1 {
		t.Fatalf("expected cached envelope (1 fetch), got %d", fetchCalls)
	}
}

func TestConnectionHasNoPersonSourceField(t *testing.T) {
	v := loadVector(t)
	decryptValue, _ := vectorDecryptValue(t, v)
	obj := map[string]any{
		"connection_id": "csc-1", "user_id": "person-1",
		"values": map[string]any{"work_email": map[string]any{"value": v.Text.Wrapper, "live": true}},
	}
	conn, err := connectionFromAPI(obj, func(string) string { return "email" }, decryptValue, nil, obj)
	if err != nil {
		t.Fatalf("connectionFromAPI: %v", err)
	}
	// Marshal the Raw + the values' Raw and assert no field_id / source slug leaks.
	raw, _ := json.Marshal(conn.Raw)
	if containsAny(string(raw), "field_id", "source_field", "source_slug") {
		t.Fatalf("source field leaked in raw: %s", raw)
	}
}

func TestChangeFieldUpdatedTypedAndIDPopulated(t *testing.T) {
	v := loadVector(t)
	decryptValue, _ := vectorDecryptValue(t, v)
	obj := map[string]any{
		"id": "chg-1", "event": "field_updated", "person_user_id": "person-1",
		"slug": "work_email", "at": "2026-06-17T12:00:00Z", "live": true, "value": v.Text.Wrapper,
	}
	change, err := changeFromAPI(obj, func(string) string { return "email" }, decryptValue, nil)
	if err != nil {
		t.Fatalf("changeFromAPI: %v", err)
	}
	if change.ID != "chg-1" || change.Event != "field_updated" || change.PersonID != "person-1" {
		t.Fatalf("change = %+v", change)
	}
	if change.Slug != "work_email" || change.Value != v.Text.Plaintext || !change.Live {
		t.Fatalf("change typing = %+v", change)
	}
}

func TestChangeConsentEventHasSlugNoValue(t *testing.T) {
	obj := map[string]any{"id": "chg-9", "event": "consent_accepted", "person_user_id": "p", "slug": "work_email"}
	change, err := changeFromAPI(obj, func(string) string { return "email" }, func(any) (string, error) { return "", nil }, nil)
	if err != nil {
		t.Fatalf("changeFromAPI: %v", err)
	}
	if change.Event != "consent_accepted" || change.Slug != "work_email" {
		t.Fatalf("change = %+v", change)
	}
	if change.Value != nil {
		t.Fatalf("consent event should carry no value, got %#v", change.Value)
	}
}

func TestChangeIncludesShareCode(t *testing.T) {
	// Every change event carries the person's profile share_code (nullable).
	body := map[string]any{"changes": []any{
		map[string]any{"id": "chg-1", "event": "connection_created",
			"person_user_id": "person-1", "share_code": "ABC123", "at": "2026-06-17T12:00:00Z"},
		map[string]any{"id": "chg-2", "event": "connection_created",
			"person_user_id": "person-2", "at": "2026-06-17T12:00:00Z"}, // no share_code -> ""
	}}
	changes, err := changesFromAPI(body, func(string) string { return "" }, func(any) (string, error) { return "", nil }, nil)
	if err != nil {
		t.Fatalf("changesFromAPI: %v", err)
	}
	if changes[0].ShareCode != "ABC123" {
		t.Fatalf("change0 ShareCode = %q, want ABC123", changes[0].ShareCode)
	}
	if changes[1].ShareCode != "" {
		t.Fatalf("change1 ShareCode = %q, want empty", changes[1].ShareCode)
	}
}

func TestLogEntriesParsed(t *testing.T) {
	body := map[string]any{"total": 2, "items": []any{
		map[string]any{"type": "email", "message": "alert", "metadata": map[string]any{"days": 3}, "created_at": "2026-06-17T06:00:00Z"},
		map[string]any{"type": "purge", "message": "purged 4", "metadata": map[string]any{"count": 4}, "created_at": "2026-06-17T07:00:00Z"},
	}}
	logs := logEntriesFromAPI(body)
	if len(logs) != 2 || logs[0].Type != "email" {
		t.Fatalf("logs = %+v", logs)
	}
	md := logs[0].Metadata.(map[string]any)
	if md["days"] != 3 {
		t.Fatalf("metadata = %#v", md)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
