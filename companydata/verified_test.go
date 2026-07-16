package companydata

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func h311(salt, pt string) string { s := sha256.Sum256([]byte(salt + pt)); return hex.EncodeToString(s[:]) }

func decryptPlain(pt string) decryptValueFn { return func(any) (string, error) { return pt, nil } }

func TestVerified311(t *testing.T) {
	pt, salt := "alice@example.com", "0011223344556677"
	// match
	v, _ := valueFromAPI(map[string]any{"value": pt, "live": true, "verified_hash": h311(salt, pt), "verified_salt": salt}, "email", decryptPlain(pt), nil)
	if !v.Verified {
		t.Fatal("expected Verified true on match")
	}
	// mismatch
	v2, _ := valueFromAPI(map[string]any{"value": pt, "live": true, "verified_hash": "deadbeef", "verified_salt": salt}, "email", decryptPlain(pt), nil)
	if v2.Verified {
		t.Fatal("expected Verified false on mismatch")
	}
	// absent
	v3, _ := valueFromAPI(map[string]any{"value": pt, "live": true}, "email", decryptPlain(pt), nil)
	if v3.Verified {
		t.Fatal("expected Verified false when absent")
	}
	// change field_updated
	c, _ := changeFromAPI(map[string]any{"id": "c1", "event": "field_updated", "person_user_id": "u1", "slug": "email_personal", "value": pt, "verified_hash": h311(salt, pt), "verified_salt": salt}, func(string) string { return "email" }, decryptPlain(pt), nil)
	if !c.Verified {
		t.Fatal("expected Change.Verified true")
	}
}
