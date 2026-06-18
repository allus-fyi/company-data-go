package companydata

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Decryption core tests.
//
// These prove the Go decryptor reproduces the SHARED cross-language test vector
// (sdks/testdata/decryption-vector.json): load the PBES2 service PEM with its
// passphrase; decrypt the text wrapper to the known plaintext; decrypt the
// binary wrapper to the JSON envelope whose hashes match (envelope-string sha256
// and inner-bytes sha256). If this passes, the Go crypto is byte-identical to
// the other five SDKs.

// vectorDoc is the structure of decryption-vector.json.
type vectorDoc struct {
	EncryptedPrivateKeyPEM string `json:"encrypted_private_key_pem"`
	Passphrase             string `json:"passphrase"`
	Text                   struct {
		Wrapper   map[string]any `json:"wrapper"`
		Plaintext string         `json:"plaintext"`
	} `json:"text"`
	Binary struct {
		Wrapper             map[string]any `json:"wrapper"`
		DecryptedJSONSHA256 string         `json:"decrypted_json_sha256"`
		InnerFullSHA256     string         `json:"inner_full_sha256"`
	} `json:"binary"`
}

func vectorPath(t *testing.T) string {
	t.Helper()
	// sdks/go/companydata -> sdks/go/testdata/decryption-vector.json
	p, err := filepath.Abs(filepath.Join("..", "testdata", "decryption-vector.json"))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return p
}

func loadVector(t *testing.T) *vectorDoc {
	t.Helper()
	data, err := os.ReadFile(vectorPath(t))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v vectorDoc
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return &v
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ── PEM-load gate (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC, 100k iters) ───────

func TestLoadPrivateKeyFromPBES2PEM(t *testing.T) {
	v := loadVector(t)
	key, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if got := key.N.BitLen(); got != 2048 {
		t.Fatalf("key size = %d, want 2048", got)
	}
}

func TestLoadPrivateKeyWrongPassphraseFails(t *testing.T) {
	v := loadVector(t)
	_, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), "the-wrong-passphrase")
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

// ── text decrypt (RSA-OAEP-SHA256 + AES-256-GCM) ──────────────────────────────

func TestDecryptTextWrapperMatchesPlaintext(t *testing.T) {
	v := loadVector(t)
	key, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	plaintext, err := Decrypt(v.Text.Wrapper, key)
	if err != nil {
		t.Fatalf("Decrypt text: %v", err)
	}
	if plaintext != v.Text.Plaintext {
		t.Fatalf("plaintext = %q, want %q", plaintext, v.Text.Plaintext)
	}
}

func TestDecryptAcceptsWrapperAsJSONString(t *testing.T) {
	v := loadVector(t)
	key, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	raw, _ := json.Marshal(v.Text.Wrapper)
	plaintext, err := Decrypt(string(raw), key)
	if err != nil {
		t.Fatalf("Decrypt json string: %v", err)
	}
	if plaintext != v.Text.Plaintext {
		t.Fatalf("plaintext = %q, want %q", plaintext, v.Text.Plaintext)
	}
}

// ── binary decrypt → envelope → inner bytes ───────────────────────────────────

func TestDecryptBinaryWrapperToEnvelopeAndInnerBytes(t *testing.T) {
	v := loadVector(t)
	key, err := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	// Decrypting a binary wrapper yields a JSON envelope STRING.
	envelopeJSON, err := Decrypt(v.Binary.Wrapper, key)
	if err != nil {
		t.Fatalf("Decrypt binary: %v", err)
	}
	if got := sha256hex([]byte(envelopeJSON)); got != v.Binary.DecryptedJSONSHA256 {
		t.Fatalf("envelope sha256 = %s, want %s", got, v.Binary.DecryptedJSONSHA256)
	}

	// ParseEnvelopeBytes base64-decodes the "full"/"file" data-URI → file bytes.
	inner, err := ParseEnvelopeBytes(envelopeJSON)
	if err != nil {
		t.Fatalf("ParseEnvelopeBytes: %v", err)
	}
	if got := sha256hex(inner); got != v.Binary.InnerFullSHA256 {
		t.Fatalf("inner sha256 = %s, want %s", got, v.Binary.InnerFullSHA256)
	}

	// And via the handle's public Bytes() entry point.
	handle := NewBinaryHandleFromEnvelope(envelopeJSON)
	hb, err := handle.Bytes()
	if err != nil {
		t.Fatalf("handle.Bytes: %v", err)
	}
	if got := sha256hex(hb); got != v.Binary.InnerFullSHA256 {
		t.Fatalf("handle bytes sha256 = %s, want %s", got, v.Binary.InnerFullSHA256)
	}
}

// ── error paths ───────────────────────────────────────────────────────────────

func TestDecryptTagMismatchFails(t *testing.T) {
	v := loadVector(t)
	key, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	bad := cloneWrapper(v.Text.Wrapper)
	raw, _ := base64.StdEncoding.DecodeString(bad["d"].(string))
	raw[len(raw)-1] ^= 0xFF // corrupt the last byte of the GCM tag
	bad["d"] = base64.StdEncoding.EncodeToString(raw)
	if _, err := Decrypt(bad, key); err == nil || !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt on tag mismatch, got %v", err)
	}
}

func TestDecryptMissingFieldFails(t *testing.T) {
	v := loadVector(t)
	key, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	if _, err := Decrypt(map[string]any{"_enc": 1, "k": "AAAA", "iv": "AAAA"}, key); err == nil {
		t.Fatal("expected error on missing 'd'")
	}
}

func TestDecryptBadBase64Fails(t *testing.T) {
	v := loadVector(t)
	key, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	bad := cloneWrapper(v.Text.Wrapper)
	bad["k"] = "not valid base64 !!!"
	if _, err := Decrypt(bad, key); err == nil || !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt on bad base64, got %v", err)
	}
}

func TestDecryptWrongIVLengthFails(t *testing.T) {
	v := loadVector(t)
	key, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	bad := cloneWrapper(v.Text.Wrapper)
	bad["iv"] = base64.StdEncoding.EncodeToString(make([]byte, 16)) // 16, not 12
	if _, err := Decrypt(bad, key); err == nil || !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt on wrong iv length, got %v", err)
	}
}

func TestParseEnvelopeWithoutFullOrFileFails(t *testing.T) {
	if _, err := ParseEnvelopeBytes(`{"thumb":"x"}`); err == nil || !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

// ── BinaryHandle.Save is atomic ───────────────────────────────────────────────

func TestBinaryHandleSaveWritesBytesAndCount(t *testing.T) {
	v := loadVector(t)
	key, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	envelopeJSON, _ := Decrypt(v.Binary.Wrapper, key)
	handle := NewBinaryHandleFromEnvelope(envelopeJSON)

	out := filepath.Join(t.TempDir(), "out.bin")
	n, err := handle.Save(out)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Save returned %d, wrote %d", n, len(data))
	}
	if got := sha256hex(data); got != v.Binary.InnerFullSHA256 {
		t.Fatalf("saved sha256 = %s, want %s", got, v.Binary.InnerFullSHA256)
	}
}

func cloneWrapper(w map[string]any) map[string]any {
	out := make(map[string]any, len(w))
	for k, v := range w {
		out[k] = v
	}
	return out
}
