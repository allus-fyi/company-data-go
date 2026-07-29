// Package companydata is the Go SDK for the allus company-data API.
//
// Point it at a JSON config file and it hands back typed, plaintext,
// your-slug-keyed conclusions with transparent hybrid decryption. See the
// package README and docs/ for the full manual; this file is the decryption
// core, whose wire format is identical across all six language SDKs.
package companydata

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/youmark/pkcs8"
)

// GCM tag/IV sizes used by the platform wrapper.
const (
	gcmTagLen = 16 // bytes — appended to the AES-GCM ciphertext
	gcmIVLen  = 12 // bytes
)

// wrapper is the platform's {"_enc":1,k,iv,d} hybrid-encryption envelope:
// k = base64(RSA-OAEP-SHA256(aesKey)), iv = base64(iv12), d =
// base64(AES-256-GCM ciphertext with the 16-byte tag appended).
type wrapper struct {
	Enc int    `json:"_enc"`
	K   string `json:"k"`
	IV  string `json:"iv"`
	D   string `json:"d"`
}

// LoadPrivateKey loads an OpenSSL-encrypted PKCS#8 PEM into an in-memory RSA
// private key. The PEM is PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC, 100k iters).
//
// Go's standard library cannot decrypt an encrypted PKCS#8 PEM
// (crypto/x509.DecryptPEMBlock is legacy/deprecated and is NOT PBES2), so this
// uses github.com/youmark/pkcs8, which handles the SHA-256 PRF. The key is
// never written back to disk in plaintext.
//
// Config-only key handling: this is the single place a passphrase
// is used, and it is driven by Config.KeyPassphrase — never passed in by
// application code (the exported callers in this package read it from Config).
func LoadPrivateKey(encryptedPEM []byte, passphrase string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(encryptedPEM)
	if block == nil {
		return nil, &DecryptError{msg: "could not find a PEM block in the private key"}
	}
	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(passphrase))
	if err != nil {
		// A wrong passphrase or a malformed PEM both land here.
		return nil, &DecryptError{msg: fmt.Sprintf("could not load private key PEM: %v", err)}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, &DecryptError{msg: "PEM did not contain an RSA private key"}
	}
	return rsaKey, nil
}

// Decrypt decrypts a platform {"_enc":1,k,iv,d} wrapper (a parsed map, a
// wrapper struct, or its JSON string) into a UTF-8 plaintext string, using the
// service private key.
//
// For a text value the plaintext is the value itself. For a binary value the
// plaintext is a JSON envelope STRING (photo: {"full":"data:...","thumb":...};
// document: {"file":"data:...",...}) — NOT raw bytes. The full binary-handle
// parse (envelope -> data-URI -> bytes) lives on BinaryHandle; here we only
// ever decrypt to that envelope string.
//
// Crypto pinning: RSA-OAEP with SHA-256 for BOTH the OAEP digest
// AND MGF1 — Go's crypto/rsa.DecryptOAEP uses the SAME hash for the OAEP digest
// and MGF1, so passing sha256.New() is correct (SHA-256/MGF1-SHA256). AES-256-GCM
// with a 12-byte nonce and the 16-byte tag appended to the ciphertext, which is
// exactly what crypto/cipher's GCM Open expects.
//
// Returns a *DecryptError on a malformed wrapper, the wrong key, or a GCM tag
// mismatch.
func Decrypt(w any, key *rsa.PrivateKey) (string, error) {
	wr, err := toWrapper(w)
	if err != nil {
		return "", err
	}
	encKey, err := b64Field(wr.K, "k")
	if err != nil {
		return "", err
	}
	iv, err := b64Field(wr.IV, "iv")
	if err != nil {
		return "", err
	}
	ciphertextWithTag, err := b64Field(wr.D, "d")
	if err != nil {
		return "", err
	}

	if len(iv) != gcmIVLen {
		return "", &DecryptError{msg: fmt.Sprintf("iv must be %d bytes, got %d", gcmIVLen, len(iv))}
	}
	if len(ciphertextWithTag) < gcmTagLen {
		return "", &DecryptError{msg: "ciphertext too short to contain a GCM tag"}
	}

	// 1) RSA-OAEP(SHA-256, MGF1-SHA256) unwrap the AES key.
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, encKey, nil)
	if err != nil {
		return "", &DecryptError{msg: fmt.Sprintf("RSA-OAEP unwrap failed (wrong key?): %v", err)}
	}
	if len(aesKey) != 32 {
		return "", &DecryptError{msg: fmt.Sprintf("unwrapped AES key must be 32 bytes (AES-256), got %d", len(aesKey))}
	}

	// 2) AES-256-GCM decrypt. crypto/cipher's GCM expects the 16-byte tag
	//    appended to the ciphertext — exactly the platform's layout.
	plaintext, err := aesGCMDecrypt(aesKey, iv, ciphertextWithTag)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// aesGCMDecrypt runs AES-256-GCM Open with the tag appended to the ciphertext.
func aesGCMDecrypt(aesKey, iv, ciphertextWithTag []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("AES cipher init failed: %v", err)}
	}
	gcm, err := cipher.NewGCM(block) // 12-byte nonce, 16-byte tag — platform default
	if err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("GCM init failed: %v", err)}
	}
	// gcm.Open expects ciphertext WITH the tag appended (the platform appends it).
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, &DecryptError{msg: "AES-GCM tag mismatch (wrong key or corrupt data)"}
	}
	return plaintext, nil
}

// toWrapper coerces a parsed map, a *wrapper / wrapper, or a JSON string into a
// wrapper and validates the required fields are present.
func toWrapper(w any) (*wrapper, error) {
	switch v := w.(type) {
	case *wrapper:
		return v, validateWrapper(v)
	case wrapper:
		return &v, validateWrapper(&v)
	case string:
		var parsed wrapper
		if err := json.Unmarshal([]byte(v), &parsed); err != nil {
			return nil, &DecryptError{msg: "wrapper string is not valid JSON"}
		}
		// json.Unmarshal leaves missing fields empty; validateWrapper checks them.
		return &parsed, validateWrapperJSON([]byte(v))
	case map[string]any:
		return wrapperFromMap(v)
	case json.RawMessage:
		var parsed wrapper
		if err := json.Unmarshal(v, &parsed); err != nil {
			return nil, &DecryptError{msg: "wrapper string is not valid JSON"}
		}
		return &parsed, validateWrapperJSON(v)
	default:
		// Last resort: round-trip through JSON (covers nested structs/maps).
		raw, err := json.Marshal(w)
		if err != nil {
			return nil, &DecryptError{msg: "wrapper must be a map, struct, or JSON object string"}
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, &DecryptError{msg: "wrapper must be a map, struct, or JSON object string"}
		}
		return wrapperFromMap(m)
	}
}

// wrapperFromMap builds a wrapper from a decoded map, requiring the k/iv/d keys.
func wrapperFromMap(m map[string]any) (*wrapper, error) {
	for _, f := range []string{"k", "iv", "d"} {
		if _, ok := m[f]; !ok {
			return nil, &DecryptError{msg: fmt.Sprintf("wrapper missing required field %q", f)}
		}
	}
	wr := &wrapper{}
	if s, ok := m["k"].(string); ok {
		wr.K = s
	} else {
		return nil, &DecryptError{msg: `wrapper field "k" must be a base64 string`}
	}
	if s, ok := m["iv"].(string); ok {
		wr.IV = s
	} else {
		return nil, &DecryptError{msg: `wrapper field "iv" must be a base64 string`}
	}
	if s, ok := m["d"].(string); ok {
		wr.D = s
	} else {
		return nil, &DecryptError{msg: `wrapper field "d" must be a base64 string`}
	}
	return wr, nil
}

// validateWrapper checks a struct wrapper has the three non-empty fields.
func validateWrapper(wr *wrapper) error {
	if wr.K == "" {
		return &DecryptError{msg: `wrapper missing required field "k"`}
	}
	if wr.IV == "" {
		return &DecryptError{msg: `wrapper missing required field "iv"`}
	}
	if wr.D == "" {
		return &DecryptError{msg: `wrapper missing required field "d"`}
	}
	return nil
}

// validateWrapperJSON checks that the raw JSON object literally carries k/iv/d
// (so a missing field is an error, not silently an empty string).
func validateWrapperJSON(raw []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return &DecryptError{msg: "wrapper string is not valid JSON object"}
	}
	for _, f := range []string{"k", "iv", "d"} {
		if _, ok := m[f]; !ok {
			return &DecryptError{msg: fmt.Sprintf("wrapper missing required field %q", f)}
		}
	}
	return nil
}

// b64Field strict-base64-decodes a wrapper field, mapping failures to DecryptError.
func b64Field(value, name string) ([]byte, error) {
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("wrapper field %q is not valid base64", name)}
	}
	return out, nil
}

// ── encryption (for a recipient public key) ────────────────────────────────

// LoadPublicKey loads a base64 SPKI/DER public key (the platform's
// GET /api/keys public_key) into an in-memory RSA public key.
//
// Config-only key handling does NOT apply to a RECIPIENT public key: it is not a
// secret and is fetched live from the API per-recipient (never configured). The
// SDK still never accepts a *private* key/passphrase as a method argument.
//
// Returns a *DecryptError on invalid base64, a non-SPKI key, or a non-RSA key.
func LoadPublicKey(spkiB64 string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return nil, &DecryptError{msg: "recipient public_key is not valid base64"}
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("recipient public_key is not a valid SPKI key: %v", err)}
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, &DecryptError{msg: "recipient public_key is not an RSA public key"}
	}
	return pub, nil
}

// EncryptForPublicKey encrypts a UTF-8 string FOR a recipient RSA public key →
// a {"_enc":1,k,iv,d} wrapper (returned as a map[string]any, JSON-serializable).
//
// The exact inverse of Decrypt:
//
//	aesKey = 32 random bytes
//	d      = AES-256-GCM(aesKey, iv=12 random bytes).Seal(plaintext)  // 16-byte tag appended
//	k      = RSA-OAEP(SHA-256, MGF1-SHA256).Encrypt(aesKey, publicKey)
//
// Crypto pinning: RSA-OAEP with SHA-256 for BOTH the OAEP digest AND
// MGF1 — Go's crypto/rsa.EncryptOAEP uses the SAME hash for the OAEP digest and
// MGF1, so passing sha256.New() pins SHA-256/MGF1-SHA256. AES-256-GCM with a
// 12-byte nonce and Go appending the 16-byte tag to the ciphertext — exactly the
// platform's layout.
//
// Used for EVERY per-person (targeted) document (json + file), independent of
// is_private — broadcast docs stay plaintext.
func EncryptForPublicKey(plaintext string, pub *rsa.PublicKey) (map[string]any, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("could not generate AES key: %v", err)}
	}
	iv := make([]byte, gcmIVLen) // 12
	if _, err := rand.Read(iv); err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("could not generate IV: %v", err)}
	}

	// AES-256-GCM: crypto/cipher's Seal appends the 16-byte tag to the ciphertext
	// (the platform layout that Decrypt expects).
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("AES cipher init failed: %v", err)}
	}
	gcm, err := cipher.NewGCM(block) // 12-byte nonce, 16-byte tag — platform default
	if err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("GCM init failed: %v", err)}
	}
	ciphertextWithTag := gcm.Seal(nil, iv, []byte(plaintext), nil)

	// RSA-OAEP(SHA-256, MGF1-SHA256) — pin SHA-256 for the digest AND MGF1.
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, &DecryptError{msg: fmt.Sprintf("RSA-OAEP wrap failed: %v", err)}
	}

	return map[string]any{
		"_enc": 1,
		"k":    base64.StdEncoding.EncodeToString(encKey),
		"iv":   base64.StdEncoding.EncodeToString(iv),
		"d":    base64.StdEncoding.EncodeToString(ciphertextWithTag),
	}, nil
}

// ── BinaryHandle ────────────────────────────────────────────

// envelopeDataURIKeys are the envelope keys that hold the primary binary data
// URI, in priority order (photo → "full", document → "file").
var envelopeDataURIKeys = []string{"full", "file"}

// BinaryFetchResult is one response from a company-facing binary file endpoint,
// in the shape a BinaryHandle needs.
//
// #590 — the route has TWO 200 shapes and the company cannot predict which it
// will get, because the answer depends on whether the person's source field is
// private, which is theirs to change:
//
//   - encrypted — application/json, {"encrypted":true,"value":<wrapper>}. The
//     wrapper decrypts to the binary ENVELOPE string, from which the file bytes
//     are extracted.
//   - plaintext — the file's own Content-Type (e.g. image/jpeg, application/pdf)
//     and the body IS the file bytes. Nothing to decrypt.
//
// The distinction is made on the response's Content-Type, never guessed from the
// body: a plaintext answer's first byte is whatever the file starts with, and a
// PDF or a JPEG that happened to begin with a brace would be indistinguishable
// from a wrapper by sniffing.
//
// ContentSha256 is the platform's X-Allus-Content-Sha256 — the sha256 of exactly
// these bytes, present on both shapes — so a consumer can record what it received
// and later prove its archived copy has not drifted.
type BinaryFetchResult struct {
	Encrypted bool
	// Wrapper is the {"_enc":1,…} wrapper (encrypted shape only).
	Wrapper any
	// Bytes are the file bytes themselves (plaintext shape only).
	Bytes         []byte
	ContentType   string
	ContentSha256 string
}

// BinaryHandle is a lazy handle for a binary (photo/document) value.
//
// A binary answer is stored server-side as a file, exposed in the hardened API
// as a slot-keyed value_url (never the source field). Bytes() and Save() GET
// that URL and return the FILE BYTES either way — the caller never has to know
// which of the two response shapes arrived.
//
// #590 — THERE ARE TWO SHAPES, AND WHICH ONE ARRIVES IS THE PERSON'S CHOICE, NOT
// THE COMPANY'S. Whether the person's source field is private decides it, they
// can change it at any time, and nothing in the API announces it in advance:
//
//   - private source → application/json {"encrypted":true,"value":<wrapper>}. The
//     wrapper decrypts to a JSON envelope STRING (photo: {"full":"data:...","thumb":...};
//     document: {"file":"data:...",...}) — NOT raw bytes — whose primary data-URI
//     payload ("full" for photos, "file" for documents) base64-decodes to the file.
//   - plaintext source → the file's own Content-Type and the body IS the file.
//     There is nothing to decrypt, and a handle built this way needs no service
//     key at all.
//
// Photos resolve to the "full" representation. There is no variant selection: one
// slot has one byte sequence and therefore one digest.
//
// The fetch + decrypt are supplied by the client as plain callables, so the
// handle never holds a key (config-only key handling):
//
//   - valueURL + fetch — fetch(valueURL) returns a BinaryFetchResult saying which
//     shape arrived (the client classifies it on the response's Content-Type; the
//     body is never sniffed).
//   - decrypt — decrypt(wrapper) returns the decrypted envelope string (a closure
//     over the loaded service private key). Only ever called for the encrypted shape.
//
// For the shared crypto test vector the decrypted envelope is already in hand,
// so a handle can also be built directly from an envelope string (no fetch) via
// NewBinaryHandleFromEnvelope.
type BinaryHandle struct {
	envelopeJSON string
	hasEnvelope  bool
	valueURL     string
	fetch        func(string) (BinaryFetchResult, error)
	decrypt      func(any) (string, error)

	// Plaintext file bytes + the response metadata, once a response has been
	// fetched (#590). hasPlain distinguishes "fetched a zero-byte file" from
	// "not fetched yet" — a nil slice alone cannot.
	plainBytes    []byte
	hasPlain      bool
	contentType   string
	contentSha256 string
}

// NewBinaryHandleFromEnvelope builds a BinaryHandle from an already-decrypted
// envelope JSON string (no lazy fetch). Used by the shared test vector and any
// inline-envelope case.
func NewBinaryHandleFromEnvelope(envelopeJSON string) *BinaryHandle {
	return &BinaryHandle{envelopeJSON: envelopeJSON, hasEnvelope: true}
}

// newLazyBinaryHandle builds a BinaryHandle that fetches + decrypts on first use.
func newLazyBinaryHandle(valueURL string, fetch func(string) (BinaryFetchResult, error), decrypt func(any) (string, error)) *BinaryHandle {
	return &BinaryHandle{valueURL: valueURL, fetch: fetch, decrypt: decrypt}
}

// ValueURL returns the slot-keyed file URL this handle fetches from (opaque to
// callers; empty for an inline-envelope handle).
func (h *BinaryHandle) ValueURL() string { return h.valueURL }

// ContentSha256 returns the platform's X-Allus-Content-Sha256 for the bytes this
// handle fetched — the sha256 of exactly what Bytes() returns, so a consumer can
// record it and later show that its archived copy has not drifted. Empty until
// something has been fetched, and on a handle built from an envelope that was
// never fetched through this class.
//
// It is the platform's word, not a signature: it proves agreement with the
// platform's record, not anything to a third party who doubts that record.
func (h *BinaryHandle) ContentSha256() string { return h.contentSha256 }

// ContentType returns the response Content-Type the bytes arrived with, once
// fetched (empty otherwise).
func (h *BinaryHandle) ContentType() string { return h.contentType }

// fetchOnce fetches once and records which shape arrived. Idempotent: the result
// is cached on the handle so repeated Bytes()/Save() calls do not re-fetch, and so
// a plaintext answer's digest survives for ContentSha256().
func (h *BinaryHandle) fetchOnce() error {
	if h.hasPlain || h.hasEnvelope {
		return nil
	}
	if h.fetch == nil || h.valueURL == "" {
		return &DecryptError{msg: "BinaryHandle has no envelope and no fetch wiring " +
			"(build it with an envelope, or valueURL + fetch + decrypt)"}
	}
	res, err := h.fetch(h.valueURL)
	if err != nil {
		return err
	}
	h.contentType = res.ContentType
	h.contentSha256 = res.ContentSha256

	if !res.Encrypted {
		// A plaintext answer needs no service key. Demanding decrypt up front (as
		// this did before #590) would make a handle built without one fail on
		// exactly the answers that do not need it.
		h.plainBytes = res.Bytes
		h.hasPlain = true
		return nil
	}
	if h.decrypt == nil {
		return &DecryptError{msg: "binary answer is encrypted but this handle has no decrypt wiring"}
	}
	env, err := h.decrypt(res.Wrapper)
	if err != nil {
		return err
	}
	h.envelopeJSON = env
	h.hasEnvelope = true
	return nil
}

// resolveEnvelope returns the decrypted envelope string, fetching+decrypting on
// first use and caching so repeated Bytes()/Save() don't re-fetch.
func (h *BinaryHandle) resolveEnvelope() (string, error) {
	if h.hasEnvelope {
		return h.envelopeJSON, nil
	}
	if err := h.fetchOnce(); err != nil {
		return "", err
	}
	if !h.hasEnvelope {
		return "", &DecryptError{msg: "binary answer arrived as plaintext bytes; use Bytes()/Save()"}
	}
	return h.envelopeJSON, nil
}

// ParseEnvelopeBytes turns a decrypted binary envelope STRING into the primary
// file bytes: a photo envelope -> the "full" data-URI payload; a document
// envelope -> the "file" data-URI payload. Returns a *DecryptError on a
// malformed envelope.
func ParseEnvelopeBytes(envelopeJSON string) ([]byte, error) {
	var envelope map[string]any
	if err := json.Unmarshal([]byte(envelopeJSON), &envelope); err != nil {
		return nil, &DecryptError{msg: "binary envelope is not valid JSON"}
	}

	var dataURI string
	found := false
	for _, key := range envelopeDataURIKeys {
		if s, ok := envelope[key].(string); ok {
			dataURI = s
			found = true
			break
		}
	}
	if !found {
		return nil, &DecryptError{msg: "binary envelope has no 'full'/'file' data-URI payload"}
	}

	const marker = "base64,"
	idx := strings.Index(dataURI, marker)
	if idx == -1 {
		return nil, &DecryptError{msg: "binary data URI is not base64-encoded"}
	}
	payload := dataURI[idx+len(marker):]
	out, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, &DecryptError{msg: "binary data-URI payload is not valid base64"}
	}
	return out, nil
}

// Bytes fetches (if needed), decrypts, and returns the decoded primary file
// bytes — the same bytes for either #590 response shape, so a caller never has
// to branch on which one the person's privacy setting produced.
func (h *BinaryHandle) Bytes() ([]byte, error) {
	if h.hasPlain {
		return h.plainBytes, nil
	}
	if !h.hasEnvelope {
		if err := h.fetchOnce(); err != nil {
			return nil, err
		}
		if h.hasPlain {
			return h.plainBytes, nil
		}
	}
	env, err := h.resolveEnvelope()
	if err != nil {
		return nil, err
	}
	return ParseEnvelopeBytes(env)
}

// Save writes the decoded file bytes to path; returns the number of bytes
// written.
//
// Crash-safe (matching the buffer's atomic-write discipline): the
// bytes are written to a temp file in the same directory, fsync'd, and
// atomically renamed into place — so a crash mid-write never leaves a truncated
// output file (the destination is either the old file or the complete new one).
func (h *BinaryHandle) Save(path string) (int, error) {
	data, err := h.Bytes()
	if err != nil {
		return 0, err
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".tmp_*.part")
	if err != nil {
		return 0, fmt.Errorf("could not create temp file for save: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return 0, err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return 0, err
	}
	if err := os.Rename(tmpName, path); err != nil { // atomic over any existing file
		_ = os.Remove(tmpName)
		return 0, err
	}
	fsyncDir(dir)
	return len(data), nil
}

// HashMatches reports whether sha256(salt ‖ plaintext) equals expectedHash (hex).
// #311 verified fields: consumers recompute this from the plaintext they just
// decrypted and trust the verified flag ONLY on a match.
func HashMatches(salt, expectedHash, plaintext string) bool {
	if salt == "" || expectedHash == "" {
		return false
	}
	sum := sha256.Sum256([]byte(salt + plaintext))
	computed := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(expectedHash)) == 1
}
