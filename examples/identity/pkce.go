package main

// PKCE (RFC 7636) verifier + S256 challenge. Pure local crypto — no network, no platform HTTP.
// The SDK takes the code_challenge into OAuthClient.AuthorizeURL and the code_verifier into
// OAuthClient.CompleteSignIn; the demo generates the pair. The OIDC scenarios (5/6) reuse the same
// pair, passing code_verifier to the oauth2 token exchange.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}
