package companydata

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// TwoFactorChallenge is a login-approval challenge returned by TwoFactorClient.Challenge (spec §3).
type TwoFactorChallenge struct {
	ChallengeID string
	Status      string // always "pending" on creation
	ExpiresAt   string
	// MatchingDigits is present only when the service has number matching on — the two digits to DISPLAY
	// on your login page. The person types them back into the allme app; the SERVER adjudicates them
	// (they never leave the app on any payload). Empty when number matching is off.
	MatchingDigits string
}

// TwoFactorResult is the outcome of TwoFactorClient.Result (spec §3).
type TwoFactorResult struct {
	// Status is one of pending | approved | denied | expired | revoked | gone (already consumed / TTL passed).
	Status      string
	ExpiresAt   string // set while pending
	CompletedAt string // set on a terminal outcome
}

// TwoFactorClient is the 2FA-by-allme relying-party challenge API (spec §3), on the SERVICE's data-client
// credentials (the same auth Client uses). Reached via Client.TwoFactor.
//
// A service asks a person (by share code) to approve a login inside the allme app, then polls for the
// outcome. The poll is the record: the first read of a terminal state delivers it and burns it. A webhook
// (2fa_challenge_completed) is the best-effort push equivalent; the poll remains authoritative.
type TwoFactorClient struct {
	http *HTTPClient
	// sleep/now are injectable so WaitForResult is unit-testable without real delays or a real
	// clock (matches OAuthClient / HTTPClient). Nil defaults to time.Sleep / time.Now.
	sleep func(time.Duration)
	now   func() time.Time
}

// TwoFactor returns the 2FA-by-allme relying-party challenge API.
func (c *Client) TwoFactor() *TwoFactorClient {
	return &TwoFactorClient{http: c.http, sleep: c.sleep}
}

// Challenge initiates a login-approval challenge for the person behind shareCode. idempotencyKey is
// required (<=64); a repeat with the same key within the TTL returns the SAME challenge and sends no second
// push. contextText is plain text shown to the person (<=200 chars; pass "" for none).
func (t *TwoFactorClient) Challenge(ctx context.Context, shareCode, idempotencyKey, contextText string) (TwoFactorChallenge, error) {
	payload := map[string]any{
		"share_code":      shareCode,
		"idempotency_key": idempotencyKey,
	}
	if contextText != "" {
		payload["context"] = contextText
	} else {
		payload["context"] = nil
	}
	body, err := t.http.Post(ctx, "/api/service-2fa/challenges", payload)
	if err != nil {
		return TwoFactorChallenge{}, err
	}
	obj, _ := body.(map[string]any)
	return TwoFactorChallenge{
		ChallengeID:    asString(obj["challenge_id"]),
		Status:         asString(obj["status"]),
		ExpiresAt:      asString(obj["expires_at"]),
		MatchingDigits: asString(obj["matching_digits"]),
	}, nil
}

// Result polls a challenge. While pending, Status is "pending"; the first terminal read burns the result.
func (t *TwoFactorClient) Result(ctx context.Context, challengeID string) (TwoFactorResult, error) {
	body, err := t.http.Get(ctx, "/api/service-2fa/challenges/"+url.PathEscape(challengeID), nil)
	if err != nil {
		return TwoFactorResult{}, err
	}
	obj, _ := body.(map[string]any)
	return TwoFactorResult{
		Status:      asString(obj["status"]),
		ExpiresAt:   asString(obj["expires_at"]),
		CompletedAt: asString(obj["completed_at"]),
	}, nil
}

// WaitForResult polls Result until the status is terminal (no longer "pending") and returns that
// first terminal TwoFactorResult (mirrors the OAuth PollResult precedent). Because the first
// terminal read burns the challenge, this returns as soon as the status leaves "pending" — it never
// re-reads a consumed result. It returns an *ApiError if timeout elapses while still pending;
// interval is the wait between polls. A non-positive timeout defaults to 600s, a non-positive
// interval to 2s (the repo's zero-means-default convention, as in OAuthClient.PollResult).
func (t *TwoFactorClient) WaitForResult(ctx context.Context, challengeID string, timeout, interval time.Duration) (TwoFactorResult, error) {
	if timeout <= 0 {
		timeout = 600 * time.Second
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	now := t.now
	if now == nil {
		now = time.Now
	}
	sleep := t.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	deadline := now().Add(timeout)
	for {
		res, err := t.Result(ctx, challengeID)
		if err != nil {
			return TwoFactorResult{}, err
		}
		if res.Status != "pending" {
			return res, nil
		}
		if !now().Before(deadline) {
			return TwoFactorResult{}, NewApiError(0, "", fmt.Sprintf("2FA challenge %s not completed within %s", challengeID, timeout))
		}
		sleep(interval)
	}
}
