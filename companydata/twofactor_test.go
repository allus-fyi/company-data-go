package companydata

// #481 additions to the 2FA client: WaitForResult (the base Challenge/Result client landed via
// #436). Ports tests/test_two_factor.py. A fake Doer replays scripted GET bodies through a real
// HTTPClient so each poll consumes one GET.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func twoFactorHTTP(t *testing.T, gets []fakeResponse) (*HTTPClient, *fakeDoer) {
	t.Helper()
	d := &fakeDoer{tokenResponses: []fakeResponse{tokenOK()}, getResponses: gets}
	return newTestHTTP(t, d, "json", nil), d
}

func TestWaitForResultReturnsFirstTerminal(t *testing.T) {
	h, d := twoFactorHTTP(t, []fakeResponse{
		{status: 200, body: `{"status":"pending"}`},
		{status: 200, body: `{"status":"pending"}`},
		{status: 200, body: `{"status":"approved","completed_at":"2026-07-24T10:00:00Z"}`},
	})
	tf := &TwoFactorClient{http: h, sleep: func(time.Duration) {}}
	res, err := tf.WaitForResult(context.Background(), "chal_1", 600*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "approved" || res.CompletedAt != "2026-07-24T10:00:00Z" {
		t.Fatalf("res = %+v", res)
	}
	// Stopped at the first terminal read — never re-read a burned challenge.
	if len(d.gets) != 3 {
		t.Fatalf("expected 3 polls, got %d", len(d.gets))
	}
}

func TestWaitForResultEachTerminalStatus(t *testing.T) {
	for _, term := range []string{"approved", "denied", "expired", "revoked", "gone"} {
		h, _ := twoFactorHTTP(t, []fakeResponse{
			{status: 200, body: `{"status":"pending"}`},
			{status: 200, body: `{"status":"` + term + `"}`},
		})
		tf := &TwoFactorClient{http: h, sleep: func(time.Duration) {}}
		res, err := tf.WaitForResult(context.Background(), "chal_1", 600*time.Second, 0)
		if err != nil || res.Status != term {
			t.Fatalf("%s: %v %+v", term, err, res)
		}
	}
}

func TestWaitForResultTimeoutRaisesApiError(t *testing.T) {
	h, _ := twoFactorHTTP(t, []fakeResponse{
		{status: 200, body: `{"status":"pending"}`},
		{status: 200, body: `{"status":"pending"}`},
	})
	// Injected clock advances by whatever the sleeper is handed, so the deadline is hit
	// deterministically without real delays (Go's value-typed timeout can't use Python's
	// timeout=0 sentinel — the repo treats 0 as "use default").
	now := time.Unix(0, 0)
	tf := &TwoFactorClient{
		http:  h,
		now:   func() time.Time { return now },
		sleep: func(d time.Duration) { now = now.Add(d) },
	}
	_, err := tf.WaitForResult(context.Background(), "chal_late", 5*time.Second, 5*time.Second)
	var ae *ApiError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *ApiError, got %v", err)
	}
	if !strings.Contains(ae.Error(), "not completed within") {
		t.Fatalf("message = %q", ae.Error())
	}
}
