package companydata

import (
	"errors"
	"fmt"
)

// Error taxonomy — the same names across all six SDKs, adapted to
// idiomatic Go error types. Each error type also has a sentinel
// (Err*) so callers can match with errors.Is, and the concrete types can be
// extracted with errors.As to read the carried fields (status, error_key,
// retry_after, …).
//
//	ConfigError                — missing/invalid config or key file at construction (fail fast)
//	AuthError                  — token fetch/refresh failed (bad client_id/secret, revoked client)
//	ApiError(status, errorKey) — any non-2xx from the API; carries the HTTP status + platform error_key + message
//	DecryptError               — wrapper malformed, wrong key, or GCM tag mismatch
//	WebhookError               — signature verification failed or an envelope couldn't be unwrapped
//	RateLimitError(retryAfter) — a 429 from a rate-limited endpoint (wraps ApiError); carries Retry-After
var (
	// ErrConfig is matched by errors.Is(err, ErrConfig) for any *ConfigError.
	ErrConfig = errors.New("config error")
	// ErrAuth is matched by errors.Is(err, ErrAuth) for any *AuthError.
	ErrAuth = errors.New("auth error")
	// ErrAPI is matched by errors.Is(err, ErrAPI) for any *ApiError (incl. *RateLimitError).
	ErrAPI = errors.New("api error")
	// ErrDecrypt is matched by errors.Is(err, ErrDecrypt) for any *DecryptError.
	ErrDecrypt = errors.New("decrypt error")
	// ErrWebhook is matched by errors.Is(err, ErrWebhook) for any *WebhookError.
	ErrWebhook = errors.New("webhook error")
	// ErrRateLimit is matched by errors.Is(err, ErrRateLimit) for any *RateLimitError.
	ErrRateLimit = errors.New("rate limit error")
)

// ConfigError is raised for missing or invalid configuration (or key file) at
// construction (fail fast).
type ConfigError struct {
	msg string
	err error // optional wrapped cause
}

func (e *ConfigError) Error() string { return "config error: " + e.msg }
func (e *ConfigError) Unwrap() error { return e.err }

// Is reports ErrConfig membership for errors.Is.
func (e *ConfigError) Is(target error) bool { return target == ErrConfig }

func newConfigError(format string, a ...any) *ConfigError {
	return &ConfigError{msg: fmt.Sprintf(format, a...)}
}

func wrapConfigError(err error, format string, a ...any) *ConfigError {
	return &ConfigError{msg: fmt.Sprintf(format, a...), err: err}
}

// AuthError is raised when the client_credentials token fetch or refresh
// failed: /oauth2/token rejected the credentials, or a 401 mid-flight
// survived the one automatic refresh-and-retry.
type AuthError struct {
	msg string
	err error
}

func (e *AuthError) Error() string        { return "auth error: " + e.msg }
func (e *AuthError) Unwrap() error        { return e.err }
func (e *AuthError) Is(target error) bool { return target == ErrAuth }

func newAuthError(format string, a ...any) *AuthError {
	return &AuthError{msg: fmt.Sprintf(format, a...)}
}

// ApiError is any non-2xx from the API. It carries the HTTP
// Status, the platform ErrorKey (when the body provided one), and a
// human-readable Message.
type ApiError struct {
	Status   int
	ErrorKey string
	Message  string
}

func (e *ApiError) Error() string {
	s := fmt.Sprintf("HTTP %d", e.Status)
	if e.ErrorKey != "" {
		s += fmt.Sprintf(" (%s)", e.ErrorKey)
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// Is reports ErrAPI membership for errors.Is.
func (e *ApiError) Is(target error) bool { return target == ErrAPI }

// NewApiError builds an *ApiError. Exported for advanced use / tests.
func NewApiError(status int, errorKey, message string) *ApiError {
	return &ApiError{Status: status, ErrorKey: errorKey, Message: message}
}

// DecryptError is raised when a wrapper is malformed, the wrong key is used, or
// the GCM tag does not match.
type DecryptError struct {
	msg string
}

func (e *DecryptError) Error() string        { return "decrypt error: " + e.msg }
func (e *DecryptError) Is(target error) bool { return target == ErrDecrypt }

// WebhookError is raised when signature verification failed, or a webhook
// envelope couldn't be unwrapped.
type WebhookError struct {
	msg string
	err error
}

func (e *WebhookError) Error() string        { return "webhook error: " + e.msg }
func (e *WebhookError) Unwrap() error        { return e.err }
func (e *WebhookError) Is(target error) bool { return target == ErrWebhook }

func newWebhookError(format string, a ...any) *WebhookError {
	return &WebhookError{msg: fmt.Sprintf(format, a...)}
}

// RateLimitError is a 429 from a rate-limited endpoint. It embeds
// an *ApiError (fixed status 429) and carries the RetryAfter value parsed from
// the Retry-After response header (seconds, or nil when absent). Because it
// embeds *ApiError, errors.As(err, &apiErr) and errors.Is(err, ErrAPI) both
// succeed for a *RateLimitError too.
type RateLimitError struct {
	*ApiError
	RetryAfter *float64
}

// Is reports both ErrRateLimit and ErrAPI membership for errors.Is.
func (e *RateLimitError) Is(target error) bool {
	return target == ErrRateLimit || target == ErrAPI
}

// NewRateLimitError builds a *RateLimitError (status fixed at 429).
func NewRateLimitError(retryAfter *float64, errorKey, message string) *RateLimitError {
	return &RateLimitError{
		ApiError:   &ApiError{Status: 429, ErrorKey: errorKey, Message: message},
		RetryAfter: retryAfter,
	}
}
