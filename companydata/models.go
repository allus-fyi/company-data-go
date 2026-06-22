package companydata

import (
	"encoding/json"
	"strings"
	"time"
)

// Output model — the conclusions.
//
// The consumer works with these and nothing else. They are produced by
// factories that turn a hardened API JSON object (slug-keyed values; NO person
// source field) into typed Go values, decrypting ciphertext via
// the injected crypto closures.
//
//	RequestField { Slug, Label, Type, OneTime, Mandatory }    // YOUR request config
//	Connection   { ID, PersonID, DisplayName, ConnectedAt, Values map[slug]Value }
//	Value        { Value, Live, UpdatedAt }
//	Change       { ID, Event, PersonID, ShareCode, Slug, Value, Live, At } // ID = stable dedup key
//	LogEntry     { Type, Message, Metadata, At }
//
// Typed values:
//   - email/phone/url/text                → string
//   - address/bank/creditcard             → map[string]any (the decrypted plaintext is a JSON object string → parsed)
//   - date/date_of_birth                  → time.Time
//   - photo/document/legal_document       → a lazy *BinaryHandle
//
// Every model carries Raw — the underlying (hardened) API object — for debugging
// or an edge case the SDK didn't model. It still never contains the person's
// source field. The person's source field is never present anywhere.
//
// Decryption is config-driven: the factories take a decryptValue
// callable (a closure over the loaded service private key) and, for binaries, a
// binaryFetch callable — never a key/secret argument.

// Field-type groupings.
var (
	structuredTypes = map[string]bool{"address": true, "bank": true, "creditcard": true}
	binaryTypes     = map[string]bool{"photo": true, "document": true, "legal_document": true}
	dateTypes       = map[string]bool{"date": true, "date_of_birth": true}
)

// decryptValueFn decrypts a ciphertext wrapper (map / struct / JSON string) →
// plaintext string. Closes over the service private key.
type decryptValueFn func(any) (string, error)

// typeForSlugFn resolves a request slug to its field type (e.g. "email", "photo").
type typeForSlugFn func(string) string

// binaryFetchFn fetches a slot file endpoint and unwraps it to the inner wrapper.
type binaryFetchFn func(string) (any, error)

// ── definitions ──────────────────────────────────────────────────────────────

// RequestField is a request-field DEFINITION — YOUR config, never
// the person's. Mandatory folds the API's two flags: true when the field is
// mandatory to provide OR mandatory to stay connected.
type RequestField struct {
	Slug      string
	Label     string
	Type      string
	OneTime   bool
	Mandatory bool
	Raw       map[string]any
}

func requestFieldFromAPI(obj map[string]any) RequestField {
	return RequestField{
		Slug:    asString(obj["slug"]),
		Label:   asString(obj["label"]),
		Type:    asString(obj["type"]),
		OneTime: coerceBool(obj["one_time"]),
		Mandatory: coerceBool(obj["mandatory_provide"]) ||
			coerceBool(obj["mandatory_connected"]),
		Raw: obj,
	}
}

// requestFieldsFromAPI parses the /request-fields response → a list of definitions.
func requestFieldsFromAPI(body any) []RequestField {
	items := extractList(body, "request_fields")
	out := make([]RequestField, 0, len(items))
	for _, o := range items {
		if m, ok := o.(map[string]any); ok {
			out = append(out, requestFieldFromAPI(m))
		}
	}
	return out
}

// ── values ───────────────────────────────────────────────────────────────────

// Value is a single answer for one of YOUR request slots.
//
// Value is the typed plaintext: a string for text-like types, a map[string]any
// for structured types, a time.Time for dates, or a *BinaryHandle for binaries
// (use a type switch / type assertion to read it). Live = the person chose "keep
// connected" (auto-updates) vs a one-time snapshot; UpdatedAt = when this answer
// last changed (nil if absent). Both ride on the Value (per-answer), not the
// definition.
type Value struct {
	Value     any
	Live      bool
	UpdatedAt *time.Time
	Raw       map[string]any
}

func valueFromAPI(obj map[string]any, fieldType string, decryptValue decryptValueFn, binaryFetch binaryFetchFn) (Value, error) {
	typed, err := typedValue(obj, fieldType, decryptValue, binaryFetch)
	if err != nil {
		return Value{}, err
	}
	return Value{
		Value:     typed,
		Live:      coerceBool(obj["live"]),
		UpdatedAt: parseISO(firstString(obj["updatedAt"], obj["updated_at"])),
		Raw:       obj,
	}, nil
}

// typedValue decrypts + coerces one value entry to its typed Go form.
func typedValue(obj map[string]any, fieldType string, decryptValue decryptValueFn, binaryFetch binaryFetchFn) (any, error) {
	ftype := strings.ToLower(fieldType)

	// Binary → a lazy handle over the slot value_url (no eager fetch/decrypt).
	_, hasValueURL := obj["value_url"]
	if binaryTypes[ftype] || hasValueURL {
		valueURL := asString(obj["value_url"])
		if valueURL == "" {
			// Binary type but no url (e.g. unanswered) → an empty handle.
			return &BinaryHandle{}, nil
		}
		return newLazyBinaryHandle(valueURL, binaryFetch, decryptValue), nil
	}

	// Non-binary → decrypt the ciphertext wrapper to plaintext.
	ciphertext, ok := obj["value"]
	if !ok || ciphertext == nil {
		return nil, nil
	}
	plaintext, err := decryptValue(ciphertext)
	if err != nil {
		return nil, err
	}

	if structuredTypes[ftype] {
		var parsed map[string]any
		dec := json.NewDecoder(strings.NewReader(plaintext))
		dec.UseNumber()
		if err := dec.Decode(&parsed); err != nil {
			return nil, &DecryptError{msg: "structured value for type " + ftype + " is not valid JSON object"}
		}
		return parsed, nil
	}

	if dateTypes[ftype] {
		if d, ok := parseDate(plaintext); ok {
			return d, nil
		}
		return plaintext, nil // fall back to the string if unparseable
	}

	// text/email/phone/url and anything unknown → the plaintext string.
	return plaintext, nil
}

// ── connection ─────────────────────────────────────────────────────────────

// Connection is a connected person — identity + the slug-keyed
// value map. NO source field anywhere: Values is keyed by YOUR request slug.
type Connection struct {
	ID          string
	PersonID    string
	DisplayName string
	ConnectedAt *time.Time
	Values      map[string]Value
	Raw         map[string]any
}

// connectionFromAPI builds a Connection from a hardened connectionDetail (or
// list) object. The list row carries identity (display_name/connected_at) AND
// the values map; connectionDetail returns {connection_id, user_id, values} and
// no identity, so identity may be supplied separately (or be the same object).
func connectionFromAPI(obj map[string]any, typeForSlug typeForSlugFn, decryptValue decryptValueFn, binaryFetch binaryFetchFn, identity map[string]any) (Connection, error) {
	if identity == nil {
		identity = map[string]any{}
	}
	connID := firstString(obj["connection_id"], obj["id"], identity["connection_id"])
	personID := firstString(obj["user_id"], obj["person_id"], obj["person_user_id"], identity["user_id"])
	displayName := firstString(obj["display_name"], identity["display_name"])
	connectedAt := parseISO(firstString(obj["connected_at"], identity["connected_at"]))

	values := map[string]Value{}
	if rawValues, ok := obj["values"].(map[string]any); ok {
		for slug, entry := range rawValues {
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			v, err := valueFromAPI(m, typeForSlug(slug), decryptValue, binaryFetch)
			if err != nil {
				return Connection{}, err
			}
			values[slug] = v
		}
	}

	return Connection{
		ID:          connID,
		PersonID:    personID,
		DisplayName: displayName,
		ConnectedAt: connectedAt,
		Values:      values,
		Raw:         obj,
	}, nil
}

// ── change ───────────────────────────────────────────────────────────────────

// Change is a change feed / webhook event.
//
// ID is the stable server change-row id (the pump dedupes on it after a
// crash/replay); At is the change time (there is NO separate UpdatedAt on a
// change). Slug/Value/Live are present only on field_updated (connection/consent
// events carry no slot/value). HasLive distinguishes "live was absent" from
// "live was false".
type Change struct {
	ID         string
	Event      string
	PersonID   string
	ShareCode  string // the person's profile share code (every event; may be empty)
	Slug       string
	Value      any
	Live       bool
	HasLive    bool
	DocumentID string // set on document_status_changed
	Status     string // set on document_status_changed
	At         *time.Time
	Raw        map[string]any
}

func changeFromAPI(obj map[string]any, typeForSlug typeForSlugFn, decryptValue decryptValueFn, binaryFetch binaryFetchFn) (Change, error) {
	slug := asString(obj["slug"])
	event := asString(obj["event"])

	var live bool
	_, hasLive := obj["live"]
	if hasLive {
		live = coerceBool(obj["live"])
	}

	var value any
	if event == "field_updated" && slug != "" {
		_, hasVal := obj["value"]
		_, hasURL := obj["value_url"]
		if hasVal || hasURL {
			v, err := typedValue(obj, typeForSlug(slug), decryptValue, binaryFetch)
			if err != nil {
				return Change{}, err
			}
			value = v
		}
	}

	var documentID, status string
	if event == "document_status_changed" {
		documentID = asString(obj["document_id"])
		status = asString(obj["status"])
	}

	return Change{
		ID:         asString(obj["id"]),
		Event:      event,
		PersonID:   firstString(obj["person_user_id"], obj["person_id"]),
		ShareCode:  asString(obj["share_code"]),
		Slug:       slug,
		Value:      value,
		Live:       live,
		HasLive:    hasLive,
		DocumentID: documentID,
		Status:     status,
		At:         parseISO(asString(obj["at"])),
		Raw:        obj,
	}, nil
}

// changesFromAPI parses the /changes response → a list of typed Change events.
func changesFromAPI(body any, typeForSlug typeForSlugFn, decryptValue decryptValueFn, binaryFetch binaryFetchFn) ([]Change, error) {
	items := extractList(body, "changes")
	out := make([]Change, 0, len(items))
	for _, o := range items {
		m, ok := o.(map[string]any)
		if !ok {
			continue
		}
		c, err := changeFromAPI(m, typeForSlug, decryptValue, binaryFetch)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// ── log ────────────────────────────────────────────────────────────────────

// LogEntry is a service activity-log entry — ops events only,
// never person data.
type LogEntry struct {
	Type     string
	Message  string
	Metadata any
	At       *time.Time
	Raw      map[string]any
}

func logEntryFromAPI(obj map[string]any) LogEntry {
	return LogEntry{
		Type:     asString(obj["type"]),
		Message:  asString(obj["message"]),
		Metadata: obj["metadata"],
		At:       parseISO(firstString(obj["at"], obj["created_at"])),
		Raw:      obj,
	}
}

func logEntriesFromAPI(body any) []LogEntry {
	items := extractList(body, "items")
	out := make([]LogEntry, 0, len(items))
	for _, o := range items {
		if m, ok := o.(map[string]any); ok {
			out = append(out, logEntryFromAPI(m))
		}
	}
	return out
}

// ── document ─────────────────────────────────────────────────────────────────

// Document is a company document the SDK created/queried (company-data side).
//
// Value semantics mirror the connection-payload contract — keyed on
// BROADCAST(plaintext) vs PER-PERSON(always encrypted), NOT on IsPrivate:
//
//	broadcast file   -> {file, original_name, mime_type, size}  (plaintext)
//	per-person file  -> {"_enc_file": "enc_…json"}              (ciphertext blob, ANY IsPrivate)
//	broadcast json   -> the JSON object                          (plaintext)
//	per-person json  -> {"_enc":1,k,iv,d}                        (ciphertext wrapper, ANY IsPrivate;
//	                                                              decrypt on demand via JSON())
//
// IsPrivate is device-display-only (lock vs decrypt-on-load), not the value shape.
type Document struct {
	ID          string
	Kind        string
	Name        string
	Description string
	Status      string
	PayloadKind string // 'file' | 'json'
	IsPrivate   bool
	Value       any
	Metadata    map[string]any
	CreatedAt   *time.Time
	UpdatedAt   *time.Time

	decryptValue decryptValueFn // injected; nil for a plaintext-only document
	Raw          map[string]any
}

// JSON returns the plaintext object for a json document.
//
// Decryption is keyed on the value shape (per-person → encrypted wrapper), NOT on
// IsPrivate: a per-person json doc (ANY IsPrivate) is an {"_enc":1,…} wrapper and
// is decrypted with the SDK's own private key; a broadcast json doc is already
// plaintext and returned as-is. Returns a *DecryptError if called on a non-json
// document or with no decrypt wiring for an encrypted value.
func (d *Document) JSON() (any, error) {
	if d.PayloadKind != "json" {
		return nil, &DecryptError{msg: "JSON() is only valid for payload_kind='json' documents"}
	}
	if m, ok := d.Value.(map[string]any); ok && isEncWrapper(m) {
		if d.decryptValue == nil {
			return nil, &DecryptError{msg: "no decrypt wiring for an encrypted (per-person) document"}
		}
		plaintext, err := d.decryptValue(m)
		if err != nil {
			return nil, err
		}
		var parsed any
		dec := json.NewDecoder(strings.NewReader(plaintext))
		dec.UseNumber()
		if err := dec.Decode(&parsed); err != nil {
			return nil, &DecryptError{msg: "decrypted document value is not valid JSON"}
		}
		return parsed, nil
	}
	return d.Value, nil
}

func documentFromAPI(obj map[string]any, decryptValue decryptValueFn) Document {
	var metadata map[string]any
	if m, ok := obj["metadata"].(map[string]any); ok {
		metadata = m
	}
	return Document{
		ID:           asString(obj["id"]),
		Kind:         asString(obj["kind"]),
		Name:         asString(obj["name"]),
		Description:  asString(obj["description"]),
		Status:       asString(obj["status"]),
		PayloadKind:  asString(obj["payload_kind"]),
		IsPrivate:    coerceBool(obj["is_private"]),
		Value:        obj["value"],
		Metadata:     metadata,
		CreatedAt:    parseISO(asString(obj["created_at"])),
		UpdatedAt:    parseISO(asString(obj["updated_at"])),
		decryptValue: decryptValue,
		Raw:          obj,
	}
}

// documentsFromAPI parses the {total, items} documents list → []Document.
func documentsFromAPI(body any, decryptValue decryptValueFn) []Document {
	items := extractList(body, "items")
	out := make([]Document, 0, len(items))
	for _, o := range items {
		if m, ok := o.(map[string]any); ok {
			out = append(out, documentFromAPI(m, decryptValue))
		}
	}
	return out
}

// isEncWrapper reports whether a decoded map is a {"_enc":1,…} ciphertext wrapper.
func isEncWrapper(m map[string]any) bool {
	v, ok := m["_enc"]
	if !ok {
		return false
	}
	switch n := v.(type) {
	case json.Number:
		return n.String() == "1"
	case float64:
		return n == 1
	case int:
		return n == 1
	default:
		return false
	}
}

// ── shared coercion helpers ───────────────────────────────────────────────

// asString returns a string for a JSON scalar (string, bool, number), else "".
func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case json.Number:
		return s.String()
	case bool:
		if s {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// firstString returns the first non-empty string among the values.
func firstString(vals ...any) string {
	for _, v := range vals {
		if s := asString(v); s != "" {
			return s
		}
	}
	return ""
}

// coerceBool coerces a JSON bool or an XML "true"/"false" string into a bool.
func coerceBool(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		low := strings.ToLower(strings.TrimSpace(b))
		return low == "true" || low == "1"
	case json.Number:
		return b.String() != "0" && b.String() != ""
	case float64:
		return b != 0
	default:
		return false
	}
}

// parseISO parses an API ISO-8601 timestamp into *time.Time (tolerant of 'Z'),
// or nil if empty/unparseable.
func parseISO(value string) *time.Time {
	if value == "" {
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, value); err == nil {
			return &t
		}
	}
	return nil
}

// parseDate parses a plaintext ISO date (first 10 chars) → time.Time at midnight UTC.
func parseDate(value string) (time.Time, bool) {
	v := strings.TrimSpace(value)
	if len(v) >= 10 {
		v = v[:10]
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// extractList pulls a list out of a body that is either {key: [...]}, a bare
// list, or a {total, items} style wrapper (when key=="items").
func extractList(body any, key string) []any {
	switch b := body.(type) {
	case map[string]any:
		if v, ok := b[key]; ok {
			if lst, ok := v.([]any); ok {
				return lst
			}
			// A single object under the key → wrap as a one-element list.
			if v != nil {
				return []any{v}
			}
		}
		return nil
	case []any:
		return b
	default:
		return nil
	}
}
