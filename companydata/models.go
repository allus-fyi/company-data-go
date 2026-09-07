package companydata

import (
	"encoding/json"
	"strconv"
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
//	RequestField { Slug, Label, Type, OneTime, Mandatory, Verified, VerifiedMaxAgeDays }
//	Connection   { ID, PersonID, DisplayName, ConnectedAt, Values map[slug]Value }
//	Value        { Value, Live, UpdatedAt, Verified, VerifiedAt, VerifiedExpiresAt,
//	               VerifiedMethod, VerifiedProvider, VerificationID }
//	Change       { ID, Event, PersonID, ShareCode, Slug, Value, Live, At } // ID = stable dedup key
//	LogEntry     { Type, Message, Metadata, At }
//
// Typed values:
//   - email/phone/url/text                → string
//   - address/bank/creditcard             → map[string]any (the decrypted plaintext is a JSON object string → parsed)
//   - date/date_of_birth                  → time.Time
//   - photo/document/legal_document and the ID-document subtypes
//     passport/photo_id/drivers_license   → a lazy *BinaryHandle
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
	// binaryTypes: the ID-document subtypes are children of legal_document and share its envelope.
	binaryTypes = map[string]bool{
		"photo": true, "document": true, "legal_document": true,
		"passport": true, "photo_id": true, "drivers_license": true,
	}
	dateTypes = map[string]bool{"date": true, "date_of_birth": true}
)

// decryptValueFn decrypts a ciphertext wrapper (map / struct / JSON string) →
// plaintext string. Closes over the service private key.
type decryptValueFn func(any) (string, error)

// typeForSlugFn resolves a request slug to its field type (e.g. "email", "photo").
type typeForSlugFn func(string) string

// binaryFetchFn fetches a slot file endpoint and classifies its response —
// an encrypted wrapper or the raw file bytes, decided on Content-Type.
type binaryFetchFn func(string) (BinaryFetchResult, error)

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
	// Audience: which customer TYPE this row applies to — "person" | "company" |
	// "both" (B2B). Empty on an older API.
	Audience string
	// Verified: this row DEMANDS a verified answer — only a value the person verified
	// satisfies it, and an unverified candidate is refused at the accepting act rather
	// than downgraded.
	Verified bool
	// VerifiedMaxAgeDays: the oldest verification the demand accepts, in days; nil = no
	// age limit. Enforced at the accepting act only — a standing live link is not
	// re-enforced afterwards, so apply your own policy from each Value's VerifiedAt.
	VerifiedMaxAgeDays *int
	Raw                map[string]any
}

func requestFieldFromAPI(obj map[string]any) RequestField {
	return RequestField{
		Slug:    asString(obj["slug"]),
		Label:   asString(obj["label"]),
		Type:    asString(obj["type"]),
		OneTime: coerceBool(obj["one_time"]),
		Mandatory: coerceBool(obj["mandatory_provide"]) ||
			coerceBool(obj["mandatory_connected"]),
		Audience:           asString(obj["audience"]),
		Verified:           coerceBool(obj["verified"]),
		VerifiedMaxAgeDays: coerceInt(obj["verified_max_age_days"]),
		Raw:                obj,
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
	// Verified: true iff the hash recomputes over the plaintext AND the verification has not lapsed.
	Verified bool
	// VerifiedAt: when the person's answering field was verified; nil when the value carries no
	// verification. A stamp, not a promise about today — read it with Verified.
	VerifiedAt *time.Time
	// VerifiedExpiresAt: when that verification lapses (a document-backed verification dies with the
	// document); nil = it does not lapse. Past → Verified reads false.
	VerifiedExpiresAt *time.Time
	// VerifiedMethod: HOW allme bound this value — email_code | sms_code | sumsub_id |
	// sumsub_address. VerifiedProvider: WHO established the proof — allme | sumsub.
	// VerificationID: the id to quote back to allme in a dispute.
	//
	// All three arrive together or not at all: a value bound before the proof log existed
	// carries the four verification keys and none of these, so all three read "". They are
	// readable whatever Verified says — that boolean stays the only trust decision.
	VerifiedMethod   string
	VerifiedProvider string
	VerificationID   string
	Raw              map[string]any
}

func valueFromAPI(obj map[string]any, fieldType string, decryptValue decryptValueFn, binaryFetch binaryFetchFn) (Value, error) {
	typed, err := typedValue(obj, fieldType, decryptValue, binaryFetch)
	if err != nil {
		return Value{}, err
	}
	return Value{
		Value:             typed,
		Live:              coerceBool(obj["live"]),
		UpdatedAt:         parseISO(firstString(obj["updatedAt"], obj["updated_at"])),
		Verified:          verifiedFrom(obj, typed),
		VerifiedAt:        parseISO(asString(obj["verified_at"])),
		VerifiedExpiresAt: parseISO(asString(obj["verified_expires_at"])),
		VerifiedMethod:    asString(obj["verified_method"]),
		VerifiedProvider:  asString(obj["verified_provider"]),
		VerificationID:    asString(obj["verification_id"]),
		Raw:               obj,
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
	// CustomerType: the connected customer's TYPE — "person" | "company" (B2B).
	// Empty on an older API. PersonID keeps its name (wire person_user_id)
	// but semantically holds the customer's user id.
	CustomerType string
	// ShareCode: the customer's profile share code (previously only via Raw).
	ShareCode string
	Raw       map[string]any
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
		ID:           connID,
		PersonID:     personID,
		DisplayName:  displayName,
		ConnectedAt:  connectedAt,
		Values:       values,
		CustomerType: firstString(obj["customer_type"], identity["customer_type"]),
		ShareCode:    firstString(obj["share_code"], identity["share_code"]),
		Raw:          obj,
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
	ID                  string
	Event               string
	PersonID            string
	ShareCode           string // the person's profile share code (every event; may be empty)
	CustomerType        string // "person" | "company" (B2B); empty on an older API
	Slug                string
	Value               any
	Live                bool
	HasLive             bool
	DocumentID          string     // set on document_status_changed
	Status              string     // set on document_status_changed
	Action              string     // set on document_status_changed for a contract: signed | accepted | cancelled
	Note                string     // set on document_status_changed: the person's optional cancellation note
	Method              string     // set on a signature: biometric | twofa | email | custodian
	ContentSHA256       string     // set on a signature: SHA-256 of the signed content
	SignedAt            string     // set on a signature: ISO timestamp the signature was recorded
	CancelEffectiveDate string     // set on a cancelled document_status_changed: ISO date the cancellation takes effect
	RequestID           string     // set on connection_request_accepted | connection_request_rejected
	PublicKeySHA256     string     // set on key_rotated — SHA-256 fingerprint of the person's NEW public key
	ConnectionID        string     // set on message_received — the connection to reply/ack on
	MessageID           string     // set on message_received — the ack boundary (upToMessageID)
	PersonPublicKey     string     // set on message_received — base64 SPKI to encrypt the reply to
	MessageBody         string     // set on message_received — the DECRYPTED message text
	Verified            bool       // true iff a field_updated value's hash matches AND the verification has not lapsed
	VerifiedAt          *time.Time // when the answering field was verified; nil when the value carries no verification
	VerifiedExpiresAt   *time.Time // when that verification lapses; nil = it does not. Past → Verified reads false
	// The proof metadata beside the binding: HOW it was bound, by WHOM, and the id to quote back
	// in a dispute. All three or none; readable whatever Verified says.
	VerifiedMethod   string
	VerifiedProvider string
	VerificationID   string
	At               *time.Time
	Raw              map[string]any
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

	var documentID, status, action, note, method, contentSHA256, signedAt, cancelEffectiveDate string
	if event == "document_status_changed" {
		documentID = asString(obj["document_id"])
		status = asString(obj["status"])
		action = asString(obj["action"])
		note = asString(obj["note"])
		method = asString(obj["method"])
		contentSHA256 = asString(obj["content_sha256"])
		signedAt = asString(obj["signed_at"])
		cancelEffectiveDate = asString(obj["cancel_effective_date"])
	}

	// 2fa_challenge_completed carries the outcome in status (approved|denied|revoked); its
	// challenge_id/completed_at stay in Raw. The poll is the record (spec §3).
	if event == "2fa_challenge_completed" {
		status = asString(obj["status"])
	}

	var requestID string
	if event == "connection_request_accepted" || event == "connection_request_rejected" {
		requestID = asString(obj["request_id"])
	}

	var publicKeySHA256 string
	if event == "key_rotated" {
		publicKeySHA256 = asString(obj["public_key_sha256"])
	}

	// message_received carries the connection to answer on, the ack boundary, the
	// person's public key for the reply, and the message ciphertext itself; its
	// created_at stays in Raw.
	var connectionID, messageID, personPublicKey, messageBody string
	if event == "message_received" {
		connectionID = asString(obj["connection_id"])
		messageID = asString(obj["message_id"])
		personPublicKey = asString(obj["person_public_key"])
		// The message ciphertext is carried under body, never value: on every other event
		// value means field ciphertext, which a message body is not. It is encrypted for
		// the SERVICE key, so the ordinary decrypt opens it.
		if cipher, ok := obj["body"]; ok && cipher != nil {
			plain, err := decryptValue(cipher)
			if err != nil {
				return Change{}, err
			}
			messageBody = plain
		}
	}

	return Change{
		ID:                  asString(obj["id"]),
		Event:               event,
		PersonID:            firstString(obj["person_user_id"], obj["person_id"]),
		ShareCode:           asString(obj["share_code"]),
		CustomerType:        asString(obj["customer_type"]),
		Slug:                slug,
		Value:               value,
		Live:                live,
		HasLive:             hasLive,
		DocumentID:          documentID,
		Status:              status,
		Action:              action,
		Note:                note,
		Method:              method,
		ContentSHA256:       contentSHA256,
		SignedAt:            signedAt,
		CancelEffectiveDate: cancelEffectiveDate,
		RequestID:           requestID,
		PublicKeySHA256:     publicKeySHA256,
		ConnectionID:        connectionID,
		MessageID:           messageID,
		PersonPublicKey:     personPublicKey,
		MessageBody:         messageBody,
		Verified:            verifiedFrom(obj, value),
		VerifiedAt:          parseISO(asString(obj["verified_at"])),
		VerifiedExpiresAt:   parseISO(asString(obj["verified_expires_at"])),
		VerifiedMethod:      asString(obj["verified_method"]),
		VerifiedProvider:    asString(obj["verified_provider"]),
		VerificationID:      asString(obj["verification_id"]),
		At:                  parseISO(asString(obj["at"])),
		Raw:                 obj,
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

// ── flow run ─────────────────────────────────────────────────────────────────

// FlowRun is a contract-flow run (company-data side).
//
// The company is one of the two bound parties. Bindings maps each party key to
// the bound user_id (the company's own is CompanyUserID); Answers are the
// per-party encrypted answer copies (the company reads the rows whose
// for_user_id == CompanyUserID, decryptable with the service private key);
// Definition is the pinned flow-version graph (nodes, edges, parties, output_mode).
type FlowRun struct {
	ID            string
	FlowID        string
	FlowVersion   any
	ServiceID     string
	ConnectionID  string
	CompanyUserID string
	Bindings      map[string]string
	Status        string
	CurrentNode   string
	DocumentID    string
	OutputMode    string
	ReferenceDate string // optional YYYY-MM-DD pinned "today" for constants; "" when absent
	Definition    map[string]any
	Answers       []map[string]any
	CreatedAt     *time.Time
	UpdatedAt     *time.Time
	Raw           map[string]any
}

// CompanyPartyKey is the party key the company is bound to (Bindings[key] == CompanyUserID).
func (r FlowRun) CompanyPartyKey() string {
	for key, uid := range r.Bindings {
		if uid == r.CompanyUserID {
			return key
		}
	}
	return ""
}

// ServiceUserID is the company's bound user_id — its answer copies use this for_user_id.
func (r FlowRun) ServiceUserID() string { return r.CompanyUserID }

func flowRunFromAPI(obj map[string]any) FlowRun {
	if obj == nil {
		obj = map[string]any{}
	}
	var def map[string]any
	if d, ok := obj["definition"].(map[string]any); ok {
		def = d
	} else {
		def = map[string]any{
			"nodes":       obj["nodes"],
			"edges":       obj["edges"],
			"parties":     obj["parties"],
			"output_mode": obj["output_mode"],
		}
	}
	bindings := map[string]string{}
	if b, ok := obj["bindings"].(map[string]any); ok {
		for k, v := range b {
			bindings[k] = asString(v)
		}
	}
	var answers []map[string]any
	if lst, ok := obj["answers"].([]any); ok {
		for _, a := range lst {
			if m, ok := a.(map[string]any); ok {
				answers = append(answers, m)
			}
		}
	}
	outputMode := asString(obj["output_mode"])
	if outputMode == "" {
		outputMode = asString(def["output_mode"])
	}
	return FlowRun{
		ID:            asString(obj["id"]),
		FlowID:        asString(obj["flow_id"]),
		FlowVersion:   obj["flow_version"],
		ServiceID:     asString(obj["service_id"]),
		ConnectionID:  asString(obj["connection_id"]),
		CompanyUserID: asString(obj["company_user_id"]),
		Bindings:      bindings,
		Status:        asString(obj["status"]),
		CurrentNode:   asString(obj["current_node"]),
		DocumentID:    asString(obj["document_id"]),
		OutputMode:    outputMode,
		ReferenceDate: asString(obj["reference_date"]),
		Definition:    def,
		Answers:       answers,
		CreatedAt:     parseISO(asString(obj["created_at"])),
		UpdatedAt:     parseISO(asString(obj["updated_at"])),
		Raw:           obj,
	}
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

	// Contract fields.
	RequiresSignature  bool
	RequiresAcceptance bool
	Signatures         []map[string]any // contract sign/accept audit trail (company-side reads only)

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
	var signatures []map[string]any
	if arr, ok := obj["signatures"].([]any); ok {
		for _, s := range arr {
			if sm, ok := s.(map[string]any); ok {
				signatures = append(signatures, sm)
			}
		}
	}
	return Document{
		ID:                 asString(obj["id"]),
		Kind:               asString(obj["kind"]),
		Name:               asString(obj["name"]),
		Description:        asString(obj["description"]),
		Status:             asString(obj["status"]),
		PayloadKind:        asString(obj["payload_kind"]),
		IsPrivate:          coerceBool(obj["is_private"]),
		Value:              obj["value"],
		Metadata:           metadata,
		CreatedAt:          parseISO(asString(obj["created_at"])),
		UpdatedAt:          parseISO(asString(obj["updated_at"])),
		RequiresSignature:  coerceBool(obj["requires_signature"]),
		RequiresAcceptance: coerceBool(obj["requires_acceptance"]),
		Signatures:         signatures,
		decryptValue:       decryptValue,
		Raw:                obj,
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

// verifiedFrom recomputes the verified flag from the just-decrypted plaintext (text values only).
//
// Two conditions, both required: the hash recomputes over the exact plaintext, AND the verification
// has not lapsed (verified_expires_at absent or still in the future). A document-backed verification
// lapses when the document itself expires, so a stale binding reads false here without any lookup.
func verifiedFrom(obj map[string]any, plaintext any) bool {
	pt, ok := plaintext.(string)
	if !ok {
		return false
	}
	vhash := asString(obj["verified_hash"])
	vsalt := asString(obj["verified_salt"])
	if vhash == "" || vsalt == "" {
		return false
	}
	if expiryPassed(asString(obj["verified_expires_at"])) {
		return false
	}
	return HashMatches(vsalt, vhash, pt)
}

// expiryPassed reports whether a verification expiry stamp has already passed.
//
// Absent → false: a verification with no expiry never lapses. Present but unparseable → true: an
// expiry that cannot be evaluated cannot be used to claim the value is still verified today.
func expiryPassed(value string) bool {
	if value == "" {
		return false
	}
	when := parseISO(value)
	if when == nil {
		return true
	}
	return !when.After(time.Now())
}

// coerceInt coerces a JSON number or an XML numeric string into an *int, or nil when absent.
func coerceInt(value any) *int {
	s := strings.TrimSpace(asString(value))
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &n
}
