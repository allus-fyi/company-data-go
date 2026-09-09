package companydata

// The field-type registry — the whole of what a contact-field TYPE means.
//
// A type is a ROW, not a literal: the row says what its parent is, which primitive draws it,
// which named check verifies it, which additive regexes it must match, which sub-fields it
// carries and on which storage lane its value lives. The rows are served by
// GET /api/contact-field-types; this file interprets them, so adding a type that reuses
// existing primitives and checks is a row and nothing else.
//
// TWO FIXED VOCABULARIES, and only these two are code. Inputs is what a platform can DRAW and
// Checks is what it can VERIFY beyond a regex; a new member of either is a change on every
// platform.
//
// INHERITANCE. A child inherits any column it leaves nil from its nearest ancestor that sets
// it — input, lane, check, options, fields. validation is the exception and is ADDITIVE: a
// value must match the regex of every ancestor that has one, root first, plus the type's own.
// Resolve answers the row with every inherited column filled in and the validations in that
// order, and every consumer works on that resolved definition rather than on a raw row.
//
// Pinned case-for-case by testdata/contract-field-validation-vector.json.

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Lanes are the storage lanes a value can live on. inline is the value itself; the other two
// are files.
var Lanes = []string{"inline", "photo", "document"}

// Inputs are the drawing primitives a row may name. A new member is code here, not a row.
var Inputs = []string{
	"line", "date", "list", "multilist", "country", "nationality", "state", "phone",
	"composite", "file", "pages",
}

// Checks are the named checks a row may name — verification beyond a regex. A new member is
// code here, not a row.
var Checks = []string{"url", "card", "number", "integer", "decimal", "float"}

// InputLanes are the lanes each primitive can store on. file is the only primitive with a
// choice, which is why a root with that input is the only row whose lane an operator picks.
var InputLanes = map[string][]string{
	"line":        {"inline"},
	"date":        {"inline"},
	"list":        {"inline"},
	"multilist":   {"inline"},
	"country":     {"inline"},
	"nationality": {"inline"},
	"state":       {"inline"},
	"phone":       {"inline"},
	"composite":   {"inline"},
	"file":        {"photo", "document"},
	"pages":       {"document"},
}

// EntryInputs are the primitives a sub-field entry may name: no composite nesting and no binary.
var EntryInputs = []string{"line", "date", "list", "country", "nationality", "state", "phone"}

// EnvelopeMembers are the members a file/pages envelope carries itself. They belong to the
// primitive, so a fields entry may never claim one — the entries are the extra metadata beside
// them.
var EnvelopeMembers = []string{
	"file", "pages", "original_name", "mime_type", "size", "name", "full", "thumb",
}

// PageMembers are the members ONE page of a pages envelope may carry.
var PageMembers = []string{"label", "file", "original_name", "mime_type", "size"}

// PageLabels are the page slots the multi-page upload draws: a front, an optional back,
// repeatable extras.
var PageLabels = []string{"front", "back", "additional"}

// MaxValidationLength is the longest a stored validation regex may be.
const MaxValidationLength = 200

// SubFieldEntry is one sub-field entry of a composite, file or pages type.
type SubFieldEntry struct {
	Key        string   `json:"key"`
	Input      *string  `json:"input"`
	Required   bool     `json:"required"`
	Check      *string  `json:"check"`
	Validation *string  `json:"validation"`
	Options    []string `json:"options"`
}

// FieldTypeRow is one raw registry row, exactly as GET /api/contact-field-types serves it.
type FieldTypeRow struct {
	Type       string          `json:"type"`
	Parent     *string         `json:"parent"`
	Label      *string         `json:"label"`
	Input      *string         `json:"input"`
	Lane       *string         `json:"lane"`
	Check      *string         `json:"check"`
	Options    []string        `json:"options"`
	Fields     []SubFieldEntry `json:"fields"`
	Validation *string         `json:"validation"`
	IsSystem   bool            `json:"is_system"`
}

// ResolvedFieldType is a row with every inherited column filled in, plus the validations
// root-first.
//
// A type the registry does not carry resolves with Known false and every column empty. That is
// a distinct answer from a known type with nothing set, and callers must read it as "this
// platform cannot draw or store this", never as a default.
type ResolvedFieldType struct {
	Type        string
	Parent      *string
	Label       string
	IsSystem    bool
	Known       bool
	Input       *string
	Lane        *string
	Check       *string
	Options     []string
	Fields      []SubFieldEntry
	Validations []string
}

var (
	urlRE        = regexp.MustCompile(`(?i)^https?://[^\s/$.?#][^\s]*\.[^\s]{2,}$`)
	urlSchemeRE  = regexp.MustCompile(`(?i)^https?://`)
	mimeRE       = regexp.MustCompile(`^[\w.+-]+/[\w.+-]+$`)
	phoneRE      = regexp.MustCompile(`^\+?\d{4,15}$`)
	phoneStripRE = regexp.MustCompile(`[ \-().]`)
	cardRE       = regexp.MustCompile(`^\d{12,19}$`)
	cardStripRE  = regexp.MustCompile(`[ -]`)
	// Numeric grammars accept ASCII digits only, so a hex literal, an Infinity/NaN spelling or a
	// Unicode digit is refused rather than accepted by the language's own numeric reader.
	integerRE = regexp.MustCompile(`^-?[0-9]+$`)
	// decimal(10,2) is a FIXED shape: up to 8 integer digits + up to 2 decimal digits.
	decimalRE = regexp.MustCompile(`^-?[0-9]{1,8}(\.[0-9]{1,2})?$`)
	// Float accepts decimal or scientific notation.
	floatRE     = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
	fieldDateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

var daysInMonthTable = [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

// Compiled stored regexes, keyed by the raw pattern. A nil value records a pattern this engine
// cannot compile, so it is attempted once rather than per value.
var (
	compiledMu sync.Mutex
	compiled   = map[string]*regexp.Regexp{}
	compiledOK = map[string]bool{}
)

func daysInMonth(year, month int) int {
	if month == 2 {
		if (year%4 == 0 && year%100 != 0) || year%400 == 0 {
			return 29
		}
		return 28
	}
	return daysInMonthTable[month-1]
}

// IsCalendarDate reports whether value is a real calendar date in YYYY-MM-DD.
func IsCalendarDate(value string) bool {
	if !fieldDateRE.MatchString(value) {
		return false
	}
	year, _ := strconv.Atoi(value[0:4])
	month, _ := strconv.Atoi(value[5:7])
	day, _ := strconv.Atoi(value[8:10])
	if month < 1 || month > 12 {
		return false
	}
	return day >= 1 && day <= daysInMonth(year, month)
}

func luhnOK(digits string) bool {
	total := 0
	dbl := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i]) - 48
		if d < 0 || d > 9 {
			return false
		}
		if dbl {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		total += d
		dbl = !dbl
	}
	return total%10 == 0
}

func finiteNumber(value string) bool {
	if value == "" {
		return false
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}
	return !math.IsNaN(n) && !math.IsInf(n, 0)
}

// NormaliseForCheck answers the CANONICAL FORM a named check verifies.
//
// It is also the form a regex below that check is tested against, since the check is what
// states it. A check with nothing to normalise, and a name that is not a check at all, answer
// the value unchanged.
func NormaliseForCheck(check, value string) string {
	switch check {
	case "url":
		if urlSchemeRE.MatchString(value) {
			return value
		}
		return "https://" + value
	case "card":
		return cardStripRE.ReplaceAllString(value, "")
	case "number", "integer", "decimal", "float":
		return strings.TrimSpace(value)
	default:
		return value
	}
}

// ApplyCheck runs one named check over the whole value in its canonical form. It answers "" when
// the value passes, else the check's name.
func ApplyCheck(check, value string) string {
	normalised := NormaliseForCheck(check, value)
	ok := true
	switch check {
	case "url":
		ok = urlRE.MatchString(normalised)
	case "card":
		ok = cardRE.MatchString(normalised) && luhnOK(normalised)
	case "number":
		ok = finiteNumber(normalised)
	case "integer":
		ok = integerRE.MatchString(normalised)
	case "decimal":
		ok = decimalRE.MatchString(normalised)
	case "float":
		ok = floatRE.MatchString(normalised)
	}
	if ok {
		return ""
	}
	return check
}

// CompileFieldRegex answers a stored regex anchored to the WHOLE value, or nil when this engine
// cannot compile it.
func CompileFieldRegex(regex string) *regexp.Regexp {
	compiledMu.Lock()
	defer compiledMu.Unlock()
	if seen, ok := compiledOK[regex]; ok {
		if !seen {
			return nil
		}
		return compiled[regex]
	}
	re, err := regexp.Compile("^(?:" + regex + ")$")
	if err != nil {
		compiledOK[regex] = false
		return nil
	}
	compiledOK[regex] = true
	compiled[regex] = re
	return re
}

// MatchesFieldRegex reports whether a value matches a stored regex, anchored to the whole value.
//
// A pattern that cannot be compiled is refused at write, so reaching this with one means the
// stored row predates the rule it is now held to: no verdict can be stated, and refusing the
// value would refuse every value of that type.
func MatchesFieldRegex(regex, value string) bool {
	re := CompileFieldRegex(regex)
	return re == nil || re.MatchString(value)
}

// isOptionArray reports whether value is a JSON LIST whose every element is a declared option.
//
// Decoded into any rather than []any so the JSON CONTAINER KIND survives: unmarshalling `null`
// into a []any succeeds and leaves a nil slice, which would read as an empty — and so trivially
// valid — list. A type assertion tells a real array from a null and from an object.
func isOptionArray(value string, options []string) bool {
	var raw any
	if err := json.Unmarshal([]byte(value), &raw); err != nil {
		return false
	}
	decoded, isList := raw.([]any)
	if !isList {
		return false
	}
	for _, e := range decoded {
		s, ok := e.(string)
		if !ok || !containsString(options, s) {
			return false
		}
	}
	return true
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func compareLabels(a, b string) bool {
	la, lb := strings.ToLower(a), strings.ToLower(b)
	if la != lb {
		return la < lb
	}
	return a < b
}

// FieldTypeRegistry is the served rows, interpreted.
//
// Built from the raw GET /api/contact-field-types array and held for the life of the client that
// fetched it. A registry with no rows knows no type, which is the honest answer for a client that
// has not loaded it: every type resolves as unknown and validates as "accept anything".
type FieldTypeRegistry struct {
	order    []string
	byType   map[string]FieldTypeRow
	resolved map[string]ResolvedFieldType
}

// NewFieldTypeRegistry builds a registry from the raw served rows.
func NewFieldTypeRegistry(rows []FieldTypeRow) *FieldTypeRegistry {
	r := &FieldTypeRegistry{
		byType:   map[string]FieldTypeRow{},
		resolved: map[string]ResolvedFieldType{},
	}
	for _, row := range rows {
		if row.Type == "" {
			continue
		}
		if _, seen := r.byType[row.Type]; !seen {
			r.order = append(r.order, row.Type)
		}
		r.byType[row.Type] = row
	}
	return r
}

// ── the tree ─────────────────────────────────────────────────────────────────

// Rows answers the raw rows in served order.
func (r *FieldTypeRegistry) Rows() []FieldTypeRow {
	out := make([]FieldTypeRow, 0, len(r.order))
	for _, t := range r.order {
		out = append(out, r.byType[t])
	}
	return out
}

// Types answers every type the registry carries, in served order.
func (r *FieldTypeRegistry) Types() []string {
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// Knows reports whether the registry carries this type at all.
func (r *FieldTypeRegistry) Knows(fieldType string) bool {
	_, ok := r.byType[fieldType]
	return ok
}

// Resolve answers the resolved definition: every inherited column filled in, validations
// root-first.
func (r *FieldTypeRegistry) Resolve(fieldType string) ResolvedFieldType {
	if cached, ok := r.resolved[fieldType]; ok {
		return cached
	}
	definition := r.resolveIn(fieldType)
	r.resolved[fieldType] = definition
	return definition
}

func (r *FieldTypeRegistry) resolveIn(fieldType string) ResolvedFieldType {
	row, ok := r.byType[fieldType]
	if !ok {
		return ResolvedFieldType{Type: fieldType, Label: fieldType, Validations: []string{}}
	}

	// Walk to the root collecting the chain, then fill downward: the nearest ancestor that sets
	// an inherited column wins, and the validations come out root-first.
	var chain []FieldTypeRow
	seen := map[string]bool{}
	cursor := fieldType
	for cursor != "" && !seen[cursor] {
		current, ok := r.byType[cursor]
		if !ok {
			break
		}
		seen[cursor] = true
		chain = append(chain, current)
		if current.Parent == nil {
			break
		}
		cursor = *current.Parent
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}

	label := fieldType
	if row.Label != nil && *row.Label != "" {
		label = *row.Label
	}
	definition := ResolvedFieldType{
		Type:        fieldType,
		Parent:      row.Parent,
		Label:       label,
		IsSystem:    row.IsSystem,
		Known:       true,
		Validations: []string{},
	}
	for _, ancestor := range chain {
		if ancestor.Input != nil {
			definition.Input = ancestor.Input
		}
		if ancestor.Lane != nil {
			definition.Lane = ancestor.Lane
		}
		if ancestor.Check != nil {
			definition.Check = ancestor.Check
		}
		if ancestor.Options != nil {
			definition.Options = ancestor.Options
		}
		if ancestor.Fields != nil {
			definition.Fields = ancestor.Fields
		}
		if ancestor.Validation != nil && *ancestor.Validation != "" {
			definition.Validations = append(definition.Validations, *ancestor.Validation)
		}
	}
	return definition
}

// Descendants answers the type and every descendant of it. An unknown type answers itself alone,
// so a lookup keyed on a type the registry does not carry still addresses that type rather than
// nothing.
func (r *FieldTypeRegistry) Descendants(fieldType string) []string {
	out := []string{fieldType}
	frontier := map[string]bool{fieldType: true}
	// Bounded by the number of rows: each pass adds only types not already collected.
	for guard := len(r.byType); guard > 0 && len(frontier) > 0; guard-- {
		next := map[string]bool{}
		for _, candidate := range r.order {
			row := r.byType[candidate]
			if row.Parent != nil && frontier[*row.Parent] && !containsString(out, candidate) {
				out = append(out, candidate)
				next[candidate] = true
			}
		}
		frontier = next
	}
	return out
}

// Accepts reports whether a request for requested is answered by a field of actual.
func (r *FieldTypeRegistry) Accepts(requested, actual string) bool {
	return actual == requested || containsString(r.Descendants(requested), actual)
}

// ── storage lane ─────────────────────────────────────────────────────────────

// IsBinary reports whether this type's value is a file rather than an inline value.
func (r *FieldTypeRegistry) IsBinary(fieldType string) bool {
	lane := r.Resolve(fieldType).Lane
	return lane != nil && *lane != "inline"
}

// IsDocumentLike reports whether this type uses the document upload/storage lane.
func (r *FieldTypeRegistry) IsDocumentLike(fieldType string) bool {
	lane := r.Resolve(fieldType).Lane
	return lane != nil && *lane == "document"
}

// IsIDDocument reports whether this type carries the multi-page ID-document envelope.
func (r *FieldTypeRegistry) IsIDDocument(fieldType string) bool {
	input := r.Resolve(fieldType).Input
	return input != nil && *input == "pages"
}

// BinaryTypes answers every type on a lane other than inline.
func (r *FieldTypeRegistry) BinaryTypes() []string {
	return r.filterTypes(r.IsBinary)
}

// DocumentLikeTypes answers every type on the document lane.
func (r *FieldTypeRegistry) DocumentLikeTypes() []string {
	return r.filterTypes(r.IsDocumentLike)
}

// IDDocumentTypes answers every type drawn by the multi-page upload.
func (r *FieldTypeRegistry) IDDocumentTypes() []string {
	return r.filterTypes(r.IsIDDocument)
}

func (r *FieldTypeRegistry) filterTypes(keep func(string) bool) []string {
	out := []string{}
	for _, t := range r.order {
		if keep(t) {
			out = append(out, t)
		}
	}
	return out
}

// ── derived sets ─────────────────────────────────────────────────────────────

// IsOptionLessChoice reports a choice type whose options are supplied elsewhere. It is usable
// only where something else carries them — a flow element — so it is offered for no contact
// field, no request row and no claim.
func (r *FieldTypeRegistry) IsOptionLessChoice(fieldType string) bool {
	definition := r.Resolve(fieldType)
	if definition.Input == nil {
		return false
	}
	isChoice := *definition.Input == "list" || *definition.Input == "multilist"
	return isChoice && len(definition.Options) == 0
}

// OptionsFor answers the option domain a choice value is held to: the ROW's own resolved options
// when it carries any, else the ones the caller supplies, and NEVER a merge of the two — a row
// that states its domain owns it, and a row that states none borrows the caller's whole.
//
// nil means neither source has a domain: an option-less row asked about with nothing supplied. A
// value cannot be measured against that, so Validate refuses rather than testing membership of an
// empty list, which would refuse every value including a legitimate one.
//
// Exported so a caller can RENDER exactly the domain the validator will enforce. suppliedOptions
// is variadic so every non-choice call site passes nothing, which is "none".
func (r *FieldTypeRegistry) OptionsFor(fieldType string, suppliedOptions ...string) []string {
	if rowOptions := r.Resolve(fieldType).Options; len(rowOptions) > 0 {
		return rowOptions
	}
	if len(suppliedOptions) > 0 {
		return suppliedOptions
	}
	return nil
}

// RequestableTypes answers the types a contact field, a service request row or an admin field may
// declare.
func (r *FieldTypeRegistry) RequestableTypes() []string {
	return r.filterTypes(func(t string) bool { return !r.IsOptionLessChoice(t) })
}

// FlowTypes answers the requestable set plus the option-less choice types a flow element supplies
// options for.
func (r *FieldTypeRegistry) FlowTypes() []string {
	out := r.RequestableTypes()
	return append(out, r.filterTypes(r.IsOptionLessChoice)...)
}

// ClaimableTypes answers the requestable set on the inline lane. A file can never be sealed to a
// relying party's app key, so no claim can name a binary type.
func (r *FieldTypeRegistry) ClaimableTypes() []string {
	out := []string{}
	for _, t := range r.RequestableTypes() {
		lane := r.Resolve(t).Lane
		if lane != nil && *lane == "inline" {
			out = append(out, t)
		}
	}
	return out
}

// ── display ──────────────────────────────────────────────────────────────────

// LabelFor answers the label to render. A seeded row's label is the fieldtype_* translation key
// and a data-added row's is the literal an operator typed; IsSystem is the discriminator, and a
// literal is rendered verbatim rather than looked up.
func (r *FieldTypeRegistry) LabelFor(fieldType string) string {
	return r.Resolve(fieldType).Label
}

// Ordered answers the requested types in display order: roots A→Z, each followed by its own
// children A→Z, recursively, by the stored label. A requested type the registry does not carry
// sorts after the tree, so a picker built from a stale set still shows every entry it was given.
func (r *FieldTypeRegistry) Ordered(types []string) []string {
	wanted := map[string]bool{}
	for _, t := range types {
		wanted[t] = true
	}

	childrenOf := func(parent *string) []string {
		type labelled struct{ label, name string }
		var found []labelled
		for _, name := range r.order {
			row := r.byType[name]
			if (row.Parent == nil) != (parent == nil) {
				continue
			}
			if row.Parent != nil && *row.Parent != *parent {
				continue
			}
			label := name
			if row.Label != nil && *row.Label != "" {
				label = *row.Label
			}
			found = append(found, labelled{label, name})
		}
		sort.SliceStable(found, func(i, j int) bool { return compareLabels(found[i].label, found[j].label) })
		out := make([]string, 0, len(found))
		for _, f := range found {
			out = append(out, f.name)
		}
		return out
	}

	out := []string{}
	var walk func(parent *string)
	walk = func(parent *string) {
		for _, name := range childrenOf(parent) {
			if wanted[name] {
				out = append(out, name)
			}
			child := name
			walk(&child)
		}
	}
	walk(nil)

	var unknown []string
	for _, t := range types {
		if !containsString(out, t) {
			unknown = append(unknown, t)
		}
	}
	sort.SliceStable(unknown, func(i, j int) bool { return compareLabels(unknown[i], unknown[j]) })
	return append(out, unknown...)
}

// EffectiveType answers the nearest ancestor, self included, that is date or number; otherwise
// the type itself. It collapses a type to the domain its comparison operators are chosen from;
// nothing in Validate consults it, and no value's shape follows it.
func (r *FieldTypeRegistry) EffectiveType(fieldType string) string {
	seen := map[string]bool{}
	cursor := fieldType
	for cursor != "" && !seen[cursor] {
		row, ok := r.byType[cursor]
		if !ok {
			break
		}
		seen[cursor] = true
		if cursor == "date" || cursor == "number" {
			return cursor
		}
		if row.Parent == nil {
			break
		}
		cursor = *row.Parent
	}
	return fieldType
}

// ── validation ───────────────────────────────────────────────────────────────

// Validate checks a plaintext value against a type, in the one fixed order: the
// primitive's own rule, then the resolved check, then every regex root-first, then the sub-field
// entries. The CHECK's normalised value is what those regexes see; the primitive's is not.
//
// An EMPTY value is valid — required is the caller's job — and a type the registry does not carry
// accepts anything, which is the pinned answer for a client older than a type. It answers "" when
// valid, else the name of the first failing rule.
func (r *FieldTypeRegistry) Validate(fieldType string, value string, suppliedOptions ...string) string {
	if value == "" {
		return ""
	}
	definition := r.Resolve(fieldType)
	if !definition.Known {
		return ""
	}

	if failure := r.applyPrimitive(definition, value, r.OptionsFor(fieldType, suppliedOptions...)); failure != "" {
		return failure
	}

	// A CHECK'S NORMALISATION CARRIES; A PRIMITIVE'S DOES NOT, and the asymmetry is the rule
	// rather than an oversight. A check states the canonical form of the value it verifies — a URL
	// with its scheme, a card number without its separators — so a regex a child adds below it
	// describes that form and is tested against it. A primitive draws a value it does not rewrite,
	// so nothing it does reaches the regex step.
	matched := value
	if definition.Check != nil && *definition.Check != "" {
		if failure := ApplyCheck(*definition.Check, value); failure != "" {
			return failure
		}
		matched = NormaliseForCheck(*definition.Check, value)
	}
	for _, regex := range definition.Validations {
		if !MatchesFieldRegex(regex, matched) {
			return "validation"
		}
	}
	return ""
}

// IsFieldValueValid reports whether value is an acceptable plaintext for fieldType.
func (r *FieldTypeRegistry) IsFieldValueValid(fieldType string, value string, suppliedOptions ...string) bool {
	return r.Validate(fieldType, value, suppliedOptions...) == ""
}

// FieldValueError answers "" when valid, else the name of the first failing rule.
func (r *FieldTypeRegistry) FieldValueError(fieldType string, value string, suppliedOptions ...string) string {
	return r.Validate(fieldType, value, suppliedOptions...)
}

// applyPrimitive runs the primitive's own rule, plus the sub-field entries for the three
// primitives that carry them.
//
// options is the domain a choice value is held to, already resolved by OptionsFor; nil is "there
// is no domain", which is refused rather than tested.
func (r *FieldTypeRegistry) applyPrimitive(definition ResolvedFieldType, value string, options []string) string {
	if definition.Input == nil {
		return ""
	}
	switch *definition.Input {
	case "line":
		return ""
	case "date":
		if IsCalendarDate(value) {
			return ""
		}
		return "date"
	case "list":
		if options == nil {
			return "options_unavailable"
		}
		if containsString(options, value) {
			return ""
		}
		return "list"
	case "multilist":
		if options == nil {
			return "options_unavailable"
		}
		if isOptionArray(value, options) {
			return ""
		}
		return "multilist"
	case "country", "nationality":
		if countryCodeSet[value] {
			return ""
		}
		return *definition.Input
	case "state":
		if usStateCodeSet[value] {
			return ""
		}
		return "state"
	case "phone":
		if phoneRE.MatchString(phoneStripRE.ReplaceAllString(value, "")) {
			return ""
		}
		return "phone"
	case "composite":
		return validateFieldObject(value, definition.Fields, nil)
	case "file", "pages":
		return validateFieldObject(value, definition.Fields, EnvelopeMembers)
	default:
		return ""
	}
}

// validateFieldObject checks a JSON object value: no unknown key, every required entry present,
// and each non-empty entry valid for its own primitive, check and regex.
//
// envelopeMembers are the primitive's own members, accepted beside the entries and validated by
// validateEnvelopeMember — the one home for what each of them looks like.
func validateFieldObject(value string, fields []SubFieldEntry, envelopeMembers []string) string {
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(value))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return "object"
	}

	entries := map[string]SubFieldEntry{}
	for _, entry := range fields {
		if entry.Key != "" {
			entries[entry.Key] = entry
		}
	}

	for key, raw := range obj {
		if entry, ok := entries[key]; ok {
			s, isString := raw.(string)
			if !isString {
				return key
			}
			if s != "" && validateFieldEntry(entry, s) != "" {
				return key
			}
			continue
		}
		if !containsString(envelopeMembers, key) {
			return "unknown_key"
		}
		if failure := validateEnvelopeMember(key, raw); failure != "" {
			return failure
		}
	}

	for key, entry := range entries {
		if !entry.Required {
			continue
		}
		got, present := obj[key]
		if !present || got == "" {
			return key
		}
	}
	return ""
}

// validateEnvelopeMember checks ONE member of a file/pages envelope by its own shape — the single
// home for what each member looks like, so a member added to the envelope is one branch here and
// nothing else.
//
// size is a JSON integer, pages the multi-page list below, mime_type a MIME string when it
// carries anything, and every other member a string.
func validateEnvelopeMember(key string, raw any) string {
	if key == "pages" {
		return validatePages(raw)
	}
	if key == "size" {
		num, isNum := raw.(json.Number)
		if !isNum {
			return "size"
		}
		if _, err := num.Int64(); err != nil || strings.ContainsAny(num.String(), ".eE") {
			return "size"
		}
		return ""
	}
	s, isString := raw.(string)
	if !isString {
		return key
	}
	if key == "mime_type" && s != "" && !mimeRE.MatchString(s) {
		return "mime_type"
	}
	return ""
}

// validatePages checks the pages member of an ID-document envelope: a LIST of page objects, never
// a scalar.
//
// Each page names one uploaded file plus that file's own metadata. file is the reference and is
// required; label says which slot the page fills, and the slots are exactly the ones the
// multi-page editor draws — a front, an optional back, and repeatable extras. An empty list is a
// document whose pages have not been uploaded yet, which is a valid envelope.
func validatePages(raw any) string {
	pages, isList := raw.([]any)
	if !isList {
		return "pages"
	}
	for _, page := range pages {
		members, isObject := page.(map[string]any)
		if !isObject {
			return "pages"
		}
		for key, member := range members {
			if !containsString(PageMembers, key) {
				return "pages"
			}
			if key == "label" {
				label, isString := member.(string)
				if !isString || !containsString(PageLabels, label) {
					return "pages"
				}
				continue
			}
			if key == "file" {
				file, isString := member.(string)
				if !isString || file == "" {
					return "pages"
				}
				continue
			}
			if validateEnvelopeMember(key, member) != "" {
				return "pages"
			}
		}
		if _, present := members["file"]; !present {
			return "pages"
		}
	}
	return ""
}

// validateFieldEntry runs one sub-field entry: its primitive rule, then its check, then its regex.
func validateFieldEntry(entry SubFieldEntry, value string) string {
	primitive := "line"
	if entry.Input != nil && *entry.Input != "" {
		primitive = *entry.Input
	}
	failure := ""
	switch primitive {
	case "date":
		if !IsCalendarDate(value) {
			failure = "date"
		}
	case "list":
		if !containsString(entry.Options, value) {
			failure = "list"
		}
	case "country", "nationality":
		if !countryCodeSet[value] {
			failure = primitive
		}
	case "state":
		if !usStateCodeSet[value] {
			failure = "state"
		}
	case "phone":
		if !phoneRE.MatchString(phoneStripRE.ReplaceAllString(value, "")) {
			failure = "phone"
		}
	}
	if failure != "" {
		return failure
	}

	// The entry runs the same primitive → check → regex order a top-level value does, and the
	// check's normalisation carries into its regex for the same reason it does there — so a
	// composite's entry can never disagree with a value of the same shape.
	matched := value
	if entry.Check != nil && *entry.Check != "" {
		if ApplyCheck(*entry.Check, value) != "" {
			return *entry.Check
		}
		matched = NormaliseForCheck(*entry.Check, value)
	}
	if entry.Validation != nil && *entry.Validation != "" && !MatchesFieldRegex(*entry.Validation, matched) {
		return "validation"
	}
	return ""
}
