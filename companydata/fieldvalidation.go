package companydata

// Field-type value validation — issue #302. Pure + i18n-free. Data-driven: each type maps to a
// "kind"; structured types map each sub-field to its own sub-rule (§2b), reusing the same kinds.
// Validate the PLAINTEXT before encryption, at input surfaces only (never on share/propagate).
// Kept byte-aligned across web / allus / iOS / Android / the 6 SDKs by
// docs/contract-field-validation-vector.json. Reference: frontend/src/fieldValidation.js. Spec:
// docs/superpowers/specs/2026-07-15-field-type-validation-design.html
//
// Contract: FieldValueValid(fieldType, value) -> bool. Empty value = valid (required is the
// caller's job). Only present, non-empty sub-fields of a structured type are checked.

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var (
	fvEmailRE  = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	fvURLRE    = regexp.MustCompile(`(?i)^https?://[^\s/$.?#][^\s]*\.[^\s]{2,}$`)
	fvSchemeRE = regexp.MustCompile(`(?i)^https?://`)
	fvMimeRE   = regexp.MustCompile(`^[\w.+-]+/[\w.+-]+$`)
	fvPhoneRE  = regexp.MustCompile(`^\+?\d{4,15}$`)
	fvCardRE   = regexp.MustCompile(`^\d{12,19}$`)
	fvDateRE   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

	fvPostalRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 -]{1,9}$`)
	fvExpiryRE  = regexp.MustCompile(`^(0[1-9]|1[0-2])/\d{2}(\d{2})?$`)
	fvCvcRE     = regexp.MustCompile(`^\d{3,4}$`)
	fvSwiftRE   = regexp.MustCompile(`^[A-Za-z]{6}[A-Za-z0-9]{2}([A-Za-z0-9]{3})?$`)
	fvRoutingRE = regexp.MustCompile(`^\d{9}$`)
	fvAccountRE = regexp.MustCompile(`^[A-Za-z0-9 ]{4,34}$`)

	fvPhoneStrip = regexp.MustCompile(`[ \-().]`)
	fvCardStrip  = regexp.MustCompile(`[ -]`)

	fvGender = []string{"Male", "Female", "Non-binary", "Prefer not to say"}

	// #303: country/nationality store an ISO 3166-1 alpha-2 code; address state = USPS 2-letter
	// code. The lists come from the generated country data (do NOT inline them — they would rot).
	fvCountrySet = fvToSet(CountryCodes)
	fvUSStateSet = fvToSet(USStateCodes)
)

func fvToSet(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}

// fvSub is a structured sub-field rule. Zero value ({}) = any non-empty string.
// isInt = a JSON integer; re = string matching a regex; kind = reuse a kind handler.
type fvSub struct {
	isInt bool
	re    *regexp.Regexp
	kind  string
}

// fvObj: structured types → each allowed key → its sub-rule (§2b).
var fvObj = map[string]map[string]fvSub{
	"address": {
		"postal_code":     {re: fvPostalRE},
		"country":         {kind: "countryCode"},
		"state":           {kind: "usState"},
		"street":          {},
		"building_number": {},
		"affix":           {},
		"city":            {},
	},
	"creditcard": {
		"number": {kind: "card"},
		"expiry": {re: fvExpiryRE},
		"cvc":    {re: fvCvcRE},
		"name":   {},
	},
	"bank": {
		"swift":          {re: fvSwiftRE},
		"routing_number": {re: fvRoutingRE},
		"account_number": {re: fvAccountRE},
		"account_holder": {},
		"bank_name":      {},
	},
	"document": {
		"size":          {isInt: true},
		"mime_type":     {re: fvMimeRE},
		"name":          {},
		"file":          {},
		"original_name": {},
	},
	"legal_document": {
		"size":            {isInt: true},
		"expiry_date":     {kind: "date"},
		"mime_type":       {re: fvMimeRE},
		"document_number": {},
		"file":            {},
		"original_name":   {},
	},
}

// fvRule is a top-level type rule.
type fvRule struct {
	kind   string
	re     *regexp.Regexp
	values []string
}

var fvRules = map[string]fvRule{
	"email":          {kind: "regex", re: fvEmailRE},
	"phone":          {kind: "phone"},
	"url":            {kind: "url"},
	"date":           {kind: "date"},
	"date_of_birth":  {kind: "date"},
	"gender":         {kind: "enum", values: fvGender},
	"address":        {kind: "object"},
	"creditcard":     {kind: "object"},
	"bank":           {kind: "object"},
	"document":       {kind: "object"},
	"legal_document": {kind: "object"},
	"number":         {kind: "number"},
	"boolean":        {kind: "boolean"},
	"country":        {kind: "countryCode"},
	"nationality":    {kind: "countryCode"},
	// text + unknown => no rule => accept anything
}

func fvLuhnOk(digits string) bool {
	sum := 0
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
		sum += d
		dbl = !dbl
	}
	return sum%10 == 0
}

func fvDaysInMonth(y, m int) int {
	leap := (y%4 == 0 && y%100 != 0) || y%400 == 0
	if m == 2 && leap {
		return 29
	}
	return []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[m-1]
}

func fvValidDate(s string) bool {
	if !fvDateRE.MatchString(s) {
		return false
	}
	y, _ := strconv.Atoi(s[0:4])
	m, _ := strconv.Atoi(s[5:7])
	d, _ := strconv.Atoi(s[8:10])
	if m < 1 || m > 12 {
		return false
	}
	if d < 1 || d > fvDaysInMonth(y, m) {
		return false
	}
	return true
}

// fvApplyKind is the "content" check shared by top-level rules AND structured sub-rules.
func fvApplyKind(kind, value string) bool {
	switch kind {
	case "phone":
		return fvPhoneRE.MatchString(fvPhoneStrip.ReplaceAllString(value, ""))
	case "url":
		u := value
		if !fvSchemeRE.MatchString(u) {
			u = "https://" + u
		}
		return fvURLRE.MatchString(u)
	case "date":
		return fvValidDate(value)
	case "card":
		s := fvCardStrip.ReplaceAllString(value, "")
		return fvCardRE.MatchString(s) && fvLuhnOk(s)
	case "number":
		t := strings.TrimSpace(value)
		if t == "" {
			return false
		}
		f, err := strconv.ParseFloat(t, 64)
		return err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	case "boolean":
		return value == "true" || value == "false"
	case "countryCode":
		_, ok := fvCountrySet[value]
		return ok
	case "usState":
		_, ok := fvUSStateSet[value]
		return ok
	default:
		return true
	}
}

func fvValidObject(fieldType, raw string) bool {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return false
	}
	spec := fvObj[fieldType]
	for k, val := range obj {
		sub, known := spec[k]
		if !known {
			return false // unknown key
		}
		if sub.isInt {
			num, isNum := val.(json.Number)
			if !isNum {
				return false
			}
			f, err := num.Float64()
			if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) {
				return false
			}
			continue
		}
		s, isStr := val.(string)
		if !isStr {
			return false
		}
		if s == "" {
			continue // empty sub-field ok (partial fill)
		}
		if sub.re != nil && !sub.re.MatchString(s) {
			return false
		}
		if sub.kind != "" && !fvApplyKind(sub.kind, s) {
			return false
		}
	}
	return true
}

// FieldValueValid reports whether value is an acceptable plaintext for fieldType.
// An empty value is valid (emptiness/required is the caller's concern).
func FieldValueValid(fieldType, value string) bool {
	if value == "" {
		return true
	}
	rule, ok := fvRules[fieldType]
	if !ok {
		return true
	}
	switch rule.kind {
	case "regex":
		return rule.re.MatchString(value)
	case "enum":
		for _, g := range rule.values {
			if g == value {
				return true
			}
		}
		return false
	case "object":
		return fvValidObject(fieldType, value)
	default:
		return fvApplyKind(rule.kind, value)
	}
}

// FieldValueError returns "" when valid, else the fieldType tag (callers may map it to an
// i18n error key). Mirrors the reference fieldValueError.
func FieldValueError(fieldType, value string) string {
	if FieldValueValid(fieldType, value) {
		return ""
	}
	return fieldType
}

// IsValidCountryCode reports whether code is an assigned ISO 3166-1 alpha-2 country code (#303).
func IsValidCountryCode(code string) bool {
	_, ok := fvCountrySet[code]
	return ok
}

// DialCodeFor returns the ITU E.164 dial code (digits only, no "+") for a country code, or "" (#303).
func DialCodeFor(code string) string {
	return DialCodes[code]
}
