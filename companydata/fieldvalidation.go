package companydata

// Country-data helpers.
//
// What a value must satisfy for its field TYPE lives in fieldtypes.go: a type is a row in the
// served registry and FieldTypeRegistry is the one interpreter of those rows. These two helpers
// are about the bundled country dataset itself, which no registry row carries.

var (
	// Country/nationality store an ISO 3166-1 alpha-2 code; an address's state sub-field is a
	// USPS 2-letter code. The lists come from the generated country data (do NOT inline them —
	// they would rot).
	countryCodeSet = toCodeSet(CountryCodes)
	usStateCodeSet = toCodeSet(USStateCodes)
)

func toCodeSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// IsValidCountryCode reports whether code is an assigned ISO 3166-1 alpha-2 country code.
func IsValidCountryCode(code string) bool {
	return countryCodeSet[code]
}

// DialCodeFor answers the ITU E.164 dial code (digits only, no +) for a country code, or "".
func DialCodeFor(code string) string {
	return DialCodes[code]
}
