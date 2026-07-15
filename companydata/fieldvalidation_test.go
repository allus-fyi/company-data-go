package companydata

// Field-type validation parity — every case in the shared vector must match.
// The same vector pins the web reference + the allus/iOS/Android/other-SDK ports.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fvCase struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	Valid bool   `json:"valid"`
}

func loadFieldValidationVector(t *testing.T) []fvCase {
	p, err := filepath.Abs(filepath.Join("..", "testdata", "contract-field-validation-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []fvCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func TestFieldValidationVector(t *testing.T) {
	cases := loadFieldValidationVector(t)
	if len(cases) == 0 {
		t.Fatal("no vector cases loaded")
	}
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			if got := FieldValueValid(c.Type, c.Value); got != c.Valid {
				t.Fatalf("%s: FieldValueValid(%q, %q) = %v, want %v", c.Name, c.Type, c.Value, got, c.Valid)
			}
		})
	}
}
