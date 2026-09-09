package companydata

// Field-type registry parity — every case in the shared vector must match; that vector is the
// contract FieldTypeRegistry is held to. Its registry member is the row set every case is
// resolved against.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

type fvCase struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	// Options is the caller's own option list, present only on a choice case.
	Options []string `json:"options"`
	Valid   bool     `json:"valid"`
}

type fvVector struct {
	Registry []FieldTypeRow `json:"registry"`
	Cases    []fvCase       `json:"cases"`
	Resolve  []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Resolved struct {
			Type        string          `json:"type"`
			Parent      *string         `json:"parent"`
			Label       string          `json:"label"`
			IsSystem    bool            `json:"is_system"`
			Known       bool            `json:"known"`
			Input       *string         `json:"input"`
			Lane        *string         `json:"lane"`
			Check       *string         `json:"check"`
			Options     []string        `json:"options"`
			Fields      []SubFieldEntry `json:"fields"`
			Validations []string        `json:"validations"`
		} `json:"resolved"`
	} `json:"resolve_cases"`
	Accepts []struct {
		Name      string `json:"name"`
		Requested string `json:"requested"`
		Actual    string `json:"actual"`
		Accepts   bool   `json:"accepts"`
	} `json:"accepts_cases"`
	Ordered []struct {
		Name    string   `json:"name"`
		Types   []string `json:"types"`
		Ordered []string `json:"ordered"`
	} `json:"ordered_cases"`
	EffectiveType []struct {
		Name          string `json:"name"`
		Type          string `json:"type"`
		EffectiveType string `json:"effective_type"`
	} `json:"effective_type_cases"`
	DerivedSets struct {
		RequestableTypes []string `json:"requestable_types"`
		FlowTypes        []string `json:"flow_types"`
		ClaimableTypes   []string `json:"claimable_types"`
	} `json:"derived_sets"`
}

func loadFieldTypeVector(t *testing.T) fvVector {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "testdata", "contract-field-validation-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc fvVector
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func loadFieldValidationVector(t *testing.T) []fvCase {
	return loadFieldTypeVector(t).Cases
}

func TestFieldValidationVector(t *testing.T) {
	doc := loadFieldTypeVector(t)
	if len(doc.Cases) == 0 {
		t.Fatal("no vector cases loaded")
	}
	registry := NewFieldTypeRegistry(doc.Registry)
	for _, c := range doc.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			if got := registry.IsFieldValueValid(c.Type, c.Value, c.Options...); got != c.Valid {
				t.Fatalf("%s: IsFieldValueValid(%q, %q) = %v, want %v", c.Name, c.Type, c.Value, got, c.Valid)
			}
		})
	}
}

func TestFieldTypeResolveVector(t *testing.T) {
	doc := loadFieldTypeVector(t)
	registry := NewFieldTypeRegistry(doc.Registry)
	for _, c := range doc.Resolve {
		got := registry.Resolve(c.Type)
		want := ResolvedFieldType{
			Type: c.Resolved.Type, Parent: c.Resolved.Parent, Label: c.Resolved.Label,
			IsSystem: c.Resolved.IsSystem, Known: c.Resolved.Known, Input: c.Resolved.Input,
			Lane: c.Resolved.Lane, Check: c.Resolved.Check, Options: c.Resolved.Options,
			Fields: c.Resolved.Fields, Validations: c.Resolved.Validations,
		}
		if want.Validations == nil {
			want.Validations = []string{}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: Resolve(%q) = %#v, want %#v", c.Name, c.Type, got, want)
		}
	}
}

func TestFieldTypeAcceptsVector(t *testing.T) {
	doc := loadFieldTypeVector(t)
	registry := NewFieldTypeRegistry(doc.Registry)
	for _, c := range doc.Accepts {
		if got := registry.Accepts(c.Requested, c.Actual); got != c.Accepts {
			t.Fatalf("%s: Accepts(%q, %q) = %v, want %v", c.Name, c.Requested, c.Actual, got, c.Accepts)
		}
	}
}

func TestFieldTypeOrderedVector(t *testing.T) {
	doc := loadFieldTypeVector(t)
	registry := NewFieldTypeRegistry(doc.Registry)
	for _, c := range doc.Ordered {
		if got := registry.Ordered(c.Types); !reflect.DeepEqual(got, c.Ordered) {
			t.Fatalf("%s: Ordered = %v, want %v", c.Name, got, c.Ordered)
		}
	}
}

func TestFieldTypeEffectiveTypeVector(t *testing.T) {
	doc := loadFieldTypeVector(t)
	registry := NewFieldTypeRegistry(doc.Registry)
	for _, c := range doc.EffectiveType {
		if got := registry.EffectiveType(c.Type); got != c.EffectiveType {
			t.Fatalf("%s: EffectiveType(%q) = %q, want %q", c.Name, c.Type, got, c.EffectiveType)
		}
	}
}

func TestFieldTypeDerivedSets(t *testing.T) {
	doc := loadFieldTypeVector(t)
	registry := NewFieldTypeRegistry(doc.Registry)
	if got := registry.RequestableTypes(); !reflect.DeepEqual(got, doc.DerivedSets.RequestableTypes) {
		t.Fatalf("RequestableTypes = %v, want %v", got, doc.DerivedSets.RequestableTypes)
	}
	if got := registry.FlowTypes(); !reflect.DeepEqual(got, doc.DerivedSets.FlowTypes) {
		t.Fatalf("FlowTypes = %v, want %v", got, doc.DerivedSets.FlowTypes)
	}
	if got := registry.ClaimableTypes(); !reflect.DeepEqual(got, doc.DerivedSets.ClaimableTypes) {
		t.Fatalf("ClaimableTypes = %v, want %v", got, doc.DerivedSets.ClaimableTypes)
	}
}

// testFieldTypesSource hands the vector's registry to a model factory the way a client does —
// as a callback read at typing time, not an instance captured before.
func testFieldTypesSource() (*FieldTypeRegistry, error) { return testFieldTypes(), nil }

// testFieldTypes is the vector's own registry, which every model test types its values against.
func testFieldTypes() *FieldTypeRegistry {
	testFieldTypesOnce.Do(func() {
		p, err := filepath.Abs(filepath.Join("..", "testdata", "contract-field-validation-vector.json"))
		if err != nil {
			panic(err)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			panic(err)
		}
		var doc fvVector
		if err := json.Unmarshal(raw, &doc); err != nil {
			panic(err)
		}
		testFieldTypesRegistry = NewFieldTypeRegistry(doc.Registry)
	})
	return testFieldTypesRegistry
}

// testFieldTypesBody is the same registry as the served GET /api/contact-field-types body, so a
// fake transport answers that route the way a deployment does.
func testFieldTypesBody() string {
	rows, err := json.Marshal(testFieldTypes().Rows())
	if err != nil {
		panic(err)
	}
	return string(rows)
}

var (
	testFieldTypesOnce     sync.Once
	testFieldTypesRegistry *FieldTypeRegistry
)
