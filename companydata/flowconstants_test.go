package companydata

// Flow constants (computed variables) parity — issue #79.
// Every case in docs/contract-flow-constants-vector.json (mirrored to
// ../testdata) must reproduce, byte-for-byte, the shared computeConstants port.
// Reuses decodeNumber() (UseNumber) from flowcondition_test.go so numbers match
// the production HTTP layer (json.Number).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type flowConstCase struct {
	Name          string          `json:"name"`
	Constants     json.RawMessage `json:"constants"`
	Answers       json.RawMessage `json:"answers"`
	ReferenceDate string          `json:"reference_date"`
	Expect        json.RawMessage `json:"expect"`
}

func loadFlowConstantsVector(t *testing.T) []flowConstCase {
	p, err := filepath.Abs(filepath.Join("..", "testdata", "contract-flow-constants-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []flowConstCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

// flowValueEq: numeric-tolerant, null-strict comparison. json.Number, float64,
// int are all "numeric" and compared by value; booleans compared by truth;
// everything else by string form; nil equals only nil.
func flowValueEq(got, want any) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	if gb, ok := got.(bool); ok {
		wb, ok := want.(bool)
		return ok && gb == wb
	}
	if _, ok := want.(bool); ok {
		return false // want is bool, got is not
	}
	gn, gok := flowToNum(got)
	wn, wok := flowToNum(want)
	if gok && wok {
		return gn == wn
	}
	if gok != wok {
		return false // one numeric, one not
	}
	return flowStr(got) == flowStr(want)
}

func TestFlowConstantsVector(t *testing.T) {
	cases := loadFlowConstantsVector(t)
	if len(cases) != 51 {
		t.Fatalf("expected 51 vector cases, got %d", len(cases))
	}
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			constsAny := decodeNumber(t, c.Constants)
			constants, _ := constsAny.([]any)

			answersAny := decodeNumber(t, c.Answers)
			answers, _ := answersAny.(map[string]any)
			if answers == nil {
				answers = map[string]any{}
			}

			expectAny := decodeNumber(t, c.Expect)
			expect, _ := expectAny.(map[string]any)

			out := ComputeConstants(constants, answers, c.ReferenceDate)

			for key, want := range expect {
				got, present := out[key]
				if !present {
					t.Fatalf("%s: key %q missing from result", c.Name, key)
				}
				if !flowValueEq(got, want) {
					t.Fatalf("%s: key %q got %#v (%T), want %#v (%T)",
						c.Name, key, got, got, want, want)
				}
			}
		})
	}
}

// TestResolveConstantsVector: the SDK-ergonomic wrapper must return EXACTLY the
// expect map's keys — constants only, no leaked answer keys — with the same
// values ComputeConstants produces.
func TestResolveConstantsVector(t *testing.T) {
	cases := loadFlowConstantsVector(t)
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			constsAny := decodeNumber(t, c.Constants)
			constants, _ := constsAny.([]any)

			answersAny := decodeNumber(t, c.Answers)
			answers, _ := answersAny.(map[string]any)
			if answers == nil {
				answers = map[string]any{}
			}

			expectAny := decodeNumber(t, c.Expect)
			expect, _ := expectAny.(map[string]any)

			out := ResolveConstants(constants, answers, c.ReferenceDate)

			if len(out) != len(expect) {
				t.Fatalf("%s: got %d keys %v, want %d keys %v", c.Name, len(out), keysOf(out), len(expect), keysOf(expect))
			}
			for key, want := range expect {
				got, present := out[key]
				if !present {
					t.Fatalf("%s: key %q missing from ResolveConstants result", c.Name, key)
				}
				if !flowValueEq(got, want) {
					t.Fatalf("%s: key %q got %#v (%T), want %#v (%T)",
						c.Name, key, got, got, want, want)
				}
			}
			for key := range out {
				if _, ok := expect[key]; !ok {
					t.Fatalf("%s: unexpected extra key %q in ResolveConstants result (answers leaked?)", c.Name, key)
				}
			}
		})
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestEvaluateFlowConditionVector: the per-call-site wrapper must preserve plain
// condition semantics — running the 27-case condition vector through
// EvaluateFlowCondition with no constants must match EvaluateCondition exactly.
func TestEvaluateFlowConditionVector(t *testing.T) {
	cases := loadFlowConditionVector(t)
	if len(cases) != 27 {
		t.Fatalf("expected 27 vector cases, got %d", len(cases))
	}
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			cond := decodeNumber(t, c.Condition)
			answersAny := decodeNumber(t, c.Answers)
			answers, _ := answersAny.(map[string]any)
			if answers == nil {
				answers = map[string]any{}
			}
			got := EvaluateFlowCondition(cond, answers, nil, "")
			if got != c.Expect {
				t.Fatalf("%s: got %v, want %v", c.Name, got, c.Expect)
			}
		})
	}
}
