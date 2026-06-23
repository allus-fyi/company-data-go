package companydata

// FlowConditionEvaluator parity — every case in the shared vector must pass.
// The same vector pins the PHP reference + the python/ts/iOS/Android ports.
// Numbers are decoded with UseNumber() to match the production HTTP layer.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type flowCondCase struct {
	Name      string          `json:"name"`
	Condition json.RawMessage `json:"condition"`
	Answers   json.RawMessage `json:"answers"`
	Expect    bool            `json:"expect"`
}

func decodeNumber(t *testing.T, raw json.RawMessage) any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func loadFlowConditionVector(t *testing.T) []flowCondCase {
	p, err := filepath.Abs(filepath.Join("..", "testdata", "contract-flow-condition-vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []flowCondCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func TestFlowConditionVector(t *testing.T) {
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
			got := EvaluateCondition(cond, answers)
			if got != c.Expect {
				t.Fatalf("%s: got %v, want %v", c.Name, got, c.Expect)
			}
		})
	}
}
