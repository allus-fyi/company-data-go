package companydata

// Pure port of the platform FlowConditionEvaluator (A-spec §4) — pinned to the
// shared contract-flow-condition-vector.json.
//
// A condition is one of:
//   - nil / a non-object → always true (the "no condition" short-circuit).
//   - a boolean node {op:"and"|"or"|"not", children:[...]} (not = one child).
//   - a comparison leaf {field, op, value} with op in
//     eq ne lt le gt ge in nin answered empty.
//
// answers is the decrypted {slug: value} map.
//
// Frozen semantics (see the vector):
//   - A blank/missing answer is "unanswered": never matches eq/ne/an ordered
//     comparison (→ false); empty true, answered false; nin true on missing.
//   - eq/ne: booleans by truth, numbers (with numeric-string coercion) by value,
//     else strings exactly. in/nin: membership in the array value.
//   - Ordered (lt/le/gt/ge): BOTH numeric → numeric compare; BOTH non-numeric →
//     string compare (so YYYY-MM-DD dates sort chronologically); MIXED → false.
//   - and over [] → true; or over [] → false.

import (
	"encoding/json"
	"strconv"
	"strings"
)

// EvaluateCondition evaluates a parsed condition (map/nil) against the decrypted
// {slug: value} answer map. Numbers may be float64, int, or json.Number
// (the HTTP layer decodes with UseNumber), all handled by numeric coercion.
func EvaluateCondition(condition any, answers map[string]any) bool {
	cond, ok := condition.(map[string]any)
	if !ok {
		return true // nil / non-object = true
	}
	op, _ := cond["op"].(string)
	switch op {
	case "and", "or", "not":
		kids := childrenOf(cond["children"])
		switch op {
		case "and":
			for _, c := range kids {
				if !EvaluateCondition(c, answers) {
					return false
				}
			}
			return true
		case "or":
			for _, c := range kids {
				if EvaluateCondition(c, answers) {
					return true
				}
			}
			return false
		default: // not
			var first any
			if len(kids) > 0 {
				first = kids[0]
			}
			return !EvaluateCondition(first, answers)
		}
	}

	slug, _ := cond["field"].(string)
	target := cond["value"]
	val, present := answers[slug]
	if !present {
		val = nil
	}

	switch op {
	case "answered":
		return flowAnswered(val)
	case "empty":
		return !flowAnswered(val)
	case "in":
		return flowInList(target, val)
	case "nin":
		return !flowInList(target, val)
	case "contains":
		// #102 substring op (text): needs an answer (like in). Case-sensitive; empty needle contained.
		return flowAnswered(val) && strings.Contains(flowStr(val), flowStr(target))
	case "not_contains":
		// true when unanswered (like nin)
		return !(flowAnswered(val) && strings.Contains(flowStr(val), flowStr(target)))
	}

	if !flowAnswered(val) {
		return false
	}
	switch op {
	case "eq":
		return flowLooseEq(target, val)
	case "ne":
		return !flowLooseEq(target, val)
	case "lt", "gt", "le", "ge":
		a, aok := flowToNum(val)
		b, bok := flowToNum(target)
		if aok && bok {
			return flowCmpNum(op, a, b)
		}
		// Mixed (one numeric, one not) → false; both non-numeric → string compare.
		if aok || bok {
			return false
		}
		return flowCmpStr(op, flowStr(val), flowStr(target))
	}
	return false
}

func childrenOf(v any) []any {
	if lst, ok := v.([]any); ok {
		return lst
	}
	return nil
}

func flowAnswered(v any) bool {
	if v == nil {
		return false
	}
	if s, ok := v.(string); ok {
		return s != ""
	}
	return true
}

func flowToNum(v any) (float64, bool) {
	switch n := v.(type) {
	case bool:
		return 0, false
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	case string:
		t := strings.TrimSpace(n)
		if t == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func flowLooseEq(a, b any) bool {
	if isBool(a) || isBool(b) {
		return flowTruthy(a) == flowTruthy(b)
	}
	na, aok := flowToNum(a)
	nb, bok := flowToNum(b)
	if aok && bok {
		return na == nb
	}
	return flowStr(a) == flowStr(b)
}

func flowInList(target, val any) bool {
	lst, ok := target.([]any)
	if !ok {
		return false
	}
	for _, x := range lst {
		if flowLooseEq(x, val) {
			return true
		}
	}
	return false
}

func isBool(v any) bool {
	_, ok := v.(bool)
	return ok
}

func flowTruthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case nil:
		return false
	case string:
		return t != ""
	}
	if n, ok := flowToNum(v); ok {
		return n != 0
	}
	return true
}

func flowStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	}
	return ""
}

func flowCmpNum(op string, a, b float64) bool {
	switch op {
	case "lt":
		return a < b
	case "gt":
		return a > b
	case "le":
		return a <= b
	default: // ge
		return a >= b
	}
}

func flowCmpStr(op, a, b string) bool {
	switch op {
	case "lt":
		return a < b
	case "gt":
		return a > b
	case "le":
		return a <= b
	default: // ge
		return a >= b
	}
}
