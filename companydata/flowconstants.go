package companydata

// Flow constants (computed variables). Pure port of the canonical
// computeConstants/evalExpr reference; pinned by contract-flow-constants-vector.json.
//
// A "constant" = {key, label, result_type, expr}. ComputeConstants materialises
// each constant's value into a NEW slug->value map (answers + {key:value}) in
// dependency (topological) order, so the existing evaluator's leaf path
// {field:<constKey>,op,value} resolves a constant with ZERO change to
// EvaluateCondition. null propagates: an unresolved operand yields nil; a nil
// constant behaves like an unanswered field in conditions.
//
// This file reuses the package helpers EvaluateCondition, flowToNum and flowStr
// from flowcondition.go unchanged, so the 27-case condition vector is untouched.

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"time"
)

// ── expr / list access helpers ─────────────────────────────────────────────

func asExpr(v any) (map[string]any, string) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ""
	}
	t, _ := m["type"].(string)
	return m, t
}

func asAnyList(v any) []any {
	l, _ := v.([]any)
	return l
}

// ── date arithmetic (UTC-midnight calendar dates) ──────────────────────────

// parseFlowDate parses a strict YYYY-MM-DD string at UTC midnight. Anything
// else (non-string, wrong shape, impossible date like 2026-02-30) -> ok=false.
func parseFlowDate(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	s = strings.TrimSpace(s)
	t, err := time.Parse("2006-01-02", s) // no zone in layout => UTC
	if err != nil {
		return time.Time{}, false
	}
	if t.Format("2006-01-02") != s { // round-trip guard
		return time.Time{}, false
	}
	return t, true
}

// diffDays: exact whole calendar days (to - from). Both operands are UTC
// midnight, so Duration integer division is exact and DST-immune.
func diffDays(from, to time.Time) int {
	return int(to.Sub(from) / (24 * time.Hour))
}

// diffMonths: (to.y-from.y)*12 + (to.m-from.m), minus 1 if to.day < from.day.
func diffMonths(from, to time.Time) int {
	n := (to.Year()-from.Year())*12 + int(to.Month()) - int(from.Month())
	if to.Day() < from.Day() {
		n--
	}
	return n
}

// diffYears: to.y-from.y, minus 1 if (to.m,to.day) < (from.m,from.day) (age).
func diffYears(from, to time.Time) int {
	n := to.Year() - from.Year()
	if to.Month() < from.Month() ||
		(to.Month() == from.Month() && to.Day() < from.Day()) {
		n--
	}
	return n
}

// finNum applies the pinned non-finite policy: a computed math result that
// overflowed to Inf/NaN -> nil (math never yields a non-finite number).
func finNum(r float64) any {
	if math.IsInf(r, 0) || math.IsNaN(r) {
		return nil
	}
	return r
}

// ── evalExpr(expr, answers, referenceDate) -> value | nil ──────────────────

func evalExpr(expr any, answers map[string]any, referenceDate string) any {
	m, typ := asExpr(expr)
	if m == nil {
		return nil
	}
	switch typ {
	case "lit":
		if v, ok := m["value"]; ok {
			return v
		}
		return nil
	case "ref":
		k, _ := m["key"].(string)
		if v, ok := answers[k]; ok { // a stored nil stays nil
			return v
		}
		return nil // operand not in the map -> nil
	case "today":
		if referenceDate != "" {
			return referenceDate
		}
		return nil
	case "if":
		for _, cs := range asAnyList(m["cases"]) {
			csm, ok := cs.(map[string]any)
			if !ok {
				continue
			}
			if EvaluateCondition(csm["when"], answers) {
				return evalExpr(csm["then"], answers, referenceDate)
			}
		}
		return evalExpr(m["else"], answers, referenceDate) // else is required
	case "concat":
		sep, _ := m["sep"].(string) // absent/non-string -> ""
		var b strings.Builder
		for i, p := range asAnyList(m["parts"]) {
			if i > 0 {
				b.WriteString(sep)
			}
			v := evalExpr(p, answers, referenceDate)
			if v != nil { // nil part -> ""
				b.WriteString(flowStr(v))
			}
		}
		return b.String() // ALWAYS text
	case "datediff":
		from, okF := parseFlowDate(evalExpr(m["from"], answers, referenceDate))
		to, okT := parseFlowDate(evalExpr(m["to"], answers, referenceDate))
		if !okF || !okT { // non-date operand -> nil
			return nil
		}
		unit, _ := m["unit"].(string)
		switch unit {
		case "days":
			return diffDays(from, to)
		case "weeks":
			return diffDays(from, to) / 7 // int/int truncates toward zero
		case "months":
			return diffMonths(from, to)
		case "years":
			return diffYears(from, to)
		}
		return nil
	case "math":
		args := asAnyList(m["args"])
		op, _ := m["op"].(string)
		// max/min are variadic and skip the arguments that are not finite numbers, so they
		// run before the any-null guard below; no numeric argument at all -> nil.
		if op == "max" || op == "min" {
			var best float64
			found := false
			for _, a := range args {
				n, ok := flowToNum(evalExpr(a, answers, referenceDate))
				if !ok || math.IsInf(n, 0) || math.IsNaN(n) {
					continue
				}
				if !found || (op == "max" && n > best) || (op == "min" && n < best) {
					best = n
					found = true
				}
			}
			if !found {
				return nil
			}
			return best
		}
		nums := make([]float64, 0, len(args))
		for _, a := range args {
			n, ok := flowToNum(evalExpr(a, answers, referenceDate))
			// any null/non-numeric (incl. boolean) arg -> nil; a non-finite arg
			// (e.g. the numeric string "1e309" coercing to Inf) -> nil (pinned policy).
			if !ok || math.IsInf(n, 0) || math.IsNaN(n) {
				return nil
			}
			nums = append(nums, n)
		}
		switch op {
		case "add":
			s := 0.0
			for _, n := range nums {
				s += n
			}
			return finNum(s)
		case "mul":
			p := 1.0
			for _, n := range nums {
				p *= n
			}
			return finNum(p)
		case "sub":
			if len(nums) >= 2 {
				return finNum(nums[0] - nums[1])
			}
			return nil
		case "div":
			if len(nums) >= 2 && nums[1] != 0 {
				return finNum(nums[0] / nums[1]) // float division
			}
			return nil // /0 -> nil
		case "mod":
			if len(nums) >= 2 && nums[1] != 0 {
				return finNum(math.Mod(nums[0], nums[1])) // truncated remainder, matches JS %
			}
			return nil // %0 -> nil
		case "neg":
			if len(nums) >= 1 {
				return finNum(-nums[0])
			}
			return nil
		case "abs":
			if len(nums) >= 1 {
				return finNum(math.Abs(nums[0]))
			}
			return nil
		case "round":
			if len(nums) >= 1 {
				return finNum(math.Round(nums[0])) // half away from zero
			}
			return nil
		case "floor":
			if len(nums) >= 1 {
				return finNum(math.Floor(nums[0]))
			}
			return nil
		case "ceil":
			if len(nums) >= 1 {
				return finNum(math.Ceil(nums[0]))
			}
			return nil
		}
		return nil
	}
	return nil
}

// ── static constant-ref collection (topological ordering only) ─────────────

// orderedKeySet collects keys in first-seen (insertion) order so the DFS
// dependency iteration is deterministic — every port breaks the same
// back-edge on a (validator-rejected) cycle. A bare Go map iterates randomly.
type orderedKeySet struct {
	seen map[string]bool
	keys []string
}

func newOrderedKeySet() *orderedKeySet {
	return &orderedKeySet{seen: map[string]bool{}}
}

func (s *orderedKeySet) add(k string) {
	if !s.seen[k] {
		s.seen[k] = true
		s.keys = append(s.keys, k)
	}
}

func collectExprConstRefs(expr any, constKeys map[string]bool, acc *orderedKeySet) {
	m, typ := asExpr(expr)
	if m == nil {
		return
	}
	switch typ {
	case "ref":
		// A nil constKeys collects every ref, not only the constant ones.
		if k, _ := m["key"].(string); constKeys == nil || constKeys[k] {
			acc.add(k)
		}
	case "lit", "today":
		return
	case "if":
		for _, cs := range asAnyList(m["cases"]) {
			if csm, ok := cs.(map[string]any); ok {
				collectCondConstRefs(csm["when"], constKeys, acc) // a when-leaf may name a constant
				collectExprConstRefs(csm["then"], constKeys, acc)
			}
		}
		collectExprConstRefs(m["else"], constKeys, acc)
	case "concat":
		for _, p := range asAnyList(m["parts"]) {
			collectExprConstRefs(p, constKeys, acc)
		}
	case "datediff":
		collectExprConstRefs(m["from"], constKeys, acc)
		collectExprConstRefs(m["to"], constKeys, acc)
	case "math":
		for _, a := range asAnyList(m["args"]) {
			collectExprConstRefs(a, constKeys, acc)
		}
	}
}

func collectCondConstRefs(cond any, constKeys map[string]bool, acc *orderedKeySet) {
	m, ok := cond.(map[string]any)
	if !ok {
		return
	}
	if op, _ := m["op"].(string); op == "and" || op == "or" || op == "not" {
		for _, ch := range asAnyList(m["children"]) {
			collectCondConstRefs(ch, constKeys, acc)
		}
		return
	}
	if f, ok := m["field"].(string); ok && (constKeys == nil || constKeys[f]) {
		acc.add(f)
	}
}

// ── ComputeConstants ───────────────────────────────────────────────────────

// ComputeConstants returns a NEW map = answers + {key:value} for every constant,
// evaluated in topological (dependency) order via 3-colour DFS post-order. A ref
// to an operand not yet in the map resolves to nil; nil propagates. Cycles
// (rejected by the validator) are broken defensively — the back-edge operand
// reads nil. Declared array order is irrelevant; the post-order guarantees each
// constant is computed after its dependencies, and dependency iteration is
// insertion-ordered so the result is fully deterministic.
func ComputeConstants(constants []any, answers map[string]any, referenceDate string) map[string]any {
	out := make(map[string]any, len(answers)+len(constants))
	for k, v := range answers {
		out[k] = v
	}

	byKey := make(map[string]map[string]any, len(constants))
	constKeys := make(map[string]bool, len(constants))
	var declared []string
	for _, c := range constants {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		key, ok := cm["key"].(string)
		if !ok {
			continue
		}
		byKey[key] = cm
		constKeys[key] = true
		declared = append(declared, key)
	}

	order := make([]string, 0, len(byKey))
	const (
		grey  = 1
		black = 2
	)
	state := make(map[string]int, len(byKey))
	var visit func(key string)
	visit = func(key string) {
		if state[key] != 0 { // grey (cycle back-edge) or black (done)
			return
		}
		state[key] = grey
		deps := newOrderedKeySet()
		collectExprConstRefs(byKey[key]["expr"], constKeys, deps)
		for _, dep := range deps.keys { // insertion order — deterministic
			if _, ok := byKey[dep]; ok {
				visit(dep)
			}
		}
		state[key] = black
		order = append(order, key) // post-order => dependencies precede dependents
	}
	for _, key := range declared {
		visit(key)
	}

	for _, key := range order {
		out[key] = evalExpr(byKey[key]["expr"], out, referenceDate)
	}
	return out
}

// ResolveConstants is the SDK-ergonomic helper: it returns ONLY the computed
// {constKey:value} entries (answers stripped out), for callers that want the
// resolved constants without the merged answer map.
//
// pluginSlugs, when given, names the definition's plugin element slugs: their
// stored answers are expanded (ExpandPluginAnswers) before the constants are
// computed, so a constant can read a plugin output such as "cao.min_wage".
func ResolveConstants(constants []any, answers map[string]any, referenceDate string, pluginSlugs ...string) map[string]any {
	if len(pluginSlugs) > 0 {
		answers = ExpandPluginAnswers(answers, pluginSlugs)
	}
	full := ComputeConstants(constants, answers, referenceDate)
	out := make(map[string]any)
	for _, c := range constants {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if key, ok := cm["key"].(string); ok {
			out[key] = full[key]
		}
	}
	return out
}

// ── plugin answers ─────────────────────────────────────────────────────────

// pluginKeyPattern is the key shape a plugin block or output must have to be
// readable as "<slug>.<key>"; the key "id" is reserved for a pick's id.
var pluginKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

func pluginKeyUsable(key string) bool {
	return key != "id" && pluginKeyPattern.MatchString(key)
}

// parsePluginPlaintext parses a stored plugin answer. ok is false when the text
// is not a JSON object; finished reports whether it carries an "outputs" array
// (an answer without one is unfinished).
func parsePluginPlaintext(plaintext string) (obj map[string]any, ok bool, finished bool) {
	if err := json.Unmarshal([]byte(plaintext), &obj); err != nil || obj == nil {
		return nil, false, false
	}
	_, finished = obj["outputs"].([]any)
	return obj, true, finished
}

// pluginSummaryOf joins the value of every block, in stored order, with " / ".
func pluginSummaryOf(obj map[string]any) string {
	parts := []string{}
	for _, b := range asAnyList(obj["blocks"]) {
		bm, _ := b.(map[string]any)
		parts = append(parts, flowStr(bm["value"]))
	}
	return strings.Join(parts, " / ")
}

// ExpandPluginAnswers returns a NEW answer map in which every finished plugin
// answer named by pluginSlugs is replaced by its summary (the block values
// joined by " / ") and joined by "<slug>.<block>" (the block's value),
// "<slug>.<block>.id" (a search_select pick's id) and "<slug>.<output>" (the
// output's typed value; a null output adds no key). A plugin answer that parses
// but carries no "outputs" array is unfinished and its entry is removed; a value
// that is not a JSON object is left as it is. The input map is not changed and a
// slug outside pluginSlugs is never touched.
func ExpandPluginAnswers(answers map[string]any, pluginSlugs []string) map[string]any {
	out := make(map[string]any, len(answers))
	for k, v := range answers {
		out[k] = v
	}
	for _, slug := range pluginSlugs {
		raw, present := answers[slug]
		if !present {
			continue
		}
		text, isString := raw.(string)
		if !isString {
			continue
		}
		obj, ok, finished := parsePluginPlaintext(text)
		if !ok {
			continue
		}
		if !finished {
			delete(out, slug)
			continue
		}
		out[slug] = pluginSummaryOf(obj)
		for _, b := range asAnyList(obj["blocks"]) {
			bm, isMap := b.(map[string]any)
			if !isMap {
				continue
			}
			key, _ := bm["key"].(string)
			if !pluginKeyUsable(key) {
				continue
			}
			if v := bm["value"]; v != nil {
				out[slug+"."+key] = v
			}
			if kind, _ := bm["kind"].(string); kind == "search_select" {
				if id, has := bm["id"]; has && id != nil {
					out[slug+"."+key+".id"] = flowStr(id)
				}
			}
		}
		for _, o := range asAnyList(obj["outputs"]) {
			om, isMap := o.(map[string]any)
			if !isMap {
				continue
			}
			key, _ := om["key"].(string)
			if !pluginKeyUsable(key) {
				continue
			}
			if v := om["value"]; v != nil {
				out[slug+"."+key] = v
			}
		}
	}
	return out
}

// PluginAnswerSummary returns a stored plugin answer's summary — its block
// values joined by " / " — and ok=false when the plaintext is not a finished
// plugin answer (a JSON object with an "outputs" array).
func PluginAnswerSummary(plaintext string) (summary string, ok bool) {
	obj, parsed, finished := parsePluginPlaintext(plaintext)
	if !parsed || !finished {
		return "", false
	}
	return pluginSummaryOf(obj), true
}

// PluginViewBlock is one block of a stored plugin answer as shown to a reader:
// its label and its value (the option label for a search_select pick).
type PluginViewBlock struct {
	Label string
	Value any
}

// PluginViewOutput is one output of a stored plugin answer as shown to a reader.
type PluginViewOutput struct {
	Label string
	Type  string
	Value any
}

// PluginView is what every surface renders for a stored plugin answer: the
// blocks, then the outputs, in stored order.
type PluginView struct {
	Blocks  []PluginViewBlock
	Outputs []PluginViewOutput
}

// PluginAnswerView returns the display form of a stored plugin answer, or nil
// when the plaintext is not a JSON object with an "outputs" array. Reading it
// needs neither the plugin nor its description: labels and order are part of
// the answer.
func PluginAnswerView(plaintext string) *PluginView {
	obj, parsed, finished := parsePluginPlaintext(plaintext)
	if !parsed || !finished {
		return nil
	}
	view := &PluginView{Blocks: []PluginViewBlock{}, Outputs: []PluginViewOutput{}}
	for _, b := range asAnyList(obj["blocks"]) {
		bm, _ := b.(map[string]any)
		view.Blocks = append(view.Blocks, PluginViewBlock{Label: flowStr(bm["label"]), Value: bm["value"]})
	}
	for _, o := range asAnyList(obj["outputs"]) {
		om, _ := o.(map[string]any)
		view.Outputs = append(view.Outputs, PluginViewOutput{Label: flowStr(om["label"]), Type: flowStr(om["type"]), Value: om["value"]})
	}
	return view
}

// EvaluateFlowCondition is the per-call-site wrapper: materialise the constants,
// then evaluate the condition with the existing (unchanged) evaluator.
func EvaluateFlowCondition(condition any, answers map[string]any, constants []any, referenceDate string) bool {
	return EvaluateCondition(condition, ComputeConstants(constants, answers, referenceDate))
}
