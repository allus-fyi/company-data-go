package companydata

// Plugins on contract flows, request fields and sign-in consent.
//
// A plugin field is answered by picking from lists a plugin serves and reading
// the outputs it computes. Its stored answer is self-describing JSON:
//
//	{"plugin":"Flex","type":"cao",
//	 "blocks":[{"key":"cao","kind":"search_select","label":"CAO","id":"hrc","value":"Horeca Fictief"},…],
//	 "outputs":[{"key":"min_wage","type":"number","label":"Minimum wage","value":9.5},…]}
//
// This file holds the typed model of that answer (PluginValue) and the helpers a
// company party of a flow uses to call a plugin: a pass from the API, the
// request sealed to the plugin's public key and posted to the forwarder over a
// plain transport that carries no allme credential, and the reply opened with a
// key pair made for the call.

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// pluginTypeKey is the reserved field-type key of a plugin row. It is never a
// registry row, so every reader branches on it before asking the registry.
const pluginTypeKey = "plugin"

// pluginTransportTimeout bounds one forwarder call (the forwarder itself gives a
// plugin 3 s, plus 1 s for a manifest refetch on a key change).
const pluginTransportTimeout = 15 * time.Second

// ── the typed answer ─────────────────────────────────────────────────────────

// PluginBlock is one answered block of a plugin answer: a search_select pick
// carries its ID and its option label as Value; a text, number or date block
// its typed Value and an empty ID.
type PluginBlock struct {
	Key   string
	Kind  string
	Label string
	ID    string
	Value any
}

// PluginOutput is one output of a plugin answer, of its declared Type (text,
// number, date or boolean); Value is nil when the plugin had no value for it.
type PluginOutput struct {
	Key   string
	Type  string
	Label string
	Value any
}

// PluginValue is a plugin answer: the plugin's name, the field type answered,
// the blocks in declared order and the outputs.
type PluginValue struct {
	Plugin  string
	Type    string
	Blocks  []PluginBlock
	Outputs []PluginOutput
	Raw     map[string]any
}

// ParsePluginValue parses the plaintext of a plugin answer — a company-data
// value of a plugin row, a flow answer of a plugin element, or a sign-in claim
// value of a plugin claim — into a PluginValue. A plaintext that is not a JSON
// object with an "outputs" array (an unfinished answer has none) is a
// *ValidationError with FieldType "plugin".
func ParsePluginValue(plaintext string) (PluginValue, error) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(plaintext), &obj); err != nil || obj == nil {
		return PluginValue{}, newValidationError("", pluginTypeKey)
	}
	if _, finished := obj["outputs"].([]any); !finished {
		return PluginValue{}, newValidationError("", pluginTypeKey)
	}
	pv := PluginValue{
		Plugin:  asString(obj["plugin"]),
		Type:    asString(obj["type"]),
		Blocks:  []PluginBlock{},
		Outputs: []PluginOutput{},
		Raw:     obj,
	}
	for _, b := range asAnyList(obj["blocks"]) {
		bm, ok := b.(map[string]any)
		if !ok {
			continue
		}
		id := ""
		if v, has := bm["id"]; has && v != nil {
			id = flowStr(v)
		}
		pv.Blocks = append(pv.Blocks, PluginBlock{
			Key:   asString(bm["key"]),
			Kind:  asString(bm["kind"]),
			Label: asString(bm["label"]),
			ID:    id,
			Value: bm["value"],
		})
	}
	for _, o := range asAnyList(obj["outputs"]) {
		om, ok := o.(map[string]any)
		if !ok {
			continue
		}
		pv.Outputs = append(pv.Outputs, PluginOutput{
			Key:   asString(om["key"]),
			Type:  asString(om["type"]),
			Label: asString(om["label"]),
			Value: om["value"],
		})
	}
	return pv, nil
}

// ── the pass and the call results ────────────────────────────────────────────

// PluginPassPlugin is one plugin a pass unlocks. PublicKey is "" when the
// plugin's description is missing or failed; such a plugin is not responding.
type PluginPassPlugin struct {
	ID        string
	PublicKey string
}

// PluginPass is a short-lived pass for the forwarder, the forwarder's address,
// the plugins it unlocks and the plugin description (plugin_spec) of every
// plugin element it covers, keyed by the element's slug.
type PluginPass struct {
	Pass         string
	ForwarderURL string
	Plugins      []PluginPassPlugin
	Specs        map[string]map[string]any
	Raw          map[string]any
}

func pluginPassFromAPI(obj map[string]any) PluginPass {
	p := PluginPass{
		Pass:         asString(obj["pass"]),
		ForwarderURL: strings.TrimRight(asString(obj["forwarder_url"]), "/"),
		Specs:        map[string]map[string]any{},
		Raw:          obj,
	}
	for _, e := range asAnyList(obj["plugins"]) {
		if m, ok := e.(map[string]any); ok {
			p.Plugins = append(p.Plugins, PluginPassPlugin{ID: asString(m["id"]), PublicKey: asString(m["public_key"])})
		}
	}
	if specs, ok := obj["specs"].(map[string]any); ok {
		for k, v := range specs {
			if m, ok := v.(map[string]any); ok {
				p.Specs[k] = m
			}
		}
	}
	return p
}

func (p PluginPass) publicKeyFor(pluginID string) string {
	for _, pl := range p.Plugins {
		if pl.ID == pluginID {
			return pl.PublicKey
		}
	}
	return ""
}

// PluginOption is one option a plugin serves for a search_select block.
type PluginOption struct {
	ID    string
	Label string
}

// PluginOptionsResult is a plugin's option list; More says the list was cut
// (at most 50 options) and a longer query narrows it.
type PluginOptionsResult struct {
	Options []PluginOption
	More    bool
}

// PluginOutputsResult is what PluginOutputs answers: a *PluginOutputs, or a
// *PluginPicksInvalid when the picks no longer fit the inputs or each other.
type PluginOutputsResult interface {
	isPluginOutputsResult()
}

// PluginOutputs carries the outputs a plugin computed, by output key (a nil
// value means the plugin had none).
type PluginOutputs struct {
	Outputs map[string]any
}

// PluginPicksInvalid says the picks no longer fit the current inputs or each
// other: clear them and pick again.
type PluginPicksInvalid struct{}

func (*PluginOutputs) isPluginOutputsResult()      {}
func (*PluginPicksInvalid) isPluginOutputsResult() {}

// ── the company party of a flow ──────────────────────────────────────────────

// pluginFlowParty is what the service Client and the CustomerClient supply to
// the shared plugin call: how to read the run, how to get a pass, which answers
// the caller can read, and which user id is its own.
type pluginFlowParty struct {
	transport     *http.Client
	fetchRun      func(ctx context.Context) (FlowRun, error)
	fetchPass     func(ctx context.Context) (PluginPass, error)
	storedAnswers func(run FlowRun) (map[string]any, error)
	ownUserID     func(run FlowRun) string
}

// newPluginTransport is the plain HTTP transport the forwarder is reached over:
// no bearer token or other allme credential, no base-URL rewriting, and no
// redirect followed.
func newPluginTransport() *http.Client {
	return &http.Client{
		Timeout: pluginTransportTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (p pluginFlowParty) options(ctx context.Context, slug, block, query string, picks map[string]string, values, draft map[string]any) (PluginOptionsResult, error) {
	reply, err := p.call(ctx, slug, draft, func(fieldType string, inputs map[string]any) map[string]any {
		return map[string]any{
			"field_type": fieldType,
			"op":         "options",
			"block":      block,
			"query":      query,
			"picks":      nonNilPicks(picks),
			"values":     nonNilMap(values),
			"inputs":     inputs,
		}
	})
	if err != nil {
		return PluginOptionsResult{}, err
	}
	list, isList := reply["options"].([]any)
	if !isList {
		return PluginOptionsResult{}, NewApiError(0, "plugin.not_responding", "the plugin reply carries no options")
	}
	out := PluginOptionsResult{Options: []PluginOption{}, More: asBool(reply["more"])}
	for _, o := range list {
		if om, ok := o.(map[string]any); ok {
			out.Options = append(out.Options, PluginOption{ID: flowStr(om["id"]), Label: flowStr(om["label"])})
		}
	}
	return out, nil
}

func (p pluginFlowParty) outputs(ctx context.Context, slug string, picks map[string]string, values, draft map[string]any) (PluginOutputsResult, error) {
	reply, err := p.call(ctx, slug, draft, func(fieldType string, inputs map[string]any) map[string]any {
		return map[string]any{
			"field_type": fieldType,
			"op":         "outputs",
			"picks":      nonNilPicks(picks),
			"values":     nonNilMap(values),
			"inputs":     inputs,
		}
	})
	if err != nil {
		return nil, err
	}
	if asBool(reply["picks_invalid"]) {
		return &PluginPicksInvalid{}, nil
	}
	outs, isMap := reply["outputs"].(map[string]any)
	if !isMap {
		return nil, NewApiError(0, "plugin.not_responding", "the plugin reply carries no outputs")
	}
	return &PluginOutputs{Outputs: outs}, nil
}

// call resolves the element's inputs from the one live answer map, seals the
// request to the plugin's key, posts it to the forwarder and opens the reply.
// A 409 plugin.key_changed reseals once with the key it names; a 401 or 403
// takes a new pass once.
func (p pluginFlowParty) call(ctx context.Context, slug string, draft map[string]any, build func(fieldType string, inputs map[string]any) map[string]any) (map[string]any, error) {
	run, err := p.fetchRun(ctx)
	if err != nil {
		return nil, err
	}
	stored, err := p.storedAnswers(run)
	if err != nil {
		return nil, err
	}
	live := liveFlowAnswers(run, stored, draft)
	pass, err := p.fetchPass(ctx)
	if err != nil {
		return nil, err
	}
	spec := pass.Specs[slug]
	if spec == nil {
		return nil, newConfigError("%q is not a plugin field on the run's current step", slug)
	}
	privacy := newFlowPrivacy(run, draft, p.ownUserID(run))
	inputs, err := pluginInputs(spec, live, privacy)
	if err != nil {
		return nil, err
	}
	pluginID := asString(spec["plugin_id"])
	request := build(asString(spec["field_type"]), inputs)

	spki := pass.publicKeyFor(pluginID)
	resealed, renewed := false, false
	for {
		if spki == "" {
			return nil, NewApiError(0, "plugin.not_responding", "the plugin has no usable description")
		}
		pluginKey, err := LoadPublicKey(spki)
		if err != nil {
			return nil, err
		}
		status, body, replyKey, err := p.post(ctx, pass, pluginID, pluginKey, request)
		if err != nil {
			return nil, err
		}
		errorKey := asString(body["error_key"])
		switch {
		case status == http.StatusOK:
			reply, err := Decrypt(body["reply"], replyKey)
			if err != nil {
				return nil, err
			}
			var out map[string]any
			if err := json.Unmarshal([]byte(reply), &out); err != nil || out == nil {
				return nil, NewApiError(0, "plugin.not_responding", "the plugin reply is not a JSON object")
			}
			return out, nil
		case status == http.StatusConflict && errorKey == "plugin.key_changed" && !resealed:
			resealed = true
			spki = asString(body["public_key"])
			continue
		case (status == http.StatusUnauthorized || status == http.StatusForbidden) && !renewed:
			renewed = true
			pass, err = p.fetchPass(ctx)
			if err != nil {
				return nil, err
			}
			spki = pass.publicKeyFor(pluginID)
			continue
		}
		return nil, NewApiError(status, errorKey, asString(body["error"]))
	}
}

// post seals the request with a reply key made for this attempt and posts
// {pass, plugin_id, request} to the forwarder. It returns the status, the
// decoded body and the reply key's private half.
func (p pluginFlowParty) post(ctx context.Context, pass PluginPass, pluginID string, pluginKey *rsa.PublicKey, request map[string]any) (int, map[string]any, *rsa.PrivateKey, error) {
	replyKey, replySPKI, err := GenerateReplyKey()
	if err != nil {
		return 0, nil, nil, err
	}
	request["reply_key"] = replySPKI
	plaintext, err := json.Marshal(request)
	if err != nil {
		return 0, nil, nil, newConfigError("could not encode the plugin request: %v", err)
	}
	sealed, err := EncryptForPublicKey(string(plaintext), pluginKey)
	if err != nil {
		return 0, nil, nil, err
	}
	sealedJSON, err := json.Marshal(sealed)
	if err != nil {
		return 0, nil, nil, newConfigError("could not encode the sealed request: %v", err)
	}
	payload, err := json.Marshal(map[string]any{"pass": pass.Pass, "plugin_id": pluginID, "request": string(sealedJSON)})
	if err != nil {
		return 0, nil, nil, newConfigError("could not encode the forwarder body: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pass.ForwarderURL+"/call", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, nil, newConfigError("invalid forwarder_url %q: %v", pass.ForwarderURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.transport.Do(req)
	if err != nil {
		return 0, nil, nil, NewApiError(0, "plugin.not_responding", "the forwarder could not be reached: "+err.Error())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, NewApiError(resp.StatusCode, "plugin.not_responding", "the forwarder answer could not be read: "+err.Error())
	}
	body := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil || body == nil {
			body = map[string]any{}
		}
	}
	return resp.StatusCode, body, replyKey, nil
}

func nonNilPicks(picks map[string]string) map[string]string {
	if picks == nil {
		return map[string]string{}
	}
	return picks
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// ── the live answer map, privacy and inputs ──────────────────────────────────

// pluginSlugsOf lists the slugs of every plugin element in a flow definition.
func pluginSlugsOf(definition map[string]any) []string {
	var out []string
	forEachElement(definition, func(_ string, el map[string]any) {
		if asString(el["kind"]) == "plugin" {
			if s := asString(el["slug"]); s != "" {
				out = append(out, s)
			}
		}
	})
	return out
}

// forEachElement visits every element of every node with the node's key.
func forEachElement(definition map[string]any, visit func(nodeKey string, el map[string]any)) {
	for _, n := range asAnyList(definition["nodes"]) {
		nm, ok := n.(map[string]any)
		if !ok {
			continue
		}
		key := asString(nm["key"])
		for _, e := range asAnyList(nm["elements"]) {
			if em, ok := e.(map[string]any); ok {
				visit(key, em)
			}
		}
	}
}

// answerElements maps every answerable slug (field and plugin elements) to its
// element and the key of the node it sits on.
func answerElements(definition map[string]any) (elements map[string]map[string]any, nodeOf map[string]string) {
	elements = map[string]map[string]any{}
	nodeOf = map[string]string{}
	forEachElement(definition, func(nodeKey string, el map[string]any) {
		kind := asString(el["kind"])
		slug := asString(el["slug"])
		if slug == "" || (kind != "field" && kind != "plugin") {
			return
		}
		elements[slug] = el
		nodeOf[slug] = nodeKey
	})
	return elements, nodeOf
}

// liveFlowAnswers is the ONE live answer map inputs and bounds are read from:
// the stored answers the caller can read, overlaid with draft for the current
// step's slugs, plugin answers expanded, constants computed.
func liveFlowAnswers(run FlowRun, stored, draft map[string]any) map[string]any {
	merged := make(map[string]any, len(stored)+len(draft))
	for k, v := range stored {
		merged[k] = v
	}
	_, nodeOf := answerElements(run.Definition)
	for k, v := range draft {
		if nodeOf[k] == run.CurrentNode && run.CurrentNode != "" {
			merged[k] = v
		}
	}
	constants, _ := run.Definition["constants"].([]any)
	return ComputeConstants(constants, ExpandPluginAnswers(merged, pluginSlugsOf(run.Definition)), run.ReferenceDate)
}

// flowPrivacy decides whether a key of the live map reaches another party's
// private value, failing closed.
type flowPrivacy struct {
	run       FlowRun
	draft     map[string]any
	ownUser   string
	private   map[string]bool
	elements  map[string]map[string]any
	nodeOf    map[string]string
	constants map[string]map[string]any
}

func newFlowPrivacy(run FlowRun, draft map[string]any, ownUser string) *flowPrivacy {
	elements, nodeOf := answerElements(run.Definition)
	fp := &flowPrivacy{
		run:       run,
		draft:     draft,
		ownUser:   ownUser,
		elements:  elements,
		nodeOf:    nodeOf,
		constants: map[string]map[string]any{},
	}
	if run.PrivateSlugs != nil {
		fp.private = map[string]bool{}
		for _, s := range run.PrivateSlugs {
			fp.private[s] = true
		}
	}
	for _, c := range asAnyList(run.Definition["constants"]) {
		if cm, ok := c.(map[string]any); ok {
			if k := asString(cm["key"]); k != "" {
				fp.constants[k] = cm
			}
		}
	}
	return fp
}

// isPrivate reports whether ref — a slug, a dotted plugin key or a constant —
// reaches a private source: a slug in private_slugs (or, when the run carried no
// private_slugs, any slug another party answers), a constant whose refs reach
// one, or a current-step draft whose field's default reaches one. A plugin
// answer's outputs are never private, whatever inputs produced them.
func (fp *flowPrivacy) isPrivate(ref string, seen map[string]bool) bool {
	base := ref
	if i := strings.Index(ref, "."); i >= 0 {
		base = ref[:i]
	}
	if seen[base] {
		return false
	}
	seen[base] = true
	if c, isConstant := fp.constants[base]; isConstant {
		return fp.exprReachesPrivate(c["expr"], seen)
	}
	if fp.private == nil {
		if node, answered := fp.nodeOf[base]; answered && fp.run.Bindings[partyOf(fp.run.Definition, node)] != fp.ownUser {
			return true
		}
	} else if fp.private[base] {
		return true
	}
	if _, drafted := fp.draft[base]; drafted && fp.nodeOf[base] == fp.run.CurrentNode {
		if el := fp.elements[base]; el != nil && el["default"] != nil {
			return fp.exprReachesPrivate(el["default"], seen)
		}
	}
	return false
}

// sourcePrivate names the submitted slugs whose answer is private by the same rule
// the plugin helpers apply to inputs: a field whose default reaches a private
// source. The submit carries source_private: true on exactly these.
func sourcePrivate(run FlowRun, submitted map[string]any, ownUser string) map[string]bool {
	fp := newFlowPrivacy(run, submitted, ownUser)
	out := map[string]bool{}
	for slug := range submitted {
		if fp.isPrivate(slug, map[string]bool{}) {
			out[slug] = true
		}
	}
	return out
}

func (fp *flowPrivacy) exprReachesPrivate(expr any, seen map[string]bool) bool {
	refs := newOrderedKeySet()
	collectExprConstRefs(expr, nil, refs)
	for _, r := range refs.keys {
		if fp.isPrivate(r, seen) {
			return true
		}
	}
	return false
}

// pluginInputs resolves a plugin element's declared inputs from the live map,
// converted to their declared types. A required input that cannot be sent is a
// *PluginInputUnavailableError; an optional one is left out of the call.
func pluginInputs(spec map[string]any, live map[string]any, privacy *flowPrivacy) (map[string]any, error) {
	snapshot, _ := spec["snapshot"].(map[string]any)
	wiring, _ := spec["inputs"].(map[string]any)
	out := map[string]any{}
	for _, in := range asAnyList(snapshot["inputs"]) {
		im, ok := in.(map[string]any)
		if !ok {
			continue
		}
		key := asString(im["key"])
		required := coerceBool(im["required"])
		ref := asString(wiring[key])
		unavailable := func(reason string) error {
			if required {
				return &PluginInputUnavailableError{Input: key, Source: ref, Reason: reason}
			}
			return nil
		}
		if ref == "" {
			if err := unavailable(PluginInputUnwired); err != nil {
				return nil, err
			}
			continue
		}
		value, present := live[ref]
		if !present || !flowAnswered(value) {
			if err := unavailable(PluginInputUnanswered); err != nil {
				return nil, err
			}
			continue
		}
		if privacy.isPrivate(ref, map[string]bool{}) {
			if err := unavailable(PluginInputOtherPartyPrivate); err != nil {
				return nil, err
			}
			continue
		}
		converted, ok := convertPluginInput(asString(im["type"]), value)
		if !ok {
			if err := unavailable(PluginInputNotConvertible); err != nil {
				return nil, err
			}
			continue
		}
		out[key] = converted
	}
	return out, nil
}

// convertPluginInput converts a live value to an input's declared type: number
// a finite JSON number (through the evaluator's number coercion), date a
// YYYY-MM-DD string, boolean a JSON boolean, text a string.
func convertPluginInput(inputType string, value any) (any, bool) {
	switch inputType {
	case "number":
		n, ok := flowToNum(value)
		if !ok || math.IsInf(n, 0) || math.IsNaN(n) {
			return nil, false
		}
		return n, true
	case "date":
		d, ok := parseFlowDate(value)
		if !ok {
			return nil, false
		}
		return d.Format("2006-01-02"), true
	case "boolean":
		switch v := value.(type) {
		case bool:
			return v, true
		case string:
			switch strings.TrimSpace(v) {
			case "true":
				return true, true
			case "false":
				return false, true
			}
		}
		return nil, false
	}
	return flowStr(value), true
}

// flowBoundError checks value against the min and max of slug's field element,
// each evaluated over the live answer map; a bound that evaluates to nil is no
// bound. Numbers compare as numbers and dates as dates. nil when within bounds.
func flowBoundError(run FlowRun, slug string, value any, live map[string]any) error {
	element := fieldElementForSlug(run.Definition, slug)
	if element == nil || !flowAnswered(value) {
		return nil
	}
	for _, bound := range []string{"min", "max"} {
		expr := element[bound]
		if expr == nil {
			continue
		}
		limit := evalExpr(expr, live, run.ReferenceDate)
		if limit == nil {
			continue
		}
		broken := false
		vn, vok := flowToNum(value)
		ln, lok := flowToNum(limit)
		if vok && lok {
			broken = (bound == "min" && vn < ln) || (bound == "max" && vn > ln)
		} else if vd, vdok := parseFlowDate(value); vdok {
			if ld, ldok := parseFlowDate(limit); ldok {
				broken = (bound == "min" && vd.Before(ld)) || (bound == "max" && vd.After(ld))
			}
		}
		if broken {
			return &ValidationError{Slug: slug, FieldType: fieldTypeOfElement(element), Bound: bound, BoundValue: limit}
		}
	}
	return nil
}
