package companydata

// A document leaf's participant PDF sources and the generation inputs they need.
//
// A leaf output rule's PDF is a company template (asset_key), a flow field's answer
// (source_field: slug → source key "field:<slug>") or what a bound customer shared on its
// connection (source_connection: {party, request_slug} → "conn:<party>:<request_slug>"). The
// generating party uploads its own copy of every HELD source of the run's current leaf, sealed
// under the call's one-time key, before it calls /generate; the server refuses a generate whose
// inputs are not exactly the held set.

import (
	"encoding/json"
	"fmt"
)

// FlowRunSourceFile is one staged copy of a connection source named in a run start's
// source_files: the source key ("conn:<party>:<request_slug>"), the bound user it is sealed
// to, and the file StageRunFile returned for the customer bound to the source's party.
type FlowRunSourceFile struct {
	SourceKey string
	ForUserID string
	File      string
}

// fileRef is the file a plaintext {"_enc_file": file, …} answer value names, else "". A
// captured, uploaded or frozen-linked file answer is that plaintext reference, never a
// ciphertext wrapper; every other answer value is a wrapper and answers "".
func fileRef(value any) string {
	if s, ok := value.(string); ok {
		var parsed any
		if err := json.Unmarshal([]byte(s), &parsed); err != nil {
			return ""
		}
		value = parsed
	}
	if m, ok := value.(map[string]any); ok {
		if f, ok := m["_enc_file"].(string); ok {
			return f
		}
	}
	return ""
}

// heldSource is one held participant source of the current leaf. Kind is "field" (Slug the
// flow field, File the generating party's own answer file) or "conn" (File the generating
// party's own copy made at run start).
type heldSource struct {
	SourceKey string
	Kind      string
	Slug      string
	File      string
}

// heldSources is the held set of the leaf nodeKey, in rule order, each source key once. It
// reads every rule of every output of the leaf (a leaf with the older pdfs list carries
// template rules only). "field:<slug>" is held when the generating party's own answer copy
// for the slug (for_user_id == ownUserID) is a file reference; "conn:<party>:<slug>" when
// sourceFiles (the run read's own copies) names it.
func heldSources(definition map[string]any, nodeKey string, answers []map[string]any, ownUserID string, sourceFiles map[string]string) []heldSource {
	node := nodeByKey(definition, nodeKey)
	if node == nil {
		return nil
	}
	outputs, ok := node["outputs"].([]any)
	if !ok {
		return nil
	}
	ownFiles := map[string]string{}
	if ownUserID != "" {
		for _, row := range answers {
			if asString(row["for_user_id"]) != ownUserID {
				continue
			}
			if f := fileRef(row["value"]); f != "" {
				if slug := asString(row["slug"]); slug != "" {
					ownFiles[slug] = f
				}
			}
		}
	}
	var out []heldSource
	seen := map[string]bool{}
	for _, o := range outputs {
		output, _ := o.(map[string]any)
		rules, _ := output["rules"].([]any)
		for _, r := range rules {
			rule, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if field, ok := rule["source_field"].(string); ok && field != "" {
				key := "field:" + field
				if f, held := ownFiles[field]; held && !seen[key] {
					seen[key] = true
					out = append(out, heldSource{SourceKey: key, Kind: "field", Slug: field, File: f})
				}
				continue
			}
			conn, ok := rule["source_connection"].(map[string]any)
			if !ok {
				continue
			}
			party, ok1 := conn["party"].(string)
			slug, ok2 := conn["request_slug"].(string)
			if !ok1 || !ok2 {
				continue
			}
			key := "conn:" + party + ":" + slug
			if f := sourceFiles[key]; f != "" && !seen[key] {
				seen[key] = true
				out = append(out, heldSource{SourceKey: key, Kind: "conn", File: f})
			}
		}
	}
	return out
}

// generateWithInputs uploads each held source, then POSTs generatePath with {otk, values,
// inputs}. envelopeOf fetches and decrypts the generating party's own copy of one source to its
// envelope JSON string. Each envelope is sealed under the SAME one-time key as values and
// POSTed to {generatePath}/inputs as {source_key, value} → {input}; inputs is [] when nothing
// is held.
func generateWithInputs(post func(path string, body any) (any, error), generatePath string, answers map[string]any, held []heldSource, envelopeOf func(heldSource) (string, error)) (any, error) {
	otk, err := newOneTimeKey()
	if err != nil {
		return nil, err
	}
	inputs := []map[string]any{}
	for _, src := range held {
		envelope, err := envelopeOf(src)
		if err != nil {
			return nil, err
		}
		sealed, err := oneTimeKeySeal(otk, envelope)
		if err != nil {
			return nil, err
		}
		res, err := post(generatePath+"/inputs", map[string]any{"source_key": src.SourceKey, "value": sealed})
		if err != nil {
			return nil, err
		}
		ident := asString(asMap(res)["input"])
		if ident == "" {
			return nil, NewApiError(0, "", fmt.Sprintf("generate/inputs answered no input for %s", src.SourceKey))
		}
		inputs = append(inputs, map[string]any{"source_key": src.SourceKey, "input": ident})
	}
	body, err := oneTimeKeyBundleWith(answers, otk)
	if err != nil {
		return nil, err
	}
	body["inputs"] = inputs
	return post(generatePath, body)
}

// sealedString is a sealed wrapper as the JSON string an upload body carries: a string as-is,
// anything else (the map EncryptForPublicKey returns) JSON-encoded.
func sealedString(sealedValue any) (string, error) {
	if s, ok := sealedValue.(string); ok {
		return s, nil
	}
	b, err := json.Marshal(sealedValue)
	if err != nil {
		return "", newConfigError("sealed value is not JSON-encodable: %v", err)
	}
	return string(b), nil
}

// sealAnswerValues sets every values[].value of the answers to the sealed wrapper's JSON string, in
// place: the map EncryptForPublicKey returns and a string both end up sent as the string.
func sealAnswerValues(answers []map[string]any) error {
	seal := func(v map[string]any) error {
		if v["value"] == nil {
			return nil
		}
		s, err := sealedString(v["value"])
		if err != nil {
			return err
		}
		v["value"] = s
		return nil
	}
	for _, a := range answers {
		if typed, ok := a["values"].([]map[string]any); ok {
			for _, v := range typed {
				if err := seal(v); err != nil {
					return err
				}
			}
			continue
		}
		for _, item := range asAnyList(a["values"]) {
			if v, ok := item.(map[string]any); ok {
				if err := seal(v); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// responseFile is the file of an upload's 201 {file} response.
func responseFile(body any) (string, error) {
	f := asString(asMap(body)["file"])
	if f == "" {
		return "", NewApiError(0, "", "the upload response carried no file")
	}
	return f, nil
}
