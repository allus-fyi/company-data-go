package companydata

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// XML inverse parser — mirrors the platform serializer:
//
//   - the document root is <response>;
//   - a list (integer keys) renders as repeated <item> children — so an element
//     whose every child is <item> becomes a list;
//   - an associative array renders as named child tags — a map;
//   - scalars are element text; booleans were written as "true"/"false".
//
// This is the minimal inverse needed for the company-data payloads (dicts of
// lists of dicts of scalars). JSON is the default wire format; XML is the opt-in
// alternative.
//
// XXE safety: Go's encoding/xml is XXE-safe by default — it does NOT resolve
// external entities or DTDs (it has no entity-resolution mechanism to enable),
// so there is no entity resolver to disable. We never wire one. HMAC is always
// computed over the raw bytes, never the parsed tree (see webhooks.go).

// parseXML parses the platform's XML serialization into Go data
// (map[string]any / []any / string), returning an *ApiError on a parse failure.
func parseXML(text string) (any, error) {
	dec := xml.NewDecoder(strings.NewReader(text))
	// Go's xml.Decoder does not expand external entities; Strict mode keeps
	// parsing well-formedness checks on. There is intentionally no entity map
	// or external-resolution callback configured.
	dec.Strict = true

	root, err := readElement(dec)
	if err != nil {
		return nil, NewApiError(0, "", fmt.Sprintf("response was not valid XML: %v", err))
	}
	if root == nil {
		return map[string]any{}, nil
	}
	return elementToGo(root), nil
}

// xmlNode is a minimal parsed element tree built from the token stream (so we
// fully control entity handling — no struct unmarshalling, no DTD).
type xmlNode struct {
	name     string
	text     string
	children []*xmlNode
}

// readElement reads one full element (and its subtree) from the decoder.
func readElement(dec *xml.Decoder) (*xmlNode, error) {
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.ProcInst, xml.Comment, xml.Directive:
			continue // skip <?xml?>, comments, and any DOCTYPE/directive
		case xml.CharData:
			if strings.TrimSpace(string(t)) == "" {
				continue
			}
			// stray top-level text — ignore
			continue
		case xml.StartElement:
			return readElementBody(dec, t)
		case xml.EndElement:
			return nil, nil
		}
	}
}

// readElementBody reads the body of an already-opened start element.
func readElementBody(dec *xml.Decoder, start xml.StartElement) (*xmlNode, error) {
	node := &xmlNode{name: start.Name.Local}
	var textBuf strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			child, err := readElementBody(dec, t)
			if err != nil {
				return nil, err
			}
			node.children = append(node.children, child)
		case xml.CharData:
			textBuf.Write(t)
		case xml.EndElement:
			node.text = textBuf.String()
			return node, nil
		case xml.ProcInst, xml.Comment, xml.Directive:
			// skip
		}
	}
}

// elementToGo converts a parsed node tree into Go data following the
// API's value-serialization conventions.
func elementToGo(node *xmlNode) any {
	if len(node.children) == 0 {
		// A leaf node: its text (or empty string). Callers coerce types from the
		// known schema; booleans came over as "true"/"false" strings.
		return node.text
	}
	// All children are <item> → a list (PHP int-keyed array). A single <item>
	// is still a list.
	allItems := true
	for _, c := range node.children {
		if c.name != "item" {
			allItems = false
			break
		}
	}
	if allItems {
		out := make([]any, 0, len(node.children))
		for _, c := range node.children {
			out = append(out, elementToGo(c))
		}
		return out
	}
	// Otherwise an object: named tags → map keys. Repeated tags collapse to a list.
	result := map[string]any{}
	for _, c := range node.children {
		value := elementToGo(c)
		if existing, ok := result[c.name]; ok {
			if lst, ok := existing.([]any); ok {
				result[c.name] = append(lst, value)
			} else {
				result[c.name] = []any{existing, value}
			}
		} else {
			result[c.name] = value
		}
	}
	return result
}
