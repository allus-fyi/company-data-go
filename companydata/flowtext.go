package companydata

import (
	"regexp"
	"strings"
)

// The value tags a contract-flow TEXT element names, read by the platform's text grammar: HTML tags
// are removed first, `\[` `\]` `\{` `\\` are escapes, and a `{{…}}` an escape breaks is not a tag. A
// tag inside a link address (`[a href=X]`) is a tag too. A starter compiles the values of the
// definition's non-owner PARTY tags before it starts a run (Client.TriggerFlowRun).

var (
	flowTextHTMLTag = regexp.MustCompile(`</?[a-zA-Z][^<>]*>`)
	flowTextTagAt   = regexp.MustCompile(`^\{\{\s*((?i)[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,2})\s*\}\}`)
)

const flowTextEscapable = "[]{\\"

func flowTextAddressCloses(s string, from int) bool {
	for i := from; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte(flowTextEscapable, s[i+1]) >= 0 {
			i++
			continue
		}
		if s[i] == ']' {
			return true
		}
	}
	return false
}

// FlowTextTags returns every value-tag key a text body names — in its text and its link addresses —
// lower-cased, first use first.
func FlowTextTags(body string) []string {
	s := flowTextHTMLTag.ReplaceAllString(body, "")
	var out []string
	seen := map[string]bool{}
	inAddress := false
	for i := 0; i < len(s); {
		c := s[i]
		if c == '\\' && i+1 < len(s) && strings.IndexByte(flowTextEscapable, s[i+1]) >= 0 {
			i += 2
			continue
		}
		if c == '{' {
			if m := flowTextTagAt.FindStringSubmatch(s[i:]); m != nil {
				k := strings.ToLower(m[1])
				if !seen[k] {
					seen[k] = true
					out = append(out, k)
				}
				i += len(m[0])
				continue
			}
		}
		if inAddress && c == ']' {
			inAddress = false
			i++
			continue
		}
		if !inAddress && c == '[' && i+8 <= len(s) && strings.ToLower(s[i:i+8]) == "[a href=" && flowTextAddressCloses(s, i+8) {
			inAddress = true
			i += 8
			continue
		}
		i++
	}
	return out
}

// PartyTag is one non-owner party tag of a definition: the tag, its party key and its field (the
// request slug).
type PartyTag struct {
	Tag   string
	Party string
	Field string
}

// NonOwnerPartyTags returns the definition's NON-OWNER party tags — the tags whose values a starter
// compiles and seals — lower-cased, first use first.
func NonOwnerPartyTags(definition map[string]any) []PartyTag {
	types := map[string]string{}
	known := map[string]bool{}
	if ps, ok := definition["parties"].([]any); ok {
		for _, p := range ps {
			if m, ok := p.(map[string]any); ok {
				if k, ok := m["key"].(string); ok {
					known[strings.ToLower(k)] = true
					if t, ok := m["type"].(string); ok {
						types[strings.ToLower(k)] = t
					}
				}
			}
		}
	}
	var out []PartyTag
	seen := map[string]bool{}
	nodes, _ := definition["nodes"].([]any)
	for _, n := range nodes {
		nm, _ := n.(map[string]any)
		els, _ := nm["elements"].([]any)
		for _, e := range els {
			el, ok := e.(map[string]any)
			if !ok || el["kind"] != "text" {
				continue
			}
			body := ""
			for _, k := range []string{"body", "text", "label"} {
				if v, ok := el[k].(string); ok && v != "" {
					body = v
					break
				}
			}
			for _, tag := range FlowTextTags(body) {
				dot := strings.IndexByte(tag, '.')
				if dot < 0 {
					continue
				}
				party := tag[:dot]
				if !known[party] || types[party] == "owner" || seen[tag] {
					continue
				}
				seen[tag] = true
				out = append(out, PartyTag{Tag: tag, Party: party, Field: tag[dot+1:]})
			}
		}
	}
	return out
}
