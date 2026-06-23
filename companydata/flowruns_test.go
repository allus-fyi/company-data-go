package companydata

// Company-side contract-flow run methods — fully mocked (no live API).
// Mirrors the Python/TS run-method tests: trigger/list/get, decrypt-only-company,
// per-party fan-out + local routing, generate one-time-key shape, and the
// ProcessFlowRun company-leaf document chain.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	companyUID = "company-1"
	personUID  = "person-1"
)

// A two-node, two-party flow as a JSON object (so it decodes the same way the
// HTTP layer would — numbers as json.Number under UseNumber()).
const flowDefJSON = `{
  "output_mode": "data_only",
  "parties": [{"key":"company"},{"key":"person"}],
  "nodes": [
    {"key":"n1","party":"company"},
    {"key":"n2","party":"person"},
    {"key":"n_end","party":"person"}
  ],
  "edges": [
    {"from":"n1","to":"n_end","sort":0,"condition":{"field":"tier","op":"eq","value":"vip"}},
    {"from":"n1","to":"n2","sort":1,"condition":null}
  ]
}`

func runObjJSON(t *testing.T, status, current string, answersJSON, defJSON, outputMode, documentID string) map[string]any {
	t.Helper()
	if defJSON == "" {
		defJSON = flowDefJSON
	}
	if answersJSON == "" {
		answersJSON = "[]"
	}
	if documentID == "" {
		documentID = "null"
	} else {
		documentID = `"` + documentID + `"`
	}
	doc := `{
      "id":"run-1","flow_id":"flow-1","flow_version":3,"service_id":"svc-1",
      "connection_id":"csc-1","company_user_id":"` + companyUID + `",
      "bindings":{"company":"` + companyUID + `","person":"` + personUID + `"},
      "status":"` + status + `","current_node":"` + current + `","document_id":` + documentID + `,
      "output_mode":"` + outputMode + `","definition":` + defJSON + `,"answers":` + answersJSON + `,
      "created_at":null,"updated_at":null
    }`
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("runObjJSON: %v", err)
	}
	return m
}

// ── trigger / list / get ──────────────────────────────────────────────────────

func TestTriggerFlowRun(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	var captured writeReq
	c, _ := newTestClientRW(t, cfg, noGET(t), func(w writeReq) (int, string) {
		captured = w
		b, _ := json.Marshal(runObjJSON(t, "awaiting_company", "n1", "", "", "data_only", ""))
		return 201, string(b)
	})
	run, err := c.TriggerFlowRun(context.Background(), "flow-1", "csc-1",
		map[string]string{"company": companyUID, "person": personUID})
	if err != nil {
		t.Fatalf("TriggerFlowRun: %v", err)
	}
	if !strings.HasSuffix(captured.path, "/company-data/flows/flow-1/runs") {
		t.Fatalf("path = %s", captured.path)
	}
	tgt, _ := captured.jsonBody["target"].(map[string]any)
	if tgt["connection_id"] != "csc-1" {
		t.Fatalf("target = %#v", captured.jsonBody["target"])
	}
	if run.CompanyPartyKey() != "company" || run.ServiceUserID() != companyUID {
		t.Fatalf("run identity = %+v", run)
	}
}

func TestFlowRunsDefaultAwaitingCompany(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	c, _ := newTestClientRW(t, cfg, func(path string, params map[string][]string) (int, string) {
		if !strings.HasSuffix(path, "/company-data/flow-runs") {
			t.Fatalf("unexpected GET %s", path)
		}
		if got := params["status"]; len(got) != 1 || got[0] != "awaiting_company" {
			t.Fatalf("status param = %#v", params["status"])
		}
		b, _ := json.Marshal(map[string]any{"total": 1, "items": []any{runObjJSON(t, "awaiting_company", "n1", "", "", "data_only", "")}})
		return 200, string(b)
	}, func(writeReq) (int, string) { return 200, "{}" })
	runs, err := c.FlowRuns(context.Background(), "")
	if err != nil {
		t.Fatalf("FlowRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].Status != "awaiting_company" {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestFlowRunByID(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	c, _ := newTestClientRW(t, cfg, func(path string, _ map[string][]string) (int, string) {
		if !strings.HasSuffix(path, "/company-data/flow-runs/run-1") {
			t.Fatalf("unexpected GET %s", path)
		}
		b, _ := json.Marshal(runObjJSON(t, "awaiting_company", "n1", "", "", "data_only", ""))
		return 200, string(b)
	}, func(writeReq) (int, string) { return 200, "{}" })
	run, err := c.FlowRun(context.Background(), "run-1")
	if err != nil {
		t.Fatalf("FlowRun: %v", err)
	}
	if run.CurrentNode != "n1" {
		t.Fatalf("current = %s", run.CurrentNode)
	}
}

// ── decrypt only the company's copies ─────────────────────────────────────────

func TestDecryptRunAnswersOnlyCompany(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	wrapper := encryptForVectorKey(t, v, "ACME BV")
	wj, _ := json.Marshal(wrapper)
	answers := `[
      {"slug":"company_name","for_user_id":"` + companyUID + `","value":` + string(wj) + `},
      {"slug":"company_name","for_user_id":"` + personUID + `","value":` + string(wj) + `},
      {"slug":"other","for_user_id":"stranger","value":` + string(wj) + `}
    ]`
	c, _ := newTestClientRW(t, cfg, noGET(t), func(writeReq) (int, string) { return 200, "{}" })
	run := flowRunFromAPI(runObjJSON(t, "awaiting_company", "n1", answers, "", "data_only", ""))
	decoded, err := c.decryptRunAnswers(run)
	if err != nil {
		t.Fatalf("decryptRunAnswers: %v", err)
	}
	if len(decoded) != 1 || decoded["company_name"] != "ACME BV" {
		t.Fatalf("decoded = %#v", decoded)
	}
}

// ── submit: per-party fan-out + local routing ─────────────────────────────────

func keyGetRouter(t *testing.T, spki string) func(string, map[string][]string) (int, string) {
	return func(path string, _ map[string][]string) (int, string) {
		if strings.HasSuffix(path, "/company-data/connections/csc-1") {
			return 200, `{"connection_id":"csc-1","share_code":"ABC123"}`
		}
		if strings.HasSuffix(path, "/api/keys/ABC123") {
			return 200, `{"public_key":"` + spki + `"}`
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	}
}

func TestSubmitFlowAnswersFanOutAndRoutesFallthrough(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	spki := vectorPubSPKIB64(t, v)
	priv, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)

	var captured writeReq
	c, _ := newTestClientRW(t, cfg, keyGetRouter(t, spki), func(w writeReq) (int, string) {
		captured = w
		b, _ := json.Marshal(runObjJSON(t, "awaiting_person", "n2", "", "", "data_only", ""))
		return 200, string(b)
	})
	run := flowRunFromAPI(runObjJSON(t, "awaiting_company", "n1", "", "", "data_only", ""))
	out, err := c.SubmitFlowAnswers(context.Background(), run, map[string]any{"company_name": "ACME BV"}, nil)
	if err != nil {
		t.Fatalf("SubmitFlowAnswers: %v", err)
	}
	if !strings.HasSuffix(captured.path, "/company-data/flow-runs/run-1/answers") {
		t.Fatalf("path = %s", captured.path)
	}
	answers, _ := captured.jsonBody["answers"].([]any)
	if len(answers) != 1 {
		t.Fatalf("answers len = %d", len(answers))
	}
	vals, _ := answers[0].(map[string]any)["values"].([]any)
	seen := map[string]map[string]any{}
	for _, vv := range vals {
		m := vv.(map[string]any)
		seen[m["for_user_id"].(string)] = m["value"].(map[string]any)
	}
	if len(seen) != 2 || seen[companyUID] == nil || seen[personUID] == nil {
		t.Fatalf("per-party copies = %#v", seen)
	}
	for _, w := range seen {
		if !isEncWrapper(w) {
			t.Fatalf("value not an _enc wrapper: %#v", w)
		}
	}
	// company copy round-trips with the service private key
	pt, err := Decrypt(seen[companyUID], priv)
	if err != nil || pt != "ACME BV" {
		t.Fatalf("company copy decrypt = %q, %v", pt, err)
	}
	// local routing: no 'tier' → fallthrough to n2
	if captured.jsonBody["next_node"] != "n2" || captured.jsonBody["next_party"] != "person" {
		t.Fatalf("routing = %#v / %#v", captured.jsonBody["next_node"], captured.jsonBody["next_party"])
	}
	if _, hasLeaf := captured.jsonBody["leaf"]; hasLeaf {
		t.Fatalf("unexpected leaf on a non-leaf submit")
	}
	if out.Status != "awaiting_person" {
		t.Fatalf("out.Status = %s", out.Status)
	}
}

func TestSubmitFlowAnswersRoutesGuardedEdge(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	spki := vectorPubSPKIB64(t, v)
	var captured writeReq
	c, _ := newTestClientRW(t, cfg, keyGetRouter(t, spki), func(w writeReq) (int, string) {
		captured = w
		b, _ := json.Marshal(runObjJSON(t, "awaiting_person", "n_end", "", "", "data_only", ""))
		return 200, string(b)
	})
	run := flowRunFromAPI(runObjJSON(t, "awaiting_company", "n1", "", "", "data_only", ""))
	if _, err := c.SubmitFlowAnswers(context.Background(), run, map[string]any{"tier": "vip"}, nil); err != nil {
		t.Fatalf("SubmitFlowAnswers: %v", err)
	}
	// guarded n1→n_end matches first; current node n1 has edges → not a leaf submit
	if captured.jsonBody["next_node"] != "n_end" {
		t.Fatalf("next_node = %#v", captured.jsonBody["next_node"])
	}
	if _, hasLeaf := captured.jsonBody["leaf"]; hasLeaf {
		t.Fatalf("unexpected leaf")
	}
}

func TestSubmitFlowAnswersSuppliedPartyPubKeys(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	priv, _ := LoadPrivateKey([]byte(v.EncryptedPrivateKeyPEM), v.Passphrase)
	personPub := &priv.PublicKey
	var captured writeReq
	c, _ := newTestClientRW(t, cfg, noGET(t), func(w writeReq) (int, string) {
		captured = w
		b, _ := json.Marshal(runObjJSON(t, "awaiting_person", "n2", "", "", "data_only", ""))
		return 200, string(b)
	})
	run := flowRunFromAPI(runObjJSON(t, "awaiting_company", "n1", "", "", "data_only", ""))
	_, err := c.SubmitFlowAnswers(context.Background(), run, map[string]any{"company_name": "X"},
		map[string]*rsa.PublicKey{personUID: personPub})
	if err != nil {
		t.Fatalf("SubmitFlowAnswers: %v", err)
	}
	answers, _ := captured.jsonBody["answers"].([]any)
	vals, _ := answers[0].(map[string]any)["values"].([]any)
	if len(vals) != 2 {
		t.Fatalf("expected 2 party copies, got %d", len(vals))
	}
}

// ── generate (document leaf) ──────────────────────────────────────────────────

func TestGenerateFlowDocument(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	wrapper := encryptForVectorKey(t, v, "ACME BV")
	wj, _ := json.Marshal(wrapper)
	answers := `[{"slug":"company_name","for_user_id":"` + companyUID + `","value":` + string(wj) + `}]`
	var captured writeReq
	c, _ := newTestClientRW(t, cfg, noGET(t), func(w writeReq) (int, string) {
		captured = w
		return 200, `{"document_id":"doc-9","status":"awaiting_signature"}`
	})
	run := flowRunFromAPI(runObjJSON(t, "generating", "n1", answers, "", "document", ""))
	res, err := c.GenerateFlowDocument(context.Background(), run)
	if err != nil {
		t.Fatalf("GenerateFlowDocument: %v", err)
	}
	rm, _ := res.(map[string]any)
	if rm["document_id"] != "doc-9" {
		t.Fatalf("res = %#v", res)
	}
	if !strings.HasSuffix(captured.path, "/company-data/flow-runs/run-1/generate") {
		t.Fatalf("path = %s", captured.path)
	}
	otk, _ := base64.StdEncoding.DecodeString(captured.jsonBody["otk"].(string))
	blob, _ := base64.StdEncoding.DecodeString(captured.jsonBody["values"].(string))
	if len(otk) != 32 || len(blob) < 12+16 {
		t.Fatalf("otk=%d blob=%d", len(otk), len(blob))
	}
	// reproduce the server read: iv(12) || ct || tag(16)
	block, _ := aes.NewCipher(otk)
	gcm, _ := cipher.NewGCM(block)
	iv := blob[:12]
	plain, err := gcm.Open(nil, iv, blob[12:], nil)
	if err != nil {
		t.Fatalf("gcm.Open: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["company_name"] != "ACME BV" {
		t.Fatalf("decrypted = %#v", got)
	}
}

// ── ProcessFlowRun: chains submit + generate on a company-leaf document flow ───

func TestProcessFlowRunCompanyLeafDocument(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	spki := vectorPubSPKIB64(t, v)
	single := `{"output_mode":"document","parties":[{"key":"company"},{"key":"person"}],
	  "nodes":[{"key":"n1","party":"company"}],"edges":[]}`

	posts := []string{}
	getRoute := func(path string, _ map[string][]string) (int, string) {
		if strings.HasSuffix(path, "/company-data/flow-runs/run-1") {
			status := "awaiting_company"
			docID := ""
			if len(posts) > 0 {
				status = "awaiting_signature"
				docID = "doc-9"
			}
			b, _ := json.Marshal(runObjJSON(t, status, "n1", "", single, "document", docID))
			return 200, string(b)
		}
		if strings.HasSuffix(path, "/company-data/connections/csc-1") {
			return 200, `{"connection_id":"csc-1","share_code":"ABC123"}`
		}
		if strings.HasSuffix(path, "/api/keys/ABC123") {
			return 200, `{"public_key":"` + spki + `"}`
		}
		t.Fatalf("unexpected GET %s", path)
		return 0, ""
	}
	writeRoute := func(w writeReq) (int, string) {
		posts = append(posts, w.path)
		if strings.HasSuffix(w.path, "/answers") {
			b, _ := json.Marshal(runObjJSON(t, "generating", "n1", "", single, "document", ""))
			return 200, string(b)
		}
		if !strings.HasSuffix(w.path, "/generate") {
			t.Fatalf("unexpected write %s", w.path)
		}
		return 200, `{"document_id":"doc-9","status":"awaiting_signature"}`
	}
	c, _ := newTestClientRW(t, cfg, getRoute, writeRoute)
	run, err := c.ProcessFlowRun(context.Background(), "run-1",
		func(node, answers map[string]any) map[string]any { return map[string]any{"company_name": "ACME BV"} }, nil)
	if err != nil {
		t.Fatalf("ProcessFlowRun: %v", err)
	}
	gotAnswers, gotGenerate := false, false
	for _, p := range posts {
		if strings.HasSuffix(p, "/answers") {
			gotAnswers = true
		}
		if strings.HasSuffix(p, "/generate") {
			gotGenerate = true
		}
	}
	if !gotAnswers || !gotGenerate {
		t.Fatalf("posts = %#v", posts)
	}
	if run.Status != "awaiting_signature" || run.DocumentID != "doc-9" {
		t.Fatalf("final run = %+v", run)
	}
}

func TestProcessFlowRunNotOurTurn(t *testing.T) {
	v := loadVector(t)
	cfg := clientConfig(t, v)
	calls := 0
	c, _ := newTestClientRW(t, cfg, func(string, map[string][]string) (int, string) {
		b, _ := json.Marshal(runObjJSON(t, "awaiting_person", "n2", "", "", "data_only", ""))
		return 200, string(b)
	}, func(writeReq) (int, string) { return 200, "{}" })
	run, err := c.ProcessFlowRun(context.Background(), "run-1",
		func(node, answers map[string]any) map[string]any { calls++; return map[string]any{"x": "y"} }, nil)
	if err != nil {
		t.Fatalf("ProcessFlowRun: %v", err)
	}
	if run.Status != "awaiting_person" || calls != 0 {
		t.Fatalf("status=%s calls=%d", run.Status, calls)
	}
}
