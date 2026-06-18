package companydata_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	companydata "github.com/allus-fyi/company-data-go/companydata"
)

// ExampleFromConfig shows the typical bootstrap: build a Client from a JSON
// config file (all keys live in config), then list connections.
func ExampleFromConfig() {
	client, err := companydata.FromConfig("./allus-config.json")
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	conns, err := client.ConnectionsList(ctx, 100, 0) // initial full sync
	if err != nil {
		log.Fatal(err)
	}
	for _, conn := range conns {
		// Values are keyed by YOUR request-field slug; the person's source field
		// is never exposed.
		if v, ok := conn.Values["work_email"]; ok {
			fmt.Printf("%s: %v (live=%t)\n", conn.DisplayName, v.Value, v.Live)
		}
	}
}

// ExampleClient_ProcessChanges shows the crash-safe streaming pump: it delivers
// one Change at a time, persists each batch durably before delivery, acks
// per-item on success, dead-letters poison events, and returns when the feed is
// empty (you schedule re-runs — no daemon mode). Your handler must be idempotent
// (dedup on Change.ID).
func ExampleClient_ProcessChanges() {
	client, err := companydata.FromConfig("./allus-config.json")
	if err != nil {
		log.Fatal(err)
	}

	err = client.ProcessChanges(func(c companydata.Change) error {
		switch c.Event {
		case "field_updated":
			fmt.Printf("[%s] %s = %v\n", c.PersonID, c.Slug, c.Value)
		case "connection_created", "connection_deleted":
			fmt.Printf("[%s] %s\n", c.PersonID, c.Event)
		}
		return nil // returning nil acks; returning an error retries → dead-letters
	}, companydata.PumpOptions{}) // defaults: batch 100, 3 retries, deadletter on poison
	if err != nil {
		log.Fatal(err)
	}
}

// ExampleClient_HandleWebhook shows the webhook receiver helper inside an
// http.HandlerFunc: verify the signature + parse the body to a Change in one
// call, all config-driven (no key/secret arguments).
func ExampleClient_HandleWebhook() {
	client, err := companydata.FromConfig("./allus-config.json")
	if err != nil {
		log.Fatal(err)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		body := readAll(r) // read the RAW body bytes (HMAC is over the raw bytes)
		change, err := client.HandleWebhook(body, r.Header)
		if err != nil {
			http.Error(w, "invalid webhook", http.StatusBadRequest)
			return
		}
		fmt.Printf("webhook: %s %s\n", change.Event, change.Slug)
		w.WriteHeader(http.StatusOK)
	}
	_ = handler
}

// readAll is a stand-in for io.ReadAll(r.Body) to keep the example focused.
func readAll(*http.Request) []byte { return nil }
