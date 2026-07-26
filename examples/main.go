package main

// One command — `go run .` from examples/ — serves the whole allme SDK example test suite: the shared
// static frontend plus the demo-backend contract for ALL THREE scenario families (identity, flow,
// company-data) on ONE port (default 8091, PORT overrides).
//
// This file is only the wiring: the shared scaffolding lives in internal/demo (the launcher, the on-disk
// runtime store, the router, and the SDK-agnostic HTTP helpers), and each family's scenario handlers —
// the part that actually calls the SDK — live in their own package (identity/, flow/, company-data/).
// demo.Main hands the shared Runtime to each family factory, then serves them behind one mutex.

import (
	companydata "github.com/allus-fyi/company-data-go/examples/company-data"
	"github.com/allus-fyi/company-data-go/examples/flow"
	"github.com/allus-fyi/company-data-go/examples/identity"
	"github.com/allus-fyi/company-data-go/examples/internal/demo"
)

func main() {
	demo.Main(
		identity.New,    // scenarios 1–8: sign-in / OIDC / 2FA
		flow.New,        // flow:run: run a contract flow
		companydata.New, // companydata:*: read / definitions / changes / webhook / documents
	)
}
