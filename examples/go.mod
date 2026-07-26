module github.com/allus-fyi/company-data-go/examples

go 1.26

replace github.com/allus-fyi/company-data-go => ..

require (
	github.com/allus-fyi/company-data-go v0.0.0
	github.com/coreos/go-oidc/v3 v3.20.0
	golang.org/x/oauth2 v0.36.0
)

require (
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.22.0 // indirect
)
