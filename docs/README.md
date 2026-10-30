[![Tests](https://github.com/c2FmZQ/acme/actions/workflows/pr.yml/badge.svg?branch=main)](https://github.com/c2FmZQ/acme/actions/workflows/pr.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/c2FmZQ/acme.svg)](https://pkg.go.dev/github.com/c2FmZQ/acme)

# acme

Package `acme` (`github.com/c2FmZQ/acme`) implements an [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) Automatic Certificate Management Environment (ACME) v2 server in Go, compatible with Certbot, [`golang.org/x/crypto/acme`](https://pkg.go.dev/golang.org/x/crypto/acme), and [`golang.org/x/crypto/acme/autocert`](https://pkg.go.dev/golang.org/x/crypto/acme/autocert).

## Features

- **RFC 8555 ACME v2 Server**: Full support for account registration, contact updates, key rollover (`keyChange`), account deactivation, order creation, pre-authorizations (`newAuthz`), authorization deactivation, finalization, certificate retrieval, and certificate revocation (`revokeCert`).
- **HTTP-01 & TLS-ALPN-01 Challenges ([RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555#section-8.3), [RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737), [RFC 8738](https://datatracker.ietf.org/doc/html/rfc8738))**: Validates control over both DNS domain names (`dns`) and IPv4/IPv6 addresses (`ip`).
- **Pluggable Signer Abstraction**: Define custom CA signing logic or multi-certificate intermediate chains via the `Signer` (and optional `Revoker`) interface, or use the built-in `CASigner`. Multiple signers can be registered (e.g., ECDSA and RSA issuing CAs) via `WithAdditionalSigner`.
- **CA Chain Export**: Exposes `GET /ca.pem` returning the server's CA certificate chain in PEM format (`application/pem-certificate-chain`).
- **Encrypted Persistent Storage**: Uses [`github.com/c2FmZQ/storage`](https://pkg.go.dev/github.com/c2FmZQ/storage) to persist accounts, orders, authorizations, challenges, and issued/revoked certificates.
- **Flexible Deployment**: Implements `net/http.Handler` for mounting on any existing `http.Server` or router, and provides `Server.Start` for standalone HTTPS operation with automatic server certificate rotation.

## Library Usage

```go
package main

import (
	"crypto/x509/pkix"
	"log"
	"net/http"

	"github.com/c2FmZQ/acme"
	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
)

func main() {
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		log.Fatal(err)
	}
	store := storage.New("./acme-data", mk)

	signer, err := acme.NewSelfSignedSigner(nil, pkix.Name{CommonName: "Example ACME CA"}, 0)
	if err != nil {
		log.Fatal(err)
	}

	policy, err := acme.ParseAllowIdentifiers(
		"example.com",
		"*.example.com",
		"192.0.2.0/24",
	)
	if err != nil {
		log.Fatal(err)
	}

	srv, err := acme.NewServer(
		signer,
		acme.WithStorage(store),
		acme.WithIdentifierPolicy(policy),
	)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", srv)
	log.Fatal(http.ListenAndServeTLS(":443", "server.crt", "server.key", nil))
}
```

## Standalone CLI Server (`./acme-server`)

The `./acme-server` command provides a standalone ACME server using `github.com/c2FmZQ/storage` for encrypted storage and optional Trusted Platform Module (TPM) support (`--tpm`) via [`github.com/c2FmZQ/tpm`](https://pkg.go.dev/github.com/c2FmZQ/tpm) for both the storage master key and the CA signing private key.

### 1. Bootstrap with a Self-Signed CA

```bash
export ACME_PASSPHRASE="your-secret-passphrase"
go run ./acme-server \
  --data-dir=/var/lib/acme-server \
  --bootstrap-self-signed \
  --key-type=ecdsa-p256 \
  --ca-cn="Internal ACME Root CA" \
  --export-ca=ca.pem
```

### 2. Generate a Key + CSR and Import a Signed CA Certificate Chain

```bash
export ACME_PASSPHRASE="your-secret-passphrase"

# Generate the CA private key in storage (or TPM with --tpm) and output a CSR:
go run ./acme-server \
  --data-dir=/var/lib/acme-server \
  --generate-csr=ca.csr \
  --key-type=ecdsa-p384 \
  --ca-cn="Internal ACME Intermediate CA"

# After signing ca.csr with your upstream/root CA, import the signed certificate chain
# (issuing intermediate certificate first, followed by any parent/root certificates):
go run ./acme-server \
  --data-dir=/var/lib/acme-server \
  --import-cert=ca-chain.pem
```

### 3. Run the Server

Either `--allow` (a comma-separated list of allowed DNS names, wildcard DNS patterns, IP addresses, or CIDRs) or `--allow-any` must be specified when starting the server:

```bash
export ACME_PASSPHRASE="your-secret-passphrase"
go run ./acme-server \
  --data-dir=/var/lib/acme-server \
  --addr=:443 \
  --hostname=acme.example.com \
  --allow="*.example.com,example.com,10.0.0.0/8"
```

See the [Go Reference](https://pkg.go.dev/github.com/c2FmZQ/acme) for full API documentation.
