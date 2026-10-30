// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package acme implements an RFC 8555 Automatic Certificate Management
// Environment (ACME) v2 server compatible with Certbot,
// [golang.org/x/crypto/acme], and [golang.org/x/crypto/acme/autocert].
//
// # Overview
//
// A [Server] manages the full ACME certificate issuance lifecycle:
//   - Account registration, contact updates, key rollover (keyChange), and deactivation
//   - Order creation, pre-authorization (newAuthz), and authorization deactivation
//   - Identifier validation using http-01 ([ChallengeHTTP01], RFC 8555 Section 8.3)
//     and tls-alpn-01 ([ChallengeTLSALPN01], RFC 8737) challenges
//   - Both DNS domain name ([IdentifierDNS]) and IPv4/IPv6 address ([IdentifierIP], RFC 8738) identifiers
//   - Order finalization via PKCS#10 Certificate Signing Requests (CSRs)
//   - Certificate chain retrieval and revocation (revokeCert)
//   - CA certificate chain export in PEM format at GET /ca.pem
//
// # Endpoints
//
// A [Server] implements [net/http.Handler] and registers the following routes
// (prefixed by the optional path configured via [WithPathPrefix]):
//   - GET, HEAD /directory and /acme: ACME directory resource
//   - GET, HEAD /ca.pem: Issuing and root CA certificate chain (application/pem-certificate-chain)
//   - GET, HEAD /acme/new-nonce: Replay-Nonce issuance
//   - POST /acme/new-account: Account creation and lookup
//   - POST /acme/acct/{id}: Account retrieval, update, and deactivation
//   - POST /acme/acct/{id}/orders: Account order list
//   - POST /acme/new-order: Certificate order creation
//   - POST /acme/new-authz: Pre-authorization creation
//   - POST /acme/order/{id}: Order status retrieval
//   - POST /acme/authz/{id}: Authorization retrieval and deactivation
//   - POST /acme/challenge/{id}: Challenge initiation and status polling
//   - POST /acme/finalize/{id}: Order finalization with a CSR
//   - POST /acme/cert/{id}: Issued certificate chain download
//   - POST /acme/revoke-cert: Certificate revocation
//   - POST /acme/key-change: Account key rollover
//
// # Certificate Signing
//
// Certificate signing is abstracted behind the [Signer] interface (and optional
// [Revoker] interface for certificate revocation callbacks). Callers can supply
// a custom implementation (such as a hardware-backed or remote CA) or use
// [CASigner] via [NewSigner] or [NewSelfSignedSigner]. Additional signers (for
// example, to match ECDSA vs. RSA leaf key algorithms) can be registered with
// [WithAdditionalSigner].
//
// # Identifier Policies
//
// Callers should restrict which DNS names and IP addresses may be certified
// using [WithIdentifierPolicy] together with [ParseAllowIdentifiers],
// [AllowIdentifiers], or a custom [IdentifierPolicy] callback.
//
// # Persistent Storage
//
// When configured with [WithStorage], [Server] persists accounts, orders,
// authorizations, challenges, and certificates in an encrypted data file
// managed by [github.com/c2FmZQ/storage]. When no storage is provided, state is
// kept in memory.
//
// # Usage
//
// Example mounting [Server] as an [net/http.Handler]:
//
//	signer, err := acme.NewSigner([]*x509.Certificate{caCert}, caKey)
//	if err != nil {
//		log.Fatal(err)
//	}
//	policy, err := acme.ParseAllowIdentifiers("example.com", "*.example.com", "192.0.2.0/24")
//	if err != nil {
//		log.Fatal(err)
//	}
//	srv, err := acme.NewServer(
//		signer,
//		acme.WithStorage(store),
//		acme.WithIdentifierPolicy(policy),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//	http.Handle("/", srv)
package acme
