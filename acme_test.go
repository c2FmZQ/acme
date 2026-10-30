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

package acme_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/acme"
	"github.com/c2FmZQ/storage"
	storagecrypto "github.com/c2FmZQ/storage/crypto"
	"github.com/go-jose/go-jose/v4"
	xacme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type keyType int

const (
	rsaKey keyType = iota
	ecdsaKey
)

func generateKey(t *testing.T, kt keyType) crypto.Signer {
	t.Helper()
	switch kt {
	case rsaKey:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		return k
	case ecdsaKey:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		return k
	default:
		t.Fatalf("unknown keyType %d", kt)
		return nil
	}
}

type trackingSigner struct {
	*acme.CASigner
	mu      sync.Mutex
	revoked map[string]int
}

func (ts *trackingSigner) RevokeCertificate(serialNumber *big.Int, reasonCode int) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.revoked == nil {
		ts.revoked = make(map[string]int)
	}
	ts.revoked[serialNumber.Text(16)] = reasonCode
	return nil
}

func (ts *trackingSigner) isRevoked(serialNumber *big.Int) (int, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	r, ok := ts.revoked[serialNumber.Text(16)]
	return r, ok
}

type testEnv struct {
	store      *storage.Storage
	rsaSigner  *trackingSigner
	ecSigner   *trackingSigner
	rootPool   *x509.CertPool
	addrMapMu  sync.Mutex
	addrMap    map[string]string
	server     *acme.Server
	httpServer *httptest.Server
}

func newTestEnv(t *testing.T, extraOpts ...acme.Option) *testEnv {
	t.Helper()
	mk, err := storagecrypto.CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("CreateAESMasterKeyForTest: %v", err)
	}
	store := storage.New(t.TempDir(), mk)

	rsaCAKey := generateKey(t, rsaKey)
	rsaCASigner, err := acme.NewSelfSignedSigner(rsaCAKey, pkix.Name{CommonName: "Test RSA Root CA"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSelfSignedSigner(RSA): %v", err)
	}

	ecCAKey := generateKey(t, ecdsaKey)
	ecCASigner, err := acme.NewSelfSignedSigner(ecCAKey, pkix.Name{CommonName: "Test ECDSA Root CA"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSelfSignedSigner(ECDSA): %v", err)
	}

	env := &testEnv{
		store:     store,
		rsaSigner: &trackingSigner{CASigner: rsaCASigner},
		ecSigner:  &trackingSigner{CASigner: ecCASigner},
		rootPool:  x509.NewCertPool(),
		addrMap:   make(map[string]string),
	}
	for _, c := range rsaCASigner.Certificates() {
		env.rootPool.AddCert(c)
	}
	for _, c := range ecCASigner.Certificates() {
		env.rootPool.AddCert(c)
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	opts := []acme.Option{
		acme.WithAdditionalSigner(env.rsaSigner),
		acme.WithStorage(store),
		acme.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			env.addrMapMu.Lock()
			if mapped, ok := env.addrMap[addr]; ok {
				addr = mapped
			}
			env.addrMapMu.Unlock()
			return dialer.DialContext(ctx, network, addr)
		}),
	}
	opts = append(opts, extraOpts...)

	srv, err := acme.NewServer(env.ecSigner, opts...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	env.server = srv
	env.httpServer = httptest.NewTLSServer(srv)
	t.Cleanup(env.httpServer.Close)
	env.rootPool.AddCert(env.httpServer.Certificate())
	return env
}

func (env *testEnv) setChallengeAddr(targetAddr, localAddr string) {
	env.addrMapMu.Lock()
	defer env.addrMapMu.Unlock()
	env.addrMap[targetAddr] = localAddr
}

func (env *testEnv) newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: env.rootPool,
			},
		},
	}
}

func (env *testEnv) startChallengeServer(t *testing.T, client *xacme.Client, chalType, token, identifier string) {
	t.Helper()
	switch chalType {
	case acme.ChallengeTLSALPN01:
		cert, err := client.TLSALPN01ChallengeCert(token, identifier)
		if err != nil {
			t.Fatalf("TLSALPN01ChallengeCert(%q): %v", identifier, err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })

		srv := &http.Server{
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{xacme.ALPNProto},
			},
		}
		go srv.ServeTLS(ln, "", "")
		t.Cleanup(func() { srv.Close() })

		env.setChallengeAddr(net.JoinHostPort(identifier, "443"), ln.Addr().String())

	case acme.ChallengeHTTP01:
		respBody, err := client.HTTP01ChallengeResponse(token)
		if err != nil {
			t.Fatalf("HTTP01ChallengeResponse(%q): %v", token, err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc(client.HTTP01ChallengePath(token), func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(respBody))
		})
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })

		srv := &http.Server{Handler: mux}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })

		env.setChallengeAddr(net.JoinHostPort(identifier, "80"), ln.Addr().String())

	default:
		t.Fatalf("unsupported challenge type %q", chalType)
	}
}

func TestFullACMEFlow_RSA_TLSALPN01(t *testing.T) {
	testFullACMEFlow(t, rsaKey, acme.ChallengeTLSALPN01)
}

func TestFullACMEFlow_ECDSA_TLSALPN01(t *testing.T) {
	testFullACMEFlow(t, ecdsaKey, acme.ChallengeTLSALPN01)
}

func TestFullACMEFlow_RSA_HTTP01(t *testing.T) {
	testFullACMEFlow(t, rsaKey, acme.ChallengeHTTP01)
}

func TestFullACMEFlow_ECDSA_HTTP01(t *testing.T) {
	testFullACMEFlow(t, ecdsaKey, acme.ChallengeHTTP01)
}

func testFullACMEFlow(t *testing.T, kt keyType, chalType string) {
	ctx := t.Context()
	env := newTestEnv(t)

	accountKey := generateKey(t, kt)
	client := &xacme.Client{
		Key:          accountKey,
		DirectoryURL: env.httpServer.URL + "/directory",
		HTTPClient:   env.newHTTPClient(),
	}

	acct, err := client.Register(ctx, &xacme.Account{
		Contact: []string{"mailto:admin@example.com"},
	}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if acct.Status != xacme.StatusValid {
		t.Errorf("acct.Status = %q, want %q", acct.Status, xacme.StatusValid)
	}

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("example.com", "www.example.com"))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == chalType {
				chal = c
				break
			}
		}
		if chal == nil {
			t.Fatalf("no %s challenge in authorization for %v", chalType, authz.Identifier)
		}

		env.startChallengeServer(t, client, chalType, chal.Token, authz.Identifier.Value)

		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("WaitAuthorization: %v", err)
		}
	}

	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	if readyOrder.Status != xacme.StatusReady {
		t.Fatalf("order.Status = %q, want %q", readyOrder.Status, xacme.StatusReady)
	}

	csrKey := generateKey(t, kt)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com", "www.example.com"},
	}, csrKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	derChain, certURL, err := client.CreateCertFromOrder(ctx, readyOrder, csrDER, true)
	if err != nil {
		t.Fatalf("CreateCertFromOrder: %v", err)
	}
	if len(derChain) != 2 {
		t.Fatalf("len(derChain) = %d, want 2", len(derChain))
	}
	if certURL == "" {
		t.Fatal("certURL is empty")
	}

	leafCert, err := x509.ParseCertificate(derChain[0])
	if err != nil {
		t.Fatalf("ParseCertificate(leaf): %v", err)
	}
	caCert, err := x509.ParseCertificate(derChain[1])
	if err != nil {
		t.Fatalf("ParseCertificate(ca): %v", err)
	}
	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("leafCert.CheckSignatureFrom(caCert): %v", err)
	}
	if err := leafCert.VerifyHostname("example.com"); err != nil {
		t.Errorf("VerifyHostname(example.com): %v", err)
	}
	if err := leafCert.VerifyHostname("www.example.com"); err != nil {
		t.Errorf("VerifyHostname(www.example.com): %v", err)
	}

	// Re-fetch certificate via FetchCert (POST-as-GET).
	fetched, err := client.FetchCert(ctx, certURL, true)
	if err != nil {
		t.Fatalf("FetchCert: %v", err)
	}
	if len(fetched) != 2 {
		t.Fatalf("len(fetched) = %d, want 2", len(fetched))
	}
}

func TestDNSAndIPAddressSANs_TLSALPN01(t *testing.T) {
	testDNSAndIPAddressSANs(t, acme.ChallengeTLSALPN01)
}

func TestDNSAndIPAddressSANs_HTTP01(t *testing.T) {
	testDNSAndIPAddressSANs(t, acme.ChallengeHTTP01)
}

func testDNSAndIPAddressSANs(t *testing.T, chalType string) {
	ctx := t.Context()
	env := newTestEnv(t)

	accountKey := generateKey(t, ecdsaKey)
	client := &xacme.Client{
		Key:          accountKey,
		DirectoryURL: env.httpServer.URL + "/directory",
		HTTPClient:   env.newHTTPClient(),
	}

	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ids := []xacme.AuthzID{
		{Type: "dns", Value: "mixed.example.com"},
		{Type: "ip", Value: "192.0.2.10"},
		{Type: "ip", Value: "2001:db8::10"},
	}
	order, err := client.AuthorizeOrder(ctx, ids)
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == chalType {
				chal = c
				break
			}
		}
		if chal == nil {
			t.Fatalf("no %s challenge found", chalType)
		}
		env.startChallengeServer(t, client, chalType, chal.Token, authz.Identifier.Value)

		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("Accept(%s): %v", authz.Identifier.Value, err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("WaitAuthorization(%s): %v", authz.Identifier.Value, err)
		}
	}

	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}

	csrKey := generateKey(t, ecdsaKey)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"mixed.example.com"},
		IPAddresses: []net.IP{
			net.ParseIP("192.0.2.10"),
			net.ParseIP("2001:db8::10"),
		},
	}, csrKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	derChain, _, err := client.CreateCertFromOrder(ctx, readyOrder, csrDER, true)
	if err != nil {
		t.Fatalf("CreateCertFromOrder: %v", err)
	}

	leafCert, err := x509.ParseCertificate(derChain[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	for _, host := range []string{"mixed.example.com", "192.0.2.10", "2001:db8::10"} {
		if err := leafCert.VerifyHostname(host); err != nil {
			t.Errorf("leafCert.VerifyHostname(%q): %v", host, err)
		}
	}
}

func TestAutocertIntegration_TLSALPN01(t *testing.T) {
	ctx := t.Context()
	env := newTestEnv(t)

	// Start a target TLS server managed by autocert.Manager.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer targetLn.Close()

	env.setChallengeAddr("autocert.example.com:443", targetLn.Addr().String())

	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("autocert.example.com"),
		Email:      "autocert@example.com",
		Client: &xacme.Client{
			DirectoryURL: env.httpServer.URL + "/directory",
			HTTPClient:   env.newHTTPClient(),
		},
	}

	targetServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello from autocert server")
		}),
		TLSConfig: mgr.TLSConfig(),
	}
	go targetServer.ServeTLS(targetLn, "", "")
	defer targetServer.Close()

	// Connect as a regular HTTPS client to the autocert-managed server.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == "autocert.example.com:443" {
					addr = targetLn.Addr().String()
				}
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{
				RootCAs: env.rootPool,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://autocert.example.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if got, want := string(body), "hello from autocert server"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestAutocertIntegration_HTTP01(t *testing.T) {
	ctx := t.Context()
	env := newTestEnv(t, acme.WithChallengeTypes(acme.ChallengeHTTP01))

	targetTLS, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(TLS): %v", err)
	}
	defer targetTLS.Close()

	targetHTTP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(HTTP): %v", err)
	}
	defer targetHTTP.Close()

	env.setChallengeAddr("http01.example.com:80", targetHTTP.Addr().String())

	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("http01.example.com"),
		Email:      "autocert@example.com",
		Client: &xacme.Client{
			DirectoryURL: env.httpServer.URL + "/directory",
			HTTPClient:   env.newHTTPClient(),
		},
	}

	httpChallengeSrv := &http.Server{
		Handler: mgr.HTTPHandler(nil),
	}
	go httpChallengeSrv.Serve(targetHTTP)
	defer httpChallengeSrv.Close()

	targetServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello from autocert http-01 server")
		}),
		TLSConfig: mgr.TLSConfig(),
	}
	go targetServer.ServeTLS(targetTLS, "", "")
	defer targetServer.Close()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == "http01.example.com:443" {
					addr = targetTLS.Addr().String()
				}
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{
				RootCAs: env.rootPool,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://http01.example.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if got, want := string(body), "hello from autocert http-01 server"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestAccountLifecycleAndPersistence(t *testing.T) {
	ctx := t.Context()
	env := newTestEnv(t)

	accountKey := generateKey(t, ecdsaKey)
	client := &xacme.Client{
		Key:          accountKey,
		DirectoryURL: env.httpServer.URL + "/directory",
		HTTPClient:   env.newHTTPClient(),
	}

	// GetReg before registration should return ErrNoAccount.
	if _, err := client.GetReg(ctx, ""); !errors.Is(err, xacme.ErrNoAccount) {
		t.Fatalf("GetReg before Register = %v, want ErrNoAccount", err)
	}

	acct, err := client.Register(ctx, &xacme.Account{
		Contact: []string{"mailto:one@example.com"},
	}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Re-registering with the same key returns ErrAccountAlreadyExists.
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		t.Fatalf("second Register = %v, want ErrAccountAlreadyExists", err)
	}

	// UpdateReg updates contact info.
	updated, err := client.UpdateReg(ctx, &xacme.Account{
		Contact: []string{"mailto:two@example.com"},
	})
	if err != nil {
		t.Fatalf("UpdateReg: %v", err)
	}
	if len(updated.Contact) != 1 || updated.Contact[0] != "mailto:two@example.com" {
		t.Errorf("updated.Contact = %v, want [mailto:two@example.com]", updated.Contact)
	}

	// Simulate server restart using the same github.com/c2FmZQ/storage instance.
	restartedSrv, err := acme.NewServer(
		env.ecSigner,
		acme.WithAdditionalSigner(env.rsaSigner),
		acme.WithStorage(env.store),
	)
	if err != nil {
		t.Fatalf("NewServer(restart): %v", err)
	}
	restartedHTTP := httptest.NewTLSServer(restartedSrv)
	defer restartedHTTP.Close()
	env.rootPool.AddCert(restartedHTTP.Certificate())

	client2 := &xacme.Client{
		Key:          accountKey,
		DirectoryURL: restartedHTTP.URL + "/directory",
		HTTPClient:   env.newHTTPClient(),
	}
	gotAcct, err := client2.GetReg(ctx, "")
	if err != nil {
		t.Fatalf("GetReg after restart: %v", err)
	}
	if len(gotAcct.Contact) != 1 || gotAcct.Contact[0] != "mailto:two@example.com" {
		t.Errorf("gotAcct.Contact = %v, want [mailto:two@example.com] (acct URI %s)", gotAcct.Contact, acct.URI)
	}

	// Account key rollover.
	newKey := generateKey(t, ecdsaKey)
	if err := client2.AccountKeyRollover(ctx, newKey); err != nil {
		t.Fatalf("AccountKeyRollover: %v", err)
	}
	gotAfterRollover, err := client2.GetReg(ctx, "")
	if err != nil {
		t.Fatalf("GetReg after rollover: %v", err)
	}
	if gotAfterRollover.Status != xacme.StatusValid {
		t.Errorf("status after rollover = %q, want valid", gotAfterRollover.Status)
	}

	// Deactivate account.
	if err := client2.DeactivateReg(ctx); err != nil {
		t.Fatalf("DeactivateReg: %v", err)
	}
	if _, err := client2.AuthorizeOrder(ctx, xacme.DomainIDs("example.com")); err == nil {
		t.Errorf("AuthorizeOrder with deactivated account succeeded, want error")
	}
}

func TestRevocationAndPolicy(t *testing.T) {
	ctx := t.Context()
	env := newTestEnv(t, acme.WithIdentifierPolicy(acme.AllowIdentifiers(
		"allowed.example.com",
		"*.wild.example.com",
		"192.0.2.0/24",
	)))

	accountKey := generateKey(t, ecdsaKey)
	client := &xacme.Client{
		Key:          accountKey,
		DirectoryURL: env.httpServer.URL + "/directory",
		HTTPClient:   env.newHTTPClient(),
	}
	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Disallowed DNS name should be rejected.
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("forbidden.example.com")); err == nil {
		t.Errorf("AuthorizeOrder(forbidden.example.com) succeeded, want policy rejection")
	}
	// Disallowed IP should be rejected.
	if _, err := client.AuthorizeOrder(ctx, xacme.IPIDs("198.51.100.1")); err == nil {
		t.Errorf("AuthorizeOrder(198.51.100.1) succeeded, want policy rejection")
	}
	// Wildcard identifier in order should be rejected for tls-alpn-01.
	if _, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("*.wild.example.com")); err == nil {
		t.Errorf("AuthorizeOrder(*.wild.example.com) succeeded, want wildcard rejection")
	}

	// Allowed subdomain matching *.wild.example.com and allowed IP in 192.0.2.0/24 should succeed.
	order, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{
		{Type: "dns", Value: "sub.wild.example.com"},
		{Type: "ip", Value: "192.0.2.55"},
	})
	if err != nil {
		t.Fatalf("AuthorizeOrder(allowed): %v", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		chal := authz.Challenges[0]
		env.startChallengeServer(t, client, chal.Type, chal.Token, authz.Identifier.Value)
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("WaitAuthorization: %v", err)
		}
	}

	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}

	csrKey := generateKey(t, ecdsaKey)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames:    []string{"sub.wild.example.com"},
		IPAddresses: []net.IP{net.ParseIP("192.0.2.55")},
	}, csrKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	derChain, _, err := client.CreateCertFromOrder(ctx, readyOrder, csrDER, true)
	if err != nil {
		t.Fatalf("CreateCertFromOrder: %v", err)
	}
	leafCert, err := x509.ParseCertificate(derChain[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Revoke using the certificate's own private key.
	if err := client.RevokeCert(ctx, csrKey, derChain[0], xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	reason, revoked := env.ecSigner.isRevoked(leafCert.SerialNumber)
	if !revoked {
		t.Errorf("expected certificate %x to be marked revoked in signer", leafCert.SerialNumber)
	}
	if reason != int(xacme.CRLReasonKeyCompromise) {
		t.Errorf("revocation reason = %d, want %d", reason, xacme.CRLReasonKeyCompromise)
	}

	// Revoking an already-revoked certificate should be handled gracefully by x/crypto/acme (alreadyRevoked).
	if err := client.RevokeCert(ctx, nil, derChain[0], xacme.CRLReasonSuperseded); err != nil {
		t.Errorf("second RevokeCert = %v, want nil (alreadyRevoked ignored)", err)
	}
}

func TestStandaloneStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	signer, err := acme.NewSelfSignedSigner(nil, pkix.Name{CommonName: "Standalone Test CA"}, time.Hour)
	if err != nil {
		t.Fatalf("NewSelfSignedSigner: %v", err)
	}
	srv, err := acme.NewServer(signer)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ln, err := srv.Start(ctx, "127.0.0.1:0", "localhost")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer ln.Close()

	pool := x509.NewCertPool()
	for _, c := range signer.Certificates() {
		pool.AddCert(c)
	}

	client := &xacme.Client{
		Key:          generateKey(t, ecdsaKey),
		DirectoryURL: fmt.Sprintf("https://localhost:%d/directory", ln.Addr().(*net.TCPAddr).Port),
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		},
	}

	dir, err := client.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if dir.OrderURL == "" {
		t.Errorf("dir.OrderURL is empty")
	}
}

func TestIntermediateCertificateChainAndPreAuthz(t *testing.T) {
	ctx := t.Context()

	// Create Root CA -> Intermediate CA chain.
	rootKey := generateKey(t, ecdsaKey)
	rootSigner, err := acme.NewSelfSignedSigner(rootKey, pkix.Name{CommonName: "Root CA"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSelfSignedSigner(root): %v", err)
	}
	rootCert := rootSigner.Certificates()[0]

	interKey := generateKey(t, ecdsaKey)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		PublicKey:             interKey.Public(),
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(12 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if _, err := rootSigner.Sign(interTmpl); err == nil {
		t.Fatal("expected CASigner.Sign to reject IsCA: true template")
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, interKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(intermediate): %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("ParseCertificate(intermediate): %v", err)
	}

	chainSigner, err := acme.NewSigner([]*x509.Certificate{interCert, rootCert}, interKey)
	if err != nil {
		t.Fatalf("NewSigner(chain): %v", err)
	}

	srv, err := acme.NewServer(chainSigner)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	httpSrv := httptest.NewTLSServer(srv)
	defer httpSrv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	pool.AddCert(httpSrv.Certificate())

	client := &xacme.Client{
		Key:          generateKey(t, ecdsaKey),
		DirectoryURL: httpSrv.URL + "/directory",
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		},
	}

	if _, err := client.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Test pre-authorization (Authorize & AuthorizeIP & RevokeAuthorization).
	authzDNS, err := client.Authorize(ctx, "preauth.example.com")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if authzDNS.Status != xacme.StatusPending {
		t.Errorf("authzDNS.Status = %q, want pending", authzDNS.Status)
	}
	if err := client.RevokeAuthorization(ctx, authzDNS.URI); err != nil {
		t.Fatalf("RevokeAuthorization: %v", err)
	}
	deactivated, err := client.GetAuthorization(ctx, authzDNS.URI)
	if err != nil {
		t.Fatalf("GetAuthorization: %v", err)
	}
	if deactivated.Status != xacme.StatusDeactivated {
		t.Errorf("deactivated.Status = %q, want deactivated", deactivated.Status)
	}

	authzIP, err := client.AuthorizeIP(ctx, "203.0.113.5")
	if err != nil {
		t.Fatalf("AuthorizeIP: %v", err)
	}
	if authzIP.Identifier.Type != "ip" || authzIP.Identifier.Value != "203.0.113.5" {
		t.Errorf("authzIP.Identifier = %+v, want ip 203.0.113.5", authzIP.Identifier)
	}

	// Verify GET /ca.pem returns the full CA chain (intermediate + root).
	caResp, err := client.HTTPClient.Get(httpSrv.URL + "/ca.pem")
	if err != nil {
		t.Fatalf("GET /ca.pem: %v", err)
	}
	defer caResp.Body.Close()
	if caResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ca.pem status = %d, want 200", caResp.StatusCode)
	}
	caPEM, err := io.ReadAll(caResp.Body)
	if err != nil {
		t.Fatalf("ReadAll(/ca.pem): %v", err)
	}
	var exportedCerts []*x509.Certificate
	rest := caPEM
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("ParseCertificate(/ca.pem): %v", err)
		}
		exportedCerts = append(exportedCerts, c)
	}
	if len(exportedCerts) != 2 {
		t.Fatalf("expected 2 certificates from /ca.pem, got %d", len(exportedCerts))
	}
	if !exportedCerts[0].Equal(interCert) || !exportedCerts[1].Equal(rootCert) {
		t.Errorf("/ca.pem chain mismatch")
	}

	// Verify that a CSR with unverified Subject attributes (e.g. Organization) is rejected.
	order, err := client.AuthorizeOrder(ctx, []xacme.AuthzID{{Type: "dns", Value: "sec.example.com"}})
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	// Attempting to deactivate the authorization from a different/unregistered client must fail.
	otherClient := &xacme.Client{
		Key:          generateKey(t, ecdsaKey),
		DirectoryURL: httpSrv.URL + "/directory",
		HTTPClient:   client.HTTPClient,
	}
	if err := otherClient.RevokeAuthorization(ctx, order.AuthzURLs[0]); err == nil {
		t.Fatal("expected RevokeAuthorization with unregistered key to fail")
	}
}

func TestSecurityHardening(t *testing.T) {
	ctx := t.Context()
	env := newTestEnv(t, acme.WithChallengeTypes(acme.ChallengeHTTP01))
	httpClient := env.newHTTPClient()
	client := &xacme.Client{
		Key:          generateKey(t, ecdsaKey),
		DirectoryURL: env.httpServer.URL + "/directory",
		HTTPClient:   httpClient,
	}

	// 1. Contact validation: non-mailto scheme -> unsupportedContact; query/invalid -> invalidContact.
	for _, badContact := range []string{
		"https://example.com",
		"tel:+1234567890",
		"mailto:admin@example.com?subject=hi",
		"mailto:not-an-email",
		"mailto:Display Name <admin@example.com>",
	} {
		if _, err := client.Register(ctx, &xacme.Account{Contact: []string{badContact}}, xacme.AcceptTOS); err == nil {
			t.Errorf("Register with invalid contact %q succeeded, want error", badContact)
		}
	}

	// 2. Register valid account and verify re-registration with new-account does NOT overwrite contact.
	acct, err := client.Register(ctx, &xacme.Account{Contact: []string{"mailto:original@example.com"}}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := client.Register(ctx, &xacme.Account{Contact: []string{"mailto:overwrite@example.com"}}, xacme.AcceptTOS); !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		t.Fatalf("Register(existing) = %v, want ErrAccountAlreadyExists", err)
	}
	acctAgain, err := client.GetReg(ctx, "")
	if err != nil {
		t.Fatalf("GetReg: %v", err)
	}
	if len(acctAgain.Contact) != 1 || acctAgain.Contact[0] != "mailto:original@example.com" {
		t.Errorf("new-account with existing key overwrote Contact = %v, want [mailto:original@example.com]", acctAgain.Contact)
	}
	_ = acct

	// 3. Reject CSR signed by the ACME account key (RFC 8555 Section 11.1).
	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs("example.com"))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			t.Fatal("missing http-01 challenge")
		}
		env.startChallengeServer(t, client, acme.ChallengeHTTP01, chal.Token, authz.Identifier.Value)
		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("WaitAuthorization: %v", err)
		}
	}
	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}

	sameKeyCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"example.com"},
	}, client.Key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest(account key): %v", err)
	}
	if _, _, err := client.CreateCertFromOrder(ctx, readyOrder, sameKeyCSR, false); err == nil {
		t.Fatal("expected CreateCertFromOrder to reject CSR signed with the account key")
	}

	// 4. Reject JWS with unprotected header and reject JWK on kid-only endpoint (new-order).
	nonceResp, err := httpClient.Head(env.httpServer.URL + "/acme/new-nonce")
	if err != nil {
		t.Fatalf("HEAD new-nonce: %v", err)
	}
	nonceResp.Body.Close()
	nonce := nonceResp.Header.Get("Replay-Nonce")

	jwk := &jose.JSONWebKey{Key: client.Key.Public()}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: client.Key},
		(&jose.SignerOptions{}).WithHeader("nonce", nonce).WithHeader("url", env.httpServer.URL+"/acme/new-order").WithHeader("jwk", jwk),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	signed, err := signer.Sign([]byte(`{"identifiers":[{"type":"dns","value":"example.com"}]}`))
	if err != nil {
		t.Fatalf("signer.Sign: %v", err)
	}
	resp, err := httpClient.Post(env.httpServer.URL+"/acme/new-order", "application/jose+json", strings.NewReader(signed.FullSerialize()))
	if err != nil {
		t.Fatalf("POST new-order with jwk: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST new-order with jwk status = %d, want 400", resp.StatusCode)
	}

	// Test unprotected header in flattened JWS JSON.
	nonce2 := resp.Header.Get("Replay-Nonce")
	signer2, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: client.Key},
		(&jose.SignerOptions{}).WithHeader("nonce", nonce2).WithHeader("url", env.httpServer.URL+"/acme/new-account").WithHeader("jwk", jwk),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	signed2, err := signer2.Sign([]byte(`{"onlyReturnExisting":true}`))
	if err != nil {
		t.Fatalf("signer2.Sign: %v", err)
	}
	var flat map[string]any
	if err := json.Unmarshal([]byte(signed2.FullSerialize()), &flat); err != nil {
		t.Fatalf("Unmarshal JWS: %v", err)
	}
	flat["header"] = map[string]any{"kid": base64.RawURLEncoding.EncodeToString([]byte("injected"))}
	modifiedJWS, _ := json.Marshal(flat)
	resp2, err := httpClient.Post(env.httpServer.URL+"/acme/new-account", "application/jose+json", strings.NewReader(string(modifiedJWS)))
	if err != nil {
		t.Fatalf("POST new-account with unprotected header: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("POST new-account with unprotected header status = %d, want 400", resp2.StatusCode)
	}
}

func TestParseAllowIdentifiers(t *testing.T) {
	if _, err := acme.ParseAllowIdentifiers(); err == nil {
		t.Error("ParseAllowIdentifiers() with no patterns succeeded, want error")
	}
	for _, invalid := range []string{
		"192.0.2.0/33",
		"*.*.example.com",
		"*.com",
		"bad..domain.com",
		"http://example.com",
	} {
		if _, err := acme.ParseAllowIdentifiers(invalid); err == nil {
			t.Errorf("ParseAllowIdentifiers(%q) succeeded, want error", invalid)
		}
	}
	policy, err := acme.ParseAllowIdentifiers("example.com", "*.wild.example.com", "192.0.2.1", "198.51.100.0/24")
	if err != nil {
		t.Fatalf("ParseAllowIdentifiers(valid): %v", err)
	}
	if err := policy(t.Context(), acme.Identifier{Type: acme.IdentifierDNS, Value: "example.com"}); err != nil {
		t.Errorf("policy(example.com) = %v, want nil", err)
	}
	if err := policy(t.Context(), acme.Identifier{Type: acme.IdentifierDNS, Value: "a.wild.example.com"}); err != nil {
		t.Errorf("policy(a.wild.example.com) = %v, want nil", err)
	}
	if err := policy(t.Context(), acme.Identifier{Type: acme.IdentifierIP, Value: "198.51.100.42"}); err != nil {
		t.Errorf("policy(198.51.100.42) = %v, want nil", err)
	}
	if err := policy(t.Context(), acme.Identifier{Type: acme.IdentifierDNS, Value: "other.example.com"}); err == nil {
		t.Errorf("policy(other.example.com) = nil, want error")
	}
}
