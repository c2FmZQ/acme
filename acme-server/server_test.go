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

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/c2FmZQ/acme"
	"github.com/google/go-tpm-tools/simulator"
	xacme "golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func TestBootstrapSelfSignedAndPersistence(t *testing.T) {
	dataDir := t.TempDir()
	passphrase := []byte("super-secret-passphrase")
	logger := appLogger{}

	store, mk, _, err := openStorage(dataDir, passphrase, false, nil, logger)
	if err != nil {
		t.Fatalf("openStorage: %v", err)
	}

	ca, err := OpenCA(CAOptions{Store: store})
	if err != nil {
		t.Fatalf("OpenCA: %v", err)
	}
	if ca.Ready() {
		t.Fatal("expected uninitialized CA to not be Ready()")
	}

	subj := pkix.Name{CommonName: "Test Root CA", Organization: []string{"Test Org"}}
	if err := ca.BootstrapSelfSigned("ecdsa-p256", subj, 365*24*time.Hour, false); err != nil {
		t.Fatalf("BootstrapSelfSigned: %v", err)
	}
	if !ca.Ready() {
		t.Fatal("expected bootstrapped CA to be Ready()")
	}
	certs := ca.Certificates()
	if len(certs) != 1 || certs[0].Subject.CommonName != "Test Root CA" {
		t.Fatalf("unexpected CA certificates: %+v", certs)
	}
	origSerial := certs[0].SerialNumber

	// Bootstrapping again without force must fail.
	if err := ca.BootstrapSelfSigned("ecdsa-p256", subj, 365*24*time.Hour, false); err == nil {
		t.Fatal("expected BootstrapSelfSigned without force to fail on initialized CA")
	}

	mk.Wipe()

	// Re-open storage and CA from disk and verify persistence.
	store2, mk2, _, err := openStorage(dataDir, passphrase, false, nil, logger)
	if err != nil {
		t.Fatalf("re-openStorage: %v", err)
	}
	defer mk2.Wipe()

	ca2, err := OpenCA(CAOptions{Store: store2})
	if err != nil {
		t.Fatalf("re-OpenCA: %v", err)
	}
	if !ca2.Ready() {
		t.Fatal("expected re-opened CA to be Ready()")
	}
	if ca2.Certificates()[0].SerialNumber.Cmp(origSerial) != 0 {
		t.Fatalf("serial mismatch after reload: got %v, want %v", ca2.Certificates()[0].SerialNumber, origSerial)
	}

	// Bootstrapping with force=true must overwrite the CA.
	if err := ca2.BootstrapSelfSigned("ed25519", pkix.Name{CommonName: "New Root CA"}, 365*24*time.Hour, true); err != nil {
		t.Fatalf("BootstrapSelfSigned(force=true): %v", err)
	}
	if ca2.Certificates()[0].Subject.CommonName != "New Root CA" {
		t.Fatalf("expected overwritten CA CN 'New Root CA', got %q", ca2.Certificates()[0].Subject.CommonName)
	}
}

func TestGenerateCSRAndImportCertificateChain(t *testing.T) {
	dataDir := t.TempDir()
	passphrase := []byte("csr-passphrase")
	logger := appLogger{}

	store, mk, _, err := openStorage(dataDir, passphrase, false, nil, logger)
	if err != nil {
		t.Fatalf("openStorage: %v", err)
	}
	defer mk.Wipe()

	ca, err := OpenCA(CAOptions{Store: store})
	if err != nil {
		t.Fatalf("OpenCA: %v", err)
	}

	csrPEM, err := ca.GenerateCSR("ecdsa-p384", pkix.Name{
		CommonName:   "Intermediate ACME CA",
		Organization: []string{"Example Corp"},
	}, false)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if ca.Ready() {
		t.Fatal("CA should not be Ready() before certificate chain is imported")
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected CERTIFICATE REQUEST PEM block, got %v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "Intermediate ACME CA" {
		t.Fatalf("unexpected CSR Subject CN: %q", csr.Subject.CommonName)
	}

	// Create an external Root CA to sign the CSR.
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "External Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(root): %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate(root): %v", err)
	}

	// 1. Test rejection of a non-CA leaf certificate.
	nonCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               csr.Subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	nonCADER, err := x509.CreateCertificate(rand.Reader, nonCATmpl, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(nonCA): %v", err)
	}
	nonCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: nonCADER})
	if err := ca.ImportCertificateChain(nonCAPEM); err == nil {
		t.Fatal("expected ImportCertificateChain to reject non-CA certificate")
	}

	// 2. Test rejection of a CA certificate with wrong public key.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrongKeyTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               csr.Subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	wrongKeyDER, err := x509.CreateCertificate(rand.Reader, wrongKeyTmpl, rootCert, &wrongKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(wrongKey): %v", err)
	}
	wrongKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongKeyDER})
	if err := ca.ImportCertificateChain(wrongKeyPEM); err == nil {
		t.Fatal("expected ImportCertificateChain to reject mismatched public key")
	}

	// 3. Sign a valid Intermediate CA certificate for the CSR.
	interSKID, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		t.Fatalf("subjectKeyID: %v", err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               csr.Subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          interSKID,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, csr.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(intermediate): %v", err)
	}

	var chainPEM bytes.Buffer
	pem.Encode(&chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: interDER})
	pem.Encode(&chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	if err := ca.ImportCertificateChain(chainPEM.Bytes()); err != nil {
		t.Fatalf("ImportCertificateChain: %v", err)
	}
	if !ca.Ready() {
		t.Fatal("expected CA to be Ready() after importing certificate chain")
	}
	if got := len(ca.Certificates()); got != 2 {
		t.Fatalf("expected 2 certificates in CA chain, got %d", got)
	}

	// Now start the ACME server using this CA and obtain a certificate via autocert.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Target listener for tls-alpn-01 challenge.
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer targetListener.Close()
	targetPort := targetListener.Addr().(*net.TCPAddr).Port

	acmeListener, httpServer, err := startServer(ctx, serverConfig{
		Addr:         "127.0.0.1:0",
		Hostname:     "acme.internal.test",
		CertValidity: 24 * time.Hour,
		CA:           ca,
		ACMEOptions: []acme.Option{
			acme.WithStorage(store),
			acme.WithChallengePort(targetPort),
			acme.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", targetListener.Addr().String())
			}),
		},
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("startServer: %v", err)
	}
	defer httpServer.Close()

	// Trust ONLY the external Root CA (not the intermediate directly) to verify
	// that both the ACME server's TLS handshake and the issued client certs
	// include the full certificate chain up to the Root CA!
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	acmeHTTPClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootPool,
				ServerName: "acme.internal.test",
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", acmeListener.Addr().String())
			},
		},
	}

	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("app.example.com"),
		Client: &xacme.Client{
			DirectoryURL: "https://" + acmeListener.Addr().String() + "/directory",
			HTTPClient:   acmeHTTPClient,
		},
	}

	targetTLSServer := &http.Server{
		TLSConfig: mgr.TLSConfig(),
	}
	go targetTLSServer.ServeTLS(targetListener, "", "")
	defer targetTLSServer.Close()

	helloCert, err := mgr.GetCertificate(&tls.ClientHelloInfo{
		ServerName:   "app.example.com",
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
	if err != nil {
		t.Fatalf("autocert.GetCertificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(helloCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate(leaf): %v", err)
	}
	interPool := x509.NewCertPool()
	for _, raw := range helloCert.Certificate[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatalf("ParseCertificate(chain): %v", err)
		}
		interPool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       "app.example.com",
		Roots:         rootPool,
		Intermediates: interPool,
	}); err != nil {
		t.Fatalf("issued certificate failed verification against external Root CA: %v", err)
	}
}

func TestTPMCABootstrapAndSigning(t *testing.T) {
	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}

	dataDir := t.TempDir()
	passphrase := []byte("tpm-secret-passphrase")
	logger := appLogger{}

	store, mk, tpmDev, err := openStorage(dataDir, passphrase, true, rwc, logger)
	if err != nil {
		t.Fatalf("openStorage(TPM): %v", err)
	}

	ca, err := OpenCA(CAOptions{
		Store: store,
		TPM:   tpmDev,
	})
	if err != nil {
		t.Fatalf("OpenCA(TPM): %v", err)
	}

	for _, kt := range []string{"ecdsa-p256", "rsa-2048"} {
		if err := ca.BootstrapSelfSigned(kt, pkix.Name{CommonName: "TPM CA " + kt}, 365*24*time.Hour, true); err != nil {
			t.Fatalf("BootstrapSelfSigned(%s): %v", kt, err)
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		now := time.Now().UTC()
		signed, err := ca.Sign(&x509.Certificate{
			Subject:               pkix.Name{CommonName: "leaf.example.com"},
			PublicKey:             &leafKey.PublicKey,
			PublicKeyAlgorithm:    x509.ECDSA,
			NotBefore:             now.Add(-time.Minute),
			NotAfter:              now.Add(24 * time.Hour),
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:              []string{"leaf.example.com"},
		})
		if err != nil {
			t.Fatalf("ca.Sign(%s): %v", kt, err)
		}
		if err := signed.CheckSignatureFrom(ca.Certificates()[0]); err != nil {
			t.Fatalf("CheckSignatureFrom(%s): %v", kt, err)
		}
	}

	mk.Wipe()
	tpmDev.Close()

	// Verify opening without TPM fails when the masterkey and CA key are TPM-backed.
	if _, _, _, err := openStorage(dataDir, passphrase, false, nil, logger); err == nil {
		t.Fatal("expected openStorage without TPM to fail for TPM-backed masterkey")
	}
}

func TestTLSCertManagerAutoRotationAndExternalFiles(t *testing.T) {
	dataDir := t.TempDir()
	passphrase := []byte("rotation-passphrase")
	logger := appLogger{}

	store, mk, _, err := openStorage(dataDir, passphrase, false, nil, logger)
	if err != nil {
		t.Fatalf("openStorage: %v", err)
	}
	defer mk.Wipe()

	ca, err := OpenCA(CAOptions{Store: store})
	if err != nil {
		t.Fatalf("OpenCA: %v", err)
	}
	if err := ca.BootstrapSelfSigned("ecdsa-p256", pkix.Name{CommonName: "Rotation CA"}, 365*24*time.Hour, false); err != nil {
		t.Fatalf("BootstrapSelfSigned: %v", err)
	}

	mgr := &tlsCertManager{
		ca:           ca,
		hostname:     "127.0.0.1",
		certLifetime: time.Hour,
	}

	cert1, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate(1): %v", err)
	}
	cert2, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate(2): %v", err)
	}
	if cert1 != cert2 {
		t.Fatal("expected cached TLS certificate to be reused before half-life")
	}

	// Simulate the certificate reaching past its half-life.
	mgr.mu.Lock()
	mgr.notBefore = time.Now().UTC().Add(-2 * time.Hour)
	mgr.notAfter = time.Now().UTC().Add(10 * time.Minute)
	mgr.mu.Unlock()

	cert3, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate(3): %v", err)
	}
	if cert3 == cert1 {
		t.Fatal("expected TLS certificate to be rotated after passing half-life")
	}

	// Test external --tls-cert and --tls-key files.
	extKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now().UTC()
	extLeaf, err := ca.Sign(&x509.Certificate{
		Subject:               pkix.Name{CommonName: "ext.example.com"},
		PublicKey:             &extKey.PublicKey,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"ext.example.com"},
	})
	if err != nil {
		t.Fatalf("ca.Sign: %v", err)
	}
	certPath := filepath.Join(dataDir, "ext-cert.pem")
	keyPath := filepath.Join(dataDir, "ext-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: extLeaf.Raw}), 0600); err != nil {
		t.Fatalf("WriteFile(cert): %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(extKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}

	extMgr := &tlsCertManager{
		ca:       ca,
		certFile: certPath,
		keyFile:  keyPath,
	}
	loadedCert, err := extMgr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("extMgr.GetCertificate: %v", err)
	}
	parsedLoaded, err := x509.ParseCertificate(loadedCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if parsedLoaded.SerialNumber.Cmp(extLeaf.SerialNumber) != 0 {
		t.Fatalf("expected external certificate serial %v, got %v", extLeaf.SerialNumber, parsedLoaded.SerialNumber)
	}
}

func TestCARevocationPersistence(t *testing.T) {
	dataDir := t.TempDir()
	passphrase := []byte("revoke-passphrase")
	logger := appLogger{}

	store, mk, _, err := openStorage(dataDir, passphrase, false, nil, logger)
	if err != nil {
		t.Fatalf("openStorage: %v", err)
	}
	defer mk.Wipe()

	ca, err := OpenCA(CAOptions{Store: store})
	if err != nil {
		t.Fatalf("OpenCA: %v", err)
	}
	if err := ca.BootstrapSelfSigned("ecdsa-p256", pkix.Name{CommonName: "Revoke CA"}, 365*24*time.Hour, false); err != nil {
		t.Fatalf("BootstrapSelfSigned: %v", err)
	}

	sn := big.NewInt(123456789)
	revoked, err := ca.IsRevoked(sn)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("expected serial not to be revoked initially")
	}

	if err := ca.RevokeCertificate(sn, 1); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	revoked, err = ca.IsRevoked(sn)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected serial to be revoked")
	}
}

func TestBuildIdentifierPolicyOption(t *testing.T) {
	logger := appLogger{}

	// Neither --allow nor --allow-any -> error.
	if _, err := buildIdentifierPolicyOption("", false, logger); err == nil {
		t.Fatal("expected error when neither --allow nor --allow-any is set")
	}

	// Both --allow and --allow-any -> error.
	if _, err := buildIdentifierPolicyOption("example.com", true, logger); err == nil {
		t.Fatal("expected error when both --allow and --allow-any are set")
	}

	// Invalid pattern in --allow -> error.
	if _, err := buildIdentifierPolicyOption("example.com,10.0.0.0/99", false, logger); err == nil {
		t.Fatal("expected error when --allow contains an invalid CIDR")
	}

	// Valid --allow -> non-nil Option.
	opt, err := buildIdentifierPolicyOption("example.com, *.example.com, 192.0.2.0/24", false, logger)
	if err != nil {
		t.Fatalf("buildIdentifierPolicyOption(valid --allow): %v", err)
	}
	if opt == nil {
		t.Fatal("expected non-nil Option for valid --allow")
	}

	// Valid --allow-any -> nil Option, no error.
	optAny, err := buildIdentifierPolicyOption("", true, logger)
	if err != nil {
		t.Fatalf("buildIdentifierPolicyOption(--allow-any): %v", err)
	}
	if optAny != nil {
		t.Fatal("expected nil Option for --allow-any")
	}
}
