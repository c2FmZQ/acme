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

// Command acme-server is a standalone RFC 8555 ACME v2 server with encrypted
// persistent storage ([github.com/c2FmZQ/storage]) and optional Trusted
// Platform Module (TPM) support ([github.com/c2FmZQ/tpm]).
//
// # CA Initialization Modes
//
// Before serving ACME requests, the Certificate Authority (CA) must be
// initialized in the encrypted storage directory (--data-dir) using one of two
// workflows:
//
//  1. Self-signed root CA (--bootstrap-self-signed): generates a new CA key
//     (in encrypted storage or inside the TPM when --tpm is set) and a
//     self-signed root CA certificate.
//  2. Subordinate / intermediate CA (--generate-csr followed by --import-cert):
//     generates a CA private key and outputs a PEM-encoded PKCS#10 Certificate
//     Signing Request (CSR) with BasicConstraints CA:TRUE, then imports the
//     PEM-encoded certificate chain signed by an upstream CA.
//
// The CA certificate chain can be exported at any time with --export-ca, written
// automatically on server startup with --ca-cert-file, or fetched over HTTPS at
// GET /ca.pem.
//
// # Running the Server
//
// When started without a one-shot initialization flag, acme-server listens for
// HTTPS connections on --addr (default ":443") and serves the ACME v2 protocol
// and GET /ca.pem. Either --allow (comma-separated DNS names, wildcard DNS
// patterns, IP addresses, or CIDRs) or --allow-any must be specified.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/c2FmZQ/acme"
	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/crypto"
	"github.com/c2FmZQ/tpm"
)

// Version is set with -ldflags="-X main.Version=${VERSION}"
var Version = "dev"

type appLogger struct {
	debug bool
}

func (l appLogger) Debug(args ...any) {
	if l.debug {
		log.Print(append([]any{"DBG "}, args...)...)
	}
}

func (l appLogger) Debugf(format string, args ...any) {
	if l.debug {
		log.Printf("DBG "+format, args...)
	}
}

func (l appLogger) Info(args ...any) {
	log.Print(append([]any{"INF "}, args...)...)
}

func (l appLogger) Infof(format string, args ...any) {
	log.Printf("INF "+format, args...)
}

func (l appLogger) Error(args ...any) {
	log.Print(append([]any{"ERR "}, args...)...)
}

func (l appLogger) Errorf(format string, args ...any) {
	log.Printf("ERR "+format, args...)
}

func (l appLogger) Fatal(args ...any) {
	log.Fatal(append([]any{"FTL "}, args...)...)
}

func (l appLogger) Fatalf(format string, args ...any) {
	log.Fatalf("FTL "+format, args...)
}

func main() {
	dataDir := flag.String("data-dir", "", "The directory where encrypted storage and masterkey are stored (required).")
	passphraseFlag := flag.String("passphrase", os.Getenv("ACME_PASSPHRASE"), "The passphrase to encrypt the master key on disk (defaults to $ACME_PASSPHRASE).")
	useTPM := flag.Bool("tpm", false, "Use the Trusted Platform Module (TPM) for the storage master key and CA signing key.")

	// CA bootstrap / CSR / import / export flags.
	bootstrapSelfSigned := flag.Bool("bootstrap-self-signed", false, "Bootstrap the CA with a new key and self-signed root certificate, then exit.")
	generateCSR := flag.String("generate-csr", "", "Generate a CA private key (if not already present) and write a PEM-encoded CSR to this file ('-' for stdout), then exit.")
	importCert := flag.String("import-cert", "", "Import a PEM-encoded signed CA certificate chain from this file ('-' for stdin), then exit.")
	exportCA := flag.String("export-ca", "", "Write the PEM-encoded CA certificate chain to this file ('-' for stdout) and exit.")
	caCertFile := flag.String("ca-cert-file", "", "Optional file where the PEM-encoded CA certificate chain is written on server start.")
	keyType := flag.String("key-type", defaultKeyType, "The CA key type: ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-2048, rsa-3072, rsa-4096, or ed25519.")
	caCN := flag.String("ca-cn", "ACME CA", "The Common Name (CN) for the CA subject when bootstrapping or generating a CSR.")
	caOrg := flag.String("ca-org", "", "The Organization (O) for the CA subject when bootstrapping or generating a CSR.")
	caValidity := flag.Duration("ca-validity", defaultCALifetime, "The validity duration for a self-signed CA certificate.")
	force := flag.Bool("force", false, "Overwrite an existing CA key or certificate when used with --bootstrap-self-signed or --generate-csr.")

	// Server configuration flags.
	addr := flag.String("addr", ":443", "The TCP address to listen on for the ACME HTTPS server.")
	hostname := flag.String("hostname", "localhost", "The public DNS name or IP address of this ACME server.")
	baseURL := flag.String("base-url", "", "The external base URL of this ACME server (e.g. https://acme.example.com). Derived from --hostname and --addr if unset.")
	pathPrefix := flag.String("path-prefix", "", "Optional URL path prefix under which ACME endpoints are mounted.")
	tlsCertFile := flag.String("tls-cert", "", "Optional external TLS certificate file for the ACME HTTPS server.")
	tlsKeyFile := flag.String("tls-key", "", "Optional external TLS private key file for the ACME HTTPS server.")
	allowList := flag.String("allow", "", "Comma-separated list of allowed DNS names, wildcard patterns (*.example.com), IP addresses, or CIDRs.")
	allowAny := flag.Bool("allow-any", false, "Allow issuing certificates for any valid DNS or IP identifier when --allow is not set.")
	challenges := flag.String("challenges", "tls-alpn-01,http-01", "Comma-separated list of enabled ACME challenge types (tls-alpn-01, http-01).")
	tlsALPNPort := flag.Int("tls-alpn-port", 443, "The TCP port to connect to when validating tls-alpn-01 challenges.")
	httpPort := flag.Int("http-port", 80, "The TCP port to connect to when validating http-01 challenges.")
	certValidity := flag.Duration("cert-validity", 90*24*time.Hour, "The validity duration for issued ACME certificates.")
	tosURL := flag.String("tos-url", "", "Optional Terms of Service URL advertised in the ACME directory.")
	requireTOS := flag.Bool("require-tos", false, "Require new ACME accounts to agree to the Terms of Service.")
	shutdownGrace := flag.Duration("shutdown-grace-period", time.Minute, "The graceful shutdown timeout on SIGINT/SIGTERM.")
	stdoutFlag := flag.Bool("stdout", false, "Log to STDOUT instead of STDERR.")
	debugFlag := flag.Bool("debug", false, "Enable debug logging.")
	versionFlag := flag.Bool("v", false, "Show the version and exit.")
	flag.Parse()

	if *versionFlag {
		fmt.Fprintf(os.Stdout, "%s %s %s/%s\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}
	if *stdoutFlag {
		log.SetOutput(os.Stdout)
	}
	logger := appLogger{debug: *debugFlag}
	logger.Infof("acme-server %s %s %s/%s", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	flag.Visit(func(f *flag.Flag) {
		if f.Name == "passphrase" {
			log.Print("WRN --passphrase is visible to other users on this host. Use $ACME_PASSPHRASE instead.")
		}
	})

	if *dataDir == "" {
		logger.Fatal("--data-dir must be set")
	}
	if *passphraseFlag == "" {
		logger.Fatal("--passphrase or $ACME_PASSPHRASE must be set")
	}
	if (*tlsCertFile == "") != (*tlsKeyFile == "") {
		logger.Fatal("--tls-cert and --tls-key must be specified together")
	}

	numInitActions := 0
	if *bootstrapSelfSigned {
		numInitActions++
	}
	if *generateCSR != "" {
		numInitActions++
	}
	if *importCert != "" {
		numInitActions++
	}
	if numInitActions > 1 {
		logger.Fatal("--bootstrap-self-signed, --generate-csr, and --import-cert are mutually exclusive")
	}

	passphrase := []byte(*passphraseFlag)
	defer wipe(passphrase)

	store, mk, tpmDev, err := openStorage(*dataDir, passphrase, *useTPM, nil, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize storage: %v", err)
	}
	defer mk.Wipe()
	if tpmDev != nil {
		defer tpmDev.Close()
	}

	ca, err := OpenCA(CAOptions{
		Store: store,
		TPM:   tpmDev,
	})
	if err != nil {
		logger.Fatalf("Failed to open CA: %v", err)
	}

	subject := pkix.Name{CommonName: *caCN}
	if *caOrg != "" {
		subject.Organization = []string{*caOrg}
	}

	// Handle one-shot CA initialization/management operations.
	if *bootstrapSelfSigned {
		if err := ca.BootstrapSelfSigned(*keyType, subject, *caValidity, *force); err != nil {
			logger.Fatalf("Bootstrap self-signed CA failed: %v", err)
		}
		logger.Infof("Bootstrapped self-signed CA (%s, subject=%q)", *keyType, subject.String())
		if *exportCA != "" {
			if err := writeCAFile(ca, *exportCA); err != nil {
				logger.Fatalf("Export CA certificate failed: %v", err)
			}
		}
		return
	}

	if *generateCSR != "" {
		csrPEM, err := ca.GenerateCSR(*keyType, subject, *force)
		if err != nil {
			logger.Fatalf("Generate CSR failed: %v", err)
		}
		if err := writeOutput(*generateCSR, csrPEM, 0644); err != nil {
			logger.Fatalf("Write CSR failed: %v", err)
		}
		logger.Infof("Generated CA key and CSR (%s, subject=%q)", *keyType, subject.String())
		return
	}

	if *importCert != "" {
		pemData, err := readInput(*importCert)
		if err != nil {
			logger.Fatalf("Read certificate chain failed: %v", err)
		}
		if err := ca.ImportCertificateChain(pemData); err != nil {
			logger.Fatalf("Import certificate chain failed: %v", err)
		}
		certs := ca.Certificates()
		logger.Infof("Imported CA certificate chain (%d certificate(s), subject=%q)", len(certs), certs[0].Subject.String())
		if *exportCA != "" {
			if err := writeCAFile(ca, *exportCA); err != nil {
				logger.Fatalf("Export CA certificate failed: %v", err)
			}
		}
		return
	}

	if *exportCA != "" {
		if err := writeCAFile(ca, *exportCA); err != nil {
			logger.Fatalf("Export CA certificate failed: %v", err)
		}
		return
	}

	if !ca.Ready() {
		logger.Fatal("CA is not initialized. Run with --bootstrap-self-signed, or --generate-csr followed by --import-cert.")
	}

	if *caCertFile != "" {
		if err := writeCAFile(ca, *caCertFile); err != nil {
			logger.Fatalf("Failed to write --ca-cert-file: %v", err)
		}
	}

	opts := []acme.Option{
		acme.WithStorage(store),
		acme.WithLogger(logger),
		acme.WithCertificateValidity(*certValidity),
		acme.WithChallengePort(*tlsALPNPort),
		acme.WithHTTPChallengePort(*httpPort),
	}
	if *baseURL != "" {
		opts = append(opts, acme.WithBaseURL(*baseURL))
	}
	if *pathPrefix != "" {
		opts = append(opts, acme.WithPathPrefix(*pathPrefix))
	}
	if *tosURL != "" || *requireTOS {
		opts = append(opts, acme.WithTermsOfService(*tosURL, *requireTOS))
	}
	policyOpt, err := buildIdentifierPolicyOption(*allowList, *allowAny, logger)
	if err != nil {
		logger.Fatalf("Invalid identifier policy configuration: %v", err)
	}
	if policyOpt != nil {
		opts = append(opts, policyOpt)
	}
	if *challenges != "" {
		chTypes := splitTrim(*challenges)
		opts = append(opts, acme.WithChallengeTypes(chTypes...))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener, httpServer, err := startServer(ctx, serverConfig{
		Addr:         *addr,
		Hostname:     *hostname,
		BaseURL:      *baseURL,
		TLSCertFile:  *tlsCertFile,
		TLSKeyFile:   *tlsKeyFile,
		CertValidity: *certValidity,
		CA:           ca,
		ACMEOptions:  opts,
		Logger:       logger,
	})
	if err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}
	logger.Infof("ACME server listening on %s (hostname=%s)", listener.Addr(), *hostname)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Infof("Received signal %d (%s), shutting down...", sig, sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), *shutdownGrace)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Errorf("HTTP server shutdown: %v", err)
	}
}

func openStorage(dataDir string, passphrase []byte, useTPM bool, tpmRWC io.ReadWriteCloser, logger crypto.Logger) (*storage.Storage, crypto.MasterKey, *tpm.TPM, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, nil, nil, err
	}
	opts := []crypto.Option{
		crypto.WithLogger(logger),
	}
	var tpmDev *tpm.TPM
	if useTPM {
		tpmOpts := []tpm.Option{tpm.WithObjectAuth(passphrase)}
		if tpmRWC != nil {
			tpmOpts = append(tpmOpts, tpm.WithTPM(tpmRWC))
		}
		t, err := tpm.New(tpmOpts...)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("tpm.New: %w", err)
		}
		opts = append(opts, crypto.WithTPM(t))
		tpmDev = t
	} else {
		opts = append(opts, crypto.WithAlgo(crypto.PickFastest))
	}

	mkFile := filepath.Join(dataDir, "masterkey")
	mk, err := crypto.ReadMasterKey(passphrase, mkFile, opts...)
	if errors.Is(err, os.ErrNotExist) {
		if mk, err = crypto.CreateMasterKey(opts...); err != nil {
			if tpmDev != nil {
				tpmDev.Close()
			}
			return nil, nil, nil, fmt.Errorf("create master key: %w", err)
		}
		if err = mk.Save(passphrase, mkFile); err != nil {
			mk.Wipe()
			if tpmDev != nil {
				tpmDev.Close()
			}
			return nil, nil, nil, fmt.Errorf("save master key: %w", err)
		}
	}
	if err != nil {
		if tpmDev != nil {
			tpmDev.Close()
		}
		return nil, nil, nil, fmt.Errorf("%s: %w", mkFile, err)
	}

	store := storage.New(dataDir, mk)
	return store, mk, tpmDev, nil
}

type serverConfig struct {
	Addr         string
	Hostname     string
	BaseURL      string
	TLSCertFile  string
	TLSKeyFile   string
	CertValidity time.Duration
	CA           *CA
	ACMEOptions  []acme.Option
	Logger       acme.Logger
}

func startServer(ctx context.Context, cfg serverConfig) (net.Listener, *http.Server, error) {
	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, nil, err
	}

	acmeOpts := append([]acme.Option(nil), cfg.ACMEOptions...)
	if cfg.BaseURL == "" && cfg.Hostname != "" {
		if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
			host := cfg.Hostname
			if tcpAddr.Port != 443 {
				host = net.JoinHostPort(cfg.Hostname, strconv.Itoa(tcpAddr.Port))
			} else if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
				host = "[" + host + "]"
			}
			acmeOpts = append(acmeOpts, acme.WithBaseURL("https://"+host))
		}
	}

	acmeSrv, err := acme.NewServer(cfg.CA, acmeOpts...)
	if err != nil {
		listener.Close()
		return nil, nil, err
	}

	certMgr := &tlsCertManager{
		ca:           cfg.CA,
		hostname:     cfg.Hostname,
		certFile:     cfg.TLSCertFile,
		keyFile:      cfg.TLSKeyFile,
		certLifetime: minDuration(cfg.CertValidity, 7*24*time.Hour),
	}
	// Prime the certificate on startup so any configuration errors fail fast.
	if _, err := certMgr.GetCertificate(nil); err != nil {
		listener.Close()
		return nil, nil, fmt.Errorf("initialize server TLS certificate: %w", err)
	}

	httpServer := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           acmeSrv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
			GetCertificate: certMgr.GetCertificate,
		},
	}

	go func() {
		if err := httpServer.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			cfg.Logger.Errorf("HTTPS server error: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		httpServer.Close()
	}()

	return listener, httpServer, nil
}

type tlsCertManager struct {
	ca           *CA
	hostname     string
	certFile     string
	keyFile      string
	certLifetime time.Duration

	mu          sync.Mutex
	tlsCert     *tls.Certificate
	notBefore   time.Time
	notAfter    time.Time
	certModTime time.Time
	keyModTime  time.Time
}

func (m *tlsCertManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.certFile != "" && m.keyFile != "" {
		certStat, err := os.Stat(m.certFile)
		if err != nil {
			if m.tlsCert != nil {
				return m.tlsCert, nil
			}
			return nil, err
		}
		keyStat, err := os.Stat(m.keyFile)
		if err != nil {
			if m.tlsCert != nil {
				return m.tlsCert, nil
			}
			return nil, err
		}
		if m.tlsCert == nil || !certStat.ModTime().Equal(m.certModTime) || !keyStat.ModTime().Equal(m.keyModTime) {
			pair, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
			if err != nil {
				if m.tlsCert != nil {
					return m.tlsCert, nil
				}
				return nil, err
			}
			m.tlsCert = &pair
			m.certModTime = certStat.ModTime()
			m.keyModTime = keyStat.ModTime()
		}
		return m.tlsCert, nil
	}

	now := time.Now().UTC()
	if m.tlsCert != nil {
		halfLife := m.notBefore.Add(m.notAfter.Sub(m.notBefore) / 2)
		if now.Before(halfLife) {
			return m.tlsCert, nil
		}
	}

	pair, notBefore, notAfter, err := m.issueServerCert(now)
	if err != nil {
		if m.tlsCert != nil && now.Before(m.notAfter) {
			return m.tlsCert, nil
		}
		return nil, err
	}
	m.tlsCert = &pair
	m.notBefore = notBefore
	m.notAfter = notAfter
	return m.tlsCert, nil
}

func (m *tlsCertManager) issueServerCert(now time.Time) (tls.Certificate, time.Time, time.Time, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}
	lifetime := m.certLifetime
	if lifetime <= 0 {
		lifetime = 7 * 24 * time.Hour
	}
	notBefore := now.Add(-time.Minute)
	notAfter := now.Add(lifetime)

	host := m.hostname
	if host == "" {
		host = "localhost"
	}
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: host},
		PublicKey:             &priv.PublicKey,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	leaf, err := m.ca.Sign(tmpl)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}

	var certPEM []byte
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})...)
	for _, caCert := range m.ca.Certificates() {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}
	defer wipe(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer wipe(keyPEM)

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}
	return pair, leaf.NotBefore, leaf.NotAfter, nil
}

func writeCAFile(ca *CA, target string) error {
	pemBytes, err := ca.ExportCertificatesPEM()
	if err != nil {
		return err
	}
	return writeOutput(target, pemBytes, 0644)
}

func writeOutput(target string, data []byte, perm os.FileMode) error {
	if target == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if dir := filepath.Dir(target); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(target, data, perm)
}

func readInput(source string) ([]byte, error) {
	if source == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(source)
}

func buildIdentifierPolicyOption(allowList string, allowAny bool, logger acme.Logger) (acme.Option, error) {
	patterns := splitTrim(allowList)
	if len(patterns) > 0 && allowAny {
		return nil, errors.New("--allow and --allow-any are mutually exclusive")
	}
	if len(patterns) > 0 {
		policy, err := acme.ParseAllowIdentifiers(patterns...)
		if err != nil {
			return nil, fmt.Errorf("invalid --allow patterns: %w", err)
		}
		if logger != nil {
			logger.Infof("Identifier policy restricted to: %s", strings.Join(patterns, ", "))
		}
		return acme.WithIdentifierPolicy(policy), nil
	}
	if allowAny {
		if logger != nil {
			logger.Infof("WARNING: --allow-any is enabled; server will issue certificates for any valid identifier")
		}
		return nil, nil
	}
	return nil, errors.New("--allow or --allow-any must be set")
}

func splitTrim(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}
