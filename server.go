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

package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/storage"
)

const (
	defaultStorageFile         = "acme-server"
	defaultCertValidity        = 90 * 24 * time.Hour
	defaultOrderTTL            = 24 * time.Hour
	defaultAuthzTTL            = 24 * time.Hour
	defaultNonceTTL            = time.Hour
	maxNoncesInMemory          = 10000
	maxIdentifiersPerOrder     = 100
	maxContactsPerAccount      = 10
	maxContactLength           = 256
	maxPendingOrdersPerAccount = 100
	maxPendingAuthzPerAccount  = 300
	maxNewAccountsPerMinute    = 60
	maxTotalAccounts           = 10000
)

type stdLogger struct{}

func (stdLogger) Debugf(format string, args ...any) {}
func (stdLogger) Infof(format string, args ...any)  { log.Printf("INF "+format, args...) }
func (stdLogger) Errorf(format string, args ...any) { log.Printf("ERR "+format, args...) }

// Option configures a [Server].
type Option func(*Server)

// WithAdditionalSigner adds an additional [Signer] to the server. When multiple
// signers are configured, the server selects a signer whose issuing CA public
// key algorithm matches the CSR's public key algorithm, falling back to the
// primary signer.
func WithAdditionalSigner(signer Signer) Option {
	return func(s *Server) {
		if signer != nil {
			s.signers = append(s.signers, signer)
		}
	}
}

// WithStorage configures persistent encrypted storage using
// [github.com/c2FmZQ/storage].
func WithStorage(store *storage.Storage) Option {
	return func(s *Server) {
		s.store = store
	}
}

// WithStorageFile sets the data file name used within [storage.Storage].
// Defaults to "acme-server".
func WithStorageFile(filename string) Option {
	return func(s *Server) {
		if filename != "" {
			s.storageFile = filename
		}
	}
}

// WithBaseURL sets the external base URL (e.g. "https://acme.example.com" or
// "https://acme.example.com/acme-prefix") used when constructing endpoint and
// resource URLs. If unset, the base URL is derived from each incoming HTTP
// request's Host header and PathPrefix.
func WithBaseURL(baseURL string) Option {
	return func(s *Server) {
		s.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithPathPrefix sets an optional URL path prefix (e.g. "/v2") under which all
// ACME endpoints are mounted.
func WithPathPrefix(prefix string) Option {
	return func(s *Server) {
		if prefix == "" || prefix == "/" {
			s.pathPrefix = ""
			return
		}
		s.pathPrefix = "/" + strings.Trim(prefix, "/")
	}
}

// WithIdentifierPolicy sets a callback function to validate whether a DNS name
// or IP address is permitted to request a certificate. If nil (the default),
// any valid DNS name or public IP address is allowed (loopback IPs require an
// explicit policy or custom dialer). Production deployments should configure an
// explicit policy such as [AllowIdentifiers] or [ParseAllowIdentifiers].
func WithIdentifierPolicy(policy IdentifierPolicy) Option {
	return func(s *Server) {
		s.identifierPolicy = policy
	}
}

// WithCertificateValidity sets the validity duration for issued certificates.
// Defaults to 90 days.
func WithCertificateValidity(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.certValidity = d
		}
	}
}

// WithDialContext sets a custom dial function used when connecting to targets
// during http-01 and tls-alpn-01 challenge verification.
func WithDialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(s *Server) {
		s.dialContext = dial
	}
}

// WithChallengePort overrides the TCP port used when connecting to targets
// during tls-alpn-01 challenge verification. Defaults to 443.
func WithChallengePort(port int) Option {
	return func(s *Server) {
		if port > 0 && port <= 65535 {
			s.challengePort = port
		}
	}
}

// WithHTTPChallengePort overrides the TCP port used when connecting to targets
// during http-01 challenge verification. Defaults to 80.
func WithHTTPChallengePort(port int) Option {
	return func(s *Server) {
		if port > 0 && port <= 65535 {
			s.httpChallengePort = port
		}
	}
}

// WithChallengeTypes sets the challenge types offered for new authorizations.
// Supported values are [ChallengeTLSALPN01] and [ChallengeHTTP01]. Defaults to
// both.
func WithChallengeTypes(types ...string) Option {
	return func(s *Server) {
		if len(types) > 0 {
			s.challengeTypes = append([]string(nil), types...)
		}
	}
}

// WithTermsOfService configures the Terms of Service URL advertised in the ACME
// directory metadata and whether new accounts must set termsOfServiceAgreed.
func WithTermsOfService(tosURL string, requireAgreed bool) Option {
	return func(s *Server) {
		s.termsOfServiceURL = tosURL
		s.requireTOSAgreed = requireAgreed
	}
}

// WithLogger sets a custom [Logger] for the server.
func WithLogger(logger Logger) Option {
	return func(s *Server) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// Server implements an RFC 8555 ACME server. It implements [http.Handler].
type Server struct {
	signers           []Signer
	store             *storage.Storage
	storageFile       string
	baseURL           string
	pathPrefix        string
	defaultHost       string
	identifierPolicy  IdentifierPolicy
	certValidity      time.Duration
	dialContext       func(ctx context.Context, network, addr string) (net.Conn, error)
	challengePort     int
	httpChallengePort int
	challengeTypes    []string
	termsOfServiceURL string
	requireTOSAgreed  bool
	logger            Logger

	mu            sync.Mutex
	state         serverState
	newAcctWindow []time.Time

	nonceMu    sync.Mutex
	nonces     map[string]time.Time
	nonceQueue []string

	challengeSem chan struct{}

	mux *http.ServeMux
}

var _ http.Handler = (*Server)(nil)

// NewServer creates a new ACME [Server] using the given primary [Signer] and
// options.
func NewServer(signer Signer, opts ...Option) (*Server, error) {
	if signer == nil {
		return nil, errors.New("acme: signer is required")
	}
	if len(signer.Certificates()) == 0 || signer.Certificates()[0] == nil {
		return nil, errors.New("acme: signer must return at least one CA certificate")
	}

	s := &Server{
		signers:           []Signer{signer},
		storageFile:       defaultStorageFile,
		certValidity:      defaultCertValidity,
		challengePort:     443,
		httpChallengePort: 80,
		challengeTypes:    []string{ChallengeTLSALPN01, ChallengeHTTP01},
		nonces:            make(map[string]time.Time),
		challengeSem:      make(chan struct{}, 64),
	}
	for _, opt := range opts {
		opt(s)
	}
	for _, ct := range s.challengeTypes {
		if ct != ChallengeTLSALPN01 && ct != ChallengeHTTP01 {
			return nil, fmt.Errorf("acme: unsupported challenge type %q", ct)
		}
	}
	for _, sg := range s.signers {
		if len(sg.Certificates()) == 0 || sg.Certificates()[0] == nil {
			return nil, errors.New("acme: all signers must return at least one CA certificate")
		}
	}
	if s.logger == nil {
		if s.store != nil && s.store.Logger() != nil {
			s.logger = s.store.Logger()
		} else {
			s.logger = stdLogger{}
		}
	}

	s.state.initMaps()
	if s.store != nil {
		s.store.CreateEmptyFile(s.storageFile, &s.state)
		if err := s.updateState(func(st *serverState) error {
			for _, authz := range st.Authorizations {
				if authz.Status != StatusPending {
					continue
				}
				for _, ch := range authz.Challenges {
					if ch.Status == StatusProcessing {
						ch.Status = StatusPending
					}
					if storedCh, ok := st.Challenges[ch.ID]; ok && storedCh.Status == StatusProcessing {
						storedCh.Status = StatusPending
					}
				}
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("acme: failed to read storage file %q: %w", s.storageFile, err)
		}
	}

	s.mux = http.NewServeMux()
	s.registerRoutes()
	return s, nil
}

func (s *Server) registerRoutes() {
	p := s.pathPrefix
	s.mux.HandleFunc(p+"/ca.pem", s.handleCACert)
	s.mux.HandleFunc(p+"/directory", s.handleDirectory)
	s.mux.HandleFunc(p+"/acme", s.handleDirectory)
	s.mux.HandleFunc(p+"/acme/new-nonce", s.handleNewNonce)
	s.mux.HandleFunc(p+"/acme/new-account", s.handleNewAccount)
	s.mux.HandleFunc(p+"/acme/acct/", s.handleAccount)
	s.mux.HandleFunc(p+"/acme/new-order", s.handleNewOrder)
	s.mux.HandleFunc(p+"/acme/new-authz", s.handleNewAuthz)
	s.mux.HandleFunc(p+"/acme/order/", s.handleOrder)
	s.mux.HandleFunc(p+"/acme/authz/", s.handleAuthorization)
	s.mux.HandleFunc(p+"/acme/challenge/", s.handleChallenge)
	s.mux.HandleFunc(p+"/acme/finalize/", s.handleFinalize)
	s.mux.HandleFunc(p+"/acme/cert/", s.handleCertificate)
	s.mux.HandleFunc(p+"/acme/revoke-cert", s.handleRevokeCert)
	s.mux.HandleFunc(p+"/acme/key-change", s.handleKeyChange)
}

// ServeHTTP implements [http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.logger.Debugf("ACME %s %s", r.Method, r.RequestURI)
	if r.URL.Path != s.pathPrefix+"/directory" && r.URL.Path != s.pathPrefix+"/acme" {
		w.Header().Add("Link", fmt.Sprintf("<%s>;rel=\"index\"", s.directoryURL(r)))
	}
	s.mux.ServeHTTP(w, r)
}

// Start starts a standalone HTTPS server for the ACME service on addr, using a
// server certificate signed by the primary [Signer] for serverName (which may
// be a DNS name or an IP address). The server shuts down when ctx is canceled.
func (s *Server) Start(ctx context.Context, addr string, serverName string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("acme: listen %q: %w", addr, err)
	}
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok && serverName != "" {
		s.mu.Lock()
		if s.defaultHost == "" {
			if tcpAddr.Port == 443 {
				if strings.Contains(serverName, ":") && !strings.HasPrefix(serverName, "[") {
					s.defaultHost = "[" + serverName + "]"
				} else {
					s.defaultHost = serverName
				}
			} else {
				s.defaultHost = net.JoinHostPort(serverName, strconv.Itoa(tcpAddr.Port))
			}
		}
		s.mu.Unlock()
	}

	var certMu sync.Mutex
	var cachedCert *tls.Certificate
	var certNotBefore, certNotAfter time.Time

	getCert := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		certMu.Lock()
		defer certMu.Unlock()

		now := time.Now().UTC()
		if cachedCert != nil {
			halfLife := certNotBefore.Add(certNotAfter.Sub(certNotBefore) / 2)
			if now.Before(halfLife) {
				return cachedCert, nil
			}
		}
		c, nb, na, err := s.generateServerCertificate(serverName)
		if err != nil {
			if cachedCert != nil && now.Before(certNotAfter) {
				return cachedCert, nil
			}
			return nil, err
		}
		cachedCert = &c
		certNotBefore = nb
		certNotAfter = na
		return cachedCert, nil
	}

	if _, err := getCert(nil); err != nil {
		listener.Close()
		return nil, fmt.Errorf("acme: generate server certificate: %w", err)
	}

	httpServer := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
			GetCertificate: getCert,
		},
	}

	go func() {
		if err := httpServer.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.logger.Errorf("ACME HTTPS server error: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		httpServer.Close()
	}()

	return listener, nil
}

func (s *Server) generateServerCertificate(serverName string) (tls.Certificate, time.Time, time.Time, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}
	skid, err := calculateSubjectKeyID(&privKey.PublicKey)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}
	sn, err := generateSerialNumber()
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}
	now := time.Now().UTC()
	notBefore := now.Add(-time.Minute)
	notAfter := now.Add(s.certValidity)
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: serverName},
		PublicKey:             &privKey.PublicKey,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SubjectKeyId:          skid,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(serverName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if serverName != "" {
		tmpl.DNSNames = []string{serverName}
	}

	signer := s.selectSigner(&privKey.PublicKey)
	leaf, err := signer.Sign(tmpl)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}

	var certPEM []byte
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})...)
	for _, ca := range signer.Certificates() {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})...)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, time.Time{}, time.Time{}, err
	}
	return pair, leaf.NotBefore, leaf.NotAfter, nil
}

func (s *Server) selectSigner(pub crypto.PublicKey) Signer {
	var wantAlgo x509.PublicKeyAlgorithm
	switch pub.(type) {
	case *ecdsa.PublicKey:
		wantAlgo = x509.ECDSA
	case ed25519.PublicKey:
		wantAlgo = x509.Ed25519
	default:
		wantAlgo = x509.RSA
	}
	for _, sg := range s.signers {
		certs := sg.Certificates()
		if len(certs) > 0 && certs[0].PublicKeyAlgorithm == wantAlgo {
			return sg
		}
	}
	return s.signers[0]
}

func (s *Server) baseURLForRequest(r *http.Request) string {
	if s.baseURL != "" {
		if s.pathPrefix != "" && !strings.HasSuffix(s.baseURL, s.pathPrefix) {
			return s.baseURL + s.pathPrefix
		}
		return s.baseURL
	}
	return "https://" + s.resolveRequestHost(r) + s.pathPrefix
}

func (s *Server) requestURL(r *http.Request) string {
	if s.baseURL != "" {
		base := s.baseURL
		if s.pathPrefix != "" && strings.HasSuffix(base, s.pathPrefix) && strings.HasPrefix(r.URL.Path, s.pathPrefix+"/") {
			base = strings.TrimSuffix(base, s.pathPrefix)
		}
		return base + r.URL.Path
	}
	return "https://" + s.resolveRequestHost(r) + r.URL.Path
}

func (s *Server) resolveRequestHost(r *http.Request) string {
	s.mu.Lock()
	defHost := s.defaultHost
	s.mu.Unlock()
	if defHost != "" {
		return defHost
	}
	if isValidHostHeader(r.Host) {
		return r.Host
	}
	return "localhost"
}

func isValidHostHeader(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	host := h
	if strings.Contains(h, ":") {
		if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
			host = h[1 : len(h)-1]
			addr, err := netip.ParseAddr(host)
			return err == nil && addr.Zone() == ""
		}
		var portStr string
		var err error
		host, portStr, err = net.SplitHostPort(h)
		if err != nil {
			return false
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	return isValidDNSName(host)
}

func (s *Server) directoryURL(r *http.Request) string {
	return s.baseURLForRequest(r) + "/directory"
}

func (s *Server) updateState(fn func(st *serverState) error) (retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		s.state.initMaps()
		s.cleanupExpired(&s.state)
		return fn(&s.state)
	}

	var st serverState
	commit, err := s.store.OpenForUpdate(s.storageFile, &st)
	if err != nil {
		return err
	}
	defer func() {
		if err := commit(false, &retErr); err != nil && !errors.Is(err, storage.ErrRolledBack) && !errors.Is(err, storage.ErrAlreadyCommitted) && retErr == nil {
			retErr = err
		}
	}()
	st.initMaps()
	s.cleanupExpired(&st)
	if err := fn(&st); err != nil {
		return err
	}
	if err := commit(true, nil); err != nil {
		return err
	}
	s.state = st
	return nil
}

func (s *Server) readState(fn func(st *serverState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.initMaps()
	s.cleanupExpired(&s.state)
	return fn(&s.state)
}

func (s *Server) cleanupExpired(st *serverState) {
	now := time.Now().UTC()
	for id, authz := range st.Authorizations {
		if now.After(authz.Expires) {
			if authz.Status == StatusPending || authz.Status == StatusValid {
				authz.Status = StatusExpired
				for _, ch := range authz.Challenges {
					if ch.Status == StatusPending || ch.Status == StatusProcessing {
						ch.Status = StatusInvalid
					}
					if storedCh, ok := st.Challenges[ch.ID]; ok && (storedCh.Status == StatusPending || storedCh.Status == StatusProcessing) {
						storedCh.Status = StatusInvalid
					}
				}
			}
			// Remove authorizations expired more than 24h ago.
			if now.Sub(authz.Expires) > 24*time.Hour {
				for _, ch := range authz.Challenges {
					delete(st.Challenges, ch.ID)
				}
				delete(st.Authorizations, id)
			}
		}
	}
	for id, order := range st.Orders {
		refreshOrderStatus(st, order)
		if now.After(order.Expires) {
			if order.Status == StatusPending || order.Status == StatusReady {
				order.Status = StatusInvalid
			}
			if now.Sub(order.Expires) > 24*time.Hour {
				delete(st.Orders, id)
			}
		}
	}
	for id, cert := range st.Certificates {
		if !cert.ExpiresAt.IsZero() && now.Sub(cert.ExpiresAt) > 24*time.Hour {
			delete(st.Certificates, id)
			delete(st.certsBySHA256, cert.SHA256)
		}
	}
	for id, ch := range st.Challenges {
		if ch == nil {
			delete(st.Challenges, id)
			continue
		}
		if _, ok := st.Authorizations[ch.AuthzID]; !ok {
			delete(st.Challenges, id)
		}
	}
}
