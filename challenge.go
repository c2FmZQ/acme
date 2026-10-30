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
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// idPeACMEIdentifierOID is the OID for the acmeValidation-v1 X.509 extension
	// defined in RFC 8737 Section 3.
	idPeACMEIdentifierOID = "1.3.6.1.5.5.7.1.31"

	challengeValidationTimeout = 10 * time.Second
)

func (s *Server) validateChallenge(chalID, authzID, chalType, token string, identifier Identifier, accountKey *jose.JSONWebKey) {
	s.challengeSem <- struct{}{}
	defer func() { <-s.challengeSem }()

	switch chalType {
	case ChallengeTLSALPN01:
		s.validateTLSALPN01Challenge(chalID, authzID, token, identifier, accountKey)
	case ChallengeHTTP01:
		s.validateHTTP01Challenge(chalID, authzID, token, identifier, accountKey)
	default:
		s.failChallenge(chalID, authzID, chalType, identifier, errMalformed, "unsupported challenge type %q", chalType)
	}
}

func (s *Server) validateHTTP01Challenge(chalID, authzID, token string, identifier Identifier, accountKey *jose.JSONWebKey) {
	expectedKeyAuth, err := keyAuthorization(token, accountKey)
	if err != nil {
		s.failChallenge(chalID, authzID, ChallengeHTTP01, identifier, errServerInternal, "failed to compute key authorization: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), challengeValidationTimeout)
	defer cancel()

	s.logger.Debugf("Validating http-01 challenge for %s (%s)", identifier.Value, identifier.Type)

	dialFn := s.dialContext
	if dialFn == nil {
		dialFn = s.safeDialContext(identifier)
	}

	transport := &http.Transport{
		DialContext: dialFn,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // Per RFC 8555 Section 8.3, HTTPS redirects do not validate certs.
		},
	}
	defer transport.CloseIdleConnections()

	httpPortStr := strconv.Itoa(s.httpChallengePort)
	httpsPortStr := strconv.Itoa(s.challengePort)
	client := &http.Client{
		Timeout:   challengeValidationTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.URL.User != nil {
				return errors.New("redirect URL must not contain userinfo")
			}
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("unsupported redirect scheme %q", req.URL.Scheme)
			}
			if port := req.URL.Port(); port != "" {
				if scheme == "http" && port != "80" && port != httpPortStr {
					return fmt.Errorf("disallowed HTTP redirect port %q", port)
				}
				if scheme == "https" && port != "443" && port != httpsPortStr {
					return fmt.Errorf("disallowed HTTPS redirect port %q", port)
				}
			}
			targetHost := req.URL.Hostname()
			if targetHost == "" {
				return errors.New("redirect missing hostname")
			}
			// RFC 8555 Section 8.3: "The server MUST NOT follow redirects to IP addresses."
			if _, err := netip.ParseAddr(targetHost); err == nil {
				return fmt.Errorf("redirects to IP address %q are not allowed", targetHost)
			}
			normTargetID, p := normalizeAndValidateIdentifier(Identifier{
				Type:  IdentifierDNS,
				Value: strings.TrimSuffix(targetHost, "."),
			})
			if p != nil {
				return fmt.Errorf("invalid redirect hostname %q: %s", targetHost, p.Detail)
			}
			if s.identifierPolicy != nil && !strings.EqualFold(normTargetID.Value, identifier.Value) {
				if err := s.identifierPolicy(req.Context(), normTargetID); err != nil {
					return fmt.Errorf("redirect target %q rejected by identifier policy: %w", normTargetID.Value, err)
				}
			}
			return nil
		},
	}

	var urlHost string
	if s.httpChallengePort == 80 {
		if strings.Contains(identifier.Value, ":") {
			urlHost = "[" + identifier.Value + "]"
		} else {
			urlHost = identifier.Value
		}
	} else {
		urlHost = net.JoinHostPort(identifier.Value, strconv.Itoa(s.httpChallengePort))
	}

	reqURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", urlHost, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		s.failChallenge(chalID, authzID, ChallengeHTTP01, identifier, errServerInternal, "failed to create HTTP request: %v", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		s.failChallenge(chalID, authzID, ChallengeHTTP01, identifier, errConnection, "failed to connect to client for http-01 challenge: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.failChallenge(chalID, authzID, ChallengeHTTP01, identifier, errUnauthorized, "client returned HTTP status %d, expected 200", resp.StatusCode)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096+1))
	if err != nil {
		s.failChallenge(chalID, authzID, ChallengeHTTP01, identifier, errConnection, "failed to read http-01 response body: %v", err)
		return
	}
	if len(bodyBytes) > 4096 {
		s.failChallenge(chalID, authzID, ChallengeHTTP01, identifier, errUnauthorized, "http-01 response body exceeds maximum length")
		return
	}

	// RFC 8555 Section 8.3: "The server SHOULD ignore whitespace at the end of the body."
	presentedKeyAuth := strings.TrimRight(string(bodyBytes), " \t\r\n")
	if presentedKeyAuth != expectedKeyAuth {
		s.failChallenge(chalID, authzID, ChallengeHTTP01, identifier, errUnauthorized, "key authorization mismatch")
		return
	}

	s.markChallengeValid(chalID, authzID, ChallengeHTTP01, identifier)
}

func (s *Server) safeDialContext(identifier Identifier) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: challengeValidationTimeout}
	httpPortStr := strconv.Itoa(s.httpChallengePort)
	httpsPortStr := strconv.Itoa(s.challengePort)
	var allowedDirectIP netip.Addr
	if identifier.Type == IdentifierIP && s.identifierPolicy != nil {
		if a, err := netip.ParseAddr(identifier.Value); err == nil {
			allowedDirectIP = a.Unmap()
		}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if port != "80" && port != "443" && port != httpPortStr && port != httpsPortStr {
			return nil, fmt.Errorf("refusing to connect to disallowed port %q", port)
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses found for %q", host)
		}
		for _, ip := range ips {
			unmapped := ip.Unmap()
			if unmapped.IsUnspecified() || unmapped.IsMulticast() || unmapped.IsLinkLocalUnicast() || unmapped.IsLinkLocalMulticast() ||
				(unmapped.Is4() && (unmapped.As4()[0] == 0 || unmapped == netip.MustParseAddr("255.255.255.255"))) {
				return nil, fmt.Errorf("refusing to connect to restricted address %s", unmapped)
			}
			if unmapped.IsLoopback() && (unmapped != allowedDirectIP || host != identifier.Value) {
				return nil, fmt.Errorf("refusing to connect to loopback address %s", unmapped)
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func (s *Server) validateTLSALPN01Challenge(chalID, authzID, token string, identifier Identifier, accountKey *jose.JSONWebKey) {
	expectedKeyAuth, err := keyAuthorization(token, accountKey)
	if err != nil {
		s.failChallenge(chalID, authzID, ChallengeTLSALPN01, identifier, errServerInternal, "failed to compute key authorization: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), challengeValidationTimeout)
	defer cancel()

	s.logger.Debugf("Validating tls-alpn-01 challenge for %s (%s)", identifier.Value, identifier.Type)

	targetAddr := net.JoinHostPort(identifier.Value, strconv.Itoa(s.challengePort))
	dialFn := s.dialContext
	if dialFn == nil {
		dialFn = s.safeDialContext(identifier)
	}

	rawConn, err := dialFn(ctx, "tcp", targetAddr)
	if err != nil {
		s.failChallenge(chalID, authzID, ChallengeTLSALPN01, identifier, errConnection, "failed to connect to %s: %v", targetAddr, err)
		return
	}
	defer rawConn.Close()

	serverName := identifier.Value
	if identifier.Type == IdentifierIP {
		if rev, err := reverseIPAddr(identifier.Value); err == nil {
			serverName = rev
		}
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{ACMETLS1Protocol},
		ServerName:         serverName,
		InsecureSkipVerify: true, // TLS-ALPN-01 uses a self-signed validation certificate.
	})
	defer tlsConn.Close()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.failChallenge(chalID, authzID, ChallengeTLSALPN01, identifier, errTLS, "TLS handshake failed for %s: %v", identifier.Value, err)
		return
	}

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != ACMETLS1Protocol {
		s.failChallenge(chalID, authzID, ChallengeTLSALPN01, identifier, errTLS, "peer negotiated ALPN protocol %q, expected %q", state.NegotiatedProtocol, ACMETLS1Protocol)
		return
	}
	if len(state.PeerCertificates) == 0 {
		s.failChallenge(chalID, authzID, ChallengeTLSALPN01, identifier, errUnauthorized, "no peer certificate presented")
		return
	}

	cert := state.PeerCertificates[0]
	if err := verifyTLSALPN01Cert(cert, identifier, expectedKeyAuth); err != nil {
		s.failChallenge(chalID, authzID, ChallengeTLSALPN01, identifier, errUnauthorized, "%v", err)
		return
	}

	s.markChallengeValid(chalID, authzID, ChallengeTLSALPN01, identifier)
}

func (s *Server) markChallengeValid(chalID, authzID, chalType string, identifier Identifier) {
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	if err := s.updateState(func(st *serverState) error {
		authz, authzOK := st.Authorizations[authzID]
		ch, chOK := st.Challenges[chalID]
		if !authzOK || !chOK {
			return nil
		}
		acct, acctOK := st.Accounts[authz.AccountID]
		if !acctOK || acct.Status != StatusValid {
			return nil
		}
		if authz.Status != StatusPending || now.After(authz.Expires) || ch.Status != StatusProcessing {
			return nil
		}
		ch.Status = StatusValid
		ch.Validated = nowStr
		ch.Error = nil
		authz.Status = StatusValid
		for _, ac := range authz.Challenges {
			if ac.ID == chalID {
				ac.Status = StatusValid
				ac.Validated = nowStr
				ac.Error = nil
			} else if ac.Status == StatusProcessing {
				ac.Status = StatusPending
				if otherCh, ok := st.Challenges[ac.ID]; ok {
					otherCh.Status = StatusPending
				}
			}
		}
		for _, order := range st.Orders {
			refreshOrderStatus(st, order)
		}
		return nil
	}); err != nil {
		s.logger.Errorf("Failed to save valid %s challenge state for %s: %v", chalType, identifier.Value, err)
		return
	}

	s.logger.Debugf("%s challenge for %s (%s) succeeded", chalType, identifier.Value, identifier.Type)
}

func verifyTLSALPN01Cert(cert *x509.Certificate, identifier Identifier, expectedKeyAuth string) error {
	// The validation certificate must be self-signed and not a CA certificate.
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return fmt.Errorf("validation certificate is not self-signed")
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		return fmt.Errorf("validation certificate must not be a CA certificate")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fmt.Errorf("validation certificate self-signature check failed: %w", err)
	}
	if count, err := countRawSANEntriesFromExtensions(cert.Extensions); err != nil || count != 1 {
		return fmt.Errorf("validation certificate must contain a single SubjectAltName entry")
	}

	// Verify the SAN matches the identifier being validated (RFC 8737 Section 3 & RFC 8738 Section 6).
	switch identifier.Type {
	case IdentifierDNS:
		if len(cert.DNSNames) != 1 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
			return fmt.Errorf("validation certificate must contain a single DNS SAN matching %q", identifier.Value)
		}
		if !strings.EqualFold(cert.DNSNames[0], identifier.Value) {
			return fmt.Errorf("validation certificate DNS SAN %q does not match %q", cert.DNSNames[0], identifier.Value)
		}

	case IdentifierIP:
		if len(cert.IPAddresses) != 1 || len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
			return fmt.Errorf("validation certificate must contain a single IP SAN matching %q", identifier.Value)
		}
		expectedAddr, err := netip.ParseAddr(identifier.Value)
		if err != nil {
			return fmt.Errorf("invalid IP identifier %q: %w", identifier.Value, err)
		}
		expectedUnmapped := expectedAddr.Unmap()
		if expectedUnmapped.Is4() && len(cert.IPAddresses[0]) != net.IPv4len {
			return fmt.Errorf("validation certificate IPv4 SAN must be 4 bytes")
		}
		presentedAddr, ok := netip.AddrFromSlice(cert.IPAddresses[0])
		if !ok || presentedAddr != expectedUnmapped {
			return fmt.Errorf("validation certificate IP SAN %q does not match %q", cert.IPAddresses[0], identifier.Value)
		}
	}

	// Verify the critical id-pe-acmeIdentifier extension (RFC 8737 Section 3:
	// DER-encoded ASN.1 OCTET STRING of 32 bytes: 0x04 0x20 || sha256(keyAuth)).
	expectedDigest := sha256.Sum256([]byte(expectedKeyAuth))
	var found bool
	for _, ext := range cert.Extensions {
		if ext.Id.String() != idPeACMEIdentifierOID {
			continue
		}
		if found {
			return fmt.Errorf("validation certificate contains multiple acmeValidation-v1 extensions")
		}
		found = true
		if !ext.Critical {
			return fmt.Errorf("acmeValidation-v1 extension must be marked critical")
		}
		if len(ext.Value) != 34 || ext.Value[0] != 0x04 || ext.Value[1] != 0x20 {
			return fmt.Errorf("invalid DER encoding for acmeValidation-v1 OCTET STRING")
		}
		var presentedDigest []byte
		rest, err := asn1.Unmarshal(ext.Value, &presentedDigest)
		if err != nil || len(rest) != 0 {
			return fmt.Errorf("failed to parse acmeValidation-v1 ASN.1 OCTET STRING: %v", err)
		}
		if !bytes.Equal(presentedDigest, expectedDigest[:]) {
			return fmt.Errorf("key authorization digest mismatch")
		}
	}
	if !found {
		return fmt.Errorf("acmeValidation-v1 extension (%s) not found in validation certificate", idPeACMEIdentifierOID)
	}
	return nil
}

func countRawSANEntriesFromExtensions(exts []pkix.Extension) (int, error) {
	var sanFound bool
	var count int
	for _, ext := range exts {
		if !ext.Id.Equal(oidExtSubjectAltName) {
			continue
		}
		if sanFound {
			return 0, errors.New("multiple SubjectAltName extensions")
		}
		sanFound = true
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &seq)
		if err != nil || len(rest) != 0 || !seq.IsCompound || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
			return 0, errors.New("invalid SubjectAltName ASN.1 sequence")
		}
		b := seq.Bytes
		for len(b) > 0 {
			var elem asn1.RawValue
			b, err = asn1.Unmarshal(b, &elem)
			if err != nil {
				return 0, err
			}
			count++
		}
	}
	return count, nil
}

func (s *Server) failChallenge(chalID, authzID, chalType string, identifier Identifier, probType, format string, args ...any) {
	prob := newProblem(http.StatusBadRequest, probType, format, args...)
	s.logger.Errorf("%s challenge for %s (%s) failed: %s", chalType, identifier.Value, identifier.Type, prob.Detail)

	if err := s.updateState(func(st *serverState) error {
		authz, authzOK := st.Authorizations[authzID]
		ch, chOK := st.Challenges[chalID]
		if !authzOK || !chOK {
			return nil
		}
		if authz.Status != StatusPending || ch.Status != StatusProcessing {
			return nil
		}
		ch.Status = StatusInvalid
		ch.Error = prob
		authz.Status = StatusInvalid
		for _, ac := range authz.Challenges {
			if ac.ID == chalID {
				ac.Status = StatusInvalid
				ac.Error = prob
			} else if ac.Status == StatusPending || ac.Status == StatusProcessing {
				ac.Status = StatusInvalid
				if otherCh, ok := st.Challenges[ac.ID]; ok {
					otherCh.Status = StatusInvalid
				}
			}
		}
		for _, order := range st.Orders {
			refreshOrderStatus(st, order)
		}
		return nil
	}); err != nil {
		s.logger.Errorf("Failed to save failed %s challenge state for %s: %v", chalType, identifier.Value, err)
	}
}

// reverseIPAddr returns the RFC 1035 / RFC 3596 reverse DNS name (without
// trailing dot) for an IPv4 or IPv6 address, as specified in RFC 8738 Section 6.
func reverseIPAddr(ipStr string) (string, error) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "", err
	}
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), nil
	}
	b := addr.As16()
	const hexDigits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(72)
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hexDigits[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hexDigits[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}
