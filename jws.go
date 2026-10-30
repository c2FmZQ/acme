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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var supportedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

func (s *Server) issueNonce(w http.ResponseWriter) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	nonce := base64.RawURLEncoding.EncodeToString(b)

	now := time.Now().UTC()
	s.nonceMu.Lock()
	for len(s.nonceQueue) > 0 {
		oldest := s.nonceQueue[0]
		t, exists := s.nonces[oldest]
		if !exists {
			s.nonceQueue[0] = ""
			s.nonceQueue = s.nonceQueue[1:]
			continue
		}
		if len(s.nonces) >= maxNoncesInMemory || len(s.nonceQueue) >= maxNoncesInMemory*2 || now.Sub(t) > defaultNonceTTL {
			delete(s.nonces, oldest)
			s.nonceQueue[0] = ""
			s.nonceQueue = s.nonceQueue[1:]
			continue
		}
		break
	}
	if cap(s.nonceQueue) > maxNoncesInMemory*2 && len(s.nonceQueue) <= maxNoncesInMemory {
		compacted := make([]string, len(s.nonceQueue), len(s.nonceQueue)+256)
		copy(compacted, s.nonceQueue)
		s.nonceQueue = compacted
	}
	s.nonces[nonce] = now
	s.nonceQueue = append(s.nonceQueue, nonce)
	s.nonceMu.Unlock()

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	return nonce
}

func (s *Server) consumeNonce(nonce string) bool {
	if nonce == "" {
		return false
	}
	now := time.Now().UTC()
	s.nonceMu.Lock()
	t, ok := s.nonces[nonce]
	if ok {
		delete(s.nonces, nonce)
	}
	s.nonceMu.Unlock()
	return ok && now.Sub(t) <= defaultNonceTTL
}

func (s *Server) writeProblem(w http.ResponseWriter, prob *Problem) {
	if w.Header().Get("Replay-Nonce") == "" {
		s.issueNonce(w)
	}
	status := prob.Status
	if status == 0 {
		status = http.StatusBadRequest
		prob.Status = status
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(prob)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	if w.Header().Get("Replay-Nonce") == "" {
		s.issueNonce(w)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// verifyJWS parses and verifies an ACME JWS request body, consumes the
// Replay-Nonce, and issues a new Replay-Nonce header on the response.
func (s *Server) verifyJWS(w http.ResponseWriter, r *http.Request, allowJWK, allowKID bool) (*jose.JSONWebSignature, *jose.JSONWebKey, *accountRecord, []byte, *Problem) {
	s.issueNonce(w)

	if r.Method != http.MethodPost {
		return nil, nil, nil, nil, newProblem(http.StatusMethodNotAllowed, errMalformed, "method %s not allowed; expected POST", r.Method)
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errMalformed, "failed to read request body: %v", err)
	}

	jws, err := jose.ParseSigned(string(body), supportedSignatureAlgorithms)
	if err != nil {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errMalformed, "failed to parse JWS: %v", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errMalformed, "JWS must have exactly one signature")
	}

	sig := jws.Signatures[0]
	if hasUnprotectedHeaders(sig.Unprotected) {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errMalformed, "JWS must not contain an unprotected header")
	}
	if !s.consumeNonce(sig.Protected.Nonce) {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errBadNonce, "invalid, expired, or missing replay nonce")
	}

	jwsURL, _ := sig.Protected.ExtraHeaders["url"].(string)
	if !s.matchesRequestURL(r, jwsURL) {
		return nil, nil, nil, nil, newProblem(http.StatusUnauthorized, errUnauthorized, "JWS protected header url %q does not match request URL %q", jwsURL, s.requestURL(r))
	}

	hasJWK := sig.Protected.JSONWebKey != nil
	hasKID := sig.Protected.KeyID != ""
	if hasJWK && hasKID {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errMalformed, "JWS protected header must not contain both jwk and kid")
	}
	if !hasJWK && !hasKID {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errMalformed, "JWS protected header must contain either jwk or kid")
	}

	if hasJWK {
		if !allowJWK {
			return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errMalformed, "JWS protected header must use kid, not jwk, for this endpoint")
		}
		jwk := sig.Protected.JSONWebKey
		if !jwk.Valid() || !jwk.IsPublic() {
			return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errBadPublicKey, "invalid JWK in protected header")
		}
		if err := validatePublicKey(jwk.Key); err != nil {
			return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errBadPublicKey, "invalid public key: %v", err)
		}
		payload, err := jws.Verify(jwk)
		if err != nil {
			return nil, nil, nil, nil, newProblem(http.StatusForbidden, errUnauthorized, "JWS signature verification failed: %v", err)
		}
		var acct *accountRecord
		if err := s.readState(func(st *serverState) error {
			acct = cloneAccount(findAccountByJWK(st, jwk))
			return nil
		}); err != nil {
			s.logger.Errorf("readState failed in verifyJWS: %v", err)
			return nil, nil, nil, nil, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error")
		}
		if acct != nil && acct.Status != StatusValid && r.URL.Path != s.pathPrefix+"/acme/revoke-cert" {
			return nil, nil, nil, nil, newProblem(http.StatusForbidden, errUnauthorized, "account status is %q", acct.Status)
		}
		return jws, jwk, acct, payload, nil
	}

	if !allowKID {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errMalformed, "JWS protected header must use jwk, not kid, for this endpoint")
	}

	acctID, ok := s.extractAccountID(r, sig.Protected.KeyID)
	if !ok {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "invalid account kid URL %q", sig.Protected.KeyID)
	}

	var acct *accountRecord
	if err := s.readState(func(st *serverState) error {
		acct = cloneAccount(st.Accounts[acctID])
		return nil
	}); err != nil {
		s.logger.Errorf("readState failed in verifyJWS: %v", err)
		return nil, nil, nil, nil, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error")
	}
	if acct == nil {
		return nil, nil, nil, nil, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found")
	}
	if acct.Status != StatusValid {
		return nil, nil, nil, nil, newProblem(http.StatusForbidden, errUnauthorized, "account status is %q", acct.Status)
	}

	jwk, err := acct.jwk()
	if err != nil {
		s.logger.Errorf("corrupt account key for %s: %v", acct.ID, err)
		return nil, nil, nil, nil, newProblem(http.StatusInternalServerError, errServerInternal, "corrupt account key")
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return nil, nil, nil, nil, newProblem(http.StatusForbidden, errUnauthorized, "JWS signature verification failed: %v", err)
	}
	return jws, jwk, acct, payload, nil
}

func hasUnprotectedHeaders(h jose.Header) bool {
	return h.KeyID != "" || h.JSONWebKey != nil || h.Algorithm != "" || h.Nonce != "" || len(h.ExtraHeaders) > 0
}

func (s *Server) matchesRequestURL(r *http.Request, jwsURL string) bool {
	if jwsURL == "" {
		return false
	}
	expected := s.requestURL(r)
	if jwsURL == expected {
		return true
	}
	u1, err1 := url.Parse(jwsURL)
	u2, err2 := url.Parse(expected)
	if err1 != nil || err2 != nil {
		return false
	}
	if u1.User != nil || u1.RawQuery != "" || u1.Fragment != "" {
		return false
	}
	if !strings.EqualFold(u1.Scheme, u2.Scheme) || u1.Path != u2.Path {
		return false
	}
	return normalizeHTTPSHost(u1.Host) == normalizeHTTPSHost(u2.Host)
}

func normalizeHTTPSHost(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(hostport)
	}
	if port == "443" {
		if strings.Contains(host, ":") {
			return "[" + strings.ToLower(host) + "]"
		}
		return strings.ToLower(host)
	}
	return net.JoinHostPort(strings.ToLower(host), port)
}

func (s *Server) extractAccountID(r *http.Request, kid string) (string, bool) {
	prefix := s.baseURLForRequest(r) + "/acme/acct/"
	if id, ok := strings.CutPrefix(kid, prefix); ok && id != "" && !strings.Contains(id, "/") {
		return id, true
	}
	u1, err1 := url.Parse(kid)
	u2, err2 := url.Parse(s.baseURLForRequest(r))
	if err1 != nil || err2 != nil {
		return "", false
	}
	if u1.User != nil || u1.RawQuery != "" || u1.Fragment != "" {
		return "", false
	}
	if !strings.EqualFold(u1.Scheme, u2.Scheme) || normalizeHTTPSHost(u1.Host) != normalizeHTTPSHost(u2.Host) {
		return "", false
	}
	pathPrefix := strings.TrimRight(u2.Path, "/") + "/acme/acct/"
	if id, ok := strings.CutPrefix(u1.Path, pathPrefix); ok && id != "" && !strings.Contains(id, "/") {
		return id, true
	}
	return "", false
}

func jwkThumbprint(key *jose.JSONWebKey) (string, error) {
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func keyAuthorization(token string, key *jose.JSONWebKey) (string, error) {
	tp, err := jwkThumbprint(key)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, tp), nil
}

func findAccountByJWK(st *serverState, key *jose.JSONWebKey) *accountRecord {
	tp, err := jwkThumbprint(key)
	if err != nil {
		return nil
	}
	if st.accountsByThumbprint != nil {
		return st.accountsByThumbprint[tp]
	}
	for _, acct := range st.Accounts {
		if acct.Thumbprint == tp {
			return acct
		}
	}
	return nil
}

func validatePublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N == nil || k.N.BitLen() < 2048 || k.N.BitLen() > 8192 {
			return fmt.Errorf("RSA key size must be between 2048 and 8192 bits")
		}
		if k.E < 3 || k.E > 1<<31-1 || k.E%2 == 0 {
			return fmt.Errorf("invalid RSA public exponent")
		}
		return nil
	case *ecdsa.PublicKey:
		if k.Curve == nil || k.Curve.Params().BitSize < 256 {
			return fmt.Errorf("ECDSA curve size must be at least 256 bits")
		}
		if k.X == nil || k.Y == nil || !k.Curve.IsOnCurve(k.X, k.Y) {
			return fmt.Errorf("ECDSA public key point is not on curve")
		}
		return nil
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid Ed25519 public key size")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}
