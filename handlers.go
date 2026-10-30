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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
)

func generateToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) accountURL(r *http.Request, id string) string {
	return fmt.Sprintf("%s/acme/acct/%s", s.baseURLForRequest(r), id)
}

func (s *Server) accountOrdersURL(r *http.Request, id string) string {
	return fmt.Sprintf("%s/acme/acct/%s/orders", s.baseURLForRequest(r), id)
}

func (s *Server) orderURL(r *http.Request, id string) string {
	return fmt.Sprintf("%s/acme/order/%s", s.baseURLForRequest(r), id)
}

func (s *Server) finalizeURL(r *http.Request, id string) string {
	return fmt.Sprintf("%s/acme/finalize/%s", s.baseURLForRequest(r), id)
}

func (s *Server) authzURL(r *http.Request, id string) string {
	return fmt.Sprintf("%s/acme/authz/%s", s.baseURLForRequest(r), id)
}

func (s *Server) challengeURL(r *http.Request, id string) string {
	return fmt.Sprintf("%s/acme/challenge/%s", s.baseURLForRequest(r), id)
}

func (s *Server) certURL(r *http.Request, id string) string {
	return fmt.Sprintf("%s/acme/cert/%s", s.baseURLForRequest(r), id)
}

func (s *Server) toWireAccount(r *http.Request, a *accountRecord) wireAccount {
	return wireAccount{
		Status:  a.Status,
		Contact: a.Contact,
		Orders:  s.accountOrdersURL(r, a.ID),
	}
}

func (s *Server) toWireOrder(r *http.Request, o *orderRecord) wireOrder {
	authzURLs := make([]string, 0, len(o.AuthzIDs))
	for _, id := range o.AuthzIDs {
		authzURLs = append(authzURLs, s.authzURL(r, id))
	}
	wo := wireOrder{
		Status:         o.Status,
		Expires:        o.Expires.UTC().Format(time.RFC3339),
		Identifiers:    o.Identifiers,
		NotBefore:      o.NotBefore,
		NotAfter:       o.NotAfter,
		Error:          o.Error,
		Authorizations: authzURLs,
		Finalize:       s.finalizeURL(r, o.ID),
	}
	if o.CertID != "" {
		wo.Certificate = s.certURL(r, o.CertID)
	}
	return wo
}

func (s *Server) toWireAuthorization(r *http.Request, a *authzRecord) wireAuthorization {
	chals := make([]wireChallenge, 0, len(a.Challenges))
	for _, c := range a.Challenges {
		chals = append(chals, s.toWireChallenge(r, c))
	}
	return wireAuthorization{
		Identifier: a.Identifier,
		Status:     a.Status,
		Expires:    a.Expires.UTC().Format(time.RFC3339),
		Challenges: chals,
		Wildcard:   a.Wildcard,
	}
}

func (s *Server) toWireChallenge(r *http.Request, c *challengeRecord) wireChallenge {
	return wireChallenge{
		Type:      c.Type,
		URL:       s.challengeURL(r, c.ID),
		Status:    c.Status,
		Token:     c.Token,
		Validated: c.Validated,
		Error:     c.Error,
	}
}

func refreshOrderStatus(st *serverState, order *orderRecord) {
	if order.Status != StatusPending && order.Status != StatusReady {
		return
	}
	now := time.Now().UTC()
	if !order.Expires.IsZero() && now.After(order.Expires) {
		order.Status = StatusInvalid
		return
	}
	allValid := true
	for _, authzID := range order.AuthzIDs {
		authz, ok := st.Authorizations[authzID]
		if !ok {
			order.Status = StatusInvalid
			return
		}
		if !authz.Expires.IsZero() && now.After(authz.Expires) && (authz.Status == StatusPending || authz.Status == StatusValid) {
			authz.Status = StatusExpired
		}
		switch authz.Status {
		case StatusValid:
		case StatusInvalid, StatusDeactivated, StatusExpired, StatusRevoked:
			order.Status = StatusInvalid
			return
		default:
			allValid = false
		}
	}
	if allValid && len(order.AuthzIDs) > 0 {
		order.Status = StatusReady
	} else if !allValid && order.Status == StatusReady {
		order.Status = StatusPending
	}
}

func requireActiveAccount(st *serverState, acctID string) (*accountRecord, *Problem) {
	a, ok := st.Accounts[acctID]
	if !ok {
		return nil, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found")
	}
	if a.Status != StatusValid {
		return nil, newProblem(http.StatusForbidden, errUnauthorized, "account status is %q", a.Status)
	}
	return a, nil
}

func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeProblem(w, newProblem(http.StatusMethodNotAllowed, errMalformed, "method %s not allowed", r.Method))
		return
	}
	var out bytes.Buffer
	seen := make(map[string]bool)
	for _, sg := range s.signers {
		for _, cert := range sg.Certificates() {
			if cert == nil || seen[string(cert.Raw)] {
				continue
			}
			seen[string(cert.Raw)] = true
			_ = pem.Encode(&out, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
		}
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(out.Bytes())
	}
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeProblem(w, newProblem(http.StatusMethodNotAllowed, errMalformed, "method %s not allowed", r.Method))
		return
	}
	base := s.baseURLForRequest(r)
	dir := wireDirectory{
		NewNonce:   base + "/acme/new-nonce",
		NewAccount: base + "/acme/new-account",
		NewOrder:   base + "/acme/new-order",
		NewAuthz:   base + "/acme/new-authz",
		RevokeCert: base + "/acme/revoke-cert",
		KeyChange:  base + "/acme/key-change",
	}
	if s.termsOfServiceURL != "" {
		dir.Meta = &wireDirectoryMeta{
			TermsOfService: s.termsOfServiceURL,
		}
	}
	s.writeJSON(w, http.StatusOK, dir)
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	s.issueNonce(w)
	switch r.Method {
	case http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		w.WriteHeader(http.StatusNoContent)
	default:
		s.writeProblem(w, newProblem(http.StatusMethodNotAllowed, errMalformed, "method %s not allowed", r.Method))
	}
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	_, jwk, _, payload, prob := s.verifyJWS(w, r, true, false)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	var req struct {
		Contact              []string `json:"contact"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &req); err != nil {
			s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid JSON payload: %v", err))
			return
		}
	}
	if p := validateContacts(req.Contact); p != nil {
		s.writeProblem(w, p)
		return
	}

	tp, err := jwkThumbprint(jwk)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadPublicKey, "failed to compute JWK thumbprint: %v", err))
		return
	}
	keyJSON, err := json.Marshal(&jose.JSONWebKey{Key: jwk.Key})
	if err != nil {
		s.logger.Errorf("failed to marshal JWK in handleNewAccount: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "failed to marshal account key"))
		return
	}

	var acct *accountRecord
	var status int
	err = s.updateState(func(st *serverState) error {
		existing := findAccountByJWK(st, jwk)
		if existing != nil {
			if existing.Status != StatusValid {
				prob = newProblem(http.StatusForbidden, errUnauthorized, "account is %s", existing.Status)
				return nil
			}
			acct = cloneAccount(existing)
			status = http.StatusOK
			return nil
		}

		if req.OnlyReturnExisting {
			prob = newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account does not exist")
			return nil
		}
		if s.requireTOSAgreed && !req.TermsOfServiceAgreed {
			prob = &Problem{
				Type:     errUserActionRequired,
				Detail:   "terms of service must be agreed to",
				Status:   http.StatusBadRequest,
				Instance: s.termsOfServiceURL,
			}
			return nil
		}

		now := time.Now().UTC()
		cutoff := now.Add(-time.Minute)
		for len(s.newAcctWindow) > 0 && s.newAcctWindow[0].Before(cutoff) {
			s.newAcctWindow = s.newAcctWindow[1:]
		}
		if len(s.newAcctWindow) >= maxNewAccountsPerMinute {
			w.Header().Set("Retry-After", "60")
			prob = newProblem(http.StatusTooManyRequests, errRateLimited, "too many new account registrations; try again later")
			return nil
		}
		if len(st.Accounts) >= maxTotalAccounts {
			w.Header().Set("Retry-After", "60")
			prob = newProblem(http.StatusTooManyRequests, errRateLimited, "maximum number of accounts reached")
			return nil
		}
		s.newAcctWindow = append(s.newAcctWindow, now)

		newAcct := &accountRecord{
			ID:         uuid.NewString(),
			KeyJSON:    keyJSON,
			Thumbprint: tp,
			Status:     StatusValid,
			Contact:    req.Contact,
			CreatedAt:  now,
		}
		st.Accounts[newAcct.ID] = newAcct
		st.accountsByThumbprint[tp] = newAcct
		acct = cloneAccount(newAcct)
		status = http.StatusCreated
		return nil
	})
	if err != nil {
		s.logger.Errorf("updateState failed in handleNewAccount: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	w.Header().Set("Location", s.accountURL(r, acct.ID))
	s.writeJSON(w, status, s.toWireAccount(r, acct))
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, s.pathPrefix+"/acme/acct/")
	if acctID, isOrders := strings.CutSuffix(path, "/orders"); isOrders {
		if acctID == "" || strings.Contains(acctID, "/") {
			s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "account not found"))
			return
		}
		s.handleAccountOrders(w, r, acctID)
		return
	}
	acctID := path
	if acctID == "" || strings.Contains(acctID, "/") {
		s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "account not found"))
		return
	}

	_, _, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct.ID != acctID {
		s.writeProblem(w, newProblem(http.StatusForbidden, errUnauthorized, "account mismatch"))
		return
	}

	// POST-as-GET
	if len(payload) == 0 {
		w.Header().Set("Location", s.accountURL(r, acct.ID))
		s.writeJSON(w, http.StatusOK, s.toWireAccount(r, acct))
		return
	}

	var req struct {
		Status  string    `json:"status"`
		Contact *[]string `json:"contact"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid JSON payload: %v", err))
		return
	}
	if req.Status != "" && req.Status != StatusValid && req.Status != StatusDeactivated {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "unsupported account status %q", req.Status))
		return
	}
	if req.Contact != nil {
		if p := validateContacts(*req.Contact); p != nil {
			s.writeProblem(w, p)
			return
		}
	}

	var updated *accountRecord
	if err := s.updateState(func(st *serverState) error {
		a, p := requireActiveAccount(st, acct.ID)
		if p != nil {
			prob = p
			return nil
		}
		if req.Contact != nil {
			a.Contact = *req.Contact
		}
		if req.Status == StatusDeactivated {
			a.Status = StatusDeactivated
			for _, authz := range st.Authorizations {
				if authz.AccountID == a.ID && (authz.Status == StatusPending || authz.Status == StatusValid) {
					authz.Status = StatusDeactivated
					for _, ch := range authz.Challenges {
						if ch.Status == StatusPending || ch.Status == StatusProcessing {
							ch.Status = StatusInvalid
						}
						if storedCh, ok := st.Challenges[ch.ID]; ok && (storedCh.Status == StatusPending || storedCh.Status == StatusProcessing) {
							storedCh.Status = StatusInvalid
						}
					}
				}
			}
			for _, order := range st.Orders {
				if order.AccountID == a.ID && (order.Status == StatusPending || order.Status == StatusReady) {
					order.Status = StatusInvalid
				}
			}
		}
		updated = cloneAccount(a)
		return nil
	}); err != nil {
		s.logger.Errorf("updateState failed in handleAccount: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	w.Header().Set("Location", s.accountURL(r, updated.ID))
	s.writeJSON(w, http.StatusOK, s.toWireAccount(r, updated))
}

func validateContacts(contacts []string) *Problem {
	if len(contacts) > maxContactsPerAccount {
		return newProblem(http.StatusBadRequest, errInvalidContact, "too many contacts (max %d)", maxContactsPerAccount)
	}
	for _, c := range contacts {
		if len(c) == 0 || len(c) > maxContactLength {
			return newProblem(http.StatusBadRequest, errInvalidContact, "invalid contact length")
		}
		if !strings.HasPrefix(strings.ToLower(c), "mailto:") {
			return newProblem(http.StatusBadRequest, errUnsupportedContact, "unsupported contact scheme; only mailto: is supported")
		}
		email := c[len("mailto:"):]
		if email == "" || strings.ContainsAny(email, "?# \t\r\n") {
			return newProblem(http.StatusBadRequest, errInvalidContact, "invalid mailto contact URI")
		}
		addr, err := mail.ParseAddress(email)
		if err != nil || addr.Name != "" || addr.Address != email {
			return newProblem(http.StatusBadRequest, errInvalidContact, "invalid email address in contact URI")
		}
	}
	return nil
}

func (s *Server) handleAccountOrders(w http.ResponseWriter, r *http.Request, acctID string) {
	_, _, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct.ID != acctID {
		s.writeProblem(w, newProblem(http.StatusForbidden, errUnauthorized, "account mismatch"))
		return
	}
	if len(payload) > 0 {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "POST-as-GET request must have an empty payload"))
		return
	}

	var urls []string
	if err := s.readState(func(st *serverState) error {
		if _, p := requireActiveAccount(st, acct.ID); p != nil {
			prob = p
			return nil
		}
		for _, o := range st.Orders {
			if o.AccountID == acctID {
				urls = append(urls, s.orderURL(r, o.ID))
			}
		}
		return nil
	}); err != nil {
		s.logger.Errorf("readState failed in handleAccountOrders: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if urls == nil {
		urls = []string{}
	}
	s.writeJSON(w, http.StatusOK, wireOrdersList{Orders: urls})
}

func (s *Server) handleKeyChange(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	_, _, acct, outerPayload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	innerJWS, err := jose.ParseSigned(string(outerPayload), supportedSignatureAlgorithms)
	if err != nil || len(innerJWS.Signatures) != 1 {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid inner JWS in key-change request"))
		return
	}

	innerSig := innerJWS.Signatures[0]
	if hasUnprotectedHeaders(innerSig.Unprotected) {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "inner JWS must not contain an unprotected header"))
		return
	}
	if innerSig.Protected.Nonce != "" {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "inner JWS must not contain a nonce"))
		return
	}
	if innerSig.Protected.KeyID != "" || innerSig.Protected.JSONWebKey == nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "inner JWS must contain jwk and not kid"))
		return
	}
	innerURL, _ := innerSig.Protected.ExtraHeaders["url"].(string)
	if !s.matchesRequestURL(r, innerURL) {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "inner JWS url does not match key-change URL"))
		return
	}

	newJWK := innerSig.Protected.JSONWebKey
	if !newJWK.Valid() || !newJWK.IsPublic() {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadPublicKey, "invalid new JWK"))
		return
	}
	if err := validatePublicKey(newJWK.Key); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadPublicKey, "invalid new public key: %v", err))
		return
	}

	innerPayload, err := innerJWS.Verify(newJWK)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusForbidden, errUnauthorized, "inner JWS signature verification failed: %v", err))
		return
	}

	var keyChangeReq struct {
		Account string           `json:"account"`
		OldKey  *jose.JSONWebKey `json:"oldKey"`
	}
	if err := json.Unmarshal(innerPayload, &keyChangeReq); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid inner JWS payload: %v", err))
		return
	}

	innerAcctID, ok := s.extractAccountID(r, keyChangeReq.Account)
	if !ok || innerAcctID != acct.ID {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "inner account URL %q does not match outer account", keyChangeReq.Account))
		return
	}
	if keyChangeReq.OldKey == nil || !keyChangeReq.OldKey.Valid() || !keyChangeReq.OldKey.IsPublic() {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "missing or invalid oldKey in key-change payload"))
		return
	}
	if err := validatePublicKey(keyChangeReq.OldKey.Key); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadPublicKey, "invalid oldKey in key-change payload: %v", err))
		return
	}
	oldTP, err := jwkThumbprint(keyChangeReq.OldKey)
	if err != nil || oldTP != acct.Thumbprint {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "oldKey does not match current account key"))
		return
	}

	newTP, err := jwkThumbprint(newJWK)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadPublicKey, "failed to compute thumbprint of new key: %v", err))
		return
	}
	newKeyJSON, err := json.Marshal(&jose.JSONWebKey{Key: newJWK.Key})
	if err != nil {
		s.logger.Errorf("failed to marshal new JWK in handleKeyChange: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "failed to marshal new account key"))
		return
	}

	var updated *accountRecord
	if err := s.updateState(func(st *serverState) error {
		a, p := requireActiveAccount(st, acct.ID)
		if p != nil {
			prob = p
			return nil
		}
		if a.Thumbprint != oldTP {
			prob = newProblem(http.StatusBadRequest, errMalformed, "oldKey does not match current account key")
			return nil
		}
		if existing := findAccountByJWK(st, newJWK); existing != nil && existing.ID != acct.ID {
			w.Header().Set("Location", s.accountURL(r, existing.ID))
			prob = newProblem(http.StatusConflict, errMalformed, "new key is already associated with an existing account")
			return nil
		}
		delete(st.accountsByThumbprint, a.Thumbprint)
		a.KeyJSON = newKeyJSON
		a.Thumbprint = newTP
		st.accountsByThumbprint[newTP] = a
		updated = cloneAccount(a)
		return nil
	}); err != nil {
		s.logger.Errorf("updateState failed in handleKeyChange: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	w.Header().Set("Location", s.accountURL(r, updated.ID))
	s.writeJSON(w, http.StatusOK, s.toWireAccount(r, updated))
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	_, _, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct == nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found"))
		return
	}

	var req struct {
		Identifiers []Identifier `json:"identifiers"`
		NotBefore   string       `json:"notBefore,omitempty"`
		NotAfter    string       `json:"notAfter,omitempty"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid JSON payload: %v", err))
		return
	}
	if len(req.Identifiers) == 0 {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "order must contain at least one identifier"))
		return
	}
	if len(req.Identifiers) > maxIdentifiersPerOrder {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "order exceeds maximum of %d identifiers", maxIdentifiersPerOrder))
		return
	}
	if req.NotBefore != "" || req.NotAfter != "" {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "custom notBefore and notAfter are not supported"))
		return
	}

	seen := make(map[Identifier]bool, len(req.Identifiers))
	normalized := make([]Identifier, 0, len(req.Identifiers))
	for _, rawID := range req.Identifiers {
		normID, p := normalizeAndValidateIdentifier(rawID)
		if p != nil {
			s.writeProblem(w, p)
			return
		}
		if s.identifierPolicy != nil {
			if err := s.identifierPolicy(r.Context(), normID); err != nil {
				s.writeProblem(w, newProblem(http.StatusForbidden, errRejectedIdentifier, "identifier %s (%s) rejected by policy: %v", normID.Value, normID.Type, err))
				return
			}
		} else if normID.Type == IdentifierIP && s.dialContext == nil {
			if addr, err := netip.ParseAddr(normID.Value); err == nil && addr.Unmap().IsLoopback() {
				s.writeProblem(w, newProblem(http.StatusForbidden, errRejectedIdentifier, "loopback IP identifier %q requires an explicit IdentifierPolicy", normID.Value))
				return
			}
		}
		if !seen[normID] {
			seen[normID] = true
			normalized = append(normalized, normID)
		}
	}

	now := time.Now().UTC()
	var order *orderRecord
	if err := s.updateState(func(st *serverState) error {
		if _, p := requireActiveAccount(st, acct.ID); p != nil {
			prob = p
			return nil
		}
		pendingOrders := 0
		for _, o := range st.Orders {
			if o.AccountID == acct.ID && (o.Status == StatusPending || o.Status == StatusReady) && now.Before(o.Expires) {
				pendingOrders++
			}
		}
		if pendingOrders >= maxPendingOrdersPerAccount {
			w.Header().Set("Retry-After", "60")
			prob = newProblem(http.StatusTooManyRequests, errRateLimited, "too many pending orders for account")
			return nil
		}
		newAuthzNeeded := 0
		for _, id := range normalized {
			if findValidAuthorization(st, acct.ID, id, now) == nil {
				newAuthzNeeded++
			}
		}
		if newAuthzNeeded > 0 {
			pendingAuthz := 0
			for _, a := range st.Authorizations {
				if a.AccountID == acct.ID && a.Status == StatusPending && now.Before(a.Expires) {
					pendingAuthz++
				}
			}
			if pendingAuthz+newAuthzNeeded > maxPendingAuthzPerAccount {
				w.Header().Set("Retry-After", "60")
				prob = newProblem(http.StatusTooManyRequests, errRateLimited, "too many pending authorizations for account")
				return nil
			}
		}
		orderID := uuid.NewString()
		newOrder := &orderRecord{
			ID:          orderID,
			AccountID:   acct.ID,
			Status:      StatusPending,
			Expires:     now.Add(defaultOrderTTL),
			NotBefore:   req.NotBefore,
			NotAfter:    req.NotAfter,
			Identifiers: normalized,
			AuthzIDs:    make([]string, 0, len(normalized)),
		}
		for _, id := range normalized {
			authz := findValidAuthorization(st, acct.ID, id, now)
			if authz == nil {
				authz = s.newAuthorization(st, acct.ID, id, now)
			}
			newOrder.AuthzIDs = append(newOrder.AuthzIDs, authz.ID)
		}
		refreshOrderStatus(st, newOrder)
		st.Orders[orderID] = newOrder
		order = cloneOrder(newOrder)
		return nil
	}); err != nil {
		s.logger.Errorf("updateState failed in handleNewOrder: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	w.Header().Set("Location", s.orderURL(r, order.ID))
	s.writeJSON(w, http.StatusCreated, s.toWireOrder(r, order))
}

func findValidAuthorization(st *serverState, acctID string, id Identifier, now time.Time) *authzRecord {
	for _, a := range st.Authorizations {
		if a != nil && a.AccountID == acctID && a.Identifier == id && !a.Wildcard && a.Status == StatusValid && now.Before(a.Expires) {
			return a
		}
	}
	return nil
}

func (s *Server) newAuthorization(st *serverState, acctID string, id Identifier, now time.Time) *authzRecord {
	authzID := uuid.NewString()
	chals := make([]*challengeRecord, 0, len(s.challengeTypes))
	for _, ct := range s.challengeTypes {
		chalID := uuid.NewString()
		chal := &challengeRecord{
			ID:      chalID,
			AuthzID: authzID,
			Type:    ct,
			Status:  StatusPending,
			Token:   generateToken(),
		}
		st.Challenges[chalID] = chal
		chals = append(chals, chal)
	}
	authz := &authzRecord{
		ID:         authzID,
		AccountID:  acctID,
		Identifier: id,
		Status:     StatusPending,
		Expires:    now.Add(defaultAuthzTTL),
		Challenges: chals,
		Wildcard:   false,
	}
	st.Authorizations[authzID] = authz
	return authz
}

func (s *Server) handleNewAuthz(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	_, _, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct == nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found"))
		return
	}

	var req struct {
		Identifier Identifier `json:"identifier"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid JSON payload: %v", err))
		return
	}

	normID, p := normalizeAndValidateIdentifier(req.Identifier)
	if p != nil {
		s.writeProblem(w, p)
		return
	}
	if s.identifierPolicy != nil {
		if err := s.identifierPolicy(r.Context(), normID); err != nil {
			s.writeProblem(w, newProblem(http.StatusForbidden, errRejectedIdentifier, "identifier %s (%s) rejected by policy: %v", normID.Value, normID.Type, err))
			return
		}
	} else if normID.Type == IdentifierIP && s.dialContext == nil {
		if addr, err := netip.ParseAddr(normID.Value); err == nil && addr.Unmap().IsLoopback() {
			s.writeProblem(w, newProblem(http.StatusForbidden, errRejectedIdentifier, "loopback IP identifier %q requires an explicit IdentifierPolicy", normID.Value))
			return
		}
	}

	now := time.Now().UTC()
	var authz *authzRecord
	if err := s.updateState(func(st *serverState) error {
		if _, p := requireActiveAccount(st, acct.ID); p != nil {
			prob = p
			return nil
		}
		pendingAuthz := 0
		for _, a := range st.Authorizations {
			if a.AccountID == acct.ID && a.Status == StatusPending && now.Before(a.Expires) {
				pendingAuthz++
			}
		}
		if pendingAuthz >= maxPendingAuthzPerAccount {
			w.Header().Set("Retry-After", "60")
			prob = newProblem(http.StatusTooManyRequests, errRateLimited, "too many pending authorizations for account")
			return nil
		}
		authz = cloneAuthz(s.newAuthorization(st, acct.ID, normID, now))
		return nil
	}); err != nil {
		s.logger.Errorf("updateState failed in handleNewAuthz: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	w.Header().Set("Location", s.authzURL(r, authz.ID))
	s.writeJSON(w, http.StatusCreated, s.toWireAuthorization(r, authz))
}

func (s *Server) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	authzID := strings.TrimPrefix(r.URL.Path, s.pathPrefix+"/acme/authz/")
	if authzID == "" || strings.Contains(authzID, "/") {
		s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "authorization not found"))
		return
	}

	_, _, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct == nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found"))
		return
	}

	if len(payload) > 0 {
		var req struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid JSON payload: %v", err))
			return
		}
		if req.Status != StatusDeactivated {
			s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "unsupported authorization status %q", req.Status))
			return
		}
		var authz *authzRecord
		if err := s.updateState(func(st *serverState) error {
			if _, p := requireActiveAccount(st, acct.ID); p != nil {
				prob = p
				return nil
			}
			a, ok := st.Authorizations[authzID]
			if !ok {
				prob = newProblem(http.StatusNotFound, errMalformed, "authorization not found")
				return nil
			}
			if a.AccountID != acct.ID {
				prob = newProblem(http.StatusForbidden, errUnauthorized, "authorization does not belong to account")
				return nil
			}
			if a.Status != StatusPending && a.Status != StatusValid && a.Status != StatusDeactivated {
				prob = newProblem(http.StatusBadRequest, errMalformed, "cannot deactivate authorization in status %q", a.Status)
				return nil
			}
			a.Status = StatusDeactivated
			for _, ch := range a.Challenges {
				if ch.Status == StatusPending || ch.Status == StatusProcessing {
					ch.Status = StatusInvalid
				}
				if storedCh, ok := st.Challenges[ch.ID]; ok && (storedCh.Status == StatusPending || storedCh.Status == StatusProcessing) {
					storedCh.Status = StatusInvalid
				}
			}
			for _, order := range st.Orders {
				refreshOrderStatus(st, order)
			}
			authz = cloneAuthz(a)
			return nil
		}); err != nil {
			s.logger.Errorf("updateState failed in handleAuthorization: %v", err)
			s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
			return
		}
		if prob != nil {
			s.writeProblem(w, prob)
			return
		}
		s.writeJSON(w, http.StatusOK, s.toWireAuthorization(r, authz))
		return
	}

	var authz *authzRecord
	if err := s.readState(func(st *serverState) error {
		if _, p := requireActiveAccount(st, acct.ID); p != nil {
			prob = p
			return nil
		}
		authz = cloneAuthz(st.Authorizations[authzID])
		return nil
	}); err != nil {
		s.logger.Errorf("readState failed in handleAuthorization: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if authz == nil {
		s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "authorization not found"))
		return
	}
	if authz.AccountID != acct.ID {
		s.writeProblem(w, newProblem(http.StatusForbidden, errUnauthorized, "authorization does not belong to account"))
		return
	}

	s.writeJSON(w, http.StatusOK, s.toWireAuthorization(r, authz))
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	chalID := strings.TrimPrefix(r.URL.Path, s.pathPrefix+"/acme/challenge/")
	if chalID == "" || strings.Contains(chalID, "/") {
		s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "challenge not found"))
		return
	}

	_, jwk, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct == nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found"))
		return
	}

	if len(payload) > 0 {
		var req map[string]any
		if err := json.Unmarshal(payload, &req); err != nil || req == nil {
			s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid JSON payload in challenge response"))
			return
		}
	}

	var chalCopy *challengeRecord
	var authzID string
	var identifier Identifier
	var startValidation bool

	if len(payload) == 0 {
		if err := s.readState(func(st *serverState) error {
			if _, p := requireActiveAccount(st, acct.ID); p != nil {
				prob = p
				return nil
			}
			chal, ok := st.Challenges[chalID]
			if !ok {
				prob = newProblem(http.StatusNotFound, errMalformed, "challenge not found")
				return nil
			}
			authz, ok := st.Authorizations[chal.AuthzID]
			if !ok {
				prob = newProblem(http.StatusInternalServerError, errServerInternal, "parent authorization not found")
				return nil
			}
			if authz.AccountID != acct.ID {
				prob = newProblem(http.StatusForbidden, errUnauthorized, "challenge does not belong to account")
				return nil
			}
			authzID = authz.ID
			chalCopy = cloneChallenge(chal)
			return nil
		}); err != nil {
			s.logger.Errorf("readState failed in handleChallenge: %v", err)
			s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
			return
		}
		if prob != nil {
			s.writeProblem(w, prob)
			return
		}
		w.Header().Add("Link", fmt.Sprintf("<%s>;rel=\"up\"", s.authzURL(r, authzID)))
		s.writeJSON(w, http.StatusOK, s.toWireChallenge(r, chalCopy))
		return
	}

	if err := s.updateState(func(st *serverState) error {
		if _, p := requireActiveAccount(st, acct.ID); p != nil {
			prob = p
			return nil
		}
		chal, ok := st.Challenges[chalID]
		if !ok {
			prob = newProblem(http.StatusNotFound, errMalformed, "challenge not found")
			return nil
		}
		authz, ok := st.Authorizations[chal.AuthzID]
		if !ok {
			prob = newProblem(http.StatusInternalServerError, errServerInternal, "parent authorization not found")
			return nil
		}
		if authz.AccountID != acct.ID {
			prob = newProblem(http.StatusForbidden, errUnauthorized, "challenge does not belong to account")
			return nil
		}
		authzID = authz.ID
		identifier = authz.Identifier

		if authz.Status != StatusPending && authz.Status != StatusValid {
			prob = newProblem(http.StatusBadRequest, errMalformed, "cannot respond to challenge in %q authorization", authz.Status)
			return nil
		}
		if chal.Status == StatusInvalid {
			prob = newProblem(http.StatusBadRequest, errMalformed, "challenge is already in invalid state")
			return nil
		}
		alreadyProcessing := false
		for _, ac := range authz.Challenges {
			if ac.Status == StatusProcessing {
				alreadyProcessing = true
				break
			}
		}
		if authz.Status == StatusPending && chal.Status == StatusPending && !alreadyProcessing {
			chal.Status = StatusProcessing
			for _, ac := range authz.Challenges {
				if ac.ID == chal.ID {
					ac.Status = StatusProcessing
				}
			}
			startValidation = true
		}
		chalCopy = cloneChallenge(chal)
		return nil
	}); err != nil {
		s.logger.Errorf("updateState failed in handleChallenge: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	if startValidation {
		go s.validateChallenge(chalCopy.ID, authzID, chalCopy.Type, chalCopy.Token, identifier, jwk)
	}

	w.Header().Add("Link", fmt.Sprintf("<%s>;rel=\"up\"", s.authzURL(r, authzID)))
	s.writeJSON(w, http.StatusOK, s.toWireChallenge(r, chalCopy))
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	orderID := strings.TrimPrefix(r.URL.Path, s.pathPrefix+"/acme/order/")
	if orderID == "" || strings.Contains(orderID, "/") {
		s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "order not found"))
		return
	}

	_, _, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct == nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found"))
		return
	}
	if len(payload) > 0 {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "POST-as-GET request must have an empty payload"))
		return
	}

	var orderCopy *orderRecord
	if err := s.readState(func(st *serverState) error {
		if _, p := requireActiveAccount(st, acct.ID); p != nil {
			prob = p
			return nil
		}
		order, ok := st.Orders[orderID]
		if !ok {
			prob = newProblem(http.StatusNotFound, errMalformed, "order not found")
			return nil
		}
		if order.AccountID != acct.ID {
			prob = newProblem(http.StatusForbidden, errUnauthorized, "order does not belong to account")
			return nil
		}
		refreshOrderStatus(st, order)
		orderCopy = cloneOrder(order)
		return nil
	}); err != nil {
		s.logger.Errorf("readState failed in handleOrder: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	w.Header().Set("Location", s.orderURL(r, orderCopy.ID))
	s.writeJSON(w, http.StatusOK, s.toWireOrder(r, orderCopy))
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	orderID := strings.TrimPrefix(r.URL.Path, s.pathPrefix+"/acme/finalize/")
	if orderID == "" || strings.Contains(orderID, "/") {
		s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "order not found"))
		return
	}

	_, acctJWK, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct == nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found"))
		return
	}

	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid JSON payload: %v", err))
		return
	}
	csrBytes, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadCSR, "invalid base64url CSR: %v", err))
		return
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadCSR, "failed to parse CSR: %v", err))
		return
	}
	if err := csr.CheckSignature(); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadCSR, "CSR signature check failed: %v", err))
		return
	}
	if err := validatePublicKey(csr.PublicKey); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadCSR, "invalid public key in CSR: %v", err))
		return
	}
	if acctJWK != nil && publicKeysEqual(csr.PublicKey, acctJWK.Key) {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errBadCSR, "CSR public key must not be the same as the account key"))
		return
	}

	var orderCopy *orderRecord
	err = s.updateState(func(st *serverState) error {
		activeAcct, p := requireActiveAccount(st, acct.ID)
		if p != nil {
			prob = p
			return nil
		}
		if curJWK, err := activeAcct.jwk(); err == nil && publicKeysEqual(csr.PublicKey, curJWK.Key) {
			prob = newProblem(http.StatusBadRequest, errBadCSR, "CSR public key must not be the same as the account key")
			return nil
		}
		order, ok := st.Orders[orderID]
		if !ok {
			prob = newProblem(http.StatusNotFound, errMalformed, "order not found")
			return nil
		}
		if order.AccountID != acct.ID {
			prob = newProblem(http.StatusForbidden, errUnauthorized, "order does not belong to account")
			return nil
		}
		refreshOrderStatus(st, order)
		if order.Status == StatusValid {
			orderCopy = cloneOrder(order)
			return nil
		}
		if order.Status != StatusReady {
			prob = newProblem(http.StatusForbidden, errOrderNotReady, "order is in status %q, expected %q", order.Status, StatusReady)
			return nil
		}
		if s.identifierPolicy != nil {
			for _, id := range order.Identifiers {
				if err := s.identifierPolicy(r.Context(), id); err != nil {
					prob = newProblem(http.StatusForbidden, errRejectedIdentifier, "identifier %s (%s) rejected by policy: %v", id.Value, id.Type, err)
					return nil
				}
			}
		}

		dnsNames, ipAddrs, p := matchCSRAndOrderIdentifiers(csr, order.Identifiers)
		if p != nil {
			prob = p
			return nil
		}

		tmpl, err := s.buildCertificateTemplate(csr, dnsNames, ipAddrs)
		if err != nil {
			s.logger.Errorf("buildCertificateTemplate failed in handleFinalize: %v", err)
			prob = newProblem(http.StatusInternalServerError, errServerInternal, "failed to build certificate template")
			return nil
		}

		signer := s.selectSigner(csr.PublicKey)
		leaf, err := signer.Sign(tmpl)
		if err != nil {
			s.logger.Errorf("signer.Sign failed in handleFinalize: %v", err)
			prob = newProblem(http.StatusInternalServerError, errServerInternal, "failed to sign certificate")
			return nil
		}

		var chainBuf bytes.Buffer
		if err := pem.Encode(&chainBuf, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}); err != nil {
			s.logger.Errorf("pem.Encode leaf failed in handleFinalize: %v", err)
			prob = newProblem(http.StatusInternalServerError, errServerInternal, "failed to encode certificate chain")
			return nil
		}
		for _, caCert := range signer.Certificates() {
			if err := pem.Encode(&chainBuf, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}); err != nil {
				s.logger.Errorf("pem.Encode CA cert failed in handleFinalize: %v", err)
				prob = newProblem(http.StatusInternalServerError, errServerInternal, "failed to encode certificate chain")
				return nil
			}
		}

		h256 := sha256.Sum256(leaf.Raw)
		certID := uuid.NewString()
		certRec := &certRecord{
			ID:           certID,
			OrderID:      order.ID,
			AccountID:    acct.ID,
			SerialNumber: hex.EncodeToString(leaf.SerialNumber.Bytes()),
			SHA256:       hex.EncodeToString(h256[:]),
			LeafDER:      leaf.Raw,
			ChainPEM:     chainBuf.Bytes(),
			IssuedAt:     leaf.NotBefore,
			ExpiresAt:    leaf.NotAfter,
		}
		st.Certificates[certID] = certRec
		st.certsBySHA256[certRec.SHA256] = certRec
		order.CertID = certID
		order.Status = StatusValid
		orderCopy = cloneOrder(order)
		return nil
	})
	if err != nil {
		s.logger.Errorf("updateState failed in handleFinalize: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	w.Header().Set("Location", s.orderURL(r, orderCopy.ID))
	s.writeJSON(w, http.StatusOK, s.toWireOrder(r, orderCopy))
}

func (s *Server) buildCertificateTemplate(csr *x509.CertificateRequest, dnsNames []string, ipAddrs []net.IP) (*x509.Certificate, error) {
	skid, err := calculateSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := csr.PublicKey.(*rsa.PublicKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	var subject pkix.Name
	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		if addr, err := netip.ParseAddr(cn); err == nil {
			subject.CommonName = addr.Unmap().String()
		} else if ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(cn, ".")); err == nil {
			subject.CommonName = strings.ToLower(ascii)
		}
	}
	now := time.Now().UTC()
	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(s.certValidity),
		SubjectKeyId:          skid,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}, nil
}

func matchCSRAndOrderIdentifiers(csr *x509.CertificateRequest, orderIDs []Identifier) ([]string, []net.IP, *Problem) {
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, nil, newProblem(http.StatusBadRequest, errBadCSR, "CSR contains unsupported SAN types (email or URI)")
	}
	oidCommonName := asn1.ObjectIdentifier{2, 5, 4, 3}
	cnCount := 0
	for _, atv := range csr.Subject.Names {
		if !atv.Type.Equal(oidCommonName) {
			return nil, nil, newProblem(http.StatusBadRequest, errBadCSR, "CSR subject contains unsupported attribute %v; only CommonName is allowed", atv.Type)
		}
		cnCount++
		if cnCount > 1 {
			return nil, nil, newProblem(http.StatusBadRequest, errBadCSR, "CSR subject contains multiple CommonName attributes")
		}
	}
	if cnCount > 0 && strings.TrimSpace(csr.Subject.CommonName) == "" {
		return nil, nil, newProblem(http.StatusBadRequest, errBadCSR, "CSR subject CommonName is empty or invalid")
	}
	oidSubjectAltName := asn1.ObjectIdentifier{2, 5, 29, 17}
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			return nil, nil, newProblem(http.StatusBadRequest, errBadCSR, "CSR contains unsupported extension %v", ext.Id)
		}
	}
	rawSANCount, err := countRawSANEntriesFromExtensions(csr.Extensions)
	if err != nil || (rawSANCount > 0 && rawSANCount != len(csr.DNSNames)+len(csr.IPAddresses)) {
		return nil, nil, newProblem(http.StatusBadRequest, errBadCSR, "CSR contains invalid or unsupported SubjectAltName entries")
	}

	csrSet := make(map[Identifier]bool)
	var dnsNames []string
	var ipAddrs []net.IP

	addDNS := func(name string) *Problem {
		normID, p := normalizeAndValidateIdentifier(Identifier{Type: IdentifierDNS, Value: name})
		if p != nil {
			return newProblem(http.StatusBadRequest, errBadCSR, "invalid DNS name %q in CSR: %s", name, p.Detail)
		}
		if !csrSet[normID] {
			csrSet[normID] = true
			dnsNames = append(dnsNames, normID.Value)
		}
		return nil
	}

	addIP := func(ip net.IP) *Problem {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return newProblem(http.StatusBadRequest, errBadCSR, "invalid IP address %q in CSR", ip)
		}
		normID, p := normalizeAndValidateIdentifier(Identifier{Type: IdentifierIP, Value: addr.Unmap().String()})
		if p != nil {
			return newProblem(http.StatusBadRequest, errBadCSR, "invalid IP address %q in CSR: %s", ip, p.Detail)
		}
		if !csrSet[normID] {
			csrSet[normID] = true
			ipAddrs = append(ipAddrs, net.IP(addr.Unmap().AsSlice()))
		}
		return nil
	}

	for _, d := range csr.DNSNames {
		if p := addDNS(d); p != nil {
			return nil, nil, p
		}
	}
	for _, ip := range csr.IPAddresses {
		if p := addIP(ip); p != nil {
			return nil, nil, p
		}
	}

	if cn := strings.TrimSpace(csr.Subject.CommonName); cn != "" {
		if addr, err := netip.ParseAddr(cn); err == nil {
			if p := addIP(net.IP(addr.Unmap().AsSlice())); p != nil {
				return nil, nil, p
			}
		} else {
			if p := addDNS(cn); p != nil {
				return nil, nil, p
			}
		}
	}

	if len(csrSet) != len(orderIDs) {
		return nil, nil, newProblem(http.StatusBadRequest, errBadCSR, "CSR identifiers do not match order identifiers")
	}
	for _, oid := range orderIDs {
		if !csrSet[oid] {
			return nil, nil, newProblem(http.StatusBadRequest, errBadCSR, "order identifier %s (%s) missing from CSR", oid.Value, oid.Type)
		}
	}

	return dnsNames, ipAddrs, nil
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	certID := strings.TrimPrefix(r.URL.Path, s.pathPrefix+"/acme/cert/")
	if certID == "" || strings.Contains(certID, "/") {
		s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "certificate not found"))
		return
	}

	_, _, acct, payload, prob := s.verifyJWS(w, r, false, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if acct == nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errAccountDoesNotExist, "account not found"))
		return
	}
	if len(payload) > 0 {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "POST-as-GET request must have an empty payload"))
		return
	}

	var cert *certRecord
	if err := s.readState(func(st *serverState) error {
		if _, p := requireActiveAccount(st, acct.ID); p != nil {
			prob = p
			return nil
		}
		cert = cloneCert(st.Certificates[certID])
		return nil
	}); err != nil {
		s.logger.Errorf("readState failed in handleCertificate: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}
	if cert == nil || len(cert.ChainPEM) == 0 {
		s.writeProblem(w, newProblem(http.StatusNotFound, errMalformed, "certificate not found"))
		return
	}
	if cert.AccountID != "" && cert.AccountID != acct.ID {
		s.writeProblem(w, newProblem(http.StatusForbidden, errUnauthorized, "certificate does not belong to account"))
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cert.ChainPEM)
}

func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		s.handleNewNonce(w, r)
		return
	}

	_, jwk, acct, payload, prob := s.verifyJWS(w, r, true, true)
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	var req struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason,omitempty"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid JSON payload: %v", err))
		return
	}

	reason := 0
	if req.Reason != nil {
		reason = *req.Reason
		if reason < 0 || reason > 10 || reason == 7 {
			s.writeProblem(w, newProblem(http.StatusBadRequest, errBadRevocationReason, "invalid CRL reason code %d", reason))
			return
		}
	}

	certDER, err := base64.RawURLEncoding.DecodeString(req.Certificate)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "invalid base64url certificate: %v", err))
		return
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		s.writeProblem(w, newProblem(http.StatusBadRequest, errMalformed, "failed to parse X.509 certificate: %v", err))
		return
	}

	h256 := sha256.Sum256(certDER)
	certHash := hex.EncodeToString(h256[:])
	signedByCertKey := jwk != nil && publicKeysEqual(jwk.Key, parsedCert.PublicKey)

	err = s.updateState(func(st *serverState) error {
		found := st.certsBySHA256[certHash]
		if found == nil {
			for _, c := range st.Certificates {
				if c.SHA256 == certHash {
					found = c
					break
				}
			}
		}
		if found == nil {
			prob = newProblem(http.StatusNotFound, errMalformed, "certificate not found")
			return nil
		}
		if !signedByCertKey {
			if acct == nil {
				prob = newProblem(http.StatusForbidden, errUnauthorized, "not authorized to revoke this certificate")
				return nil
			}
			if _, p := requireActiveAccount(st, acct.ID); p != nil {
				prob = p
				return nil
			}
			if found.AccountID != acct.ID {
				prob = newProblem(http.StatusForbidden, errUnauthorized, "not authorized to revoke this certificate")
				return nil
			}
		}
		if found.Revoked {
			prob = newProblem(http.StatusBadRequest, errAlreadyRevoked, "certificate has already been revoked")
			return nil
		}
		for _, sg := range s.signers {
			revoker, ok := sg.(Revoker)
			if !ok {
				continue
			}
			certs := sg.Certificates()
			if len(certs) > 0 && bytes.Equal(parsedCert.RawIssuer, certs[0].RawSubject) && parsedCert.CheckSignatureFrom(certs[0]) == nil {
				if err := revoker.RevokeCertificate(parsedCert.SerialNumber, reason); err != nil {
					s.logger.Errorf("RevokeCertificate failed in handleRevokeCert: %v", err)
					prob = newProblem(http.StatusInternalServerError, errServerInternal, "failed to revoke certificate in CA")
					return nil
				}
			}
		}
		found.Revoked = true
		found.RevokedAt = time.Now().UTC()
		found.RevocationReason = reason
		return nil
	})
	if err != nil {
		s.logger.Errorf("updateState failed in handleRevokeCert: %v", err)
		s.writeProblem(w, newProblem(http.StatusInternalServerError, errServerInternal, "internal storage error"))
		return
	}
	if prob != nil {
		s.writeProblem(w, prob)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	switch ka := a.(type) {
	case *rsa.PublicKey:
		kb, ok := b.(*rsa.PublicKey)
		return ok && ka.E == kb.E && ka.N.Cmp(kb.N) == 0
	case *ecdsa.PublicKey:
		kb, ok := b.(*ecdsa.PublicKey)
		return ok && ka.Curve == kb.Curve && ka.X.Cmp(kb.X) == 0 && ka.Y.Cmp(kb.Y) == 0
	case ed25519.PublicKey:
		kb, ok := b.(ed25519.PublicKey)
		return ok && bytes.Equal(ka, kb)
	default:
		return false
	}
}
