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
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// IdentifierDNS is the ACME identifier type for DNS domain names (RFC 8555).
	IdentifierDNS = "dns"
	// IdentifierIP is the ACME identifier type for IPv4 and IPv6 addresses (RFC 8738).
	IdentifierIP = "ip"

	// ChallengeTLSALPN01 is the ACME challenge type for TLS-ALPN-01 (RFC 8737).
	ChallengeTLSALPN01 = "tls-alpn-01"
	// ChallengeHTTP01 is the ACME challenge type for HTTP-01 (RFC 8555).
	ChallengeHTTP01 = "http-01"

	// ACMETLS1Protocol is the negotiated ALPN protocol for TLS-ALPN-01 challenges.
	ACMETLS1Protocol = "acme-tls/1"
)

// Standard ACME status values (RFC 8555 Section 7.1.6).
const (
	// StatusPending indicates that an order, authorization, or challenge is
	// awaiting client action or validation.
	StatusPending = "pending"
	// StatusProcessing indicates that a challenge or order is actively being
	// validated or finalized by the server.
	StatusProcessing = "processing"
	// StatusValid indicates that an account, order, authorization, or challenge
	// has been validated and is active.
	StatusValid = "valid"
	// StatusInvalid indicates that validation or finalization failed, or an
	// order's authorization became unusable.
	StatusInvalid = "invalid"
	// StatusReady indicates that all authorizations for an order are valid and
	// the client may submit a CSR to the order's finalize URL.
	StatusReady = "ready"
	// StatusDeactivated indicates that an account or authorization was
	// deactivated by the client.
	StatusDeactivated = "deactivated"
	// StatusExpired indicates that an authorization or order passed its
	// expiration time.
	StatusExpired = "expired"
	// StatusRevoked indicates that an authorization or certificate was
	// revoked by the server or client.
	StatusRevoked = "revoked"
)

// Standard ACME error types (RFC 8555 Section 6.7).
const (
	errAccountDoesNotExist   = "urn:ietf:params:acme:error:accountDoesNotExist"
	errAlreadyRevoked        = "urn:ietf:params:acme:error:alreadyRevoked"
	errBadCSR                = "urn:ietf:params:acme:error:badCSR"
	errBadNonce              = "urn:ietf:params:acme:error:badNonce"
	errBadPublicKey          = "urn:ietf:params:acme:error:badPublicKey"
	errBadRevocationReason   = "urn:ietf:params:acme:error:badRevocationReason"
	errBadSignatureAlgorithm = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	errConnection            = "urn:ietf:params:acme:error:connection"
	errIncorrectResponse     = "urn:ietf:params:acme:error:incorrectResponse"
	errInvalidContact        = "urn:ietf:params:acme:error:invalidContact"
	errMalformed             = "urn:ietf:params:acme:error:malformed"
	errOrderNotReady         = "urn:ietf:params:acme:error:orderNotReady"
	errRateLimited           = "urn:ietf:params:acme:error:rateLimited"
	errRejectedIdentifier    = "urn:ietf:params:acme:error:rejectedIdentifier"
	errServerInternal        = "urn:ietf:params:acme:error:serverInternal"
	errTLS                   = "urn:ietf:params:acme:error:tls"
	errUnauthorized          = "urn:ietf:params:acme:error:unauthorized"
	errUnsupportedContact    = "urn:ietf:params:acme:error:unsupportedContact"
	errUnsupportedIdentifier = "urn:ietf:params:acme:error:unsupportedIdentifier"
	errUserActionRequired    = "urn:ietf:params:acme:error:userActionRequired"
)

// Identifier represents an ACME identifier (DNS name or IP address) as defined
// in RFC 8555 Section 9.7.7 and RFC 8738.
type Identifier struct {
	// Type is the identifier type, such as [IdentifierDNS] ("dns") or
	// [IdentifierIP] ("ip").
	Type string `json:"type"`
	// Value is the textual representation of the identifier, such as a
	// domain name ("example.com") or an IP address ("192.0.2.1" or "2001:db8::1").
	Value string `json:"value"`
}

// Problem represents an RFC 7807 / RFC 8555 Section 6.7 problem document
// returned when an ACME request fails or when a challenge or order encounters
// an error. It implements the [error] interface.
type Problem struct {
	// Type is a URI reference identifying the problem type (for example,
	// "urn:ietf:params:acme:error:malformed").
	Type string `json:"type"`
	// Detail is a human-readable explanation specific to this occurrence of
	// the problem.
	Detail string `json:"detail,omitempty"`
	// Status is the HTTP status code generated by the server for this
	// occurrence of the problem.
	Status int `json:"status,omitempty"`
	// Instance is a URI reference that identifies the specific occurrence
	// of the problem (e.g., a Terms of Service URL when Type is
	// "urn:ietf:params:acme:error:userActionRequired").
	Instance string `json:"instance,omitempty"`
	// Subproblems contains optional per-identifier problem details.
	Subproblems []Subproblem `json:"subproblems,omitempty"`
}

// Subproblem represents a per-identifier subproblem within an ACME [Problem]
// document (RFC 8555 Section 6.7.1).
type Subproblem struct {
	// Type is a URI reference identifying the problem type.
	Type string `json:"type"`
	// Detail is a human-readable explanation of the subproblem.
	Detail string `json:"detail,omitempty"`
	// Identifier is the ACME identifier to which this subproblem applies.
	Identifier Identifier `json:"identifier"`
}

// Error implements the [error] interface.
func (p *Problem) Error() string {
	return fmt.Sprintf("acme problem (%d %s): %s", p.Status, p.Type, p.Detail)
}

func newProblem(status int, probType, format string, args ...any) *Problem {
	return &Problem{
		Type:   probType,
		Detail: fmt.Sprintf(format, args...),
		Status: status,
	}
}

// Logger is the logging interface used by [Server]. It is compatible with the
// logger interface used by [github.com/c2FmZQ/storage].
type Logger interface {
	// Debugf logs a formatted debug message.
	Debugf(format string, args ...any)
	// Infof logs a formatted informational message.
	Infof(format string, args ...any)
	// Errorf logs a formatted error message.
	Errorf(format string, args ...any)
}

// serverState is the persisted state of the ACME server. All fields use
// concrete types so both encoding/gob (used by github.com/c2FmZQ/storage) and
// encoding/json can serialize it directly.
type serverState struct {
	Accounts       map[string]*accountRecord
	Orders         map[string]*orderRecord
	Authorizations map[string]*authzRecord
	Challenges     map[string]*challengeRecord
	Certificates   map[string]*certRecord

	accountsByThumbprint map[string]*accountRecord
	certsBySHA256        map[string]*certRecord
}

func (st *serverState) initMaps() {
	if st.Accounts == nil {
		st.Accounts = make(map[string]*accountRecord)
	}
	if st.Orders == nil {
		st.Orders = make(map[string]*orderRecord)
	}
	if st.Authorizations == nil {
		st.Authorizations = make(map[string]*authzRecord)
	}
	if st.Challenges == nil {
		st.Challenges = make(map[string]*challengeRecord)
	}
	if st.Certificates == nil {
		st.Certificates = make(map[string]*certRecord)
	}
	if st.accountsByThumbprint == nil {
		st.accountsByThumbprint = make(map[string]*accountRecord, len(st.Accounts))
		for _, a := range st.Accounts {
			if a != nil && a.Thumbprint != "" {
				st.accountsByThumbprint[a.Thumbprint] = a
			}
		}
	}
	if st.certsBySHA256 == nil {
		st.certsBySHA256 = make(map[string]*certRecord, len(st.Certificates))
		for _, c := range st.Certificates {
			if c != nil && c.SHA256 != "" {
				st.certsBySHA256[c.SHA256] = c
			}
		}
	}
	for _, authz := range st.Authorizations {
		if authz == nil {
			continue
		}
		for i, ch := range authz.Challenges {
			if ch == nil {
				continue
			}
			if stored, ok := st.Challenges[ch.ID]; ok && stored != nil {
				authz.Challenges[i] = stored
			} else {
				st.Challenges[ch.ID] = ch
			}
		}
	}
}

type accountRecord struct {
	ID         string
	KeyJSON    []byte
	Thumbprint string
	Status     string
	Contact    []string
	CreatedAt  time.Time
}

func (a *accountRecord) jwk() (*jose.JSONWebKey, error) {
	var k jose.JSONWebKey
	if err := json.Unmarshal(a.KeyJSON, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

type orderRecord struct {
	ID          string
	AccountID   string
	Status      string
	Expires     time.Time
	NotBefore   string
	NotAfter    string
	Identifiers []Identifier
	AuthzIDs    []string
	CertID      string
	Error       *Problem
}

type authzRecord struct {
	ID         string
	AccountID  string
	Identifier Identifier
	Status     string
	Expires    time.Time
	Challenges []*challengeRecord
	Wildcard   bool
}

type challengeRecord struct {
	ID        string
	AuthzID   string
	Type      string
	Status    string
	Token     string
	Validated string
	Error     *Problem
}

type certRecord struct {
	ID               string
	OrderID          string
	AccountID        string
	SerialNumber     string
	SHA256           string
	LeafDER          []byte
	ChainPEM         []byte
	IssuedAt         time.Time
	ExpiresAt        time.Time
	Revoked          bool
	RevokedAt        time.Time
	RevocationReason int
}

func cloneProblem(p *Problem) *Problem {
	if p == nil {
		return nil
	}
	cp := *p
	if len(p.Subproblems) > 0 {
		cp.Subproblems = slices.Clone(p.Subproblems)
	}
	return &cp
}

func cloneAccount(a *accountRecord) *accountRecord {
	if a == nil {
		return nil
	}
	cp := *a
	cp.KeyJSON = slices.Clone(a.KeyJSON)
	cp.Contact = slices.Clone(a.Contact)
	return &cp
}

func cloneOrder(o *orderRecord) *orderRecord {
	if o == nil {
		return nil
	}
	cp := *o
	cp.Identifiers = slices.Clone(o.Identifiers)
	cp.AuthzIDs = slices.Clone(o.AuthzIDs)
	cp.Error = cloneProblem(o.Error)
	return &cp
}

func cloneChallenge(c *challengeRecord) *challengeRecord {
	if c == nil {
		return nil
	}
	cp := *c
	cp.Error = cloneProblem(c.Error)
	return &cp
}

func cloneAuthz(a *authzRecord) *authzRecord {
	if a == nil {
		return nil
	}
	cp := *a
	if len(a.Challenges) > 0 {
		cp.Challenges = make([]*challengeRecord, len(a.Challenges))
		for i, ch := range a.Challenges {
			cp.Challenges[i] = cloneChallenge(ch)
		}
	}
	return &cp
}

func cloneCert(c *certRecord) *certRecord {
	if c == nil {
		return nil
	}
	cp := *c
	cp.LeafDER = slices.Clone(c.LeafDER)
	cp.ChainPEM = slices.Clone(c.ChainPEM)
	return &cp
}

// Wire response types for JSON serialization.

type wireDirectory struct {
	NewNonce   string             `json:"newNonce"`
	NewAccount string             `json:"newAccount"`
	NewOrder   string             `json:"newOrder"`
	NewAuthz   string             `json:"newAuthz,omitempty"`
	RevokeCert string             `json:"revokeCert"`
	KeyChange  string             `json:"keyChange"`
	Meta       *wireDirectoryMeta `json:"meta,omitempty"`
}

type wireDirectoryMeta struct {
	TermsOfService string `json:"termsOfService,omitempty"`
}

type wireAccount struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
	Orders  string   `json:"orders,omitempty"`
}

type wireOrdersList struct {
	Orders []string `json:"orders"`
}

type wireOrder struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Error          *Problem     `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
}

type wireAuthorization struct {
	Identifier Identifier      `json:"identifier"`
	Status     string          `json:"status"`
	Expires    string          `json:"expires,omitempty"`
	Challenges []wireChallenge `json:"challenges"`
	Wildcard   bool            `json:"wildcard,omitempty"`
}

type wireChallenge struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Status    string   `json:"status"`
	Token     string   `json:"token"`
	Validated string   `json:"validated,omitempty"`
	Error     *Problem `json:"error,omitempty"`
}
