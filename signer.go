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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// Signer is the interface for signing X.509 certificates issued by a [Server].
// A Signer may optionally also implement [Revoker] to receive certificate
// revocation notifications.
type Signer interface {
	// Certificates returns the CA certificate chain, starting with the
	// issuing CA certificate at index 0 followed by any parent intermediate
	// or root CA certificates.
	Certificates() []*x509.Certificate
	// Sign signs the given leaf certificate template and returns the parsed
	// X.509 certificate. The subject's public key is populated in
	// template.PublicKey.
	Sign(template *x509.Certificate) (*x509.Certificate, error)
}

// Revoker is an optional interface that a [Signer] may implement to be notified
// when a certificate issued by that signer is revoked via the ACME revokeCert
// endpoint (RFC 8555 Section 7.6).
type Revoker interface {
	// RevokeCertificate records the revocation of the certificate with the
	// given serialNumber and RFC 5280 Section 5.3.1 CRL reasonCode.
	RevokeCertificate(serialNumber *big.Int, reasonCode int) error
}

// CASigner implements [Signer] using an in-memory [crypto.Signer] and a CA
// certificate chain.
type CASigner struct {
	certs []*x509.Certificate
	key   crypto.Signer
}

var _ Signer = (*CASigner)(nil)

// NewSigner creates a new [CASigner] from a CA certificate chain (with the
// issuing CA certificate at index 0) and its corresponding private key.
func NewSigner(certs []*x509.Certificate, key crypto.Signer) (*CASigner, error) {
	if len(certs) == 0 || certs[0] == nil {
		return nil, errors.New("acme: at least one CA certificate is required")
	}
	if key == nil {
		return nil, errors.New("acme: signer private key is required")
	}
	for i, cert := range certs {
		if cert == nil {
			return nil, fmt.Errorf("acme: certificate %d in chain is nil", i)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, fmt.Errorf("acme: certificate %d in chain is not a CA certificate", i)
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("acme: certificate %d in chain does not have KeyUsageCertSign", i)
		}
		if i > 0 && (cert.MaxPathLenZero || (cert.MaxPathLen > 0 && cert.MaxPathLen < i)) {
			return nil, fmt.Errorf("acme: certificate %d in chain violates MaxPathLen constraint", i)
		}
	}
	for i := 0; i < len(certs)-1; i++ {
		if !bytes.Equal(certs[i].RawIssuer, certs[i+1].RawSubject) {
			return nil, fmt.Errorf("acme: certificate %d issuer does not match certificate %d subject", i, i+1)
		}
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("acme: certificate %d in chain is not signed by certificate %d: %w", i, i+1, err)
		}
	}
	if !publicKeysEqual(certs[0].PublicKey, key.Public()) {
		return nil, errors.New("acme: issuing certificate public key does not match signer key")
	}
	return &CASigner{
		certs: slices.Clone(certs),
		key:   key,
	}, nil
}

// NewSelfSignedSigner generates a self-signed CA certificate and returns a
// [CASigner]. If key is nil, a new ECDSA P-256 key is generated. If subject is
// empty, a default subject is used. If validity is non-positive, it defaults
// to 10 years.
func NewSelfSignedSigner(key crypto.Signer, subject pkix.Name, validity time.Duration) (*CASigner, error) {
	var err error
	if key == nil {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	if subject.String() == "" {
		subject = pkix.Name{
			Organization: []string{"ACME CA"},
		}
	}
	if validity <= 0 {
		validity = 10 * 365 * 24 * time.Hour
	}

	pubKey := key.Public()
	skid, err := calculateSubjectKeyID(pubKey)
	if err != nil {
		return nil, err
	}
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          skid,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pubKey, key)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}
	return NewSigner([]*x509.Certificate{caCert}, key)
}

// Certificates returns a copy of the CA certificate chain.
func (s *CASigner) Certificates() []*x509.Certificate {
	return slices.Clone(s.certs)
}

// Sign signs the leaf certificate template using the issuing CA certificate and
// private key. It enforces end-entity constraints (BasicConstraints IsCA=false,
// non-CA KeyUsage, validity bounded by the issuing CA certificate, and random
// 128-bit serial number if not already set).
func (s *CASigner) Sign(template *x509.Certificate) (*x509.Certificate, error) {
	if template == nil {
		return nil, errors.New("acme: nil certificate template")
	}
	if template.PublicKey == nil {
		return nil, errors.New("acme: certificate template missing PublicKey")
	}
	if template.IsCA || template.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return nil, errors.New("acme: Sign cannot issue CA certificates")
	}
	for _, ext := range template.ExtraExtensions {
		if isForbiddenExtraExtensionOID(ext.Id) {
			return nil, fmt.Errorf("acme: forbidden extension OID %s in ExtraExtensions", ext.Id)
		}
	}
	if publicKeysEqual(template.PublicKey, s.key.Public()) {
		return nil, errors.New("acme: cannot sign certificate with CA's own public key")
	}

	caCert := s.certs[0]
	now := time.Now().UTC()
	for i, c := range s.certs {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return nil, fmt.Errorf("acme: CA certificate %d in chain is not currently valid", i)
		}
	}

	tmpl := *template
	tmpl.BasicConstraintsValid = true
	tmpl.IsCA = false
	tmpl.MaxPathLen = -1
	tmpl.MaxPathLenZero = false
	if tmpl.NotAfter.After(caCert.NotAfter) {
		tmpl.NotAfter = caCert.NotAfter
	}
	if !tmpl.NotAfter.After(tmpl.NotBefore) {
		return nil, errors.New("acme: certificate template NotAfter must be after NotBefore")
	}
	if tmpl.SerialNumber == nil {
		sn, err := generateSerialNumber()
		if err != nil {
			return nil, err
		}
		tmpl.SerialNumber = sn
	}
	if len(tmpl.SubjectKeyId) == 0 {
		skid, err := calculateSubjectKeyID(tmpl.PublicKey)
		if err != nil {
			return nil, err
		}
		tmpl.SubjectKeyId = skid
	}
	if len(tmpl.AuthorityKeyId) == 0 && len(caCert.SubjectKeyId) > 0 {
		tmpl.AuthorityKeyId = caCert.SubjectKeyId
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, tmpl.PublicKey, s.key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func calculateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(spki)
	return hash[:], nil
}

func generateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

var (
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

func isForbiddenExtraExtensionOID(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(oidExtKeyUsage) ||
		oid.Equal(oidExtSubjectAltName) ||
		oid.Equal(oidExtBasicConstraints) ||
		oid.Equal(oidExtExtendedKeyUsage)
}
