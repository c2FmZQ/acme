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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/c2FmZQ/acme"
	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/tpm"
)

const (
	defaultCAStorageFile = "acme-ca"
	defaultKeyType       = "ecdsa-p256"
	defaultCALifetime    = 10 * 365 * 24 * time.Hour
)

// CAOptions configures the persistent Certificate Authority opened by [OpenCA].
type CAOptions struct {
	// Store is the encrypted storage instance used to persist the CA state
	// (required).
	Store *storage.Storage
	// StorageFile is the data file name within Store used for the CA state.
	// If empty, it defaults to "acme-ca".
	StorageFile string
	// TPM is an optional TPM device used to create and use hardware-backed
	// CA signing keys.
	TPM *tpm.TPM
}

type caState struct {
	KeyType    string
	TPMBacked  bool
	PrivateKey []byte
	CertChain  [][]byte
	Revoked    map[string]revocationEntry
}

type revocationEntry struct {
	SerialNumber string
	RevokedAt    time.Time
	ReasonCode   int
}

// CA manages the ACME server's Certificate Authority key and certificate chain
// in encrypted storage (and optionally in a TPM). It implements [acme.Signer]
// and [acme.Revoker].
type CA struct {
	store *storage.Storage
	file  string
	tpm   *tpm.TPM

	mu    sync.RWMutex
	certs []*x509.Certificate
}

var (
	_ acme.Signer  = (*CA)(nil)
	_ acme.Revoker = (*CA)(nil)
)

// OpenCA opens the CA state from storage. If the CA has not been bootstrapped
// or had its certificate imported yet, Ready() will return false until
// BootstrapSelfSigned or ImportCertificateChain is called.
func OpenCA(opts CAOptions) (*CA, error) {
	if opts.Store == nil {
		return nil, errors.New("ca: storage is required")
	}
	file := opts.StorageFile
	if file == "" {
		file = defaultCAStorageFile
	}
	ca := &CA{
		store: opts.Store,
		file:  file,
		tpm:   opts.TPM,
	}
	ca.store.CreateEmptyFile(ca.file, &caState{})
	if err := ca.reloadCerts(); err != nil {
		return nil, err
	}
	return ca, nil
}

func (c *CA) reloadCerts() error {
	var st caState
	if err := c.store.ReadDataFile(c.file, &st); err != nil {
		return fmt.Errorf("ca: read storage: %w", err)
	}
	defer wipe(st.PrivateKey)

	if len(st.PrivateKey) > 0 {
		if st.TPMBacked && c.tpm == nil {
			return errors.New("ca: CA key is TPM-backed, but --tpm was not enabled")
		}
		if !st.TPMBacked && c.tpm != nil {
			return errors.New("ca: CA key was created without TPM, but --tpm was enabled")
		}
	}

	var certs []*x509.Certificate
	for i, raw := range st.CertChain {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("ca: parse stored certificate %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	c.mu.Lock()
	c.certs = certs
	c.mu.Unlock()
	return nil
}

// Ready reports whether the CA has both a private key and a signed CA
// certificate chain ready to issue certificates.
func (c *CA) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.certs) > 0
}

// Certificates implements [acme.Signer].
func (c *CA) Certificates() []*x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return slices.Clone(c.certs)
}

// Sign implements [acme.Signer].
func (c *CA) Sign(template *x509.Certificate) (*x509.Certificate, error) {
	if template == nil {
		return nil, errors.New("ca: nil certificate template")
	}
	if template.PublicKey == nil {
		return nil, errors.New("ca: certificate template missing PublicKey")
	}
	if template.IsCA || template.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return nil, errors.New("ca: Sign cannot issue CA certificates")
	}
	for _, ext := range template.ExtraExtensions {
		if isForbiddenExtraExtensionOID(ext.Id) {
			return nil, fmt.Errorf("ca: forbidden extension OID %s in ExtraExtensions", ext.Id)
		}
	}

	c.mu.RLock()
	if len(c.certs) == 0 {
		c.mu.RUnlock()
		return nil, errors.New("ca: CA certificate is not initialized")
	}
	certs := slices.Clone(c.certs)
	caCert := certs[0]

	var st caState
	if err := c.store.ReadDataFile(c.file, &st); err != nil {
		c.mu.RUnlock()
		return nil, fmt.Errorf("ca: read storage: %w", err)
	}
	c.mu.RUnlock()
	defer wipe(st.PrivateKey)

	now := time.Now().UTC()
	for i, cert := range certs {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return nil, fmt.Errorf("ca: CA certificate %d in chain is not currently valid", i)
		}
	}

	signer, err := c.parsePrivateKey(st.PrivateKey, st.TPMBacked)
	if err != nil {
		return nil, err
	}

	// Prevent signing a certificate that reuses the CA's own public key.
	if keysEqual(template.PublicKey, signer.Public()) {
		return nil, errors.New("ca: cannot sign certificate with CA's own public key")
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
		return nil, errors.New("ca: certificate template NotAfter must be after NotBefore")
	}
	if tmpl.SerialNumber == nil {
		sn, err := randomSerialNumber()
		if err != nil {
			return nil, err
		}
		tmpl.SerialNumber = sn
	}
	if len(tmpl.SubjectKeyId) == 0 {
		skid, err := subjectKeyID(tmpl.PublicKey)
		if err != nil {
			return nil, err
		}
		tmpl.SubjectKeyId = skid
	}
	if len(tmpl.AuthorityKeyId) == 0 && len(caCert.SubjectKeyId) > 0 {
		tmpl.AuthorityKeyId = caCert.SubjectKeyId
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caCert, tmpl.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("ca: x509.CreateCertificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// RevokeCertificate implements [acme.Revoker].
func (c *CA) RevokeCertificate(serialNumber *big.Int, reasonCode int) (retErr error) {
	if serialNumber == nil {
		return errors.New("ca: nil serial number")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	var st caState
	commit, err := c.store.OpenForUpdate(c.file, &st)
	if err != nil {
		return err
	}
	defer func() {
		if err := commit(false, &retErr); err != nil && !errors.Is(err, storage.ErrRolledBack) && !errors.Is(err, storage.ErrAlreadyCommitted) && retErr == nil {
			retErr = err
		}
		wipe(st.PrivateKey)
	}()

	if st.Revoked == nil {
		st.Revoked = make(map[string]revocationEntry)
	}
	snHex := hex.EncodeToString(serialNumber.Bytes())
	st.Revoked[snHex] = revocationEntry{
		SerialNumber: snHex,
		RevokedAt:    time.Now().UTC(),
		ReasonCode:   reasonCode,
	}
	return commit(true, nil)
}

// IsRevoked reports whether the certificate with the given serial number has
// been revoked.
func (c *CA) IsRevoked(serialNumber *big.Int) (bool, error) {
	if serialNumber == nil {
		return false, nil
	}
	c.mu.RLock()
	var st caState
	err := c.store.ReadDataFile(c.file, &st)
	c.mu.RUnlock()
	if err != nil {
		return false, err
	}
	defer wipe(st.PrivateKey)
	if st.Revoked == nil {
		return false, nil
	}
	_, ok := st.Revoked[hex.EncodeToString(serialNumber.Bytes())]
	return ok, nil
}

// BootstrapSelfSigned generates a new CA key and self-signed root CA
// certificate and stores them in encrypted storage. If a CA key or certificate
// already exists, force must be true to overwrite it.
func (c *CA) BootstrapSelfSigned(keyType string, subject pkix.Name, validity time.Duration, force bool) (retErr error) {
	if keyType == "" {
		keyType = defaultKeyType
	}
	if subject.String() == "" {
		subject = pkix.Name{CommonName: "ACME CA"}
	}
	if validity <= 0 {
		validity = defaultCALifetime
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var st caState
	commit, err := c.store.OpenForUpdate(c.file, &st)
	if err != nil {
		return err
	}
	defer func() {
		if err := commit(false, &retErr); err != nil && !errors.Is(err, storage.ErrRolledBack) && !errors.Is(err, storage.ErrAlreadyCommitted) && retErr == nil {
			retErr = err
		}
		wipe(st.PrivateKey)
	}()

	if (len(st.PrivateKey) > 0 || len(st.CertChain) > 0) && !force {
		return errors.New("ca: CA already exists in storage (use --force to overwrite)")
	}

	signer, keyBytes, err := c.generateKey(keyType)
	if err != nil {
		return err
	}
	defer wipe(keyBytes)

	skid, err := subjectKeyID(signer.Public())
	if err != nil {
		return err
	}
	sn, err := randomSerialNumber()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return fmt.Errorf("ca: x509.CreateCertificate: %w", err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return err
	}

	st = caState{
		KeyType:    strings.ToLower(keyType),
		TPMBacked:  c.tpm != nil,
		PrivateKey: slices.Clone(keyBytes),
		CertChain:  [][]byte{raw},
		Revoked:    make(map[string]revocationEntry),
	}
	if err := commit(true, nil); err != nil {
		return err
	}
	c.certs = []*x509.Certificate{cert}
	return nil
}

type basicConstraintsExt struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// GenerateCSR generates a CA private key (or reuses the existing CA private key
// unless force is true) and returns a PEM-encoded PKCS#10 Certificate Signing
// Request for a CA certificate.
func (c *CA) GenerateCSR(keyType string, subject pkix.Name, force bool) (_ []byte, retErr error) {
	if keyType == "" {
		keyType = defaultKeyType
	}
	if subject.String() == "" {
		subject = pkix.Name{CommonName: "ACME CA"}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var st caState
	commit, err := c.store.OpenForUpdate(c.file, &st)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := commit(false, &retErr); err != nil && !errors.Is(err, storage.ErrRolledBack) && !errors.Is(err, storage.ErrAlreadyCommitted) && retErr == nil {
			retErr = err
		}
		wipe(st.PrivateKey)
	}()

	var signer crypto.Signer
	var changed bool
	if len(st.PrivateKey) == 0 || force {
		if len(st.CertChain) > 0 && !force {
			return nil, errors.New("ca: CA certificate already exists in storage (use --force to overwrite)")
		}
		var keyBytes []byte
		signer, keyBytes, err = c.generateKey(keyType)
		if err != nil {
			return nil, err
		}
		defer wipe(keyBytes)
		st.KeyType = strings.ToLower(keyType)
		st.TPMBacked = c.tpm != nil
		st.PrivateKey = slices.Clone(keyBytes)
		if force {
			st.CertChain = nil
			c.certs = nil
		}
		changed = true
	} else {
		if st.TPMBacked != (c.tpm != nil) {
			return nil, errors.New("ca: existing CA key TPM mode does not match --tpm flag")
		}
		signer, err = c.parsePrivateKey(st.PrivateKey, st.TPMBacked)
		if err != nil {
			return nil, err
		}
	}

	bcBytes, err := asn1.Marshal(basicConstraintsExt{IsCA: true, MaxPathLen: 0})
	if err != nil {
		return nil, err
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: subject,
		ExtraExtensions: []pkix.Extension{
			{
				// id-ce-basicConstraints (2.5.29.19)
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Critical: true,
				Value:    bcBytes,
			},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, signer)
	if err != nil {
		return nil, fmt.Errorf("ca: x509.CreateCertificateRequest: %w", err)
	}

	if err := commit(changed, nil); err != nil && !errors.Is(err, storage.ErrRolledBack) {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}), nil
}

// ImportCertificateChain imports a PEM-encoded CA certificate chain (starting
// with the issuing CA certificate matching the stored CA private key, followed
// by any intermediate or root CA certificates).
func (c *CA) ImportCertificateChain(pemData []byte) (retErr error) {
	var certs []*x509.Certificate
	var rawChain [][]byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("ca: unexpected PEM block type %q (expected CERTIFICATE)", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("ca: parse certificate: %w", err)
		}
		certs = append(certs, cert)
		rawChain = append(rawChain, slices.Clone(block.Bytes))
	}
	if len(certs) == 0 {
		return errors.New("ca: no PEM CERTIFICATE blocks found")
	}

	now := time.Now().UTC()
	for i, cert := range certs {
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return fmt.Errorf("ca: certificate %d in chain is not a CA certificate (IsCA is false)", i)
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("ca: certificate %d in chain does not have KeyUsageCertSign", i)
		}
		if i > 0 && (cert.MaxPathLenZero || (cert.MaxPathLen > 0 && cert.MaxPathLen < i)) {
			return fmt.Errorf("ca: certificate %d in chain violates MaxPathLen constraint", i)
		}
		if now.Before(cert.NotBefore) {
			return fmt.Errorf("ca: certificate %d in chain is not valid until %s", i, cert.NotBefore.Format(time.RFC3339))
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("ca: certificate %d in chain expired at %s", i, cert.NotAfter.Format(time.RFC3339))
		}
	}
	leaf := certs[0]

	for i := 0; i < len(certs)-1; i++ {
		if !bytes.Equal(certs[i].RawIssuer, certs[i+1].RawSubject) {
			return fmt.Errorf("ca: certificate %d issuer does not match certificate %d subject", i, i+1)
		}
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return fmt.Errorf("ca: certificate %d in chain is not signed by certificate %d: %w", i, i+1, err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var st caState
	commit, err := c.store.OpenForUpdate(c.file, &st)
	if err != nil {
		return err
	}
	defer func() {
		if err := commit(false, &retErr); err != nil && !errors.Is(err, storage.ErrRolledBack) && !errors.Is(err, storage.ErrAlreadyCommitted) && retErr == nil {
			retErr = err
		}
		wipe(st.PrivateKey)
	}()

	if len(st.PrivateKey) == 0 {
		return errors.New("ca: no CA private key in storage (run --generate-csr first)")
	}
	signer, err := c.parsePrivateKey(st.PrivateKey, st.TPMBacked)
	if err != nil {
		return err
	}
	if !keysEqual(leaf.PublicKey, signer.Public()) {
		return errors.New("ca: imported certificate public key does not match stored CA private key")
	}

	st.CertChain = rawChain
	if st.Revoked == nil {
		st.Revoked = make(map[string]revocationEntry)
	}
	if err := commit(true, nil); err != nil {
		return err
	}
	c.certs = certs
	return nil
}

// ExportCertificatesPEM returns the CA certificate chain encoded as PEM.
func (c *CA) ExportCertificatesPEM() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.certs) == 0 {
		return nil, errors.New("ca: CA certificate is not initialized")
	}
	var buf bytes.Buffer
	for _, cert := range c.certs {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (c *CA) generateKey(keyType string) (crypto.Signer, []byte, error) {
	kt := strings.ToLower(strings.TrimSpace(keyType))
	if c.tpm != nil {
		switch kt {
		case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
			var crv elliptic.Curve
			switch kt {
			case "ecdsa-p256":
				crv = elliptic.P256()
			case "ecdsa-p384":
				crv = elliptic.P384()
			case "ecdsa-p521":
				crv = elliptic.P521()
			}
			key, err := c.tpm.CreateKey(tpm.WithECC(crv), tpm.WithSigningOnly())
			if err != nil {
				return nil, nil, fmt.Errorf("ca: tpm.CreateKey(%s): %w", kt, err)
			}
			keyBytes, err := key.Marshal()
			if err != nil {
				return nil, nil, err
			}
			return key, keyBytes, nil

		case "rsa-2048", "rsa-3072", "rsa-4096":
			var bits int
			switch kt {
			case "rsa-2048":
				bits = 2048
			case "rsa-3072":
				bits = 3072
			case "rsa-4096":
				bits = 4096
			}
			key, err := c.tpm.CreateKey(tpm.WithRSA(bits), tpm.WithSigningOnly())
			if err != nil {
				return nil, nil, fmt.Errorf("ca: tpm.CreateKey(%s): %w", kt, err)
			}
			keyBytes, err := key.Marshal()
			if err != nil {
				return nil, nil, err
			}
			return key, keyBytes, nil

		default:
			return nil, nil, fmt.Errorf("ca: unsupported TPM key type %q (supported: ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-2048, rsa-3072, rsa-4096)", keyType)
		}
	}

	var priv crypto.Signer
	var err error
	switch kt {
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa-p256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ecdsa-p521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "rsa-2048":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, nil, fmt.Errorf("ca: unsupported key type %q (supported: ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-2048, rsa-3072, rsa-4096, ed25519)", keyType)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate key: %w", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: marshal private key: %w", err)
	}
	return priv, keyBytes, nil
}

func (c *CA) parsePrivateKey(keyBytes []byte, tpmBacked bool) (crypto.Signer, error) {
	if len(keyBytes) == 0 {
		return nil, errors.New("ca: private key is empty")
	}
	if tpmBacked {
		if c.tpm == nil {
			return nil, errors.New("ca: CA key is TPM-backed, but TPM is not configured")
		}
		return c.tpm.UnmarshalKey(keyBytes)
	}
	pk, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse PKCS#8 private key: %w", err)
	}
	signer, ok := pk.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ca: unexpected private key type %T", pk)
	}
	return signer, nil
}

func keysEqual(a, b crypto.PublicKey) bool {
	derA, errA := x509.MarshalPKIXPublicKey(a)
	derB, errB := x509.MarshalPKIXPublicKey(b)
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(derA, derB)
}

func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki)
	return sum[:], nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
