// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// KeyPair is a self-signed certificate for a service provider's signing key.
type KeyPair struct {
	PrivateKeyPEM  string
	CertificatePEM string
	Certificate    *x509.Certificate
	PrivateKey     *rsa.PrivateKey
}

func (k KeyPair) Fingerprint256() string {
	sum := sha256.Sum256(k.Certificate.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func (k KeyPair) ValidTo() string {
	stamp := k.Certificate.NotAfter.UTC().Format("Jan 02 15:04:05 2006 GMT")
	return strings.ReplaceAll(stamp, " 0", "  ")
}

// CreateSelfSignedKeyPair writes an RSA key and a self-signed certificate.
func CreateSelfSignedKeyPair(commonName string, days, bits int) (*KeyPair, error) {
	if days <= 0 {
		days = 1095
	}
	if bits == 0 {
		bits = 3072
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().UTC().Add(-60 * time.Second)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PrivateKeyPEM:  privateKeyPEM(key),
		CertificatePEM: certificatePEM(cert),
		Certificate:    cert,
		PrivateKey:     key,
	}, nil
}

func loadPrivateKey(pemText string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key cannot sign")
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unrecognized private key")
}

func loadCertificate(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certificatePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func privateKeyPEM(key *rsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func rsaPrivate(key crypto.Signer) (*rsa.PrivateKey, string) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, ""
	case *ecdsa.PrivateKey:
		return nil, "ec"
	case ed25519.PrivateKey:
		return nil, "ed25519"
	default:
		return nil, fmt.Sprintf("%T", key)
	}
}

func samePublic(key *rsa.PrivateKey, cert *x509.Certificate) bool {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	return key.N.Cmp(pub.N) == 0 && key.E == pub.E
}

func certDERBody(cert *x509.Certificate) string {
	return pemBody(certificatePEM(cert))
}
