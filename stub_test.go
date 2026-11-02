// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
)

const (
	idpEntity = "https://idp.test/saml2"
	spEntity  = "https://sp.test/saml/metadata"
	acsURL    = "https://sp.test/saml/acs"
	ssoURL    = "https://idp.test/saml2/sso"
)

var (
	spPair   *KeyPair
	idpPair  *KeyPair
	txKey    *rsa.PrivateKey
	otherKey *rsa.PrivateKey
)

func TestMain(m *testing.M) {
	var err error
	spPair, err = CreateSelfSignedKeyPair("sp.test", 30, 2048)
	if err != nil {
		panic(err)
	}
	idpPair, err = CreateSelfSignedKeyPair("idp.test", 30, 2048)
	if err != nil {
		panic(err)
	}
	txKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	otherKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func isoOff(ms int) string {
	return time.Now().UTC().Add(time.Duration(ms) * time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func idpMetadata(ars string) string {
	if ars == "" {
		ars = "https://idp.test/saml2/ars"
	}
	return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + idpEntity + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + pemBody(idpPair.CertificatePEM) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="` + ars + `" index="0" isDefault="true"/>` +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + ssoURL + `"/>` +
		`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + ssoURL + `"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`
}

func testConfig(extra map[string]any, ars string) map[string]any {
	out := map[string]any{
		"entityId":    spEntity,
		"acsUrl":      acsURL,
		"privateKey":  spPair.PrivateKeyPEM,
		"certificate": spPair.CertificatePEM,
		"idpMetadata": idpMetadata(ars),
	}
	for key, value := range extra {
		out[key] = value
	}
	return out
}

func mustSP(t *testing.T, extra map[string]any, ars string) *ServiceProvider {
	t.Helper()
	sp, err := Create(testConfig(extra, ars), "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return sp
}

func rejects(t *testing.T, fn func() error, code, pattern string) {
	t.Helper()
	err := fn()
	var samlErr *SamlError
	if !errors.As(err, &samlErr) {
		t.Fatalf("expected SamlError, got %v", err)
	}
	if samlErr.Code != code {
		t.Fatalf("code %s, want %s: %s", samlErr.Code, code, samlErr.Message)
	}
	if pattern != "" && !regexp.MustCompile(pattern).MatchString(samlErr.Error()) {
		t.Fatalf("message %q does not match %s", samlErr.Error(), pattern)
	}
}

type assertionOpt struct {
	inResponseTo   string
	nameID         string
	audience       string
	recipient      string
	notOnOrAfterMS int
	hasExpiry      bool
	issuer         string
	extra          string
}

func assertionXML(o assertionOpt) (string, string) {
	aid := newID()
	irt := ""
	if o.inResponseTo != "" {
		irt = ` InResponseTo="` + o.inResponseTo + `"`
	}
	name := o.nameID
	if name == "" {
		name = "alice-1234"
	}
	audience := o.audience
	if audience == "" {
		audience = spEntity
	}
	recipient := o.recipient
	if recipient == "" {
		recipient = acsURL
	}
	expiry := 300000
	if o.hasExpiry {
		expiry = o.notOnOrAfterMS
	}
	issuer := o.issuer
	if issuer == "" {
		issuer = idpEntity
	}
	xml := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + aid + `" Version="2.0" IssueInstant="` + isoOff(0) + `">` +
		`<saml:Issuer>` + issuer + `</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` + name + `</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<saml:SubjectConfirmationData Recipient="` + recipient + `" NotOnOrAfter="` + isoOff(expiry) + `"` + irt + `/>` +
		`</saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="` + isoOff(-5000) + `" NotOnOrAfter="` + isoOff(expiry) + `">` +
		`<saml:AudienceRestriction><saml:Audience>` + audience + `</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="` + isoOff(-1000) + `" SessionIndex="_session1"><saml:AuthnContext>` +
		`<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>` +
		`</saml:AuthnContext></saml:AuthnStatement>` +
		`<saml:AttributeStatement><saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail">` +
		`<saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>` +
		`<saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>` +
		o.extra + `</saml:AttributeStatement></saml:Assertion>`
	return xml, aid
}

func signXML(xml, id string, key *rsa.PrivateKey, cert *x509.Certificate) string {
	if key == nil {
		key = idpPair.PrivateKey
	}
	if cert == nil {
		cert = idpPair.Certificate
	}
	signed, err := signEnveloped(xml, id, key, cert)
	if err != nil {
		shown := xml
		if len(shown) > 180 {
			shown = shown[:180]
		}
		panic(err.Error() + " :: " + shown)
	}
	return signed
}

func signedAssertion(o assertionOpt) (string, string) {
	xml, id := assertionXML(o)
	return signXML(xml, id, nil, nil), id
}

type responseOpt struct {
	inResponseTo    string
	sign            bool
	assertion       string
	hasAssertion    bool
	status          string
	destination     string
	hasDestination  bool
	omitDestination bool
	issuer          string
}

func responseXML(o responseOpt) string {
	rid := newID()
	irt := ""
	if o.inResponseTo != "" {
		irt = ` InResponseTo="` + o.inResponseTo + `"`
	}
	dest := ""
	if !o.omitDestination {
		value := acsURL
		if o.hasDestination {
			value = o.destination
		}
		dest = ` Destination="` + value + `"`
	}
	status := o.status
	if status == "" {
		status = "urn:oasis:names:tc:SAML:2.0:status:Success"
	}
	assertion := o.assertion
	if !o.hasAssertion {
		if strings.HasSuffix(status, "Success") {
			assertion, _ = signedAssertion(assertionOpt{inResponseTo: o.inResponseTo})
		} else {
			assertion = ""
		}
	}
	issuer := o.issuer
	if issuer == "" {
		issuer = idpEntity
	}
	xml := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + rid + `" Version="2.0" IssueInstant="` + isoOff(0) + `"` + dest + irt + `>` +
		`<saml:Issuer>` + issuer + `</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="` + status + `"/></samlp:Status>` +
		assertion + `</samlp:Response>`
	if o.sign {
		return signXML(xml, rid, nil, nil)
	}
	return xml
}

func encryptAssertion(assertion, cipherName, transport, wrapper string) string {
	if cipherName == "" {
		cipherName = "aes-256-gcm"
	}
	if transport == "" {
		transport = "mgf1p"
	}
	if wrapper == "" {
		wrapper = "EncryptedAssertion"
	}
	keyLen := 32
	if cipherName != "aes-256-gcm" {
		keyLen = 16
	}
	key := make([]byte, keyLen)
	_, _ = rand.Read(key)
	var blob []byte
	var alg string
	if cipherName == "aes-256-gcm" {
		iv := make([]byte, 12)
		_, _ = rand.Read(iv)
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		blob = append(iv, gcm.Seal(nil, iv, []byte(assertion), nil)...)
		alg = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	} else {
		iv := make([]byte, 16)
		_, _ = rand.Read(iv)
		plain := []byte(assertion)
		pad := 16 - (len(plain) % 16)
		plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		out := make([]byte, len(plain))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
		blob = append(iv, out...)
		alg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	}
	var digest hash.Hash
	if transport == "mgf1p" {
		digest = sha1.New()
	} else {
		digest = sha256.New()
	}
	wrapped, err := rsa.EncryptOAEP(digest, rand.Reader, &spPair.PrivateKey.PublicKey, key, nil)
	if err != nil {
		panic(err)
	}
	keyMethod := `<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>`
	if transport != "mgf1p" {
		keyMethod = `<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">` +
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
			`<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>` +
			`</xenc:EncryptionMethod>`
	}
	return `<saml:` + wrapper + ` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
		`<xenc:EncryptionMethod Algorithm="` + alg + `"/>` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>` + keyMethod +
		`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(wrapped) + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(blob) + `</xenc:CipherValue></xenc:CipherData>` +
		`</xenc:EncryptedData></saml:` + wrapper + `>`
}

func redirectResponseQuery(xml, relay string, key *rsa.PrivateKey) string {
	if key == nil {
		key = idpPair.PrivateKey
	}
	parts := []string{"SAMLResponse=" + uriEscape(base64.StdEncoding.EncodeToString(mustDeflate(xml)))}
	if relay != "" {
		parts = append(parts, "RelayState="+uriEscape(relay))
	}
	parts = append(parts, "SigAlg="+uriEscape(rsaSHA256))
	signed := strings.Join(parts, "&")
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signed + "&Signature=" + uriEscape(base64.StdEncoding.EncodeToString(sig))
}

func mustDeflate(xml string) []byte {
	out, err := deflateRaw([]byte(xml))
	if err != nil {
		panic(err)
	}
	return out
}

func artifactFor(entity string) string {
	if entity == "" {
		entity = idpEntity
	}
	out := make([]byte, 44)
	out[0] = 0
	out[1] = 4
	sum := sha1.Sum([]byte(entity))
	copy(out[4:24], sum[:])
	_, _ = rand.Read(out[24:])
	return base64.StdEncoding.EncodeToString(out)
}

type arsServer struct {
	mu       sync.Mutex
	store    map[string]string
	resolved []string
	url      string
	listener net.Listener
	server   *http.Server
}

func (a *arsServer) put(artifact, response string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.store[artifact] = response
}

func (a *arsServer) close() {
	_ = a.server.Close()
}

func startARS(t *testing.T) *arsServer {
	t.Helper()
	holder := &arsServer{store: map[string]string{}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ars", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		ok := false
		resolveID := ""
		artifact := ""
		root, err := parseXML(string(raw), "the ArtifactResolve")
		if err == nil {
			found := descendants(root, nsSamlp, "ArtifactResolve")
			if len(found) > 0 {
				body := found[0]
				resolveID = attrOr(body, "ID")
				arts := children(body, nsSamlp, "Artifact")
				if len(arts) > 0 {
					artifact = strings.TrimSpace(iterText(arts[0]))
				}
				signed, err := verifySigned(body, []*x509.Certificate{spPair.Certificate}, "the ArtifactResolve")
				ok = err == nil && signed != ""
			}
		}
		holder.mu.Lock()
		message := ""
		if ok {
			message = holder.store[artifact]
			delete(holder.store, artifact)
			if message != "" {
				holder.resolved = append(holder.resolved, artifact)
			}
		}
		holder.mu.Unlock()
		answer := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` +
			`<samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + newID() + `" Version="2.0" IssueInstant="` + isoOff(0) + `" InResponseTo="` + resolveID + `">` +
			`<saml:Issuer>` + idpEntity + `</saml:Issuer>` +
			`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
			message + `</samlp:ArtifactResponse></soap:Body></soap:Envelope>`
		w.Header().Set("content-type", "text/xml")
		_, _ = w.Write([]byte(answer))
	})
	holder.listener = listener
	holder.server = &http.Server{Handler: mux}
	go holder.server.Serve(listener)
	holder.url = "http://" + listener.Addr().String() + "/ars"
	return holder
}

func postACS(sp *ServiceProvider, xml string, requestID string, relay *string) (*SamlLogin, error) {
	body := map[string]string{"SAMLResponse": base64.StdEncoding.EncodeToString([]byte(xml))}
	if relay != nil {
		body["RelayState"] = *relay
	}
	var ids []string
	if requestID != "" {
		ids = []string{requestID}
	}
	return sp.Acs("POST", "/saml/acs", body, ids)
}

func verifyOK(root *etree.Element, cert *x509.Certificate) bool {
	signed, err := verifySigned(root, []*x509.Certificate{cert}, "the message")
	return err == nil && signed != ""
}
