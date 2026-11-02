// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

// idpCa: the install script writes the whole listener CA trust chain to the
// file the parameter names, and the library takes that file as its trust store,
// verifying the host name and refusing a forged leaf in front of the real CAs.
//
// The stub identity provider is HTTPS on a four-certificate chain shaped like
// iya-sts's (leaf, TLS Issuing CA, Intermediate, Root) and publishes it, leaf
// first, at GET /tls/server-certificate. The scripts run with the test image's
// python3 and openssl (Dockerfile, test stage).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	defaultIdpCa  = "file:generated/idp-ca.pem"
	idpCaFile     = "generated/idp-ca.pem"
	stubMetadata  = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://stub.example/idp"/>`
	stubMetaPath  = "/saml2/metadata/demo"
	stubChainPath = "/tls/server-certificate"
)

type chainCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func makeChainCert(t *testing.T, cn string, issuer *chainCert, ca bool, ip string) *chainCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &chainCert{cert: cert, key: key, pem: string(block)}
}

type stsChain struct {
	root, intermediate, issuing, leaf *chainCert
	published                         string
}

func newStsChain(t *testing.T) stsChain {
	t.Helper()
	root := makeChainCert(t, "sts Root CA", nil, true, "")
	intermediate := makeChainCert(t, "sts Intermediate CA", root, true, "")
	issuing := makeChainCert(t, "sts TLS Issuing CA", intermediate, true, "")
	// The leaf names only IP 127.0.0.1, so "localhost" is the wrong name.
	leaf := makeChainCert(t, "127.0.0.1", issuing, false, "127.0.0.1")
	return stsChain{
		root: root, intermediate: intermediate, issuing: issuing, leaf: leaf,
		published: leaf.pem + issuing.pem + intermediate.pem + root.pem,
	}
}

// startStub serves HTTPS with the leaf followed by presented (the CAs the
// handshake sends), publishes published at /tls/server-certificate, and
// answers IdP metadata at stubMetaPath. It returns https://127.0.0.1:<port>.
func startStub(t *testing.T, leaf *chainCert, presented []*chainCert, published string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(stubChainPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte(published))
	})
	mux.HandleFunc(stubMetaPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(stubMetadata))
	})
	chain := [][]byte{leaf.cert.Raw}
	for _, ca := range presented {
		chain = append(chain, ca.cert.Raw)
	}
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leaf.key}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

func (c stsChain) start(t *testing.T) string {
	return startStub(t, c.leaf, []*chainCert{c.issuing, c.intermediate}, c.published)
}

// chainDemoDir copies the shipped demo/saml.json into a temp demo/ with a key
// pair in generated/, so the install script never generates one. idpMetadata
// stays the shipped file path: the install script writes it.
func chainDemoDir(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("demo", "saml.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	delete(config, "ssf")
	dir := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(dir, "generated"), 0o755); err != nil {
		t.Fatal(err)
	}
	pair, err := CreateSelfSignedKeyPair("saml2-sp test", 1, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "generated", "sp.key"), []byte(pair.PrivateKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "generated", "sp.crt"), []byte(pair.CertificatePEM), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(dir, "saml.json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fakeSaml2Sp puts a saml2-sp on PATH that prints stand-in metadata, so the
// install script reaches its admin-secret check without `go run`.
func fakeSaml2Sp(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\necho '<md:EntityDescriptor/>'\n"
	if err := os.WriteFile(filepath.Join(bin, "saml2-sp"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")
}

func runPython(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("python3 is not on PATH; run the suite with docker build --target test .")
	}
	abs := make([]string, 0, len(args))
	for i, arg := range args {
		if i == 0 {
			arg, _ = filepath.Abs(arg)
		}
		abs = append(abs, arg)
	}
	cmd := exec.Command("python3", abs...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func fingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	parts := make([]string, len(digest))
	for i, b := range digest {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func TestShippedDemoNamesGeneratedIdpCaPem(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("demo", "saml.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if config["idpCa"] != defaultIdpCa {
		t.Fatalf("idpCa %v", config["idpCa"])
	}
}

func TestInstallScriptWritesWholeChainToIdpCa(t *testing.T) {
	chain := newStsChain(t)
	origin := chain.start(t)
	dir := chainDemoDir(t)
	target := filepath.Join(dir, idpCaFile)
	// A stale single certificate is replaced: the chain is written every run.
	if err := os.WriteFile(target, []byte(chain.root.pem), 0o644); err != nil {
		t.Fatal(err)
	}
	// No admin secret: the install script saves the chain first, then stops
	// at the missing secret. The chain is what this test is about.
	out, err := runPython(t, []string{"ADMIN_API_CLIENT_SECRET=", "STS_ADMIN_API_CLIENT_SECRET=", fakeSaml2Sp(t)},
		"scripts/configure_iya_sts.py", "--config", filepath.Join(dir, "saml.json"), "--idp", origin, "--public-url", "http://127.0.0.1:3000")
	if err == nil {
		t.Fatalf("the install script ran on without an admin secret:\n%s", out)
	}
	saved, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("no chain at %s: %v\n%s", target, readErr, out)
	}
	if string(saved) != chain.published {
		t.Fatalf("saved chain is not the published one:\n%s\n%s", saved, out)
	}
	if strings.Count(string(saved), "BEGIN CERTIFICATE") != 4 {
		t.Fatalf("saved %d certificates", strings.Count(string(saved), "BEGIN CERTIFICATE"))
	}
	if !strings.Contains(out, "(4 certificate(s)) to "+target) || !strings.Contains(out, "CN=sts Root CA") {
		t.Fatalf("output does not name the path and the anchor:\n%s", out)
	}
	if !strings.Contains(out, "sha256 "+fingerprint(chain.root.cert)) {
		t.Fatalf("output does not carry the anchor's SHA-256:\n%s", out)
	}
}

func TestInstallScriptFallsBackToHandshakeChain(t *testing.T) {
	chain := newStsChain(t)
	// /tls/server-certificate answers nothing usable: the handshake's chain
	// (leaf, Issuing, Intermediate, and here the Root too) is saved instead.
	origin := startStub(t, chain.leaf, []*chainCert{chain.issuing, chain.intermediate, chain.root}, "")
	dir := chainDemoDir(t)
	out, err := runPython(t, nil, "scripts/trust_chain.py", "--config", filepath.Join(dir, "saml.json"), "--idp", origin)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	saved, err := os.ReadFile(filepath.Join(dir, idpCaFile))
	if err != nil || string(saved) != chain.published {
		t.Fatalf("the handshake chain was not saved: %v\n%s\n%s", err, saved, out)
	}
}

// libraryTrust resolves the demo config the way the demo does and returns the
// TLS options the service provider dials the identity provider with.
func libraryTrust(t *testing.T, dir string) *TLSOptions {
	t.Helper()
	config, err := ReadConfigFile(filepath.Join(dir, "saml.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	options := (&ServiceProvider{Config: config}).tls()
	if options == nil || options.CA == "" {
		t.Fatal("idpCa did not resolve to the saved chain")
	}
	return options
}

func TestLibraryTrustsProviderThroughSavedFile(t *testing.T) {
	chain := newStsChain(t)
	origin := chain.start(t)
	dir := chainDemoDir(t)
	url := origin + stubMetaPath
	if _, err := send(url, "GET", nil, "", nil, "metadata"); err == nil {
		t.Fatal("the stub was trusted without idpCa")
	}
	if out, err := runPython(t, nil, "scripts/trust_chain.py", "--config", filepath.Join(dir, "saml.json"), "--idp", origin); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	options := libraryTrust(t, dir)
	if options.CA != chain.published {
		t.Fatal("idpCa resolved to something other than the saved chain")
	}
	answer, err := send(url, "GET", nil, "", options, "metadata")
	if err != nil {
		t.Fatal(err)
	}
	if answer.Status != 200 || answer.Body != stubMetadata {
		t.Fatalf("metadata answered %d %s", answer.Status, answer.Body)
	}
	// The root alone is enough: every PEM block of the file is a trust anchor,
	// not only the first (which is the leaf).
	if _, err := send(url, "GET", nil, "", &TLSOptions{CA: chain.root.pem}, "metadata"); err != nil {
		t.Fatalf("root only: %v", err)
	}
}

func TestLibraryVerifiesTheHostName(t *testing.T) {
	chain := newStsChain(t)
	origin := chain.start(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin, "https://"))
	options := &TLSOptions{CA: chain.published}
	if _, err := send("https://127.0.0.1:"+port+stubMetaPath, "GET", nil, "", options, "metadata"); err != nil {
		t.Fatalf("127.0.0.1 through the IP SAN: %v", err)
	}
	// Right chain, wrong name: the leaf names only IP 127.0.0.1, not localhost.
	_, err := send("https://localhost:"+port+stubMetaPath, "GET", nil, "", options, "metadata")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("localhost was accepted on a 127.0.0.1-only certificate: %v", err)
	}
}

func TestLibraryRefusesForgedLeafBeforeRealCAs(t *testing.T) {
	chain := newStsChain(t)
	forger := makeChainCert(t, "forger CA", nil, true, "")
	forged := makeChainCert(t, "127.0.0.1", forger, false, "127.0.0.1")
	// The forged leaf, followed by the real Issuing and Intermediate CAs.
	origin := startStub(t, forged, []*chainCert{chain.issuing, chain.intermediate}, chain.published)
	if _, err := send(origin+stubMetaPath, "GET", nil, "", &TLSOptions{CA: chain.published}, "metadata"); err == nil {
		t.Fatal("a forged leaf in front of the real CA certificates was trusted")
	}
}
