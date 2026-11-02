// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

func TestRefusesAConfigurationWithoutAKeyOrWithAnotherCertificate(t *testing.T) {
	bad := testConfig(nil, "")
	bad["privateKey"] = nil
	rejects(t, func() error { _, err := Create(bad, "", nil); return err }, "config", "privateKey")
	rejects(t, func() error {
		_, err := Create(testConfig(map[string]any{"certificate": idpPair.CertificatePEM}, ""), "", nil)
		return err
	}, "config", "not for the private key")
}

func TestReadsTheIdentityProviderFromItsMetadata(t *testing.T) {
	sp := mustSP(t, nil, "")
	if sp.Idp.EntityID != idpEntity {
		t.Fatalf("entity %s", sp.Idp.EntityID)
	}
	if sp.Idp.SSO["redirect"] != ssoURL {
		t.Fatalf("sso %s", sp.Idp.SSO["redirect"])
	}
	if len(sp.Idp.Certs) != 1 {
		t.Fatalf("certs %d", len(sp.Idp.Certs))
	}
}

func TestWritesMetadataWithASignedRequestsKeyAndTheAcsOnAllThreeBindings(t *testing.T) {
	sp := mustSP(t, nil, "")
	xml := sp.Metadata()
	root, err := parseXML(xml, "metadata")
	if err != nil {
		t.Fatal(err)
	}
	acs := descendants(root, nsMd, "AssertionConsumerService")
	var bindings []string
	for _, item := range acs {
		binding := attrOr(item, "Binding")
		bindings = append(bindings, binding[strings.LastIndex(binding, ":")+1:])
		if attrOr(item, "Location") != acsURL {
			t.Fatalf("location %s", attrOr(item, "Location"))
		}
	}
	if strings.Join(bindings, ",") != "HTTP-POST,HTTP-Redirect,HTTP-Artifact" {
		t.Fatalf("bindings %v", bindings)
	}
	if !regexp.MustCompile(`AuthnRequestsSigned="true"`).MatchString(xml) {
		t.Fatal(xml)
	}
	if !regexp.MustCompile(`<md:KeyDescriptor use="encryption">[\s\S]*xmlenc11#aes256-gcm[\s\S]*</md:KeyDescriptor>`).MatchString(xml) {
		t.Fatal("encryption descriptor")
	}
}

func TestOmitsSignalsUnlessItIsFalse(t *testing.T) {
	sp := mustSP(t, nil, "")
	if sp.Config.Has("signals") {
		t.Fatal("signals present")
	}
	if sp.Config.EntityID != spEntity || sp.Config.AcsURL != acsURL || sp.Config.RequestBinding != "redirect" || sp.Config.ResponseBinding != "post" {
		t.Fatalf("%+v", sp.Config)
	}
	explicit := mustSP(t, map[string]any{"signals": true}, "")
	if explicit.Config.Has("signals") {
		t.Fatal("explicit true stored")
	}
	if explicit.Config.EntityID != sp.Config.EntityID || explicit.Config.AcsURL != sp.Config.AcsURL {
		t.Fatal("endpoints changed")
	}
}

func TestRecordsSignalsFalseAndStillResolvesTheSamlFields(t *testing.T) {
	sp := mustSP(t, map[string]any{"signals": false, "wantAssertionsEncrypted": true}, "")
	if sp.Config.Signals == nil || *sp.Config.Signals {
		t.Fatal("signals false missing")
	}
	if sp.Config.EntityID != spEntity || sp.Config.AcsURL != acsURL || sp.Config.RequestBinding != "redirect" || sp.Config.ResponseBinding != "post" {
		t.Fatal("saml fields")
	}
	if !sp.Config.WantAssertionsSigned || !sp.Config.WantAssertionsEncrypted || sp.Config.AllowUnsolicited || sp.Config.ClockSkewMS != 60000 {
		t.Fatalf("%+v", sp.Config)
	}
	if sp.Idp.EntityID != idpEntity {
		t.Fatal(sp.Idp.EntityID)
	}
}

func TestRefusesASignalsValueThatIsNotTrueOrFalse(t *testing.T) {
	rejects(t, func() error {
		_, err := Create(testConfig(map[string]any{"signals": "no"}, ""), "", nil)
		return err
	}, "config", `^signals must be true or false$`)
}

func TestRedirectAuthnRequestIsDeflatedAndSigned(t *testing.T) {
	sp := mustSP(t, nil, "")
	home := "/home"
	req, err := sp.Login(LoginOptions{RelayState: &home})
	if err != nil {
		t.Fatal(err)
	}
	if req.Binding != "redirect" || !strings.HasPrefix(req.URL, ssoURL+"?") {
		t.Fatalf("%s %s", req.Binding, req.URL)
	}
	raw := strings.SplitN(req.URL, "?", 2)[1]
	parts := strings.SplitN(raw, "&Signature=", 2)
	sig, err := url.PathUnescape(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0]))
	if err := rsa.VerifyPKCS1v15(&spPair.PrivateKey.PublicKey, crypto.SHA256, sum[:], mustB64(sig)); err != nil {
		t.Fatal(err)
	}
	query, _ := url.ParseQuery(raw)
	inflated, err := inflateRaw(mustB64(query.Get("SAMLRequest")))
	if err != nil {
		t.Fatal(err)
	}
	xml := string(inflated)
	if !strings.Contains(xml, `ID="`+req.ID+`"`) || !strings.Contains(xml, `ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`) || !strings.Contains(xml, `Destination="`+ssoURL+`"`) {
		t.Fatal(xml)
	}
	if query.Get("RelayState") != "/home" {
		t.Fatal(query.Get("RelayState"))
	}
}

func mustB64(value string) []byte {
	out, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return out
}

func TestPostAuthnRequestIsAnEnvelopedSignatureInAForm(t *testing.T) {
	sp := mustSP(t, map[string]any{"requestBinding": "post"}, "")
	req, err := sp.Login(LoginOptions{ResponseBinding: "artifact", Nonce: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Binding != "post" {
		t.Fatal(req.Binding)
	}
	xml := string(mustB64(req.Fields["SAMLRequest"]))
	if !regexp.MustCompile(`<saml:Issuer>[^<]+</saml:Issuer><ds:Signature`).MatchString(xml) || !strings.Contains(xml, "HTTP-Artifact") {
		t.Fatal(xml)
	}
	root, err := parseXML(xml, "the AuthnRequest")
	if err != nil || !verifyOK(root, spPair.Certificate) {
		shown := xml
		if len(shown) > 600 {
			shown = shown[:600]
		}
		t.Fatalf("verify %v\n%s", err, shown)
	}
	if !regexp.MustCompile(`<script nonce="abc">`).MatchString(req.HTML) || !regexp.MustCompile(`<button type="submit">`).MatchString(req.HTML) {
		t.Fatal(req.HTML)
	}
}

func TestSubjectHintFollowsTheIssuerAndItsSignature(t *testing.T) {
	sp := mustSP(t, map[string]any{"requestBinding": "post"}, "")
	hint := "alice<&>"
	format := "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	req, err := sp.Login(LoginOptions{SubjectHint: &hint, SubjectHintFormat: &format, ForceAuthn: true})
	if err != nil {
		t.Fatal(err)
	}
	xml := string(mustB64(req.Fields["SAMLRequest"]))
	if !regexp.MustCompile(`</ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice&lt;&amp;&gt;</saml:NameID></saml:Subject><samlp:NameIDPolicy`).MatchString(xml) {
		t.Fatal(xml)
	}
	if !strings.Contains(xml, `ForceAuthn="true"`) {
		t.Fatal("force")
	}
	root, err := parseXML(xml, "the AuthnRequest")
	if err != nil || !verifyOK(root, spPair.Certificate) {
		t.Fatal(err)
	}
	plain, err := sp.Login(LoginOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.XML, "<saml:Subject>") {
		t.Fatal(plain.XML)
	}
}

func TestRefusesARelayStateOver80Bytes(t *testing.T) {
	sp := mustSP(t, nil, "")
	relay := strings.Repeat("x", 81)
	_, err := sp.Login(LoginOptions{RelayState: &relay})
	var samlErr *SamlError
	if err == nil || !errorsAs(err, &samlErr) || !strings.Contains(samlErr.Error(), "80 bytes") {
		t.Fatal(err)
	}
}

func errorsAs(err error, target **SamlError) bool {
	if err == nil {
		return false
	}
	found, ok := err.(*SamlError)
	if ok {
		*target = found
		return true
	}
	return false
}

func TestSignedResponseAndSignedAssertion(t *testing.T) {
	sp := mustSP(t, nil, "")
	home := "/home"
	who, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_req1", sign: true}), "_req1", &home)
	if err != nil {
		t.Fatal(err)
	}
	if who.NameID != "alice-1234" || who.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" || who.SessionIndex != "_session1" {
		t.Fatalf("%+v", who)
	}
	if who.RelayState == nil || *who.RelayState != "/home" || who.Binding != "post" {
		t.Fatalf("relay/binding %+v", who)
	}
	if strings.Join(who.Attributes["groups"], ",") != "staff,admins" {
		t.Fatal(who.Attributes["groups"])
	}
	mail := "urn:oid:0.9.2342.19200300.100.1.3"
	if strings.Join(who.Attributes[mail], ",") != "alice@example.com" || who.AttributeFriendlyNames[mail] != "mail" {
		t.Fatal(who.Attributes, who.AttributeFriendlyNames)
	}
	if who.AuthnContextClassRef != "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" {
		t.Fatal(who.AuthnContextClassRef)
	}
}

func TestAcceptsASignedAssertionInAnUnsignedResponse(t *testing.T) {
	sp := mustSP(t, nil, "")
	who, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_req1"}), "_req1", nil)
	if err != nil || who.NameID != "alice-1234" {
		t.Fatal(err, who)
	}
}

func TestRefusesAnUnsignedAssertionByDefault(t *testing.T) {
	sp := mustSP(t, nil, "")
	raw, _ := assertionXML(assertionOpt{inResponseTo: "_r"})
	xml := responseXML(responseOpt{inResponseTo: "_r", sign: true, assertion: raw, hasAssertion: true})
	rejects(t, func() error { _, err := postACS(sp, xml, "_r", nil); return err }, "validation", "not signed")
	lax := mustSP(t, map[string]any{"wantAssertionsSigned": false}, "")
	who, err := postACS(lax, xml, "_r", nil)
	if err != nil || who.NameID != "alice-1234" {
		t.Fatal(err)
	}
}

func TestRefusesAResponseWithNothingSigned(t *testing.T) {
	sp := mustSP(t, map[string]any{"wantAssertionsSigned": false}, "")
	raw, _ := assertionXML(assertionOpt{inResponseTo: "_r"})
	xml := responseXML(responseOpt{inResponseTo: "_r", assertion: raw, hasAssertion: true})
	rejects(t, func() error { _, err := postACS(sp, xml, "_r", nil); return err }, "validation", "neither")
}

func TestRefusesAnAssertionAlteredAfterItWasSigned(t *testing.T) {
	sp := mustSP(t, nil, "")
	xml := strings.Replace(responseXML(responseOpt{inResponseTo: "_r"}), "alice-1234", "mallory", 1)
	rejects(t, func() error { _, err := postACS(sp, xml, "_r", nil); return err }, "signature", "")
}

func TestRefusesASignatureByAnotherKey(t *testing.T) {
	sp := mustSP(t, nil, "")
	raw, id := assertionXML(assertionOpt{inResponseTo: "_r"})
	signed := signXML(raw, id, spPair.PrivateKey, spPair.Certificate)
	xml := responseXML(responseOpt{inResponseTo: "_r", assertion: signed, hasAssertion: true})
	rejects(t, func() error { _, err := postACS(sp, xml, "_r", nil); return err }, "signature", "does not verify")
}

func TestIsNotFooledBySignatureWrapping(t *testing.T) {
	sp := mustSP(t, nil, "")
	signed, id := signedAssertion(assertionOpt{inResponseTo: "_r"})
	forged, _ := assertionXML(assertionOpt{inResponseTo: "_r", nameID: "mallory"})
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: forged + signed, hasAssertion: true}), "_r", nil)
		return err
	}, "validation", "exactly one")
	hidden := regexp.MustCompile(`ID="[^"]+"`).ReplaceAllString(forged, `ID="`+id+`"`)
	hidden = strings.Replace(hidden, "</saml:Assertion>", "<saml:Advice>"+signed+"</saml:Advice></saml:Assertion>", 1)
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: hidden, hasAssertion: true}), "_r", nil)
		return err
	}, "signature", "two elements")
	sig := regexp.MustCompile(`<ds:Signature[\s\S]*</ds:Signature>`).FindString(signed)
	moved := regexp.MustCompile(`(</saml:Issuer>)`).ReplaceAllString(forged, "${1}"+sig)
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: moved, hasAssertion: true}), "_r", nil)
		return err
	}, "signature", "refers to")
}

func TestRefusesAResponseForAnotherAudienceAcsOrThatHasExpired(t *testing.T) {
	sp := mustSP(t, nil, "")
	audience, _ := signedAssertion(assertionOpt{inResponseTo: "_r", audience: "https://other.test"})
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: audience, hasAssertion: true}), "_r", nil)
		return err
	}, "validation", "not for")
	recipient, _ := signedAssertion(assertionOpt{inResponseTo: "_r", recipient: "https://other.test/acs"})
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: recipient, hasAssertion: true}), "_r", nil)
		return err
	}, "validation", "Recipient")
	expired, _ := signedAssertion(assertionOpt{inResponseTo: "_r", hasExpiry: true, notOnOrAfterMS: -120000})
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: expired, hasAssertion: true}), "_r", nil)
		return err
	}, "validation", "expired")
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", hasDestination: true, destination: "https://other.test/acs"}), "_r", nil)
		return err
	}, "validation", "addressed to")
	issuer, _ := signedAssertion(assertionOpt{inResponseTo: "_r", issuer: "https://evil.test"})
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: issuer, hasAssertion: true}), "_r", nil)
		return err
	}, "validation", "issued by")
}

func TestRefusesAnAnswerToAnotherRequestAndAnUnsolicitedOne(t *testing.T) {
	sp := mustSP(t, nil, "")
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r"}), "_other", nil)
		return err
	}, "validation", "not a request this browser")
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r"}), "", nil)
		return err
	}, "validation", "not a request this browser")
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{}), "", nil)
		return err
	}, "validation", "unsolicited")
	open := mustSP(t, map[string]any{"allowUnsolicited": true}, "")
	who, err := postACS(open, responseXML(responseOpt{}), "", nil)
	if err != nil || who.InResponseTo != nil {
		t.Fatal(err, who)
	}
}

func TestRefusesTheSameAssertionTwice(t *testing.T) {
	sp := mustSP(t, nil, "")
	xml := responseXML(responseOpt{inResponseTo: "_r", sign: true})
	if _, err := postACS(sp, xml, "_r", nil); err != nil {
		t.Fatal(err)
	}
	rejects(t, func() error { _, err := postACS(sp, xml, "_r", nil); return err }, "replay", "")
}

func TestReportsANonSuccessStatus(t *testing.T) {
	sp := mustSP(t, nil, "")
	_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", status: "urn:oasis:names:tc:SAML:2.0:status:Responder"}), "_r", nil)
	var samlErr *SamlError
	if !errorsAs(err, &samlErr) || samlErr.Code != "status" || samlErr.Status == nil || samlErr.Status.Code != "urn:oasis:names:tc:SAML:2.0:status:Responder" {
		t.Fatal(err)
	}
}

func TestRefusesADoctype(t *testing.T) {
	sp := mustSP(t, nil, "")
	xml := `<!DOCTYPE x [<!ENTITY e "x">]>` + responseXML(responseOpt{inResponseTo: "_r"})
	rejects(t, func() error { _, err := postACS(sp, xml, "_r", nil); return err }, "xml", "DOCTYPE")
}

func TestDecryptsAnEncryptedAssertion(t *testing.T) {
	sp := mustSP(t, nil, "")
	for _, cipherName := range []string{"aes-256-gcm", "aes-128-cbc"} {
		made, _ := signedAssertion(assertionOpt{inResponseTo: "_r"})
		who, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", sign: true, assertion: encryptAssertion(made, cipherName, "", ""), hasAssertion: true}), "_r", nil)
		if err != nil || who.NameID != "alice-1234" || !who.Encrypted {
			t.Fatalf("%s %v %+v", cipherName, err, who)
		}
	}
	made, _ := signedAssertion(assertionOpt{inResponseTo: "_r"})
	who, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: encryptAssertion(made, "aes-256-gcm", "oaep256", ""), hasAssertion: true}), "_r", nil)
	if err != nil || who.NameID != "alice-1234" {
		t.Fatal(err)
	}
}

func TestRefusesAPlaintextAssertionWhenEncryptionIsRequired(t *testing.T) {
	sp := mustSP(t, map[string]any{"wantAssertionsEncrypted": true}, "")
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", sign: true}), "_r", nil)
		return err
	}, "validation", "not encrypted")
	made, _ := signedAssertion(assertionOpt{inResponseTo: "_r"})
	who, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: encryptAssertion(made, "", "", ""), hasAssertion: true}), "_r", nil)
	if err != nil || !who.Encrypted {
		t.Fatal(err)
	}
}

func TestRefusesAnEncryptedAssertionWhoseCiphertextWasAltered(t *testing.T) {
	sp := mustSP(t, nil, "")
	made, _ := signedAssertion(assertionOpt{inResponseTo: "_r"})
	enc := encryptAssertion(made, "", "", "")
	values := regexp.MustCompile(`<xenc:CipherValue>([^<]+)</xenc:CipherValue>`).FindAllStringSubmatch(enc, -1)
	last := values[len(values)-1][1]
	blob := mustB64(last)
	blob[20] ^= 1
	rejects(t, func() error {
		_, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: strings.Replace(enc, last, base64.StdEncoding.EncodeToString(blob), 1), hasAssertion: true}), "_r", nil)
		return err
	}, "decryption", "")
}

func TestDecryptsAnEncryptedAttribute(t *testing.T) {
	sp := mustSP(t, nil, "")
	secret := encryptAssertion(`<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="employeeNumber"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>`, "aes-256-gcm", "oaep256", "EncryptedAttribute")
	raw, id := assertionXML(assertionOpt{inResponseTo: "_r", extra: secret})
	who, err := postACS(sp, responseXML(responseOpt{inResponseTo: "_r", assertion: signXML(raw, id, nil, nil), hasAssertion: true}), "_r", nil)
	if err != nil || strings.Join(who.Attributes["employeeNumber"], ",") != "E-42" {
		t.Fatal(err, who)
	}
}

func TestRedirectResponseVerifiesTheQuerySignature(t *testing.T) {
	sp := mustSP(t, nil, "")
	query := redirectResponseQuery(responseXML(responseOpt{inResponseTo: "_r"}), "/there", nil)
	who, err := sp.Acs("GET", "/saml/acs?"+query, nil, []string{"_r"})
	if err != nil || who.Binding != "redirect" || who.RelayState == nil || *who.RelayState != "/there" {
		t.Fatal(err, who)
	}
}

func TestRefusesAQuerySignatureByAnotherKeyAndAChangedRelayState(t *testing.T) {
	sp := mustSP(t, nil, "")
	forged := redirectResponseQuery(responseXML(responseOpt{inResponseTo: "_r"}), "/x", spPair.PrivateKey)
	rejects(t, func() error { _, err := sp.Acs("GET", "/saml/acs?"+forged, nil, []string{"_r"}); return err }, "signature", "")
	changed := strings.Replace(redirectResponseQuery(responseXML(responseOpt{inResponseTo: "_r"}), "/x", nil), "RelayState=%2Fx", "RelayState=%2Fy", 1)
	rejects(t, func() error { _, err := sp.Acs("GET", "/saml/acs?"+changed, nil, []string{"_r"}); return err }, "signature", "")
}

func TestResolvesTheArtifact(t *testing.T) {
	ars := startARS(t)
	defer ars.close()
	sp := mustSP(t, map[string]any{"responseBinding": "artifact"}, ars.url)
	req, err := sp.Login(LoginOptions{})
	if err != nil || !strings.Contains(req.XML, "HTTP-Artifact") {
		t.Fatal(err, req)
	}
	artifact := artifactFor("")
	ars.put(artifact, responseXML(responseOpt{inResponseTo: req.ID}))
	who, err := sp.Acs("GET", "/saml/acs?SAMLart="+url.QueryEscape(artifact)+"&RelayState=%2Fa", nil, []string{req.ID})
	if err != nil {
		t.Fatal(err)
	}
	if who.Binding != "artifact" || who.RelayState == nil || *who.RelayState != "/a" || who.NameID != "alice-1234" {
		t.Fatalf("%+v", who)
	}
	if strings.Join(ars.resolved, ",") != artifact {
		t.Fatalf("resolved %v", ars.resolved)
	}
}

func TestAcceptsTheArtifactOnAPostAndFailsWhenAlreadyUsed(t *testing.T) {
	ars := startARS(t)
	defer ars.close()
	sp := mustSP(t, nil, ars.url)
	artifact := artifactFor("")
	ars.put(artifact, responseXML(responseOpt{inResponseTo: "_r"}))
	who, err := sp.Acs("POST", "/saml/acs", "SAMLart="+url.QueryEscape(artifact), []string{"_r"})
	if err != nil || who.Binding != "artifact" {
		t.Fatal(err, who)
	}
	rejects(t, func() error {
		_, err := sp.Acs("POST", "/saml/acs", map[string]string{"SAMLart": artifact}, []string{"_r"})
		return err
	}, "artifact", "did not resolve")
}

func TestRefusesAnArtifactFromAnotherIdentityProvider(t *testing.T) {
	sp := mustSP(t, nil, "https://idp.test/saml2/ars")
	rejects(t, func() error {
		_, err := sp.Acs("GET", "/saml/acs?SAMLart="+url.QueryEscape(artifactFor("https://evil.test")), nil, []string{"_r"})
		return err
	}, "artifact", "not issued by")
}

func TestRefusesARequestWithNoSamlMessage(t *testing.T) {
	sp := mustSP(t, nil, "")
	rejects(t, func() error { _, err := sp.Acs("GET", "/saml/acs", nil, nil); return err }, "binding", "")
}

func TestParseXMLHelperStaysAvailable(t *testing.T) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<a/>`); err != nil {
		t.Fatal(err)
	}
}
