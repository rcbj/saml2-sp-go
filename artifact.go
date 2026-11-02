// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"

	"github.com/beevik/etree"
)

func iso(when time.Time) string {
	if when.IsZero() {
		when = time.Now().UTC()
	}
	return when.UTC().Format("2006-01-02T15:04:05.000Z")
}

func newID() string {
	buf := make([]byte, 20)
	_, _ = rand.Read(buf)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 1+len(buf)*2)
	out[0] = '_'
	for i, b := range buf {
		out[1+i*2] = hexdigits[b>>4]
		out[2+i*2] = hexdigits[b&15]
	}
	return string(out)
}

type parsedArtifact struct {
	EndpointIndex int
	SourceID      []byte
}

func parseArtifact(samlArt string) (*parsedArtifact, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(samlArt), ""))
	if err != nil || len(raw) != 44 || binary.BigEndian.Uint16(raw[0:2]) != 0x0004 {
		return nil, errCode("artifact", "SAMLart is not a SAML 2.0 type 0x0004 artifact")
	}
	source := make([]byte, 20)
	copy(source, raw[4:24])
	return &parsedArtifact{EndpointIndex: int(binary.BigEndian.Uint16(raw[2:4])), SourceID: source}, nil
}

type artifactInput struct {
	Artifact                   string
	EntityID                   string
	IdpEntityID                string
	ArtifactResolutionServices map[int]string
	FirstARS                   string
	IdpCertificates            []*x509.Certificate
	Key                        *rsa.PrivateKey
	Certificate                *x509.Certificate
	TLS                        *TLSOptions
}

func resolveArtifact(data artifactInput) (string, *etree.Element, error) {
	parsed, err := parseArtifact(data.Artifact)
	if err != nil {
		return "", nil, err
	}
	sum := sha1.Sum([]byte(data.IdpEntityID))
	if string(parsed.SourceID) != string(sum[:]) {
		return "", nil, errCode("artifact", "the artifact was not issued by "+data.IdpEntityID)
	}
	location, ok := data.ArtifactResolutionServices[parsed.EndpointIndex]
	if !ok && parsed.EndpointIndex == 0 && len(data.ArtifactResolutionServices) > 0 {
		location = data.FirstARS
		ok = location != ""
	}
	if !ok || location == "" {
		return "", nil, errCode("artifact", "the identity provider's metadata has no SOAP ArtifactResolutionService with index "+itoa(parsed.EndpointIndex))
	}
	elementID := newID()
	unsigned := `<samlp:ArtifactResolve xmlns:samlp="` + nsSamlp + `" xmlns:saml="` + nsSaml + `" ID="` + elementID + `" Version="2.0" IssueInstant="` + iso(time.Time{}) + `" Destination="` + escapeXML(location) + `"><saml:Issuer>` + escapeXML(data.EntityID) + `</saml:Issuer><samlp:Artifact>` + escapeXML(data.Artifact) + `</samlp:Artifact></samlp:ArtifactResolve>`
	signed, err := signEnveloped(unsigned, elementID, data.Key, data.Certificate)
	if err != nil {
		return "", nil, err
	}
	envelope := `<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="` + nsSoap + `"><soap:Body>` + signed + `</soap:Body></soap:Envelope>`
	answer, err := send(location, "POST", map[string]string{
		"content-type": "text/xml; charset=utf-8",
		"soapaction":   `"http://www.oasis-open.org/committees/security"`,
		"accept":       "text/xml",
	}, envelope, data.TLS, "artifact")
	if err != nil {
		return "", nil, err
	}
	if answer.Status != 200 {
		return "", nil, errCode("artifact", "the artifact resolution service answered HTTP "+itoa(answer.Status))
	}
	root, err := parseXML(answer.Body, "the ArtifactResponse")
	if err != nil {
		return "", nil, err
	}
	if err := assertUniqueIDs(root); err != nil {
		return "", nil, err
	}
	var body *etree.Element
	if same(root, nsSoap, "Envelope") {
		body, err = child(root, nsSoap, "Body")
		if err != nil {
			return "", nil, err
		}
	}
	var artifactResponse *etree.Element
	if body != nil {
		artifactResponse, err = child(body, nsSamlp, "ArtifactResponse")
		if err != nil {
			return "", nil, err
		}
	}
	if artifactResponse == nil {
		return "", nil, errCode("artifact", "the artifact resolution service did not answer with a SOAP ArtifactResponse")
	}
	xml := answer.Body
	signedResponse, err := verifySigned(artifactResponse, data.IdpCertificates, "the ArtifactResponse")
	if err != nil {
		return "", nil, err
	}
	if signedResponse != "" {
		xml = signedResponse
		artifactResponse, err = parseXML(signedResponse, "the signed ArtifactResponse")
		if err != nil {
			return "", nil, err
		}
	}
	if attrOr(artifactResponse, "InResponseTo") != elementID {
		return "", nil, errCode("artifact", "the ArtifactResponse does not answer this ArtifactResolve")
	}
	issuer, err := child(artifactResponse, nsSaml, "Issuer")
	if err != nil {
		return "", nil, err
	}
	if issuer != nil && textOf(issuer) != data.IdpEntityID {
		return "", nil, errCode("artifact", "the ArtifactResponse was issued by "+textOf(issuer))
	}
	status, err := child(artifactResponse, nsSamlp, "Status")
	if err != nil {
		return "", nil, err
	}
	var code string
	if status != nil {
		codeEl, err := child(status, nsSamlp, "StatusCode")
		if err != nil {
			return "", nil, err
		}
		if codeEl != nil {
			code = attrOr(codeEl, "Value")
		} else {
			code = attrOr(status, "Value")
		}
	}
	if code != statusSuccess {
		shown := code
		if shown == "" {
			shown = "no status"
		}
		return "", nil, errCode("artifact", "the artifact resolution failed: "+shown)
	}
	responses := children(artifactResponse, nsSamlp, "Response")
	if len(responses) == 0 {
		return "", nil, errCode("artifact", "the identity provider did not resolve the artifact (unknown, expired, or already used)")
	}
	return xml, responses[0], nil
}
