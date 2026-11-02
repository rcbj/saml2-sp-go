// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto/x509"
	"strconv"
	"strings"

	"github.com/beevik/etree"
)

var encryptionMethods = []string{
	"http://www.w3.org/2009/xmlenc11#aes256-gcm",
	"http://www.w3.org/2009/xmlenc11#aes128-gcm",
	"http://www.w3.org/2009/xmlenc11#rsa-oaep",
	"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
}

// ReadIDPMetadata reads an identity provider's metadata document.
func ReadIDPMetadata(xml string) (*IdpMetadata, error) {
	return readIDPMetadata(xml, "")
}

// MetadataDocument is this service provider's metadata, without contacting the identity provider.
func MetadataDocument(cfg *Config) string {
	return writeSPMetadata(cfg.EntityID, cfg.AcsURL, cfg.Certificate, cfg.WantAssertionsSigned, cfg.NameIDFormat)
}

// IdpMetadata is the identity provider material this service provider needs.
type IdpMetadata struct {
	EntityID                   string
	SSO                        map[string]string
	ArtifactResolutionServices map[int]string
	firstARS                   string
	Certs                      []*x509.Certificate
	WantAuthnRequestsSigned    bool
}

func certificatesOf(role *etree.Element, use string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, descriptor := range children(role, nsMd, "KeyDescriptor") {
		declared := attrOr(descriptor, "use")
		if declared != "" && declared != use {
			continue
		}
		for _, data := range descendants(descriptor, nsDsig, "X509Data") {
			first := children(data, nsDsig, "X509Certificate")
			if len(first) == 0 {
				continue
			}
			cert, err := loadCertificate(toPEM(textOf(first[0])))
			if err != nil {
				return nil, errCause("metadata", "a "+use+" certificate in the identity provider's metadata cannot be read", err)
			}
			out = append(out, cert)
		}
	}
	return out, nil
}

func readIDPMetadata(xml string, entityID string) (*IdpMetadata, error) {
	root, err := parseXML(xml, "the identity provider metadata")
	if err != nil {
		return nil, err
	}
	var entity *etree.Element
	if same(root, nsMd, "EntityDescriptor") {
		entity = root
	} else if same(root, nsMd, "EntitiesDescriptor") {
		var all []*etree.Element
		for _, e := range descendants(root, nsMd, "EntityDescriptor") {
			if len(descendants(e, nsMd, "IDPSSODescriptor")) > 0 {
				all = append(all, e)
			}
		}
		if entityID != "" {
			for _, e := range all {
				if attrOr(e, "entityID") == entityID {
					entity = e
					break
				}
			}
		} else if len(all) == 1 {
			entity = all[0]
		}
		if entity == nil {
			if entityID != "" {
				return nil, errCode("metadata", "the metadata aggregate has no identity provider "+entityID)
			}
			return nil, errCode("metadata", "the metadata aggregate holds "+itoa(len(all))+" identity providers; name one with idpEntityId")
		}
	} else {
		return nil, errCode("metadata", "the identity provider metadata is not an EntityDescriptor")
	}
	identifier := attrOr(entity, "entityID")
	if identifier == "" {
		return nil, errCode("metadata", "the identity provider metadata has no entityID")
	}
	if entityID != "" && identifier != entityID {
		return nil, errCode("metadata", "the metadata describes "+identifier+", not "+entityID)
	}
	roles := children(entity, nsMd, "IDPSSODescriptor")
	if len(roles) == 0 {
		return nil, errCode("metadata", identifier+"'s metadata has no IDPSSODescriptor")
	}
	role := roles[0]
	sso := map[string]string{}
	for _, item := range children(role, nsMd, "SingleSignOnService") {
		location := attrOr(item, "Location")
		if location == "" {
			continue
		}
		binding := attrOr(item, "Binding")
		if binding == bindingRedirect {
			if _, ok := sso["redirect"]; !ok {
				sso["redirect"] = location
			}
		}
		if binding == bindingPost {
			if _, ok := sso["post"]; !ok {
				sso["post"] = location
			}
		}
	}
	services := map[int]string{}
	first := ""
	for _, ars := range children(role, nsMd, "ArtifactResolutionService") {
		location := attrOr(ars, "Location")
		if attrOr(ars, "Binding") == bindingSOAP && location != "" {
			index, _ := strconv.Atoi(attrOr(ars, "index"))
			if _, ok := services[index]; !ok {
				services[index] = location
				if first == "" {
					first = location
				}
			}
		}
	}
	signing, err := certificatesOf(role, "signing")
	if err != nil {
		return nil, err
	}
	if len(signing) == 0 {
		return nil, errCode("metadata", identifier+"'s metadata names no signing certificate")
	}
	if _, okR := sso["redirect"]; !okR {
		if _, okP := sso["post"]; !okP {
			return nil, errCode("metadata", identifier+"'s metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService")
		}
	}
	return &IdpMetadata{
		EntityID:                   identifier,
		SSO:                        sso,
		ArtifactResolutionServices: services,
		firstARS:                   first,
		Certs:                      signing,
		WantAuthnRequestsSigned:    attrOr(role, "WantAuthnRequestsSigned") == "true",
	}, nil
}

func writeSPMetadata(entityID, acsURL string, cert *x509.Certificate, wantAssertionsSigned bool, nameIDFormat string) string {
	certBody := pemBody(certificatePEM(cert))
	keyInfo := "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + certBody + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
	var methods strings.Builder
	for _, method := range encryptionMethods {
		methods.WriteString("\n      <md:EncryptionMethod Algorithm=\"" + method + "\"/>")
	}
	key := func(use string) string {
		extra := ""
		if use == "encryption" {
			extra = methods.String()
		}
		return "    <md:KeyDescriptor use=\"" + use + "\">\n      " + keyInfo + extra + "\n    </md:KeyDescriptor>"
	}
	nameID := ""
	if nameIDFormat != "" {
		nameID = "\n    <md:NameIDFormat>" + escapeXML(nameIDFormat) + "</md:NameIDFormat>"
	}
	want := "false"
	if wantAssertionsSigned {
		want = "true"
	}
	acs := escapeXML(acsURL)
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<md:EntityDescriptor xmlns:md=\"" + nsMd + "\" xmlns:ds=\"" + nsDsig + "\" entityID=\"" + escapeXML(entityID) + "\">\n" +
		"  <md:SPSSODescriptor protocolSupportEnumeration=\"" + nsSamlp + "\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"" + want + "\">\n" +
		key("signing") + "\n" +
		key("encryption") + nameID + "\n" +
		"    <md:AssertionConsumerService Binding=\"" + bindingPost + "\" Location=\"" + acs + "\" index=\"0\" isDefault=\"true\"/>\n" +
		"    <md:AssertionConsumerService Binding=\"" + bindingRedirect + "\" Location=\"" + acs + "\" index=\"1\"/>\n" +
		"    <md:AssertionConsumerService Binding=\"" + bindingArtifact + "\" Location=\"" + acs + "\" index=\"2\"/>\n" +
		"  </md:SPSSODescriptor>\n" +
		"</md:EntityDescriptor>\n"
}
