// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"encoding/base64"
	"net/url"
	"os"
	"strings"
	"time"
)

// LoginOptions selects how an AuthnRequest is built. A nil RelayState is omitted.
type LoginOptions struct {
	RelayState        *string
	ForceAuthn        bool
	IsPassive         bool
	SubjectHint       *string
	SubjectHintFormat *string
	RequestBinding    string
	ResponseBinding   string
	Nonce             string
}

// LoginRequest is the signed AuthnRequest, as a redirect or a POST form.
type LoginRequest struct {
	ID              string
	Binding         string
	ResponseBinding string
	URL             string
	XML             string
	Fields          map[string]string
	HTML            string
}

// ServiceProvider is the SAML 2.0 service provider.
type ServiceProvider struct {
	Config *Config
	Idp    *IdpMetadata
	replay *MemoryReplayCache
}

// Create resolves config and loads the identity provider's metadata.
func Create(config map[string]any, baseDir string, replay *MemoryReplayCache) (*ServiceProvider, error) {
	resolved, err := ResolveConfig(config, baseDir)
	if err != nil {
		return nil, err
	}
	sp := &ServiceProvider{Config: resolved, replay: replay}
	if sp.replay == nil {
		sp.replay = NewMemoryReplayCache(0)
	}
	if _, err := sp.RefreshMetadata(); err != nil {
		return nil, err
	}
	return sp, nil
}

// FromFile loads saml.json. Nil override values are ignored.
func FromFile(path string, overrides map[string]any, replay *MemoryReplayCache) (*ServiceProvider, error) {
	resolved, err := ReadConfigFile(path, overrides)
	if err != nil {
		return nil, err
	}
	sp := &ServiceProvider{Config: resolved, replay: replay}
	if sp.replay == nil {
		sp.replay = NewMemoryReplayCache(0)
	}
	if _, err := sp.RefreshMetadata(); err != nil {
		return nil, err
	}
	return sp, nil
}

func (sp *ServiceProvider) tls() *TLSOptions {
	if sp.Config.IdpCA == "" {
		return nil
	}
	return &TLSOptions{CA: sp.Config.IdpCA}
}

// RefreshMetadata reads the identity provider metadata again.
func (sp *ServiceProvider) RefreshMetadata() (*IdpMetadata, error) {
	source := sp.Config.IdpMetadata
	var xml string
	switch {
	case strings.HasPrefix(source, "<"):
		xml = source
	case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
		answer, err := send(source, "GET", map[string]string{"accept": "application/samlmetadata+xml, application/xml, text/xml"}, "", sp.tls(), "metadata")
		if err != nil {
			return nil, err
		}
		if answer.Status != 200 {
			return nil, errCode("metadata", source+" answered HTTP "+itoa(answer.Status))
		}
		xml = answer.Body
	default:
		raw, err := os.ReadFile(source)
		if err != nil {
			return nil, errCause("metadata", "the identity provider metadata file "+source+" cannot be read", err)
		}
		xml = string(raw)
	}
	meta, err := readIDPMetadata(xml, sp.Config.IdpEntityID)
	if err != nil {
		return nil, err
	}
	sp.Idp = meta
	return meta, nil
}

// Metadata is this service provider's metadata.
func (sp *ServiceProvider) Metadata() string {
	return MetadataDocument(sp.Config)
}

func (sp *ServiceProvider) idp() (*IdpMetadata, error) {
	if sp.Idp == nil {
		return nil, errCode("metadata", "the identity provider's metadata has not been loaded")
	}
	return sp.Idp, nil
}

// Login builds a signed AuthnRequest.
func (sp *ServiceProvider) Login(opt LoginOptions) (*LoginRequest, error) {
	idp, err := sp.idp()
	if err != nil {
		return nil, err
	}
	binding := opt.RequestBinding
	if binding == "" {
		binding = sp.Config.RequestBinding
	}
	response := opt.ResponseBinding
	if response == "" {
		response = sp.Config.ResponseBinding
	}
	if response == "artifact" && len(idp.ArtifactResolutionServices) == 0 {
		return nil, errCode("config", "the identity provider has no SOAP ArtifactResolutionService, so the Response cannot come by artifact")
	}
	destination := idp.SSO[binding]
	if destination == "" {
		which := "Redirect"
		if binding == "post" {
			which = "POST"
		}
		return nil, errCode("config", "the identity provider has no SingleSignOnService on HTTP-"+which)
	}
	if opt.RelayState != nil && len([]byte(*opt.RelayState)) > 80 {
		return nil, errCode("config", "relayState is longer than the 80 bytes the bindings allow")
	}
	elementID := newID()
	force := ""
	if opt.ForceAuthn {
		force = ` ForceAuthn="true"`
	}
	passive := ""
	if opt.IsPassive {
		passive = ` Is passive="true"`
	}
	subject := ""
	if opt.SubjectHint != nil {
		form := ""
		if opt.SubjectHintFormat != nil && *opt.SubjectHintFormat != "" {
			form = ` Format="` + escapeXML(*opt.SubjectHintFormat) + `"`
		}
		subject = `<saml:Subject><saml:NameID` + form + `>` + escapeXML(*opt.SubjectHint) + `</saml:NameID></saml:Subject>`
	}
	policy := `<samlp:NameIDPolicy AllowCreate="true"/>`
	if sp.Config.NameIDFormat != "" {
		policy = `<samlp:NameIDPolicy Format="` + escapeXML(sp.Config.NameIDFormat) + `" AllowCreate="true"/>`
	}
	protocol := map[string]string{"post": bindingPost, "redirect": bindingRedirect, "artifact": bindingArtifact}[response]
	xml := `<samlp:AuthnRequest xmlns:samlp="` + nsSamlp + `" xmlns:saml="` + nsSaml + `" ID="` + elementID + `" Version="2.0" IssueInstant="` + iso(time.Time{}) + `" Destination="` + escapeXML(destination) + `" AssertionConsumerServiceURL="` + escapeXML(sp.Config.AcsURL) + `" ProtocolBinding="` + protocol + `"` + force + passive + `><saml:Issuer>` + escapeXML(sp.Config.EntityID) + `</saml:Issuer>` + subject + policy + `</samlp:AuthnRequest>`
	if binding == "redirect" {
		query, err := redirectQuery("SAMLRequest", xml, opt.RelayState, sp.Config.PrivateKey)
		if err != nil {
			return nil, err
		}
		join := "?"
		if strings.Contains(destination, "?") {
			join = "&"
		}
		return &LoginRequest{ID: elementID, Binding: binding, ResponseBinding: response, URL: destination + join + query, XML: xml}, nil
	}
	signed, err := signEnveloped(xml, elementID, sp.Config.PrivateKey, sp.Config.Certificate)
	if err != nil {
		return nil, err
	}
	fields := map[string]string{"SAMLRequest": base64.StdEncoding.EncodeToString([]byte(signed))}
	order := []string{"SAMLRequest"}
	if opt.RelayState != nil {
		fields["RelayState"] = *opt.RelayState
		order = append(order, "RelayState")
	}
	html := postFormHTML(destination, fields, order, opt.Nonce, "")
	return &LoginRequest{ID: elementID, Binding: binding, ResponseBinding: response, URL: destination, Fields: fields, HTML: html, XML: signed}, nil
}

// Acs consumes a Response on POST, redirect, or artifact.
func (sp *ServiceProvider) Acs(method, rawURL string, body any, requestIDs []string) (*SamlLogin, error) {
	idp, err := sp.idp()
	if err != nil {
		return nil, err
	}
	verb := strings.ToUpper(method)
	rawQuery := ""
	if i := strings.IndexByte(rawURL, '?'); i >= 0 {
		rawQuery = rawURL[i+1:]
		if j := strings.IndexByte(rawQuery, '#'); j >= 0 {
			rawQuery = rawQuery[:j]
		}
	}
	query := firstQuery(rawQuery)
	form := map[string]string{}
	if verb == "POST" {
		form = formOf(body)
	}
	ctx := &validationContext{
		EntityID:                sp.Config.EntityID,
		AcsURL:                  sp.Config.AcsURL,
		IdpEntityID:             idp.EntityID,
		IdpCertificates:         idp.Certs,
		DecryptionKey:           sp.Config.PrivateKey,
		ClockSkewMS:             sp.Config.ClockSkewMS,
		WantAssertionsSigned:    sp.Config.WantAssertionsSigned,
		WantAssertionsEncrypted: sp.Config.WantAssertionsEncrypted,
		AllowUnsolicited:        sp.Config.AllowUnsolicited,
		Replay:                  sp.replay,
		ExpectedRequestIDs:      requestIDs,
	}
	if art := firstNonEmpty(form["SAMLart"], query["SAMLart"]); art != "" {
		xml, response, err := resolveArtifact(artifactInput{
			Artifact:                   art,
			EntityID:                   sp.Config.EntityID,
			IdpEntityID:                idp.EntityID,
			ArtifactResolutionServices: idp.ArtifactResolutionServices,
			FirstARS:                   idp.firstARS,
			IdpCertificates:            idp.Certs,
			Key:                        sp.Config.PrivateKey,
			Certificate:                sp.Config.Certificate,
			TLS:                        sp.tls(),
		})
		if err != nil {
			return nil, err
		}
		var relay *string
		if form["SAMLart"] != "" {
			if value, ok := form["RelayState"]; ok {
				relay = &value
			}
		} else if value, ok := query["RelayState"]; ok {
			relay = &value
		}
		return validateResponse(&receivedMessage{XML: xml, Response: response, Binding: "artifact", RelayState: relay, AuthenticatedByBinding: true}, ctx)
	}
	if verb == "POST" && form["SAMLResponse"] != "" {
		xml, err := readPost(form["SAMLResponse"], "SAMLResponse")
		if err != nil {
			return nil, err
		}
		root, err := parseXML(xml, "the Response")
		if err != nil {
			return nil, err
		}
		var relay *string
		if value, ok := form["RelayState"]; ok {
			relay = &value
		}
		return validateResponse(&receivedMessage{XML: xml, Response: root, Binding: "post", RelayState: relay, AuthenticatedByBinding: false}, ctx)
	}
	if query["SAMLResponse"] != "" {
		message, err := readRedirect(rawQuery, "SAMLResponse", idp.Certs)
		if err != nil {
			return nil, err
		}
		root, err := parseXML(message.XML, "the Response")
		if err != nil {
			return nil, err
		}
		return validateResponse(&receivedMessage{XML: message.XML, Response: root, Binding: "redirect", RelayState: message.RelayState, AuthenticatedByBinding: message.Signed}, ctx)
	}
	return nil, errCode("binding", "the request carries no SAMLResponse or SAMLart")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstQuery(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" {
		return out
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		parts := strings.Split(raw, "&")
		for _, part := range parts {
			if part == "" {
				continue
			}
			eq := strings.IndexByte(part, '=')
			key, val := part, ""
			if eq >= 0 {
				key, val = part[:eq], part[eq+1:]
			}
			if un, err := url.QueryUnescape(key); err == nil {
				key = un
			}
			if un, err := url.QueryUnescape(val); err == nil {
				val = un
			}
			if _, ok := out[key]; !ok {
				out[key] = val
			}
		}
		return out
	}
	for key, list := range values {
		if len(list) > 0 {
			if _, ok := out[key]; !ok {
				out[key] = list[0]
			}
		}
	}
	return out
}

func formOf(body any) map[string]string {
	switch typed := body.(type) {
	case nil:
		return map[string]string{}
	case string:
		return firstQuery(typed)
	case map[string]string:
		out := map[string]string{}
		for k, v := range typed {
			out[k] = v
		}
		return out
	case map[string]any:
		out := map[string]string{}
		for k, v := range typed {
			if text, ok := v.(string); ok {
				out[k] = text
			}
		}
		return out
	default:
		return map[string]string{}
	}
}
