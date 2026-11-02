// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"regexp"
	"strings"

	"github.com/beevik/etree"
)

const (
	nsSamlp  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsSaml   = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMd     = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDsig   = "http://www.w3.org/2000/09/xmldsig#"
	nsXenc   = "http://www.w3.org/2001/04/xmlenc#"
	nsXenc11 = "http://www.w3.org/2009/xmlenc11#"
	nsSoap   = "http://schemas.xmlsoap.org/soap/envelope/"

	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindingArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	bindingSOAP     = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"

	statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	cmBearer      = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

	excC14N         = "http://www.w3.org/2001/10/xml-exc-c14n#"
	excC14NComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	c14n10          = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	c14n10Comments  = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	enveloped       = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"

	rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	rsaSHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	rsaSHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	digest256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	digest384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	digest512 = "http://www.w3.org/2001/04/xmlenc#sha512"
)

var doctypeRE = regexp.MustCompile(`(?i)<!DOCTYPE|<!ENTITY`)

func parseXML(text, what string) (*etree.Element, error) {
	if doctypeRE.MatchString(text) {
		return nil, errCode("xml", what+" carries a DOCTYPE or an entity declaration, which SAML never needs")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(text); err != nil {
		return nil, errCause("xml", what+" is not well-formed XML: "+err.Error(), err)
	}
	root := doc.Root()
	if root == nil {
		return nil, errCode("xml", what+" is not well-formed XML: no document element")
	}
	return root, nil
}

func serialize(el *etree.Element) string {
	root := el
	for root.Parent() != nil && root.Parent().Tag != "" {
		root = root.Parent()
	}
	doc := etree.NewDocument()
	doc.SetRoot(root.Copy())
	out, err := doc.WriteToString()
	if err != nil {
		return ""
	}
	return out
}

func nsOf(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return lookupNS(el, el.Space)
}

func lookupNS(el *etree.Element, prefix string) string {
	for n := el; n != nil; n = n.Parent() {
		for _, a := range n.Attr {
			if prefix == "" && a.Space == "" && a.Key == "xmlns" {
				return a.Value
			}
			if a.Space == "xmlns" && a.Key == prefix {
				return a.Value
			}
		}
	}
	if prefix == "xml" {
		return "http://www.w3.org/XML/1998/namespace"
	}
	return ""
}

func same(el *etree.Element, ns, local string) bool {
	return el != nil && el.Tag == local && nsOf(el) == ns
}

func children(el *etree.Element, ns, local string) []*etree.Element {
	if el == nil {
		return nil
	}
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if same(c, ns, local) {
			out = append(out, c)
		}
	}
	return out
}

func child(el *etree.Element, ns, local string) (*etree.Element, error) {
	found := children(el, ns, local)
	if len(found) > 1 {
		return nil, errCode("validation", "<"+el.Tag+"> has more than one <"+local+">")
	}
	if len(found) == 0 {
		return nil, nil
	}
	return found[0], nil
}

func descendants(el *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element
	if el == nil {
		return out
	}
	var walk func(*etree.Element)
	walk = func(n *etree.Element) {
		for _, c := range n.ChildElements() {
			if same(c, ns, local) {
				out = append(out, c)
			}
			walk(c)
		}
	}
	walk(el)
	return out
}

func textOf(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return strings.TrimSpace(iterText(el))
}

func iterText(el *etree.Element) string {
	if el == nil {
		return ""
	}
	var b strings.Builder
	var walk func(*etree.Element)
	walk = func(n *etree.Element) {
		b.WriteString(n.Text())
		for _, c := range n.ChildElements() {
			walk(c)
			b.WriteString(c.Tail())
		}
	}
	walk(el)
	return b.String()
}

func attr(el *etree.Element, name string) (string, bool) {
	if el == nil {
		return "", false
	}
	for _, a := range el.Attr {
		if a.Space == "" && a.Key == name {
			return a.Value, true
		}
	}
	return "", false
}

func attrOr(el *etree.Element, name string) string {
	v, _ := attr(el, name)
	return v
}

func documentRoot(el *etree.Element) *etree.Element {
	for el != nil && el.Parent() != nil {
		el = el.Parent()
	}
	return el
}

func assertUniqueIDs(root *etree.Element) error {
	seen := map[string]struct{}{}
	var walk func(*etree.Element) error
	walk = func(n *etree.Element) error {
		for _, name := range []string{"ID", "Id", "id"} {
			value, ok := attr(n, name)
			if !ok || value == "" {
				continue
			}
			if _, dup := seen[value]; dup {
				return errCode("signature", "two elements carry the ID "+value)
			}
			seen[value] = struct{}{}
		}
		for _, c := range n.ChildElements() {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	if root == nil {
		return nil
	}
	return walk(root)
}

func escapeXML(value string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(value)
}

func elementByID(root *etree.Element, id string) *etree.Element {
	var found *etree.Element
	var walk func(*etree.Element)
	walk = func(n *etree.Element) {
		if found != nil {
			return
		}
		for _, name := range []string{"ID", "Id", "id"} {
			if v, ok := attr(n, name); ok && v == id {
				found = n
				return
			}
		}
		for _, c := range n.ChildElements() {
			walk(c)
		}
	}
	walk(root)
	return found
}

func pemBody(pem string) string {
	pem = strings.ReplaceAll(pem, "\r", "")
	var b strings.Builder
	for _, line := range strings.Split(pem, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

func toPEM(b64 string) string {
	b64 = strings.Join(strings.Fields(b64), "")
	var lines []string
	for i := 0; i < len(b64); i += 64 {
		j := i + 64
		if j > len(b64) {
			j = len(b64)
		}
		lines = append(lines, b64[i:j])
	}
	return "-----BEGIN CERTIFICATE-----\n" + strings.Join(lines, "\n") + "\n-----END CERTIFICATE-----\n"
}
