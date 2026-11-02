// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/url"
	"regexp"
	"strings"
)

const maxInflated = 1024 * 1024

var (
	b64RE = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

func badPercent(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if i+2 >= len(value) || !isHex(value[i+1]) || !isHex(value[i+2]) {
			return true
		}
		i += 2
	}
	return false
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func uriEscape(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.ContainsRune("-_.!~*'()", rune(c)) {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

func uriUnescape(value string) (string, error) {
	text := strings.ReplaceAll(value, "+", "%20")
	if badPercent(text) {
		return "", errCode("binding", "the query string is not validly percent-encoded")
	}
	out, err := url.PathUnescape(text)
	if err != nil {
		return "", errCode("binding", "the query string is not validly percent-encoded")
	}
	return out, nil
}

func deflateRaw(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func inflateRaw(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(r, maxInflated+1)); err != nil {
		return nil, errCode("binding", "the message inflates past the limit")
	}
	if buf.Len() > maxInflated {
		return nil, errCode("binding", "the message inflates past the limit")
	}
	return buf.Bytes(), nil
}

func redirectQuery(param, xml string, relayState *string, key *rsa.PrivateKey) (string, error) {
	deflated, err := deflateRaw([]byte(xml))
	if err != nil {
		return "", errCause("binding", "the message could not be deflated", err)
	}
	encoded := base64.StdEncoding.EncodeToString(deflated)
	parts := []string{param + "=" + uriEscape(encoded)}
	if relayState != nil {
		parts = append(parts, "RelayState="+uriEscape(*relayState))
	}
	parts = append(parts, "SigAlg="+uriEscape(rsaSHA256))
	signed := strings.Join(parts, "&")
	sum := sha256Sum([]byte(signed))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum)
	if err != nil {
		return "", errCause("signature", "the query string could not be signed", err)
	}
	return signed + "&Signature=" + uriEscape(base64.StdEncoding.EncodeToString(sig)), nil
}

func sha256Sum(data []byte) []byte {
	sum := hashNew(crypto.SHA256)
	sum.Write(data)
	return sum.Sum(nil)
}

type redirectMessage struct {
	XML        string
	RelayState *string
	Signed     bool
}

func readRedirect(rawQuery, param string, certs []*x509.Certificate) (*redirectMessage, error) {
	query := rawQuery
	if strings.HasPrefix(query, "?") {
		query = query[1:]
	}
	raw := map[string]string{}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		namePart := pair
		value := ""
		if eq >= 0 {
			namePart = pair[:eq]
			value = pair[eq+1:]
		}
		name, err := uriUnescape(namePart)
		if err != nil {
			return nil, err
		}
		if _, exists := raw[name]; exists {
			return nil, errCode("binding", "the query string carries "+name+" twice")
		}
		raw[name] = value
	}
	message, ok := raw[param]
	if !ok {
		return nil, errCode("binding", "the query string carries no "+param)
	}
	unescaped, err := uriUnescape(message)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(unescaped)
	if err != nil {
		return nil, errCause("binding", param+" is not a DEFLATE-encoded message", err)
	}
	inflated, err := inflateRaw(decoded)
	if err != nil {
		if _, ok := err.(*SamlError); ok {
			return nil, err
		}
		return nil, errCause("binding", param+" is not a DEFLATE-encoded message", err)
	}
	var relay *string
	if rawRelay, ok := raw["RelayState"]; ok {
		text, err := uriUnescape(rawRelay)
		if err != nil {
			return nil, err
		}
		relay = &text
	}
	if _, ok := raw["Signature"]; !ok {
		return &redirectMessage{XML: string(inflated), RelayState: relay, Signed: false}, nil
	}
	sigAlg, err := uriUnescape(raw["SigAlg"])
	if err != nil {
		return nil, err
	}
	hashID, ok := signatureAlgs[sigAlg]
	if !ok {
		shown := sigAlg
		if shown == "" {
			shown = "(no SigAlg)"
		}
		return nil, errCode("signature", "the query is signed with "+shown+", which is refused")
	}
	signedParts := []string{param + "=" + message}
	if _, ok := raw["RelayState"]; ok {
		signedParts = append(signedParts, "RelayState="+raw["RelayState"])
	}
	signedParts = append(signedParts, "SigAlg="+raw["SigAlg"])
	data := []byte(strings.Join(signedParts, "&"))
	sigText, err := uriUnescape(raw["Signature"])
	if err != nil {
		return nil, errCode("signature", "the query string signature does not verify against the identity provider's certificate")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigText)
	if err != nil {
		return nil, errCause("signature", "the query string signature does not verify against the identity provider's certificate", err)
	}
	sum := hashNew(hashID)
	sum.Write(data)
	digest := sum.Sum(nil)
	for _, cert := range certs {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if rsa.VerifyPKCS1v15(pub, hashID, digest, sigBytes) == nil {
			return &redirectMessage{XML: string(inflated), RelayState: relay, Signed: true}, nil
		}
	}
	return nil, errCode("signature", "the query string signature does not verify against the identity provider's certificate")
}

func readPost(value, param string) (string, error) {
	compact := strings.Join(strings.Fields(value), "")
	if compact == "" || !b64RE.MatchString(compact) {
		return "", errCode("binding", param+" is not base64")
	}
	raw, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return "", errCode("binding", param+" is not base64")
	}
	return string(raw), nil
}

// PostFormHTML is the browser form that carries an HTTP-POST SAML message.
func PostFormHTML(action string, fields map[string]string, nonce, title string) string {
	var inputs []string
	for name, value := range fields {
		inputs = append(inputs, `<input type="hidden" name="`+escapeXML(name)+`" value="`+escapeXML(value)+`">`)
	}
	// Map iteration order is random. Callers that need stable tests pass one field
	// or the ordered helper below. The demo and login use orderedFields.
	_ = inputs
	return postFormHTML(action, fields, nil, nonce, title)
}

func postFormHTML(action string, fields map[string]string, order []string, nonce, title string) string {
	if title == "" {
		title = "Signing in"
	}
	if order == nil {
		order = make([]string, 0, len(fields))
		for name := range fields {
			order = append(order, name)
		}
	}
	lines := make([]string, 0, len(order))
	for _, name := range order {
		value, ok := fields[name]
		if !ok {
			continue
		}
		lines = append(lines, `<input type="hidden" name="`+escapeXML(name)+`" value="`+escapeXML(value)+`">`)
	}
	script := ""
	if nonce != "" {
		script = "\n    <script nonce=\"" + escapeXML(nonce) + "\">document.forms[0].submit();</script>"
	}
	return "<!doctype html>\n<html lang=\"en\">\n  <head><meta charset=\"utf-8\"><title>" + escapeXML(title) + "</title></head>\n  <body>\n    <form method=\"post\" action=\"" + escapeXML(action) + "\">\n      " + strings.Join(lines, "\n      ") + "\n      <noscript><p>Your browser is not running scripts. Press Continue to go on.</p></noscript>\n      <button type=\"submit\">Continue</button>\n    </form>" + script + "\n  </body>\n</html>\n"
}
