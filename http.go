// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	maxBytes = 2 * 1024 * 1024
	timeout  = 15 * time.Second
)

// TLSOptions is the back channel's trust and client certificate.
type TLSOptions struct {
	CA   string
	Cert string
	Key  string
}

type httpAnswer struct {
	Status      int
	ContentType string
	Body        string
}

// isLoopbackHost is true for 127.0.0.0/8, ::1 and the name localhost: the
// hosts where plain http never leaves the machine.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if strings.Contains(host, ":") {
		return ip.Equal(net.IPv6loopback)
	}
	return ip.To4()[0] == 127
}

// refusePlainHTTP is nil unless u is a plain http URL off loopback. Userinfo
// is never loopback, so "http://localhost:80@host/" cannot pass as localhost.
// The message names the scheme and host[:port] only: never userinfo, path or
// query.
func refusePlainHTTP(u *url.URL, code string) error {
	if !strings.EqualFold(u.Scheme, "http") {
		return nil
	}
	if u.User == nil && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return errCode(code, "http://"+u.Host+" is refused: plain http is allowed only to a loopback host (127.0.0.0/8, ::1, localhost); use https")
}

func send(rawURL, method string, headers map[string]string, body string, tlsOpt *TLSOptions, code string) (*httpAnswer, error) {
	// A URL with whitespace or a control character is refused before any
	// parser reads it, so two parsers cannot disagree about its host. The
	// message does not repeat the URL, which may carry a secret.
	for _, r := range rawURL {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return nil, errCode(code, "a URL containing whitespace or a control character is refused")
		}
	}
	if !(strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://")) {
		return nil, errCode(code, rawURL+" is not an http(s) URL")
	}
	var reader io.Reader
	if body != "" || method == http.MethodPost || method == http.MethodPut {
		if method != http.MethodGet && method != http.MethodHead {
			reader = strings.NewReader(body)
		}
	}
	// Every fetch this package makes goes through here: the identity
	// provider's metadata (its signing keys), the ArtifactResolve (the signed
	// request out, the assertion back) and the Shared Signals transmitter
	// (SETs, its JWKS and the bearer token). None of them may travel in the
	// clear off this machine, so plain http is refused before any DNS lookup
	// or connection unless the host is loopback.
	if strings.HasPrefix(rawURL, "http://") {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, errCode(code, "an http:// URL that cannot be parsed is refused")
		}
		if refused := refusePlainHTTP(parsed, code); refused != nil {
			return nil, refused
		}
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		return nil, errCause(code, rawURL+": "+err.Error(), err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.HasPrefix(rawURL, "https://") {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if tlsOpt != nil && tlsOpt.CA != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(tlsOpt.CA)) {
				return nil, errCode(code, rawURL+": the CA certificate cannot be read")
			}
			cfg.RootCAs = pool
		}
		if tlsOpt != nil && tlsOpt.Cert != "" && tlsOpt.Key != "" {
			pair, err := tls.X509KeyPair([]byte(tlsOpt.Cert), []byte(tlsOpt.Key))
			if err != nil {
				return nil, errCause(code, rawURL+": "+err.Error(), err)
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
		transport.TLSClientConfig = cfg
	}
	// A redirect is a fetch too: an https URL may not hand the request on to
	// plain http off loopback.
	client := &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return refusePlainHTTP(next.URL, code)
	}}
	resp, err := client.Do(req)
	if err != nil {
		var refused *SamlError
		if errors.As(err, &refused) {
			return nil, refused
		}
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "timeout") || strings.Contains(message, "timed out") {
			return nil, errCause(code, rawURL+" did not answer within 15 s", err)
		}
		return nil, errCause(code, rawURL+": "+err.Error(), err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, errCause(code, rawURL+": "+err.Error(), err)
	}
	if len(payload) > maxBytes {
		return nil, errCode(code, rawURL+" answered more than "+itoa(maxBytes)+" bytes")
	}
	return &httpAnswer{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: string(payload)}, nil
}
