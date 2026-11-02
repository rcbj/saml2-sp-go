// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"time"
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

func send(rawURL, method string, headers map[string]string, body string, tlsOpt *TLSOptions, code string) (*httpAnswer, error) {
	if !(strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://")) {
		return nil, errCode(code, rawURL+" is not an http(s) URL")
	}
	var reader io.Reader
	if body != "" || method == http.MethodPost || method == http.MethodPut {
		if method != http.MethodGet && method != http.MethodHead {
			reader = strings.NewReader(body)
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
	client := &http.Client{Timeout: timeout, Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
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
