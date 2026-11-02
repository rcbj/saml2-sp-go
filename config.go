// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var absoluteURL = regexp.MustCompile(`^https?://`)

// Config is the configuration with its files read and its defaults filled in.
// Signals is present only when CAEP and RISC are off. A nil Signals means on.
type Config struct {
	EntityID                string
	AcsURL                  string
	PrivateKey              *rsa.PrivateKey
	PrivateKeyPEM           string
	Certificate             *x509.Certificate
	CertificatePEM          string
	IdpMetadata             string
	RequestBinding          string
	ResponseBinding         string
	ClockSkewMS             int64
	WantAssertionsSigned    bool
	WantAssertionsEncrypted bool
	AllowUnsolicited        bool
	Signals                 *bool
	IdpCA                   string
	IdpEntityID             string
	NameIDFormat            string
}

func (c *Config) Has(key string) bool {
	if key == "signals" {
		return c != nil && c.Signals != nil
	}
	return false
}

func expand(value string) (string, error) {
	seen := 0
	for strings.HasPrefix(value, "env:") || strings.HasPrefix(value, "file:") {
		seen++
		if seen > 4 {
			return "", errCode("config", "the placeholder "+value+" is nested too deeply")
		}
		if strings.HasPrefix(value, "env:") {
			name := value[4:]
			got, ok := os.LookupEnv(name)
			if name == "" || !ok {
				shown := name
				if shown == "" {
					shown = value
				}
				return "", errCode("config", "environment variable "+shown+" is not set")
			}
			value = got
			continue
		}
		value = value[5:]
	}
	return value, nil
}

func looksLikePEM(value string) bool {
	return strings.Contains(value, "-----BEGIN ")
}

func material(value, baseDir, what string) (string, error) {
	value, err := expand(value)
	if err != nil {
		return "", err
	}
	if looksLikePEM(value) {
		return value, nil
	}
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	path = filepath.Clean(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", errCause("config", what+" is neither a PEM nor a readable file ("+path+")", err)
	}
	return string(raw), nil
}

func absolute(value any, what string) (string, error) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", errCode("config", what+" is required")
	}
	if !absoluteURL.MatchString(text) {
		return "", errCode("config", what+" must be an absolute http(s) URL, not "+text)
	}
	return text, nil
}

func oneOf(value any, allowed []string, fallback, what string) (string, error) {
	if value == nil || value == "" {
		return fallback, nil
	}
	text, ok := value.(string)
	if !ok {
		return "", errCode("config", what+" must be one of "+strings.Join(allowed, ", ")+", not "+stringify(value))
	}
	for _, item := range allowed {
		if text == item {
			return text, nil
		}
	}
	return "", errCode("config", what+" must be one of "+strings.Join(allowed, ", ")+", not "+text)
}

func stringify(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(raw)
}

func isNumber(value any) (float64, bool) {
	switch n := value.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, !math.IsNaN(n) && !math.IsInf(n, 0)
	case json.Number:
		f, err := n.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

func boolOr(value any, fallback bool) bool {
	if value == nil {
		return fallback
	}
	b, ok := value.(bool)
	if !ok {
		return fallback
	}
	return b
}

// ResolveConfig reads files named by the configuration and fills in defaults.
func ResolveConfig(config map[string]any, baseDir string) (*Config, error) {
	if config == nil {
		return nil, errCode("config", "the configuration must be an object")
	}
	base := baseDir
	if base == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, errCause("config", err.Error(), err)
		}
		base = wd
	}
	entityID, _ := config["entityId"].(string)
	if strings.TrimSpace(entityID) == "" {
		return nil, errCode("config", "entityId is required")
	}
	acsURL, err := absolute(config["acsUrl"], "acsUrl")
	if err != nil {
		return nil, err
	}
	keyText, keyOK := config["privateKey"].(string)
	certText, certOK := config["certificate"].(string)
	if !keyOK || !certOK {
		return nil, errCode("config", "privateKey and certificate are required: every AuthnRequest is signed")
	}
	keyPEM, err := material(keyText, base, "privateKey")
	if err != nil {
		return nil, err
	}
	certPEM, err := material(certText, base, "certificate")
	if err != nil {
		return nil, err
	}
	signer, err := loadPrivateKey(keyPEM)
	if err != nil {
		return nil, errCause("config", "the private key or certificate cannot be read: "+err.Error(), err)
	}
	certificate, err := loadCertificate(certPEM)
	if err != nil {
		return nil, errCause("config", "the private key or certificate cannot be read: "+err.Error(), err)
	}
	privateKey, kind := rsaPrivate(signer)
	if privateKey == nil {
		return nil, errCode("config", "the private key is "+kind+"; an RSA key is required")
	}
	if !samePublic(privateKey, certificate) {
		return nil, errCode("config", "the certificate is not for the private key")
	}
	idpMeta, _ := config["idpMetadata"].(string)
	if strings.TrimSpace(idpMeta) == "" {
		return nil, errCode("config", "idpMetadata is required")
	}
	idpMeta, err = expand(strings.TrimSpace(idpMeta))
	if err != nil {
		return nil, err
	}
	if !absoluteURL.MatchString(idpMeta) && !strings.HasPrefix(idpMeta, "<") {
		if !filepath.IsAbs(idpMeta) {
			idpMeta = filepath.Clean(filepath.Join(base, idpMeta))
		}
	}
	skewValue := 60.0
	if raw, ok := config["clockSkewSeconds"]; ok && raw != nil {
		n, ok := isNumber(raw)
		if !ok || n < 0 || n > 600 {
			return nil, errCode("config", "clockSkewSeconds must be a number from 0 to 600")
		}
		skewValue = n
	}
	if raw, ok := config["signals"]; ok && raw != nil {
		if _, isBool := raw.(bool); !isBool {
			return nil, errCode("config", "signals must be true or false")
		}
	} else if raw, ok := config["signals"]; ok && raw == nil {
		// JSON null is not a boolean.
		return nil, errCode("config", "signals must be true or false")
	}
	out := &Config{
		EntityID:                entityID,
		AcsURL:                  acsURL,
		PrivateKey:              privateKey,
		PrivateKeyPEM:           privateKeyPEM(privateKey),
		Certificate:             certificate,
		CertificatePEM:          certificatePEM(certificate),
		IdpMetadata:             idpMeta,
		ClockSkewMS:             int64(int(skewValue)) * 1000,
		WantAssertionsSigned:    true,
		WantAssertionsEncrypted: false,
		AllowUnsolicited:        false,
	}
	if raw, ok := config["wantAssertionsSigned"]; ok && raw != nil {
		out.WantAssertionsSigned = boolOr(raw, true)
	}
	if raw, ok := config["wantAssertionsEncrypted"]; ok && raw != nil {
		out.WantAssertionsEncrypted = boolOr(raw, false)
	}
	if raw, ok := config["allowUnsolicited"]; ok && raw != nil {
		out.AllowUnsolicited = boolOr(raw, false)
	}
	request, err := oneOf(config["requestBinding"], []string{"redirect", "post"}, "redirect", "requestBinding")
	if err != nil {
		return nil, err
	}
	response, err := oneOf(config["responseBinding"], []string{"post", "redirect", "artifact"}, "post", "responseBinding")
	if err != nil {
		return nil, err
	}
	out.RequestBinding = request
	out.ResponseBinding = response
	if config["signals"] == false {
		off := false
		out.Signals = &off
	}
	if text, _ := config["idpCa"].(string); text != "" {
		ca, err := material(text, base, "idpCa")
		if err != nil {
			return nil, err
		}
		out.IdpCA = ca
	}
	if text, _ := config["idpEntityId"].(string); text != "" {
		out.IdpEntityID = text
	}
	if text, _ := config["nameIdFormat"].(string); text != "" {
		out.NameIDFormat = text
	}
	return out, nil
}

// ReadConfigFile loads a JSON configuration. Nil overrides are ignored.
func ReadConfigFile(path string, overrides map[string]any) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errCause("config", path+" cannot be read as JSON: "+err.Error(), err)
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, errCause("config", path+" cannot be read as JSON: "+err.Error(), err)
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return nil, errCode("config", "the configuration must be an object")
	}
	for k, v := range overrides {
		if v != nil {
			obj[k] = v
		}
	}
	return ResolveConfig(obj, filepath.Dir(absPath(path)))
}

func absPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
