// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"math/big"
	"regexp"
	"strings"
)

type jwsAlg struct {
	hash  crypto.Hash
	kty   string
	pss   bool
	p1363 bool
	size  int
}

var jwsAlgs = map[string]jwsAlg{
	"RS256":   {crypto.SHA256, "RSA", false, false, 0},
	"RS384":   {crypto.SHA384, "RSA", false, false, 0},
	"RS512":   {crypto.SHA512, "RSA", false, false, 0},
	"PS256":   {crypto.SHA256, "RSA", true, false, 0},
	"PS384":   {crypto.SHA384, "RSA", true, false, 0},
	"PS512":   {crypto.SHA512, "RSA", true, false, 0},
	"ES256":   {crypto.SHA256, "EC", false, true, 32},
	"ES384":   {crypto.SHA384, "EC", false, true, 48},
	"ES512":   {crypto.SHA512, "EC", false, true, 66},
	"EdDSA":   {0, "OKP", false, false, 0},
	"Ed25519": {0, "OKP", false, false, 0},
}

func supportedJWS() string {
	return "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, Ed25519"
}

var b64urlRE = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

func b64urlDecode(value, what string) ([]byte, error) {
	if !b64urlRE.MatchString(value) {
		return nil, errCode("signature", "the SET's "+what+" is not base64url")
	}
	pad := strings.Repeat("=", (4-len(value)%4)%4)
	out, err := base64.URLEncoding.DecodeString(value + pad)
	if err != nil {
		return nil, errCode("signature", "the SET's "+what+" is not base64url")
	}
	return out, nil
}

func jwsHash(id crypto.Hash) hash.Hash {
	switch id {
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

func keyForJWK(jwk map[string]any) (any, error) {
	kty := stringOf(jwk["kty"])
	defer func() {
		_ = recover()
	}()
	switch kty {
	case "RSA":
		nBytes, err := b64urlDecode(stringOf(jwk["n"]), "key")
		if err != nil {
			return nil, err
		}
		eBytes, err := b64urlDecode(stringOf(jwk["e"]), "key")
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		var curve elliptic.Curve
		switch stringOf(jwk["crv"]) {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errCode("signature", "the transmitter's key "+stringOf(jwk["kid"])+" cannot be read: unsupported curve")
		}
		xBytes, err := b64urlDecode(stringOf(jwk["x"]), "key")
		if err != nil {
			return nil, err
		}
		yBytes, err := b64urlDecode(stringOf(jwk["y"]), "key")
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
	case "OKP":
		raw, err := b64urlDecode(stringOf(jwk["x"]), "key")
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, errCode("signature", "the transmitter's key "+stringOf(jwk["kid"])+" cannot be read: bad OKP length")
		}
		return ed25519.PublicKey(raw), nil
	default:
		return nil, errCode("signature", "the transmitter's key "+stringOf(jwk["kid"])+" cannot be read: unsupported kty "+kty)
	}
}

func verifyJWS(key any, spec jwsAlg, data, sig []byte) bool {
	if spec.hash == 0 {
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(pub, data, sig)
	}
	sum := jwsHash(spec.hash)
	sum.Write(data)
	digest := sum.Sum(nil)
	if spec.pss {
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return rsa.VerifyPSS(pub, spec.hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash}) == nil
	}
	if spec.p1363 {
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != spec.size*2 {
			return false
		}
		r := new(big.Int).SetBytes(sig[:spec.size])
		s := new(big.Int).SetBytes(sig[spec.size:])
		return ecdsa.Verify(pub, digest, r, s)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return false
	}
	return rsa.VerifyPKCS1v15(pub, spec.hash, digest, sig) == nil
}

// VerifyCompactJWS checks a Security Event Token against the transmitter's keys.
func VerifyCompactJWS(token string, keys []map[string]any) (map[string]any, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, errCode("signature", "the SET is not a compact JWS")
	}
	headerRaw, err := b64urlDecode(parts[0], "header")
	if err != nil {
		return nil, nil, err
	}
	payloadRaw, err := b64urlDecode(parts[1], "payload")
	if err != nil {
		return nil, nil, err
	}
	var header any
	var payload any
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, nil, errCause("signature", "the SET's header or payload is not JSON", err)
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil, nil, errCause("signature", "the SET's header or payload is not JSON", err)
	}
	headerObj, okH := header.(map[string]any)
	payloadObj, okP := payload.(map[string]any)
	if !okH || !okP {
		return nil, nil, errCode("signature", "the SET's header or payload is not a JSON object")
	}
	alg := stringOf(headerObj["alg"])
	spec, ok := jwsAlgs[alg]
	if !ok {
		shown := alg
		if shown == "" {
			shown = "(no alg)"
		}
		return nil, nil, errCode("signature", "the SET is signed with "+shown+", which this receiver does not verify ("+supportedJWS()+")")
	}
	if _, crit := headerObj["crit"]; crit {
		return nil, nil, errCode("signature", "the SET's header has a crit member this receiver does not understand")
	}
	kid := ""
	if text, ok := headerObj["kid"].(string); ok {
		kid = text
	}
	var candidates []map[string]any
	for _, key := range keys {
		if kid != "" && stringOf(key["kid"]) != kid {
			continue
		}
		if stringOf(key["kty"]) != spec.kty {
			continue
		}
		if use := stringOf(key["use"]); use != "" && use != "sig" {
			continue
		}
		if keyAlg := stringOf(key["alg"]); keyAlg != "" && keyAlg != alg {
			continue
		}
		candidates = append(candidates, key)
	}
	if len(candidates) == 0 {
		which := ""
		if kid != "" {
			which = " with kid " + kid
		}
		return nil, nil, errCode("signature", "the transmitter publishes no "+spec.kty+" signing key"+which)
	}
	data := []byte(parts[0] + "." + parts[1])
	signature, err := b64urlDecode(parts[2], "signature")
	if err != nil {
		return nil, nil, err
	}
	for _, jwk := range candidates {
		key, err := keyForJWK(jwk)
		if err != nil {
			continue
		}
		if verifyJWS(key, spec, data, signature) {
			return headerObj, payloadObj, nil
		}
	}
	return nil, nil, errCode("signature", "the SET's signature does not verify against the transmitter's keys")
}
