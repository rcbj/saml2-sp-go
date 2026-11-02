// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"strings"

	"github.com/beevik/etree"
)

type cipherSpec struct {
	name   string
	gcm    bool
	keyLen int
}

var ciphers = map[string]cipherSpec{
	"http://www.w3.org/2009/xmlenc11#aes128-gcm":  {"aes-128-gcm", true, 16},
	"http://www.w3.org/2009/xmlenc11#aes192-gcm":  {"aes-192-gcm", true, 24},
	"http://www.w3.org/2009/xmlenc11#aes256-gcm":  {"aes-256-gcm", true, 32},
	"http://www.w3.org/2001/04/xmlenc#aes128-cbc": {"aes-128-cbc", false, 16},
	"http://www.w3.org/2001/04/xmlenc#aes192-cbc": {"aes-192-cbc", false, 24},
	"http://www.w3.org/2001/04/xmlenc#aes256-cbc": {"aes-256-cbc", false, 32},
}

const (
	oaepMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	oaep11    = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

var oaepDigests = map[string]string{
	"http://www.w3.org/2000/09/xmldsig#sha1":        "sha1",
	"http://www.w3.org/2001/04/xmlenc#sha256":       "sha256",
	"http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
	"http://www.w3.org/2001/04/xmlenc#sha512":       "sha512",
}

var oaepMGFs = map[string]string{
	"http://www.w3.org/2009/xmlenc11#mgf1sha1":   "sha1",
	"http://www.w3.org/2009/xmlenc11#mgf1sha256": "sha256",
	"http://www.w3.org/2009/xmlenc11#mgf1sha384": "sha384",
	"http://www.w3.org/2009/xmlenc11#mgf1sha512": "sha512",
}

func decryptFail(message string, cause error) error {
	if cause == nil {
		return errCode("decryption", message)
	}
	return errCause("decryption", message, cause)
}

func b64(value string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
}

func hashByName(name string) hash.Hash {
	switch name {
	case "sha1":
		return sha1.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	default:
		return sha256.New()
	}
}

func unwrapKey(encryptedKey *etree.Element, key *rsa.PrivateKey) ([]byte, error) {
	method, err := child(encryptedKey, nsXenc, "EncryptionMethod")
	if err != nil {
		return nil, err
	}
	alg := ""
	if method != nil {
		alg = attrOr(method, "Algorithm")
	}
	if alg != oaepMGF1P && alg != oaep11 {
		return nil, decryptFail("the content key is wrapped with "+orNone(alg)+"; only RSA-OAEP is accepted", nil)
	}
	digest := "sha1"
	if method != nil {
		digestMethod, err := child(method, nsDsig, "DigestMethod")
		if err != nil {
			return nil, err
		}
		if digestMethod != nil {
			digestAlg := attrOr(digestMethod, "Algorithm")
			found, ok := oaepDigests[digestAlg]
			if !ok {
				return nil, decryptFail("the OAEP digest "+digestAlg+" is not supported", nil)
			}
			digest = found
		}
	}
	mgf := "sha1"
	if alg == oaep11 && method != nil {
		mgfEl, err := child(method, nsXenc11, "MGF")
		if err != nil {
			return nil, err
		}
		if mgfEl != nil && attrOr(mgfEl, "Algorithm") != "" {
			mgfAlg := attrOr(mgfEl, "Algorithm")
			found, ok := oaepMGFs[mgfAlg]
			if !ok {
				return nil, decryptFail("the OAEP mask generation function "+mgfAlg+" is not supported", nil)
			}
			mgf = found
		}
	}
	if mgf != digest {
		return nil, decryptFail("OAEP with digest "+digest+" and MGF1 "+mgf+" is not supported; one hash is used for both", nil)
	}
	values := descendants(encryptedKey, nsXenc, "CipherValue")
	raw := ""
	if len(values) > 0 {
		raw = textOf(values[0])
	}
	blob, err := b64(raw)
	if err != nil {
		return nil, decryptFail("the content key could not be unwrapped with this service provider's key", err)
	}
	plain, err := rsa.DecryptOAEP(hashByName(digest), nil, key, blob, nil)
	if err != nil {
		return nil, decryptFail("the content key could not be unwrapped with this service provider's key", err)
	}
	return plain, nil
}

func decryptElement(encrypted *etree.Element, key *rsa.PrivateKey) (string, error) {
	data, err := child(encrypted, nsXenc, "EncryptedData")
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", decryptFail("<"+encrypted.Tag+"> has no EncryptedData", nil)
	}
	method, err := child(data, nsXenc, "EncryptionMethod")
	if err != nil {
		return "", err
	}
	alg := ""
	if method != nil {
		alg = attrOr(method, "Algorithm")
	}
	spec, ok := ciphers[alg]
	if !ok {
		return "", decryptFail("the content is encrypted with "+orNone(alg)+", which is not supported", nil)
	}
	keys := descendants(encrypted, nsXenc, "EncryptedKey")
	if len(keys) == 0 {
		return "", decryptFail("<"+encrypted.Tag+"> carries no EncryptedKey", nil)
	}
	contentKey, err := unwrapKey(keys[0], key)
	if err != nil {
		return "", err
	}
	if len(contentKey) != spec.keyLen {
		return "", decryptFail("the content key is "+itoa(len(contentKey))+" bytes; "+spec.name+" needs "+itoa(spec.keyLen), nil)
	}
	cipherData, err := child(data, nsXenc, "CipherData")
	if err != nil {
		return "", err
	}
	var cipherValue *etree.Element
	if cipherData != nil {
		cipherValue, err = child(cipherData, nsXenc, "CipherValue")
		if err != nil {
			return "", err
		}
	}
	blob, err := b64(textOf(cipherValue))
	if err != nil {
		return "", decryptFail("the content could not be decrypted", err)
	}
	if spec.gcm {
		if len(blob) < 12+16 {
			return "", decryptFail("the ciphertext is too short", nil)
		}
		block, err := aes.NewCipher(contentKey)
		if err != nil {
			return "", decryptFail("the content could not be decrypted", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", decryptFail("the content could not be decrypted", err)
		}
		plain, err := gcm.Open(nil, blob[:12], blob[12:], nil)
		if err != nil {
			return "", decryptFail("the content could not be decrypted", err)
		}
		return string(plain), nil
	}
	if len(blob) < 32 || len(blob)%16 != 0 {
		return "", decryptFail("the ciphertext is not a whole number of blocks", nil)
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return "", decryptFail("the content could not be decrypted", err)
	}
	plain := make([]byte, len(blob)-16)
	cipher.NewCBCDecrypter(block, blob[:16]).CryptBlocks(plain, blob[16:])
	if len(plain) == 0 {
		return "", decryptFail("the decrypted content is not padded as XML Encryption pads it", nil)
	}
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > 16 || pad > len(plain) {
		return "", decryptFail("the decrypted content is not padded as XML Encryption pads it", nil)
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return "", decryptFail("the decrypted content is not padded as XML Encryption pads it", nil)
		}
	}
	return string(plain[:len(plain)-pad]), nil
}
