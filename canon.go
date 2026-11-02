// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"hash"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

var signatureAlgs = map[string]crypto.Hash{
	rsaSHA256: crypto.SHA256,
	rsaSHA384: crypto.SHA384,
	rsaSHA512: crypto.SHA512,
}

var digestAlgs = map[string]crypto.Hash{
	digest256: crypto.SHA256,
	digest384: crypto.SHA384,
	digest512: crypto.SHA512,
}

func hashNew(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

func cloneForC14N(el *etree.Element) *etree.Element {
	clone := el.Copy()
	seen := map[string]bool{}
	for _, a := range clone.Attr {
		if a.Space == "xmlns" {
			seen[a.Key] = true
		} else if a.Space == "" && a.Key == "xmlns" {
			seen[""] = true
		}
	}
	var extra []etree.Attr
	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			key := ""
			ok := false
			if a.Space == "xmlns" {
				key, ok = a.Key, true
			} else if a.Space == "" && a.Key == "xmlns" {
				ok = true
			}
			if !ok || seen[key] {
				continue
			}
			seen[key] = true
			extra = append(extra, a)
		}
	}
	if len(extra) > 0 {
		clone.Attr = append(extra, clone.Attr...)
	}
	return clone
}

func canonicalize(el *etree.Element, algorithm, prefixList string) ([]byte, error) {
	switch algorithm {
	case excC14N:
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList).Canonicalize(cloneForC14N(el))
	case excC14NComments:
		return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList).Canonicalize(cloneForC14N(el))
	case c14n10:
		return dsig.MakeC14N10RecCanonicalizer().Canonicalize(el)
	case c14n10Comments:
		return dsig.MakeC14N10WithCommentsCanonicalizer().Canonicalize(el)
	default:
		return nil, errCode("signature", "the signature uses the canonicalization "+orNone(algorithm)+", which is refused")
	}
}

func orNone(v string) string {
	if v == "" {
		return "(none)"
	}
	return v
}

func inclusivePrefixes(transform *etree.Element) string {
	if transform == nil {
		return ""
	}
	for _, c := range transform.ChildElements() {
		if c.Tag == "InclusiveNamespaces" {
			return attrOr(c, "PrefixList")
		}
	}
	return ""
}

func algorithmOf(parent *etree.Element, local string) string {
	found, err := child(parent, nsDsig, local)
	if err != nil || found == nil {
		return ""
	}
	return attrOr(found, "Algorithm")
}

func compactText(el *etree.Element) string {
	return strings.TrimSpace(iterText(el))
}

func applyTransforms(el, signature *etree.Element, transforms []*etree.Element) ([]byte, error) {
	node := el
	var data []byte
	if len(transforms) == 0 {
		return canonicalize(el, c14n10, "")
	}
	for index, transform := range transforms {
		alg := attrOr(transform, "Algorithm")
		if data != nil {
			parsed, err := parseXML(string(data), "the transformed reference")
			if err != nil {
				return nil, err
			}
			node = parsed
			data = nil
		}
		if alg == enveloped {
			copied := node.Copy()
			original := ""
			if values := children(signature, nsDsig, "SignatureValue"); len(values) > 0 {
				original = strings.ReplaceAll(compactText(values[0]), " ", "")
			}
			for _, sig := range children(copied, nsDsig, "Signature") {
				value := ""
				if values := children(sig, nsDsig, "SignatureValue"); len(values) > 0 {
					value = strings.ReplaceAll(compactText(values[0]), " ", "")
				}
				if value == original || sig.Parent() == copied {
					copied.RemoveChild(sig)
					break
				}
			}
			node = copied
			continue
		}
		if alg == excC14N || alg == excC14NComments || alg == c14n10 || alg == c14n10Comments {
			out, err := canonicalize(node, alg, inclusivePrefixes(transform))
			if err != nil {
				return nil, err
			}
			data = out
			node = nil
			if index == len(transforms)-1 {
				return data, nil
			}
			continue
		}
		return nil, errCode("signature", "the signature uses the transform "+orNone(alg)+", which is refused")
	}
	if data != nil {
		return data, nil
	}
	return canonicalize(node, c14n10, "")
}

// verifySigned returns the exclusive canonical form of el with its signature removed,
// or an empty string when el is not signed.
func verifySigned(el *etree.Element, certs []*x509.Certificate, what string) (string, error) {
	sigEl, err := child(el, nsDsig, "Signature")
	if err != nil {
		return "", err
	}
	if sigEl == nil {
		return "", nil
	}
	elementID := attrOr(el, "ID")
	if elementID == "" {
		return "", errCode("signature", what+" is signed but has no ID for the signature to refer to")
	}
	signedInfo, err := child(sigEl, nsDsig, "SignedInfo")
	if err != nil {
		return "", err
	}
	if signedInfo == nil {
		return "", errCode("signature", what+"'s signature has no SignedInfo")
	}
	c14nAlg := algorithmOf(signedInfo, "CanonicalizationMethod")
	if c14nAlg != excC14N && c14nAlg != excC14NComments && c14nAlg != c14n10 && c14nAlg != c14n10Comments {
		return "", errCode("signature", what+"'s signature uses the canonicalization "+orNone(c14nAlg)+", which is refused")
	}
	sigAlg := algorithmOf(signedInfo, "SignatureMethod")
	hashID, ok := signatureAlgs[sigAlg]
	if !ok {
		return "", errCode("signature", what+"'s signature uses "+orNone(sigAlg)+", which is refused (SHA-1 and non-RSA algorithms are not accepted)")
	}
	refs := children(signedInfo, nsDsig, "Reference")
	if len(refs) != 1 {
		return "", errCode("signature", what+"'s signature has "+itoa(len(refs))+" references; exactly one is accepted")
	}
	ref := refs[0]
	if attrOr(ref, "URI") != "#"+elementID {
		return "", errCode("signature", what+"'s signature refers to "+orNothing(attrOr(ref, "URI"))+", not to "+what+" itself (#"+elementID+")")
	}
	digestAlg := algorithmOf(ref, "DigestMethod")
	digestHash, ok := digestAlgs[digestAlg]
	if !ok {
		return "", errCode("signature", what+"'s signature digests with "+orNone(digestAlg)+", which is refused")
	}
	var transformEls []*etree.Element
	transformsEl, err := child(ref, nsDsig, "Transforms")
	if err != nil {
		return "", err
	}
	if transformsEl != nil {
		transformEls = children(transformsEl, nsDsig, "Transform")
	}
	for _, transform := range transformEls {
		alg := attrOr(transform, "Algorithm")
		if alg != enveloped && alg != excC14N && alg != excC14NComments && alg != c14n10 && alg != c14n10Comments {
			return "", errCode("signature", what+"'s signature uses the transform "+orNone(alg)+", which is refused")
		}
	}
	if len(certs) == 0 {
		return "", errCode("signature", "no signing certificate is known for the identity provider, so "+what+" cannot be verified")
	}
	reference, err := applyTransforms(el, sigEl, transformEls)
	if err != nil {
		if se, ok := err.(*SamlError); ok {
			return "", se
		}
		return "", errCause("signature", what+"'s signature does not verify against the identity provider's certificate: the signature does not verify", err)
	}
	digestValue, err := child(ref, nsDsig, "DigestValue")
	if err != nil {
		return "", err
	}
	got, decErr := base64.StdEncoding.DecodeString(compactText(digestValue))
	if decErr != nil {
		return "", errCause("signature", what+"'s signature does not verify against the identity provider's certificate: the digest is not base64", decErr)
	}
	sum := hashNew(digestHash)
	sum.Write(reference)
	want := sum.Sum(nil)
	if !hmacEqual(got, want) {
		return "", errCode("signature", what+"'s signature does not verify against the identity provider's certificate: the signature does not verify")
	}
	infoPrefixes := ""
	method, err := child(signedInfo, nsDsig, "CanonicalizationMethod")
	if err != nil {
		return "", err
	}
	if method != nil {
		infoPrefixes = inclusivePrefixes(method)
	}
	signedBytes, err := canonicalize(signedInfo, c14nAlg, infoPrefixes)
	if err != nil {
		return "", errCode("signature", what+"'s signature does not verify against the identity provider's certificate: the signature does not verify")
	}
	signatureValue, err := child(sigEl, nsDsig, "SignatureValue")
	if err != nil {
		return "", err
	}
	sigBytes, decErr := base64.StdEncoding.DecodeString(compactText(signatureValue))
	if decErr != nil {
		return "", errCause("signature", what+"'s signature does not verify against the identity provider's certificate: the signature value is not base64", decErr)
	}
	verified := false
	for _, cert := range certs {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		sum := hashNew(hashID)
		sum.Write(signedBytes)
		if rsa.VerifyPKCS1v15(pub, hashID, sum.Sum(nil), sigBytes) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return "", errCode("signature", what+"'s signature does not verify against the identity provider's certificate: the signature does not verify")
	}
	return canonicalWithoutSignatures(el)
}

func canonicalWithoutSignatures(el *etree.Element) (string, error) {
	copied := cloneForC14N(el)
	for _, sig := range children(copied, nsDsig, "Signature") {
		copied.RemoveChild(sig)
	}
	out, err := canonicalize(copied, excC14N, "")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func orNothing(v string) string {
	if v == "" {
		return "(nothing)"
	}
	return v
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func signEnveloped(xml, elementID string, key *rsa.PrivateKey, cert *x509.Certificate) (string, error) {
	root, err := parseXML(xml, "the message to sign")
	if err != nil {
		return "", err
	}
	target := elementByID(root, elementID)
	if target == nil {
		return "", errCode("signature", "no element has ID "+elementID)
	}
	reference, err := canonicalize(target, excC14N, "")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(reference)
	digest := base64.StdEncoding.EncodeToString(sum[:])
	signature := signatureElement(elementID, digest, cert)
	insertAfterIssuer(target, signature)
	signedInfo := children(signature, nsDsig, "SignedInfo")[0]
	signedBytes, err := canonicalize(signedInfo, excC14N, "")
	if err != nil {
		return "", err
	}
	hashed := sha256.Sum256(signedBytes)
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", errCause("signature", "the message could not be signed", err)
	}
	children(signature, nsDsig, "SignatureValue")[0].SetText(base64.StdEncoding.EncodeToString(sig))
	return serialize(root), nil
}

func signatureElement(elementID, digest string, cert *x509.Certificate) *etree.Element {
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", nsDsig)
	signedInfo := sig.CreateElement("ds:SignedInfo")
	signedInfo.CreateAttr("xmlns:ds", nsDsig)
	c14n := signedInfo.CreateElement("ds:CanonicalizationMethod")
	c14n.CreateAttr("Algorithm", excC14N)
	method := signedInfo.CreateElement("ds:SignatureMethod")
	method.CreateAttr("Algorithm", rsaSHA256)
	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "#"+elementID)
	transforms := ref.CreateElement("ds:Transforms")
	env := transforms.CreateElement("ds:Transform")
	env.CreateAttr("Algorithm", enveloped)
	exc := transforms.CreateElement("ds:Transform")
	exc.CreateAttr("Algorithm", excC14N)
	digestMethod := ref.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", digest256)
	digestValue := ref.CreateElement("ds:DigestValue")
	digestValue.SetText(digest)
	sig.CreateElement("ds:SignatureValue")
	keyInfo := sig.CreateElement("ds:KeyInfo")
	data := keyInfo.CreateElement("ds:X509Data")
	certEl := data.CreateElement("ds:X509Certificate")
	certEl.SetText(certDERBody(cert))
	return sig
}

func insertAfterIssuer(target, signature *etree.Element) {
	for _, c := range target.Child {
		el, ok := c.(*etree.Element)
		if !ok || !same(el, nsSaml, "Issuer") {
			continue
		}
		idx := childTokenIndex(target, el)
		target.InsertChildAt(idx+1, signature)
		return
	}
	target.InsertChildAt(0, signature)
}

func childTokenIndex(parent *etree.Element, child *etree.Element) int {
	for i, token := range parent.Child {
		if el, ok := token.(*etree.Element); ok && el == child {
			return i
		}
	}
	return 0
}
