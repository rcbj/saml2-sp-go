// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
)

var dateTimeRE = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$`)

// SamlLogin is a person the assertion consumer accepted.
type SamlLogin struct {
	NameID                 string
	NameIDFormat           string
	NameQualifier          string
	SPNameQualifier        string
	SessionIndex           string
	SessionNotOnOrAfter    *time.Time
	AuthnInstant           time.Time
	AuthnContextClassRef   string
	Attributes             map[string][]string
	AttributeFriendlyNames map[string]string
	Issuer                 string
	InResponseTo           *string
	RelayState             *string
	Binding                string
	Encrypted              bool
	ResponseID             string
	AssertionID            string
}

type receivedMessage struct {
	XML                    string
	Response               *etree.Element
	Binding                string
	RelayState             *string
	AuthenticatedByBinding bool
}

type validationContext struct {
	EntityID                string
	AcsURL                  string
	IdpEntityID             string
	IdpCertificates         []*x509.Certificate
	DecryptionKey           *rsa.PrivateKey
	ClockSkewMS             int64
	WantAssertionsSigned    bool
	WantAssertionsEncrypted bool
	AllowUnsolicited        bool
	Replay                  *MemoryReplayCache
	ExpectedRequestIDs      []string
	Now                     time.Time
}

func invalid(message string) error {
	return errCode("validation", message)
}

func parseInstant(value, what string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	if !dateTimeRE.MatchString(value) {
		return nil, invalid(what + " is not a UTC dateTime: " + value)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, invalid(what + " is not a dateTime: " + value)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func issuerOf(el *etree.Element, required bool, expected, what string) error {
	issuer, err := child(el, nsSaml, "Issuer")
	if err != nil {
		return err
	}
	if issuer == nil {
		if required {
			return invalid(what + " has no Issuer")
		}
		return nil
	}
	form := attrOr(issuer, "Format")
	if form != "" && form != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" {
		return invalid(what + "'s Issuer has the Format " + form)
	}
	if textOf(issuer) != expected {
		return invalid(what + " was issued by " + textOf(issuer) + ", not by " + expected)
	}
	return nil
}

func statusOf(response *etree.Element) (*SamlStatus, error) {
	status, err := child(response, nsSamlp, "Status")
	if err != nil {
		return nil, err
	}
	if status == nil {
		return nil, invalid("the Response has no Status")
	}
	top, err := child(status, nsSamlp, "StatusCode")
	if err != nil {
		return nil, err
	}
	if top == nil {
		return nil, invalid("the Response has no StatusCode")
	}
	out := &SamlStatus{Code: attrOr(top, "Value")}
	sub, err := child(top, nsSamlp, "StatusCode")
	if err != nil {
		return nil, err
	}
	if sub != nil && attrOr(sub, "Value") != "" {
		out.SubCode = attrOr(sub, "Value")
	}
	message, err := child(status, nsSamlp, "StatusMessage")
	if err != nil {
		return nil, err
	}
	if text := textOf(message); text != "" {
		out.Message = text
	}
	return out, nil
}

func validateResponse(received *receivedMessage, ctx *validationContext) (*SamlLogin, error) {
	now := ctx.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowMS := now.UnixMilli()
	skew := ctx.ClockSkewMS
	response := received.Response
	if err := assertUniqueIDs(documentRoot(response)); err != nil {
		return nil, err
	}
	if !same(response, nsSamlp, "Response") {
		return nil, invalid("the message is a <" + response.Tag + ">, not a Response")
	}
	signed, err := verifySigned(response, ctx.IdpCertificates, "the Response")
	if err != nil {
		return nil, err
	}
	if signed != "" {
		parsed, err := parseXML(signed, "the signed Response")
		if err != nil {
			return nil, err
		}
		response = parsed
	}
	responseAuthenticated := signed != "" || received.AuthenticatedByBinding
	if attrOr(response, "Version") != "2.0" {
		version := attrOr(response, "Version")
		if version == "" {
			version = "(none)"
		}
		return nil, invalid("the Response is version " + version + ", not 2.0")
	}
	responseID, ok := attr(response, "ID")
	if !ok || responseID == "" {
		return nil, invalid("the Response has no ID")
	}
	if err := issuerOf(response, false, ctx.IdpEntityID, "the Response"); err != nil {
		return nil, err
	}
	destination, hasDest := attr(response, "Destination")
	if hasDest && destination != ctx.AcsURL {
		return nil, invalid("the Response is addressed to " + destination + ", not to " + ctx.AcsURL)
	}
	if !hasDest && responseAuthenticated && received.Binding != "artifact" {
		return nil, invalid("the Response is signed but has no Destination")
	}
	inResponseTo, hasIn := attr(response, "InResponseTo")
	var inPtr *string
	if hasIn {
		inPtr = &inResponseTo
		found := false
		for _, id := range ctx.ExpectedRequestIDs {
			if id == inResponseTo {
				found = true
				break
			}
		}
		if !found {
			return nil, invalid("the Response answers " + inResponseTo + ", which is not a request this browser has outstanding")
		}
	} else if !ctx.AllowUnsolicited {
		return nil, invalid("the Response is unsolicited (it has no InResponseTo), and unsolicited Responses are not accepted")
	}
	status, err := statusOf(response)
	if err != nil {
		return nil, err
	}
	if status.Code != statusSuccess {
		detail := status.Code
		if status.SubCode != "" {
			detail = status.SubCode
		}
		suffix := ""
		if status.Message != "" {
			suffix = ": " + status.Message
		}
		return nil, errStatus("the identity provider answered "+detail+suffix, status)
	}
	plain := children(response, nsSaml, "Assertion")
	encrypted := children(response, nsSaml, "EncryptedAssertion")
	if len(plain)+len(encrypted) != 1 {
		return nil, invalid("the Response holds " + itoa(len(plain)+len(encrypted)) + " assertions; exactly one is accepted")
	}
	var assertion *etree.Element
	wasEncrypted := false
	if len(encrypted) == 1 {
		wasEncrypted = true
		assertionXML, err := decryptElement(encrypted[0], ctx.DecryptionKey)
		if err != nil {
			return nil, err
		}
		doc, err := parseXML(assertionXML, "the decrypted assertion")
		if err != nil {
			return nil, err
		}
		if err := assertUniqueIDs(doc); err != nil {
			return nil, err
		}
		assertion = doc
		if !same(assertion, nsSaml, "Assertion") {
			return nil, invalid("the EncryptedAssertion does not hold an Assertion")
		}
	} else {
		if ctx.WantAssertionsEncrypted {
			return nil, invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on")
		}
		assertion = plain[0]
	}
	signedAssertion, err := verifySigned(assertion, ctx.IdpCertificates, "the assertion")
	if err != nil {
		return nil, err
	}
	if signedAssertion != "" {
		parsed, err := parseXML(signedAssertion, "the signed assertion")
		if err != nil {
			return nil, err
		}
		assertion = parsed
	} else if ctx.WantAssertionsSigned {
		return nil, invalid("the assertion is not signed, and wantAssertionsSigned is on")
	} else if !responseAuthenticated {
		return nil, invalid("neither the Response nor its assertion is signed")
	}
	if attrOr(assertion, "Version") != "2.0" {
		return nil, invalid("the assertion is not version 2.0")
	}
	assertionID, ok := attr(assertion, "ID")
	if !ok || assertionID == "" {
		return nil, invalid("the assertion has no ID")
	}
	if err := issuerOf(assertion, true, ctx.IdpEntityID, "the assertion"); err != nil {
		return nil, err
	}
	subject, err := child(assertion, nsSaml, "Subject")
	if err != nil {
		return nil, err
	}
	if subject == nil {
		return nil, invalid("the assertion has no Subject")
	}
	nameID, err := child(subject, nsSaml, "NameID")
	if err != nil {
		return nil, err
	}
	encryptedID, err := child(subject, nsSaml, "EncryptedID")
	if err != nil {
		return nil, err
	}
	if nameID == nil && encryptedID != nil {
		xml, err := decryptElement(encryptedID, ctx.DecryptionKey)
		if err != nil {
			return nil, err
		}
		nameID, err = parseXML(xml, "the decrypted NameID")
		if err != nil {
			return nil, err
		}
		if !same(nameID, nsSaml, "NameID") {
			return nil, invalid("the EncryptedID does not hold a NameID")
		}
	}
	if nameID == nil || textOf(nameID) == "" {
		return nil, invalid("the assertion's Subject has no NameID")
	}
	var reasons []string
	var confirmedUntil *time.Time
	for _, confirmation := range children(subject, nsSaml, "SubjectConfirmation") {
		if attrOr(confirmation, "Method") != cmBearer {
			reasons = append(reasons, "method "+attrOr(confirmation, "Method"))
			continue
		}
		data, err := child(confirmation, nsSaml, "SubjectConfirmationData")
		if err != nil {
			return nil, err
		}
		if data == nil {
			reasons = append(reasons, "no SubjectConfirmationData")
			continue
		}
		recipient := attrOr(data, "Recipient")
		notOnOrAfter, err := parseInstant(attrOr(data, "NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter")
		if err != nil {
			return nil, err
		}
		_, hasNotBefore := attr(data, "NotBefore")
		scIn, hasSC := attr(data, "InResponseTo")
		if recipient != ctx.AcsURL {
			shown := recipient
			if shown == "" {
				shown = "(none)"
			}
			reasons = append(reasons, "Recipient "+shown)
		} else if notOnOrAfter == nil {
			reasons = append(reasons, "no NotOnOrAfter")
		} else if notOnOrAfter.UnixMilli() <= nowMS-skew {
			reasons = append(reasons, "expired at "+notOnOrAfter.UTC().Format("2006-01-02T15:04:05.000Z"))
		} else if hasNotBefore {
			reasons = append(reasons, "a NotBefore, which a bearer confirmation must not have")
		} else if (hasSC && (inPtr == nil || scIn != *inPtr)) || (!hasSC && inPtr != nil) {
			shown := scIn
			if !hasSC || shown == "" {
				shown = "(none)"
			}
			reasons = append(reasons, "InResponseTo "+shown)
		} else {
			confirmedUntil = notOnOrAfter
			break
		}
	}
	if confirmedUntil == nil {
		why := "there is none"
		if len(reasons) > 0 {
			why = strings.Join(reasons, "; ")
		}
		return nil, invalid("no bearer SubjectConfirmation of the assertion fits: " + why)
	}
	conditions, err := child(assertion, nsSaml, "Conditions")
	if err != nil {
		return nil, err
	}
	if conditions == nil {
		return nil, invalid("the assertion has no Conditions, so it names no audience")
	}
	notBeforeC, err := parseInstant(attrOr(conditions, "NotBefore"), "Conditions NotBefore")
	if err != nil {
		return nil, err
	}
	notOnOrAfterC, err := parseInstant(attrOr(conditions, "NotOnOrAfter"), "Conditions NotOnOrAfter")
	if err != nil {
		return nil, err
	}
	if notBeforeC != nil && notBeforeC.UnixMilli() > nowMS+skew {
		return nil, invalid("the assertion is not valid before " + notBeforeC.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	if notOnOrAfterC != nil && notOnOrAfterC.UnixMilli() <= nowMS-skew {
		return nil, invalid("the assertion expired at " + notOnOrAfterC.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	restrictions := children(conditions, nsSaml, "AudienceRestriction")
	if len(restrictions) == 0 {
		return nil, invalid("the assertion has no AudienceRestriction")
	}
	for _, restriction := range restrictions {
		okAud := false
		for _, audience := range children(restriction, nsSaml, "Audience") {
			if textOf(audience) == ctx.EntityID {
				okAud = true
				break
			}
		}
		if !okAud {
			return nil, invalid("the assertion is not for " + ctx.EntityID)
		}
	}
	authnStatements := children(assertion, nsSaml, "AuthnStatement")
	if len(authnStatements) == 0 {
		return nil, invalid("the assertion has no AuthnStatement")
	}
	authn := authnStatements[0]
	authnInstant, err := parseInstant(attrOr(authn, "AuthnInstant"), "AuthnInstant")
	if err != nil {
		return nil, err
	}
	if authnInstant == nil {
		return nil, invalid("the AuthnStatement has no AuthnInstant")
	}
	sessionNotOnOrAfter, err := parseInstant(attrOr(authn, "SessionNotOnOrAfter"), "SessionNotOnOrAfter")
	if err != nil {
		return nil, err
	}
	if sessionNotOnOrAfter != nil && sessionNotOnOrAfter.UnixMilli() <= nowMS-skew {
		return nil, invalid("the identity provider's session has already ended")
	}
	contextEl, err := child(authn, nsSaml, "AuthnContext")
	if err != nil {
		return nil, err
	}
	classRef := ""
	if contextEl != nil {
		ref, err := child(contextEl, nsSaml, "AuthnContextClassRef")
		if err != nil {
			return nil, err
		}
		classRef = textOf(ref)
	}
	attributes := map[string][]string{}
	friendly := map[string]string{}
	for _, statement := range children(assertion, nsSaml, "AttributeStatement") {
		var decrypted []*etree.Element
		for _, enc := range children(statement, nsSaml, "EncryptedAttribute") {
			xml, err := decryptElement(enc, ctx.DecryptionKey)
			if err != nil {
				return nil, err
			}
			element, err := parseXML(xml, "the decrypted attribute")
			if err != nil {
				return nil, err
			}
			if !same(element, nsSaml, "Attribute") {
				return nil, invalid("an EncryptedAttribute does not hold an Attribute")
			}
			decrypted = append(decrypted, element)
		}
		attrs := append(children(statement, nsSaml, "Attribute"), decrypted...)
		for _, attribute := range attrs {
			name := attrOr(attribute, "Name")
			if name == "" {
				continue
			}
			var values []string
			for _, value := range children(attribute, nsSaml, "AttributeValue") {
				values = append(values, iterText(value))
			}
			attributes[name] = append(attributes[name], values...)
			if friend := attrOr(attribute, "FriendlyName"); friend != "" {
				friendly[name] = friend
			}
		}
	}
	keep := confirmedUntil.UnixMilli()
	if notOnOrAfterC != nil && notOnOrAfterC.UnixMilli() > keep {
		keep = notOnOrAfterC.UnixMilli()
	}
	keep += skew
	replayed, err := ctx.Replay.CheckAndRecord(ctx.IdpEntityID+" "+assertionID, time.UnixMilli(keep).UTC())
	if err != nil {
		return nil, err
	}
	if replayed {
		return nil, errCode("replay", "the assertion "+assertionID+" has been accepted before")
	}
	var classPtr string
	if classRef != "" {
		classPtr = classRef
	}
	login := &SamlLogin{
		NameID:                 textOf(nameID),
		NameIDFormat:           attrOr(nameID, "Format"),
		NameQualifier:          attrOr(nameID, "NameQualifier"),
		SPNameQualifier:        attrOr(nameID, "SPNameQualifier"),
		SessionIndex:           attrOr(authn, "SessionIndex"),
		SessionNotOnOrAfter:    sessionNotOnOrAfter,
		AuthnInstant:           *authnInstant,
		AuthnContextClassRef:   classPtr,
		Attributes:             attributes,
		AttributeFriendlyNames: friendly,
		Issuer:                 ctx.IdpEntityID,
		InResponseTo:           inPtr,
		RelayState:             received.RelayState,
		Binding:                received.Binding,
		Encrypted:              wasEncrypted,
		ResponseID:             responseID,
		AssertionID:            assertionID,
	}
	return login, nil
}
