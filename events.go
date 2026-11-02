// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

const (
	caepPrefix = "https://schemas.openid.net/secevent/caep/event-type/"
	riscPrefix = "https://schemas.openid.net/secevent/risc/event-type/"
	ssfPrefix  = "https://schemas.openid.net/secevent/ssf/event-type/"
)

// Event URIs for CAEP, RISC, and SSF.
var Event = map[string]string{
	"session_revoked":                    caepPrefix + "session-revoked",
	"token_claims_change":                caepPrefix + "token-claims-change",
	"credential_change":                  caepPrefix + "credential-change",
	"assurance_level_change":             caepPrefix + "assurance-level-change",
	"device_compliance_change":           caepPrefix + "device-compliance-change",
	"session_established":                caepPrefix + "session-established",
	"session_presented":                  caepPrefix + "session-presented",
	"risk_level_change":                  caepPrefix + "risk-level-change",
	"account_credential_change_required": riscPrefix + "account-credential-change-required",
	"account_purged":                     riscPrefix + "account-purged",
	"account_disabled":                   riscPrefix + "account-disabled",
	"account_enabled":                    riscPrefix + "account-enabled",
	"identifier_changed":                 riscPrefix + "identifier-changed",
	"identifier_recycled":                riscPrefix + "identifier-recycled",
	"credential_compromise":              riscPrefix + "credential-compromise",
	"opt_in":                             riscPrefix + "opt-in",
	"opt_out_initiated":                  riscPrefix + "opt-out-initiated",
	"opt_out_cancelled":                  riscPrefix + "opt-out-cancelled",
	"opt_out_effective":                  riscPrefix + "opt-out-effective",
	"recovery_activated":                 riscPrefix + "recovery-activated",
	"recovery_information_changed":       riscPrefix + "recovery-information-changed",
	"sessions_revoked":                   riscPrefix + "sessions-revoked",
	"verification":                       ssfPrefix + "verification",
	"stream_updated":                     ssfPrefix + "stream-updated",
}

func eventsWithPrefix(prefix string) []string {
	var out []string
	order := []string{
		"session_revoked", "token_claims_change", "credential_change", "assurance_level_change",
		"device_compliance_change", "session_established", "session_presented", "risk_level_change",
		"account_credential_change_required", "account_purged", "account_disabled", "account_enabled",
		"identifier_changed", "identifier_recycled", "credential_compromise", "opt_in",
		"opt_out_initiated", "opt_out_cancelled", "opt_out_effective", "recovery_activated",
		"recovery_information_changed", "sessions_revoked", "verification", "stream_updated",
	}
	for _, key := range order {
		if value := Event[key]; len(value) >= len(prefix) && value[:len(prefix)] == prefix {
			out = append(out, value)
		}
	}
	return out
}

// CAEPEvents is every CAEP event type, in declaration order.
func CAEPEvents() []string { return eventsWithPrefix(caepPrefix) }

// RISCEvents is every RISC event type, in declaration order.
func RISCEvents() []string { return eventsWithPrefix(riscPrefix) }

// DefaultEventsRequested is the receiver's default subscription.
func DefaultEventsRequested() []string {
	return []string{
		Event["session_revoked"], Event["credential_change"], Event["assurance_level_change"], Event["token_claims_change"],
		Event["account_disabled"], Event["account_enabled"], Event["account_purged"], Event["credential_compromise"],
		Event["sessions_revoked"], Event["account_credential_change_required"],
	}
}

// DefaultEndingEvents end the local sessions they name.
func DefaultEndingEvents() []string {
	return []string{
		Event["session_revoked"], Event["account_disabled"], Event["account_purged"], Event["credential_compromise"], Event["sessions_revoked"],
	}
}

func simpleSubject(identifier any, issuer string) map[string]string {
	obj, ok := identifier.(map[string]any)
	if !ok {
		return map[string]string{}
	}
	form := stringOf(obj["format"])
	if form == "" {
		form = stringOf(obj["subject_type"])
	}
	switch form {
	case "iss_sub":
		sub := stringOf(obj["sub"])
		iss := obj["iss"]
		if sub != "" && (iss == nil || stringOf(iss) == issuer) {
			return map[string]string{"sub": sub}
		}
	case "email":
		if email := stringOf(obj["email"]); email != "" {
			return map[string]string{"email": email}
		}
	case "opaque":
		if id := stringOf(obj["id"]); id != "" {
			return map[string]string{"opaque": id}
		}
	case "aliases":
		items, _ := obj["identifiers"].([]any)
		merged := map[string]string{}
		for _, item := range items {
			for k, v := range simpleSubject(item, issuer) {
				merged[k] = v
			}
		}
		return merged
	}
	return map[string]string{}
}

func stringOf(value any) string {
	text, _ := value.(string)
	return text
}

// SubjectOf reads who an event's sub_id names.
func SubjectOf(subID any, issuer string) map[string]string {
	obj, ok := subID.(map[string]any)
	if !ok {
		return map[string]string{}
	}
	form := stringOf(obj["format"])
	if form == "" {
		form = stringOf(obj["subject_type"])
	}
	if form == "complex" || (form == "" && (obj["user"] != nil || obj["session"] != nil)) {
		user := simpleSubject(obj["user"], issuer)
		session := simpleSubject(obj["session"], issuer)
		out := map[string]string{}
		if user["sub"] != "" {
			out["person"] = user["sub"]
		}
		if user["email"] != "" {
			out["email"] = user["email"]
		}
		sessionID := session["opaque"]
		if sessionID == "" {
			sessionID = session["sub"]
		}
		if sessionID != "" {
			out["idp_session"] = sessionID
		}
		return out
	}
	one := simpleSubject(obj, issuer)
	out := map[string]string{}
	if one["sub"] != "" {
		out["person"] = one["sub"]
	}
	if one["email"] != "" {
		out["email"] = one["email"]
	}
	return out
}
