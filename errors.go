// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import "fmt"

// SamlStatus is a non-success status an identity provider answered with.
type SamlStatus struct {
	Code    string
	SubCode string
	Message string
}

func (s SamlStatus) String() string {
	return fmt.Sprintf("SamlStatus(code=%q, sub_code=%q, message=%q)", s.Code, s.SubCode, s.Message)
}

// SamlError is every failure this package reports.
type SamlError struct {
	Code    string
	Message string
	Status  *SamlStatus
	Cause   error
}

func (e *SamlError) Error() string { return e.Message }

func (e *SamlError) Unwrap() error { return e.Cause }

func errCode(code, message string) *SamlError {
	return &SamlError{Code: code, Message: message}
}

func errCause(code, message string, cause error) *SamlError {
	return &SamlError{Code: code, Message: message, Cause: cause}
}

func errStatus(message string, status *SamlStatus) *SamlError {
	return &SamlError{Code: "status", Message: message, Status: status}
}
