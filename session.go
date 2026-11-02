// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"strings"
	"sync"
	"time"
)

const DefaultSubjectAttribute = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"

var mailAttributes = []string{
	"urn:oid:0.9.2342.19200300.100.1.3",
	"mail",
	"email",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
}

const emailNameID = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

// SessionRecord is one local session the receiver can end.
type SessionRecord struct {
	LocalID    string
	Person     string
	Email      string
	IdPSession string
	ExpiresAt  *time.Time
}

// MemorySessionIndex remembers which local sessions belong to which person.
type MemorySessionIndex struct {
	mu       sync.Mutex
	sessions map[string]SessionRecord
	order    []string
	max      int
}

func NewMemorySessionIndex(maxEntries int) *MemorySessionIndex {
	if maxEntries <= 0 {
		maxEntries = 100000
	}
	return &MemorySessionIndex{sessions: map[string]SessionRecord{}, max: maxEntries}
}

func (s *MemorySessionIndex) dropLocked(localID string) {
	delete(s.sessions, localID)
	next := s.order[:0]
	for _, id := range s.order {
		if id != localID {
			next = append(next, id)
		}
	}
	s.order = next
}

func (s *MemorySessionIndex) Add(session SessionRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[session.LocalID]; !exists && len(s.sessions) >= s.max {
		now := time.Now().UTC().UnixMilli()
		var expired []string
		for _, key := range s.order {
			value := s.sessions[key]
			if value.ExpiresAt != nil && value.ExpiresAt.UnixMilli() <= now {
				expired = append(expired, key)
			}
		}
		for _, key := range expired {
			s.dropLocked(key)
		}
		for len(s.sessions) >= s.max && len(s.order) > 0 {
			s.dropLocked(s.order[0])
		}
	}
	if session.Email != "" {
		session.Email = strings.ToLower(session.Email)
	}
	if _, exists := s.sessions[session.LocalID]; !exists {
		s.order = append(s.order, session.LocalID)
	}
	s.sessions[session.LocalID] = session
}

func (s *MemorySessionIndex) Remove(localID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(localID)
}

func (s *MemorySessionIndex) find(match func(SessionRecord) bool) []string {
	now := time.Now().UTC().UnixMilli()
	var out []string
	keep := s.order[:0]
	for _, key := range s.order {
		value, ok := s.sessions[key]
		if !ok {
			continue
		}
		if value.ExpiresAt != nil && value.ExpiresAt.UnixMilli() <= now {
			delete(s.sessions, key)
			continue
		}
		keep = append(keep, key)
		if match(value) {
			out = append(out, key)
		}
	}
	s.order = keep
	return out
}

func (s *MemorySessionIndex) ByPerson(person string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.find(func(session SessionRecord) bool { return session.Person == person })
}

func (s *MemorySessionIndex) ByEmail(email string) []string {
	wanted := strings.ToLower(email)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.find(func(session SessionRecord) bool { return session.Email == wanted })
}

func (s *MemorySessionIndex) ByIdPSession(idpSession string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.find(func(session SessionRecord) bool { return session.IdPSession == idpSession })
}

// TrackedFrom builds the index record for a SAML login.
func TrackedFrom(localID string, login *SamlLogin, subjectAttribute string, expiresAt *time.Time) SessionRecord {
	attribute := subjectAttribute
	if attribute == "" {
		attribute = DefaultSubjectAttribute
	}
	person := ""
	if values := login.Attributes[attribute]; len(values) > 0 {
		person = values[0]
	}
	email := ""
	for _, name := range mailAttributes {
		if values := login.Attributes[name]; len(values) > 0 && values[0] != "" {
			email = values[0]
			break
		}
	}
	if email == "" && login.NameIDFormat == emailNameID {
		email = login.NameID
	}
	when := expiresAt
	if when == nil {
		when = login.SessionNotOnOrAfter
	}
	return SessionRecord{LocalID: localID, Person: person, Email: email, IdPSession: login.SessionIndex, ExpiresAt: when}
}
