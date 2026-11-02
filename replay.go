// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package saml

import (
	"sync"
	"time"
)

// MemoryReplayCache remembers which assertions have been accepted.
type MemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]int64
	max     int
}

func NewMemoryReplayCache(maxEntries int) *MemoryReplayCache {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &MemoryReplayCache{entries: map[string]int64{}, max: maxEntries}
}

// CheckAndRecord reports whether assertionID was already accepted.
func (c *MemoryReplayCache) CheckAndRecord(assertionID string, expiresAt time.Time) (bool, error) {
	now := time.Now().UTC().UnixMilli()
	c.mu.Lock()
	defer c.mu.Unlock()
	if until, ok := c.entries[assertionID]; ok && until > now {
		return true, nil
	}
	if len(c.entries) >= c.max {
		for k, v := range c.entries {
			if v <= now {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			return false, errCode("replay", "the replay cache holds "+itoa(c.max)+" live assertions and cannot record another")
		}
	}
	c.entries[assertionID] = expiresAt.UTC().UnixMilli()
	return false, nil
}
