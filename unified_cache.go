package reality

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// v5.1 Unified Cache + Two-Stage Decision
// ============================================================================

// UnifiedCacheEntry combines layout and profile data in one structure.
// This eliminates the need for separate sync.Map lookups.
type UnifiedCacheEntry struct {
	// Layout fields (from HandshakeLayout)
	ServerHelloLen         int
	EncryptedExtensionsLen int
	CertificateLen         int
	CertificateVerifyLen   int
	FinishedLen            int

	// Profile fields (from RealityProfile)
	RecordLens    [7]int
	Fingerprint   uint64
	CipherSuite   uint16
	ALPN          string
	RecordCount   int

	// Metadata
	CapturedAt time.Time
	LastHit    time.Time
	HitCount   atomic.Uint64
	MissCount  atomic.Uint64
}

// IsExpired checks if the entry has exceeded the TTL.
func (e *UnifiedCacheEntry) IsExpired() bool {
	return time.Since(e.CapturedAt) > ProfileTTL
}

// Weight returns the hit ratio for soft scoring fallback.
func (e *UnifiedCacheEntry) Weight() float64 {
	total := e.HitCount.Load() + e.MissCount.Load()
	if total == 0 {
		return 0.5
	}
	return float64(e.HitCount.Load()) / float64(total)
}

// UnifiedCache is the single cache for all REALITY data.
type UnifiedCache struct {
	mu      sync.RWMutex
	entries map[string]*UnifiedCacheEntry
	maxSize int
}

// NewUnifiedCache creates a new unified cache.
func NewUnifiedCache(maxSize int) *UnifiedCache {
	return &UnifiedCache{
		entries: make(map[string]*UnifiedCacheEntry, maxSize),
		maxSize: maxSize,
	}
}

// Stage1_HardFilter performs deterministic cache lookup.
// Returns (entry, true) on exact fingerprint match, (nil, false) on miss.
// No scoring, no weight calculation — pure O(1) lookup.
func (c *UnifiedCache) Stage1_HardFilter(key string, fp uint64) (*UnifiedCacheEntry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Hard filter: fingerprint must match exactly
	if entry.Fingerprint != fp {
		return nil, false
	}

	// Hard filter: must not be expired
	if entry.IsExpired() {
		return nil, false
	}

	// Record hit
	entry.HitCount.Add(1)
	entry.LastHit = time.Now()

	return entry, true
}

// Stage2_SoftSelect finds the best entry for a given key (used on MISS).
// This is where scoring happens — but only when hard filter failed.
func (c *UnifiedCache) Stage2_SoftSelect(key string) *UnifiedCacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var best *UnifiedCacheEntry
	for _, entry := range c.entries {
		if entry.IsExpired() {
			continue
		}
		if best == nil || entry.Weight() > best.Weight() {
			best = entry
		}
	}
	return best
}

// Store adds or updates an entry.
func (c *UnifiedCache) Store(key string, entry *UnifiedCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If cache is full and key is new, evict lowest weight
	if len(c.entries) >= c.maxSize {
		if _, exists := c.entries[key]; !exists {
			c.evictLowest()
		}
	}

	// Only set CapturedAt if not already set (preserve original value)
	if entry.CapturedAt.IsZero() {
		entry.CapturedAt = time.Now()
	}
	c.entries[key] = entry
}

// evictLowest removes the entry with the lowest weight.
func (c *UnifiedCache) evictLowest() {
	var lowestKey string
	var lowestWeight float64

	for key, entry := range c.entries {
		w := entry.Weight()
		if lowestKey == "" || w < lowestWeight {
			lowestKey = key
			lowestWeight = w
		}
	}

	if lowestKey != "" {
		delete(c.entries, lowestKey)
	}
}

// Len returns the number of entries.
func (c *UnifiedCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Delete removes an entry.
func (c *UnifiedCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// CleanExpired removes all expired entries.
func (c *UnifiedCache) CleanExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for key, entry := range c.entries {
		if entry.IsExpired() {
			delete(c.entries, key)
			removed++
		}
	}
	return removed
}

// ============================================================================
// v5.1 Simplified Scoring Engine
// ============================================================================

// SimplifiedScoring uses only 2 signals: success_rate and stability.
// RTT and layout_hit are demoted to debug metrics only.
type SimplifiedScoring struct {
	mu       sync.RWMutex
	variants map[uint64]*UnifiedCacheEntry
}

// NewSimplifiedScoring creates a new simplified scoring engine.
func NewSimplifiedScoring() *SimplifiedScoring {
	return &SimplifiedScoring{
		variants: make(map[uint64]*UnifiedCacheEntry),
	}
}

// Score computes the simplified score for an entry.
// Formula: 0.6 * success_rate + 0.4 * stability
func (s *SimplifiedScoring) Score(entry *UnifiedCacheEntry) float64 {
	successRate := entry.Weight()
	stability := computeStability(entry)
	return 0.6*successRate + 0.4*stability
}

// computeStability calculates how stable an entry is based on recent hits.
func computeStability(entry *UnifiedCacheEntry) float64 {
	total := entry.HitCount.Load() + entry.MissCount.Load()
	if total == 0 {
		return 0.5
	}

	// Recency factor: recent hits are more stable
	lastHit := entry.LastHit
	if lastHit.IsZero() {
		return 0.3
	}
	age := time.Since(lastHit).Hours()
	recency := 1.0 - math.Min(age/168.0, 1.0) // linear decay over 1 week

	// Consistency factor: high hit rate = stable
	consistency := entry.Weight()

	return 0.5*recency + 0.5*consistency
}

// Ranked returns entries sorted by simplified score.
func (s *SimplifiedScoring) Ranked() []*UnifiedCacheEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var entries []*UnifiedCacheEntry
	for _, entry := range s.variants {
		if !entry.IsExpired() {
			entries = append(entries, entry)
		}
	}

	// Sort by score (highest first)
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && s.Score(entries[j]) > s.Score(entries[j-1]); j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}

	return entries
}

// GetOrCreate returns the entry for a fingerprint, creating if needed.
func (s *SimplifiedScoring) GetOrCreate(fp uint64, entry *UnifiedCacheEntry) *UnifiedCacheEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.variants[fp]; ok {
		return existing
	}
	s.variants[fp] = entry
	return entry
}

// Remove removes a fingerprint from scoring.
func (s *SimplifiedScoring) Remove(fp uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.variants, fp)
}

// ============================================================================
// Global instances
// ============================================================================

var (
	// unifiedCache is the single cache for all REALITY data.
	unifiedCache *UnifiedCache

	// simplifiedScoring is the simplified scoring engine.
	simplifiedScoring *SimplifiedScoring

	initOnce sync.Once
)

// InitUnifiedCache initializes the unified cache system.
func InitUnifiedCache(maxSize int) {
	initOnce.Do(func() {
		unifiedCache = NewUnifiedCache(maxSize)
		simplifiedScoring = NewSimplifiedScoring()
	})
}
