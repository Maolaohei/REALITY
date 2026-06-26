package reality

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ProfileState represents the state of a cached profile.
type ProfileState int

const (
	ProfileValid   ProfileState = iota // Fresh and valid
	ProfileStale                       // Expired but usable (stale-while-revalidate)
	ProfileNegative                    // Probe failed, don't retry too often
)

// ProfileEntry wraps a RealityProfile with state metadata.
type ProfileEntry struct {
	Profile   *RealityProfile
	State     ProfileState
	FailCount int
	NextRetry time.Time
	TTL       time.Duration // dynamic TTL based on stability
}

// CacheManager manages all REALITY cache state.
// It is a pure observer — it never modifies TLS connection state.
type CacheManager struct {
	entries      sync.Map // map[string]*ProfileEntry
	fingerprints sync.Map // map[string]*targetFingerprintCache
	singleflight sync.Map // map[string]*probeFlight — prevents concurrent probes
	stats        CacheManagerStats
	dirty        atomic.Bool
	maxProfiles  int
	baseTTL      time.Duration
}

// probeFlight tracks an in-flight probe for singleflight.
type probeFlight struct {
	done  chan struct{}
	value *RealityProfile
	err   error
}

// CacheManagerStats tracks cache metrics.
type CacheManagerStats struct {
	ProfileEntries     atomic.Int64
	ProfileInvalidated atomic.Uint64
	FingerprintChanged atomic.Uint64
	StaleServed        atomic.Uint64
	NegativeHits       atomic.Uint64
}

// NewCacheManager creates a new cache manager.
func NewCacheManager() *CacheManager {
	return &CacheManager{
		maxProfiles: 1000,
		baseTTL:     ProfileTTL,
	}
}

// --- Singleflight: prevent concurrent probes for the same key ---

// DoProbe executes fn once per key, even if called concurrently.
// Other callers block and share the result.
func (m *CacheManager) DoProbe(key string, fn func() (*RealityProfile, error)) (*RealityProfile, error) {
	val, _ := m.singleflight.LoadOrStore(key, &probeFlight{done: make(chan struct{})})
	flight := val.(*probeFlight)

	// First caller — run the probe.
	select {
	case <-flight.done:
		// Already completed (by us or another goroutine).
		return flight.value, flight.err
	default:
	}

	// We are the probe runner.
	flight.value, flight.err = fn()
	close(flight.done)
	m.singleflight.Delete(key)
	return flight.value, flight.err
}

// --- Stale-while-revalidate ---

// GetProfile retrieves a profile. Returns (profile, isStale).
// If the profile is expired but exists, returns it as stale (stale-while-revalidate).
// If the profile doesn't exist at all, returns (nil, false).
func (m *CacheManager) GetProfile(key string) (*RealityProfile, bool) {
	val, ok := m.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := val.(*ProfileEntry)

	switch entry.State {
	case ProfileValid:
		if time.Since(entry.Profile.CapturedAt) < entry.TTL {
			return entry.Profile, false
		}
		// Expired → transition to stale.
		entry.State = ProfileStale
		m.stats.StaleServed.Add(1)
		return entry.Profile, true

	case ProfileStale:
		m.stats.StaleServed.Add(1)
		return entry.Profile, true

	case ProfileNegative:
		if time.Now().Before(entry.NextRetry) {
			m.stats.NegativeHits.Add(1)
			return nil, false
		}
		// Retry window passed → allow probe.
		m.entries.Delete(key)
		return nil, false
	}

	return nil, false
}

// GetProfileOrExpired retrieves a profile regardless of state.
func (m *CacheManager) GetProfileOrExpired(key string) *RealityProfile {
	val, ok := m.entries.Load(key)
	if !ok {
		return nil
	}
	return val.(*ProfileEntry).Profile
}

// --- Store / Invalidate ---

// StoreProfile stores a valid profile entry.
func (m *CacheManager) StoreProfile(key string, profile *RealityProfile) bool {
	entry := &ProfileEntry{
		Profile: profile,
		State:   ProfileValid,
		TTL:     m.baseTTL,
	}
	_, loaded := m.entries.LoadOrStore(key, entry)
	if !loaded {
		m.stats.ProfileEntries.Add(1)
		m.dirty.Store(true)
		m.evictIfFull()
	}
	return !loaded
}

// MarkStale marks a profile as stale (triggers background refresh).
func (m *CacheManager) MarkStale(key string) {
	if val, ok := m.entries.Load(key); ok {
		entry := val.(*ProfileEntry)
		entry.State = ProfileStale
	}
}

// MarkNegative records a probe failure with exponential backoff.
func (m *CacheManager) MarkNegative(key string) {
	val, ok := m.entries.Load(key)
	if !ok {
		// No entry — create a negative cache entry.
		backoff := time.Minute
		entry := &ProfileEntry{
			State:     ProfileNegative,
			FailCount: 1,
			NextRetry: time.Now().Add(backoff),
			TTL:       m.baseTTL,
		}
		m.entries.Store(key, entry)
		return
	}
	entry := val.(*ProfileEntry)
	entry.FailCount++
	// Exponential backoff: 1min, 2min, 4min, 8min, max 30min.
	backoff := time.Duration(1<<min(entry.FailCount-1, 4)) * time.Minute
	if backoff > 30*time.Minute {
		backoff = 30 * time.Minute
	}
	entry.State = ProfileNegative
	entry.NextRetry = time.Now().Add(backoff)
}

// InvalidateProfile removes a profile from the cache.
func (m *CacheManager) InvalidateProfile(key string) {
	if _, loaded := m.entries.LoadAndDelete(key); loaded {
		m.stats.ProfileInvalidated.Add(1)
		m.dirty.Store(true)
	}
}

// InvalidateFingerprint records that a target's fingerprint changed.
func (m *CacheManager) InvalidateFingerprint() {
	m.stats.FingerprintChanged.Add(1)
}

// StoreFingerprint stores a target fingerprint.
func (m *CacheManager) StoreFingerprint(key string, fp *targetFingerprintCache) {
	m.fingerprints.Store(key, fp)
}

// --- Eviction ---

func (m *CacheManager) evictIfFull() {
	if int(m.stats.ProfileEntries.Load()) <= m.maxProfiles {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	m.entries.Range(func(key, val any) bool {
		entry := val.(*ProfileEntry)
		if oldestKey == "" || entry.Profile.CapturedAt.Before(oldestTime) {
			oldestKey = key.(string)
			oldestTime = entry.Profile.CapturedAt
		}
		return true
	})
	if oldestKey != "" {
		m.entries.Delete(oldestKey)
		m.stats.ProfileEntries.Add(-1)
	}
}

// --- Serialization ---

// SnapshotProfiles returns a shallow copy for consistent serialization.
func (m *CacheManager) SnapshotProfiles() map[string]*RealityProfile {
	snap := make(map[string]*RealityProfile)
	m.entries.Range(func(key, val any) bool {
		entry := val.(*ProfileEntry)
		if entry.State != ProfileNegative {
			cp := *entry.Profile
			snap[key.(string)] = &cp
		}
		return true
	})
	return snap
}

// CacheReport generates diagnostics.
func (m *CacheManager) CacheReport() string {
	entries := m.stats.ProfileEntries.Load()
	invalidated := m.stats.ProfileInvalidated.Load()
	stale := m.stats.StaleServed.Load()
	negative := m.stats.NegativeHits.Load()

	return fmt.Sprintf(`REALITY cache report:
  active profiles:  %d
  invalidated:      %d
  stale served:     %d
  negative hits:    %d`, entries, invalidated, stale, negative)
}

// IsDirty returns true if the cache has unsaved changes.
func (m *CacheManager) IsDirty() bool {
	return m.dirty.Load()
}

// ClearDirty resets the dirty flag after a successful save.
func (m *CacheManager) ClearDirty() {
	m.dirty.Store(false)
}

// Global cache manager instance.
var globalCacheManager = NewCacheManager()
