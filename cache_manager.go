package reality

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// CacheManager manages all REALITY cache state.
// It is a pure observer — it never modifies TLS connection state.
type CacheManager struct {
	profiles     sync.Map // map[string]*RealityProfile
	fingerprints sync.Map // map[string]*targetFingerprintCache
	stats        CacheManagerStats
	dirty        atomic.Bool // true when cache has unsaved changes
	maxProfiles  int         // max profiles before LRU eviction
}

// CacheManagerStats tracks cache hit/miss rates for diagnostics.
type CacheManagerStats struct {
	ProfileEntries     atomic.Int64
	ProfileInvalidated atomic.Uint64
	FingerprintChanged atomic.Uint64
}

// NewCacheManager creates a new cache manager.
func NewCacheManager() *CacheManager {
	return &CacheManager{
		maxProfiles: 1000,
	}
}

// StoreProfile stores a profile in the cache. Returns true if it was a new entry.
// If the cache exceeds maxProfiles, the oldest profile is evicted.
func (m *CacheManager) StoreProfile(key string, profile *RealityProfile) bool {
	_, loaded := m.profiles.LoadOrStore(key, profile)
	if !loaded {
		m.stats.ProfileEntries.Add(1)
		m.dirty.Store(true)
		m.evictIfFull()
	}
	return !loaded
}

// evictIfFull removes the oldest profile if cache exceeds maxProfiles.
func (m *CacheManager) evictIfFull() {
	if int(m.stats.ProfileEntries.Load()) <= m.maxProfiles {
		return
	}
	// Find and remove the oldest profile.
	var oldestKey string
	var oldestTime time.Time
	m.profiles.Range(func(key, val any) bool {
		p := val.(*RealityProfile)
		if oldestKey == "" || p.CapturedAt.Before(oldestTime) {
			oldestKey = key.(string)
			oldestTime = p.CapturedAt
		}
		return true
	})
	if oldestKey != "" {
		m.profiles.Delete(oldestKey)
		m.stats.ProfileEntries.Add(-1)
	}
}

// GetProfile retrieves a profile from the cache. Returns nil if not found or expired.
func (m *CacheManager) GetProfile(key string) *RealityProfile {
	val, ok := m.profiles.Load(key)
	if !ok {
		return nil
	}
	profile := val.(*RealityProfile)
	if profile.IsExpired() {
		m.profiles.Delete(key)
		return nil
	}
	return profile
}

// GetProfileOrExpired retrieves a profile, even if expired.
// Used for fallback during TTL gap (between expiration and next refresh).
// Returns nil only if the profile doesn't exist at all.
func (m *CacheManager) GetProfileOrExpired(key string) *RealityProfile {
	val, ok := m.profiles.Load(key)
	if !ok {
		return nil
	}
	return val.(*RealityProfile)
}

// InvalidateProfile removes a profile from the cache.
func (m *CacheManager) InvalidateProfile(key string) {
	if _, loaded := m.profiles.LoadAndDelete(key); loaded {
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

// CacheReport generates a human-readable diagnostics report.
func (m *CacheManager) CacheReport() string {
	entries := m.stats.ProfileEntries.Load()
	invalidated := m.stats.ProfileInvalidated.Load()
	fpChanged := m.stats.FingerprintChanged.Load()

	return fmt.Sprintf(`REALITY cache report:
  active profiles:     %d
  invalidated:         %d
  fingerprint changed: %d`, entries, invalidated, fpChanged)
}

// RangeProfiles iterates over all cached profiles. Return true to continue.
func (m *CacheManager) RangeProfiles(fn func(key string, profile *RealityProfile) bool) {
	m.profiles.Range(func(key, val any) bool {
		return fn(key.(string), val.(*RealityProfile))
	})
}

// SnapshotProfiles returns a shallow copy of all profiles for consistent serialization.
func (m *CacheManager) SnapshotProfiles() map[string]*RealityProfile {
	snap := make(map[string]*RealityProfile)
	m.profiles.Range(func(key, val any) bool {
		p := val.(*RealityProfile)
		cp := *p // shallow copy
		snap[key.(string)] = &cp
		return true
	})
	return snap
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
