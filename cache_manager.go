package reality

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// CacheManager manages all REALITY cache state.
// It is a pure observer — it never modifies TLS connection state.
type CacheManager struct {
	profiles     sync.Map // map[string]*RealityProfile
	fingerprints sync.Map // map[string]*targetFingerprintCache
	stats        CacheManagerStats
	dirty        atomic.Bool // true when cache has unsaved changes
}

// CacheManagerStats tracks cache hit/miss rates for diagnostics.
type CacheManagerStats struct {
	ProfileEntries     atomic.Int64
	ProfileInvalidated atomic.Uint64
	FingerprintChanged atomic.Uint64
}

// NewCacheManager creates a new cache manager.
func NewCacheManager() *CacheManager {
	return &CacheManager{}
}

// StoreProfile stores a profile in the cache. Returns true if it was a new entry.
func (m *CacheManager) StoreProfile(key string, profile *RealityProfile) bool {
	_, loaded := m.profiles.LoadOrStore(key, profile)
	if !loaded {
		m.stats.ProfileEntries.Add(1)
		m.dirty.Store(true)
	}
	return !loaded
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
