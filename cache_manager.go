package reality

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ProfileState represents the state of a cached profile.
type ProfileState int

const (
	ProfileValid    ProfileState = iota // Fresh and valid
	ProfileStale                        // Expired but usable (stale-while-revalidate)
	ProfileNegative                     // Probe failed, don't retry too often
)

// ProfileEntry wraps a RealityProfile with state metadata.
type ProfileEntry struct {
	mu             sync.Mutex
	Profile        *RealityProfile
	State          ProfileState
	FailCount      int
	NextRetry      time.Time
	TTL            time.Duration
	StabilityScore int
}

// CacheManager manages all REALITY cache state.
type CacheManager struct {
	entries      sync.Map // map[string]*ProfileEntry
	fingerprints sync.Map // map[string]*targetFingerprintCache
	singleflight sync.Map // map[string]*probeFlight (background refresh)
	handshakeSF  sync.Map // map[string]*probeFlight (handshake path, short timeout)
	destIndex    map[string]map[string]struct{} // dest → set of cache keys (secondary index)
	indexMu      sync.Mutex                     // protects destIndex
	stats        CacheManagerStats
	dirty        atomic.Bool
	maxProfiles  int
	baseTTL      time.Duration
}

type probeFlight struct {
	done  chan struct{}
	value *RealityProfile
	err   error
}

type CacheManagerStats struct {
	ProfileEntries     atomic.Int64
	ProfileInvalidated atomic.Uint64
	FingerprintChanged atomic.Uint64
	StaleServed        atomic.Int64
	NegativeHits       atomic.Int64
	HotSwaps           atomic.Uint64
	ProbeAttempts      atomic.Uint64
	ProbeSuccesses     atomic.Uint64
}

func NewCacheManager() *CacheManager {
	return &CacheManager{
		destIndex:   make(map[string]map[string]struct{}),
		maxProfiles: 1000,
		baseTTL:     ProfileTTL,
	}
}

// --- Unified index operations ---

// putLocked stores a profile entry and updates the dest secondary index.
// This is the ONLY way to add entries to the cache. All callers must use this.
func (m *CacheManager) putLocked(key, dest string, entry *ProfileEntry) {
	m.entries.Store(key, entry)
	m.indexMu.Lock()
	if m.destIndex[dest] == nil {
		m.destIndex[dest] = make(map[string]struct{})
	}
	m.destIndex[dest][key] = struct{}{}
	m.indexMu.Unlock()
}

// deleteLocked removes a profile entry and cleans up the dest secondary index.
// This is the ONLY way to remove entries from the cache. All callers must use this.
func (m *CacheManager) deleteLocked(key, dest string) {
	m.entries.Delete(key)
	m.indexMu.Lock()
	if keys, ok := m.destIndex[dest]; ok {
		delete(keys, key)
		if len(keys) == 0 {
			delete(m.destIndex, dest)
		}
	}
	m.indexMu.Unlock()
}

// keysByDest returns all cache keys for a given dest. Caller must not modify the returned map.
func (m *CacheManager) keysByDest(dest string) map[string]struct{} {
	m.indexMu.Lock()
	defer m.indexMu.Unlock()
	return m.destIndex[dest]
}

// --- Singleflight ---

func (m *CacheManager) DoProbe(key string, fn func() (*RealityProfile, error)) (*RealityProfile, error) {
	m.stats.ProbeAttempts.Add(1)
	flight := &probeFlight{done: make(chan struct{})}
	val, loaded := m.singleflight.LoadOrStore(key, flight)
	if loaded {
		existing := val.(*probeFlight)
		<-existing.done
		if existing.err == nil {
			m.stats.ProbeSuccesses.Add(1)
		}
		return existing.value, existing.err
	}
	flight.value, flight.err = fn()
	close(flight.done)
	m.singleflight.Delete(key)
	if flight.err == nil {
		m.stats.ProbeSuccesses.Add(1)
	}
	return flight.value, flight.err
}

// GetOrProbeForHandshake retrieves a cached profile or probes the target if
// no valid cache entry exists. Uses a separate singleflight group with a
// shorter timeout (5s) to avoid blocking handshake goroutines on slow probes.
func (m *CacheManager) GetOrProbeForHandshake(ctx context.Context, key, dest, serverName string, alpn int) (*RealityProfile, error) {
	// Fast path: check cache first.
	if val, ok := m.entries.Load(key); ok {
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		if entry.State == ProfileValid || entry.State == ProfileStale {
			if time.Since(entry.Profile.CapturedAt) < entry.TTL {
				entry.mu.Unlock()
				return entry.Profile, nil
			}
		}
		entry.mu.Unlock()
	}

	// Slow path: probe with singleflight dedup.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return m.doHandshakeProbe(key, func() (*RealityProfile, error) {
		return probeTargetRaw(dest, serverName, alpn)
	})
}

func (m *CacheManager) doHandshakeProbe(key string, fn func() (*RealityProfile, error)) (*RealityProfile, error) {
	flight := &probeFlight{done: make(chan struct{})}
	val, loaded := m.handshakeSF.LoadOrStore(key, flight)
	if loaded {
		existing := val.(*probeFlight)
		<-existing.done
		return existing.value, existing.err
	}
	flight.value, flight.err = fn()
	close(flight.done)
	m.handshakeSF.Delete(key)
	return flight.value, flight.err
}

// --- GetProfile ---

// GetProfile retrieves a profile for a new connection.
// Returns (profile, isStale).
func (m *CacheManager) GetProfile(key string) (*RealityProfile, bool) {
	val, ok := m.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := val.(*ProfileEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	switch entry.State {
	case ProfileValid:
		if time.Since(entry.Profile.CapturedAt) < entry.TTL {
			return entry.Profile, false
		}
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
		m.entries.Delete(key)
		m.deleteLocked(key, DestFromKey(key))
		m.stats.ProfileEntries.Add(-1)
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

// --- Store / Hot-swap ---

// StoreProfile stores a profile entry. If the key already exists, the old
// entry is kept (LoadOrStore semantics).
func (m *CacheManager) StoreProfile(key string, profile *RealityProfile) bool {
	entry := &ProfileEntry{
		Profile: profile,
		State:   ProfileValid,
		TTL:     m.baseTTL,
	}
	_, loaded := m.entries.LoadOrStore(key, entry)
	if !loaded {
		m.putLocked(key, DestFromKey(key), entry)
		m.stats.ProfileEntries.Add(1)
		m.dirty.Store(true)
		m.evictIfFull()
	}
	return !loaded
}

// HotSwapProfile replaces a profile atomically.
// The old entry is deleted from the map immediately. Any goroutine that
// already loaded the old entry continues using it (safe for read-only use);
// new connections will get the new entry from the map.
func (m *CacheManager) HotSwapProfile(key string, newProfile *RealityProfile) {
	newEntry := &ProfileEntry{
		Profile: newProfile,
		State:   ProfileValid,
		TTL:     m.baseTTL,
	}
	m.entries.Store(key, newEntry)
	m.putLocked(key, DestFromKey(key), newEntry)
	m.stats.HotSwaps.Add(1)
	m.dirty.Store(true)
}

// MarkStale marks a profile as stale.
func (m *CacheManager) MarkStale(key string) {
	if val, ok := m.entries.Load(key); ok {
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.State == ProfileValid || entry.State == ProfileStale {
			entry.State = ProfileStale
			if entry.StabilityScore < 4 {
				entry.StabilityScore++
				entry.TTL = m.baseTTL * time.Duration(1+entry.StabilityScore)
			}
		}
	}
}

// MarkNegative records a probe failure with exponential backoff.
func (m *CacheManager) MarkNegative(key string) {
	val, ok := m.entries.Load(key)
	if !ok {
		entry := &ProfileEntry{
			State:     ProfileNegative,
			FailCount: 1,
			NextRetry: time.Now().Add(time.Minute),
			TTL:       m.baseTTL,
		}
		m.entries.Store(key, entry)
		m.putLocked(key, DestFromKey(key), entry)
		return
	}
	entry := val.(*ProfileEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.FailCount++
	entry.StabilityScore = 0
	backoff := time.Duration(1<<min(entry.FailCount-1, 4)) * time.Minute
	if backoff > 30*time.Minute {
		backoff = 30 * time.Minute
	}
	entry.State = ProfileNegative
	entry.NextRetry = time.Now().Add(backoff)
}

// InvalidateProfile deletes a profile from the cache immediately.
func (m *CacheManager) InvalidateProfile(key string) {
	val, ok := m.entries.Load(key)
	if !ok {
		return
	}
	if m.entries.CompareAndDelete(key, val) {
		m.deleteLocked(key, DestFromKey(key))
		m.stats.ProfileEntries.Add(-1)
		m.stats.ProfileInvalidated.Add(1)
		m.dirty.Store(true)
	}
}

func (m *CacheManager) InvalidateFingerprint() {
	m.stats.FingerprintChanged.Add(1)
}

func (m *CacheManager) StoreFingerprint(key string, fp *targetFingerprintCache) {
	m.fingerprints.Store(key, fp)
}

// ValidateRecordLens checks that a RecordLens array contains sane values:
// every non-zero length must be between recordHeaderLen and maxTLSRecordPayload.
// Returns false if any lens is out of range (indicating a corrupt or stale profile).
func ValidateRecordLens(lens [7]int) bool {
	for _, l := range lens {
		if l == 0 {
			continue // absent record is OK (e.g. no NewSessionTicket yet)
		}
		if l < recordHeaderLen || l > maxTLSRecordPayload {
			return false
		}
	}
	return true
}

// FindCachedProfileByDest searches for a cached profile matching the given dest,
// cipher suite, ALPN, and TLS version. Returns the profile's RecordLens and
// TLSVersion if found and valid. This is used by Server() to skip target reads
// when a cached profile is available.
func (m *CacheManager) FindCachedProfileByDest(dest string, cipherSuite uint16, alpn string, tlsVersion uint16) (lens [7]int, foundTLSVersion uint16, ok bool) {
	keys := m.keysByDest(dest)
	for key := range keys {
		val, exists := m.entries.Load(key)
		if !exists {
			continue
		}
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		if entry.State == ProfileNegative {
			entry.mu.Unlock()
			continue
		}
		if time.Since(entry.Profile.CapturedAt) >= entry.TTL {
			entry.mu.Unlock()
			continue
		}
		if entry.Profile.CipherSuite != cipherSuite ||
			entry.Profile.ALPN != alpn ||
			entry.Profile.TLSVersion != tlsVersion {
			entry.mu.Unlock()
			continue
		}
		if !ValidateRecordLens(entry.Profile.RecordLens) {
			entry.mu.Unlock()
			continue
		}
		lens = entry.Profile.RecordLens
		foundTLSVersion = entry.Profile.TLSVersion
		entry.mu.Unlock()
		ok = true
		return
	}
	return
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
		m.deleteLocked(oldestKey, DestFromKey(oldestKey))
		m.stats.ProfileEntries.Add(-1)
	}
}

// --- Serialization ---

func (m *CacheManager) SnapshotProfiles() map[string]*RealityProfile {
	snap := make(map[string]*RealityProfile)
	now := time.Now()
	m.entries.Range(func(key, val any) bool {
		entry := val.(*ProfileEntry)
		if entry.State == ProfileNegative {
			return true
		}
		if now.Sub(entry.Profile.CapturedAt) > entry.TTL {
			return true
		}
		cp := *entry.Profile
		snap[key.(string)] = &cp
		return true
	})
	return snap
}

func (m *CacheManager) CacheReport() string {
	entries := m.stats.ProfileEntries.Load()
	invalidated := m.stats.ProfileInvalidated.Load()
	stale := m.stats.StaleServed.Load()
	negative := m.stats.NegativeHits.Load()
	hotSwaps := m.stats.HotSwaps.Load()
	attempts := m.stats.ProbeAttempts.Load()
	successes := m.stats.ProbeSuccesses.Load()
	var successRate float64
	if attempts > 0 {
		successRate = float64(successes) / float64(attempts) * 100
	}

	return fmt.Sprintf(`REALITY cache report:
  active profiles:     %d
  invalidated:         %d
  stale served:        %d
  negative hits:       %d
  hot swaps:           %d
  probe attempts:      %d
  probe successes:     %d
  probe success rate:  %.1f%%`, entries, invalidated, stale, negative, hotSwaps, attempts, successes, successRate)
}

// InvalidateByDest deletes all cached profiles for a given dest.
// Used when the cache fast path verification fails, indicating the target
// has changed (e.g. OCSP/certificate rotation).
func (m *CacheManager) InvalidateByDest(dest string) {
	keys := m.keysByDest(dest)
	for key := range keys {
		m.InvalidateProfile(key)
	}
}

// InvalidateAndReprobe clears cached profiles for a dest and immediately
// triggers an async re-probe. Uses DoProbe singleflight to prevent
// concurrent probe storms.
func (m *CacheManager) InvalidateAndReprobe(dest, serverName, alpn string) {
	m.InvalidateByDest(dest)
	key := CacheKey(dest, serverName, alpn, VersionTLS13)
	go m.DoProbe(key, func() (*RealityProfile, error) {
		return probeTargetRaw(dest, serverName, alpnToInt(alpn))
	})
}

func (m *CacheManager) IsDirty() bool {
	return m.dirty.Load()
}

func (m *CacheManager) ClearDirty() {
	m.dirty.Store(false)
}

// CheckConsistency verifies that the entries map and destIndex are in sync.
// Returns a list of problems (empty = consistent). For testing only.
func (m *CacheManager) CheckConsistency() []string {
	var problems []string
	m.entries.Range(func(k, v any) bool {
		key := k.(string)
		dest := DestFromKey(key)
		m.indexMu.Lock()
		keys, ok := m.destIndex[dest]
		m.indexMu.Unlock()
		if !ok {
			problems = append(problems, fmt.Sprintf("entry %s: dest %s missing from destIndex", key, dest))
			return true
		}
		if _, exists := keys[key]; !exists {
			problems = append(problems, fmt.Sprintf("entry %s missing from destIndex[%s]", key, dest))
		}
		return true
	})
	m.indexMu.Lock()
	for dest, keys := range m.destIndex {
		for key := range keys {
			if _, ok := m.entries.Load(key); !ok {
				problems = append(problems, fmt.Sprintf("dangling destIndex entry: dest=%s key=%s", dest, key))
			}
		}
	}
	m.indexMu.Unlock()
	return problems
}

// Reset clears all cache state for test isolation.
func (m *CacheManager) Reset() {
	// Delete all entries one by one to ensure sync.Map internal state is clean.
	var keys []any
	m.entries.Range(func(key, _ any) bool {
		keys = append(keys, key)
		return true
	})
	for _, key := range keys {
		m.entries.Delete(key)
	}
	m.fingerprints.Range(func(key, _ any) bool {
		m.fingerprints.Delete(key)
		return true
	})
	m.singleflight.Range(func(key, _ any) bool {
		m.singleflight.Delete(key)
		return true
	})
	m.handshakeSF.Range(func(key, _ any) bool {
		m.handshakeSF.Delete(key)
		return true
	})
	m.indexMu.Lock()
	m.destIndex = make(map[string]map[string]struct{})
	m.indexMu.Unlock()
	m.stats.ProfileEntries.Store(0)
	m.stats.ProfileInvalidated.Store(0)
	m.stats.FingerprintChanged.Store(0)
	m.stats.StaleServed.Store(0)
	m.stats.NegativeHits.Store(0)
	m.stats.HotSwaps.Store(0)
	m.stats.ProbeAttempts.Store(0)
	m.stats.ProbeSuccesses.Store(0)
	m.dirty.Store(false)
}

var globalCacheManager = NewCacheManager()
