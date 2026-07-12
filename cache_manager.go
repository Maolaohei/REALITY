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
	L1Hits             atomic.Uint64
	L2Hits             atomic.Uint64
	L2Fails            atomic.Uint64
	Quarantines        atomic.Uint64
}

func NewCacheManager() *CacheManager {
	return &CacheManager{
		maxProfiles: 1000,
		baseTTL:     ProfileTTL,
	}
}

// maxTTLMultiplier caps how much a profile's TTL can grow via stability
// scoring. Prevents stale profiles from being served as Valid for too long
// without a RefreshManager heartbeat.
const maxTTLMultiplier = 2

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
// no valid cache entry exists.
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
		m.stats.ProfileEntries.Add(1)
		m.dirty.Store(true)
		m.evictIfFull()
	}
	return !loaded
}

// HotSwapProfile replaces a profile atomically.
func (m *CacheManager) HotSwapProfile(key string, newProfile *RealityProfile) {
	newEntry := &ProfileEntry{
		Profile: newProfile,
		State:   ProfileValid,
		TTL:     m.baseTTL,
	}
	m.entries.Store(key, newEntry)
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
			// Adaptive TTL: extend based on stability
			if entry.StabilityScore < 4 {
				entry.StabilityScore++
				mult := 1 + entry.StabilityScore
				if mult > maxTTLMultiplier {
					mult = maxTTLMultiplier
				}
				entry.TTL = m.baseTTL * time.Duration(mult)
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

// ValidateRecordLens checks that a RecordLens array contains sane values.
func ValidateRecordLens(lens [7]int) bool {
	for _, l := range lens {
		if l == 0 {
			continue
		}
		if l < recordHeaderLen || l > maxTLSRecordPayload {
			return false
		}
	}
	return true
}


// FindFullCachedProfile searches for a cached profile with ServerHello data.
func (m *CacheManager) FindFullCachedProfile(dest, serverName string, cipherSuites []uint16, alpn string) *RealityProfile {
	key := CacheKey(serverName, alpn, VersionTLS13)
	if val, found := m.entries.Load(key); found {
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		if entry.State != ProfileNegative &&
			time.Since(entry.Profile.CapturedAt) < entry.TTL &&
			ValidateRecordLens(entry.Profile.RecordLens) {
			for _, cs := range cipherSuites {
				if cs == entry.Profile.CipherSuite {
					p := *entry.Profile
					entry.mu.Unlock()
					return &p
				}
			}
		}
		entry.mu.Unlock()
	}
	return nil
}

// --- Eviction ---

func (m *CacheManager) evictIfFull() {
	if int(m.stats.ProfileEntries.Load()) <= m.maxProfiles {
		return
	}
	// Eviction priority: Negative > Stale > oldest Valid.
	// This protects fresh active profiles from being evicted by
	// transient scan bursts.
	var (
		negativeKey string
		staleKey    string
		oldestKey   string
		oldestTime  time.Time
	)
	m.entries.Range(func(key, val any) bool {
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		state := entry.State
		entry.mu.Unlock()
		switch state {
		case ProfileNegative:
			if negativeKey == "" {
				negativeKey = key.(string)
			}
		case ProfileStale:
			if staleKey == "" {
				staleKey = key.(string)
			}
		default:
			if oldestKey == "" || entry.Profile.CapturedAt.Before(oldestTime) {
				oldestKey = key.(string)
				oldestTime = entry.Profile.CapturedAt
			}
		}
		return true
	})
	// Pick the best candidate to evict.
	evictKey := negativeKey
	if evictKey == "" {
		evictKey = staleKey
	}
	if evictKey == "" {
		evictKey = oldestKey
	}
	if evictKey != "" {
		m.entries.Delete(evictKey)
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

// InvalidateAll deletes all cached profiles.
func (m *CacheManager) InvalidateAll() {
	m.entries.Range(func(key, val any) bool {
		m.entries.Delete(key)
		m.stats.ProfileEntries.Add(-1)
		m.stats.ProfileInvalidated.Add(1)
		return true
	})
	m.dirty.Store(true)
}


func (m *CacheManager) IsDirty() bool {
	return m.dirty.Load()
}

func (m *CacheManager) ClearDirty() {
	m.dirty.Store(false)
}

// Reset clears all cache state for test isolation.
func (m *CacheManager) Reset() {
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
	m.stats.ProfileEntries.Store(0)
	m.stats.ProfileInvalidated.Store(0)
	m.stats.FingerprintChanged.Store(0)
	m.stats.StaleServed.Store(0)
	m.stats.NegativeHits.Store(0)
	m.stats.HotSwaps.Store(0)
	m.stats.ProbeAttempts.Store(0)
	m.stats.ProbeSuccesses.Store(0)
	m.stats.L1Hits.Store(0)
	m.stats.L2Hits.Store(0)
	m.stats.L2Fails.Store(0)
	m.stats.Quarantines.Store(0)
	m.dirty.Store(false)
}

var globalCacheManager = NewCacheManager()
