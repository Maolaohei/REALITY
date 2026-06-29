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
	ProfileValid       ProfileState = iota // Fresh and valid
	ProfileStale                           // Expired but usable (stale-while-revalidate)
	ProfileNegative                        // Probe failed, don't retry too often
	ProfilePendingDelete                   // Marked for deletion, waiting for refCount=0
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
	RefCount       int32     // pinned connections using this profile (atomic for read-heavy path)
	PendingSince   time.Time // when state became PendingDelete (fallback TTL)
}

// CacheManager manages all REALITY cache state.
type CacheManager struct {
	entries      sync.Map // map[string]*ProfileEntry
	fingerprints sync.Map // map[string]*targetFingerprintCache
	singleflight sync.Map // map[string]*probeFlight
	stats        CacheManagerStats
	dirty        atomic.Bool
	maxProfiles  int
	baseTTL      time.Duration
	mu           sync.Mutex // protects eviction and pending-delete cleanup
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
	StaleServed        atomic.Uint64
	NegativeHits       atomic.Uint64
	HotSwaps           atomic.Uint64
	Pins               atomic.Int64
}

func NewCacheManager() *CacheManager {
	return &CacheManager{
		maxProfiles: 1000,
		baseTTL:     ProfileTTL,
	}
}

// --- Singleflight ---

func (m *CacheManager) DoProbe(key string, fn func() (*RealityProfile, error)) (*RealityProfile, error) {
	flight := &probeFlight{done: make(chan struct{})}
	val, loaded := m.singleflight.LoadOrStore(key, flight)
	if loaded {
		existing := val.(*probeFlight)
		<-existing.done
		return existing.value, existing.err
	}
	flight.value, flight.err = fn()
	close(flight.done)
	m.singleflight.Delete(key)
	return flight.value, flight.err
}

// --- GetProfile with hot-swap support ---

// GetProfile retrieves a profile for a new connection.
// Returns (profile, isStale).
// Skips ProfilePendingDelete entries (old connections only).
func (m *CacheManager) GetProfile(key string) (*RealityProfile, bool) {
	val, ok := m.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := val.(*ProfileEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Skip pending-delete for new connections — they should use the new profile.
	if entry.State == ProfilePendingDelete {
		return nil, false
	}

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

// --- Pin / Unpin for hot-swap ---

// Pin increments the reference count for a profile.
// Call this when a connection starts using a profile.
// Returns the profile and true if found, nil and false if not found.
func (m *CacheManager) Pin(key string) (*RealityProfile, bool) {
	val, ok := m.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := val.(*ProfileEntry)
	atomic.AddInt32(&entry.RefCount, 1)
	m.stats.Pins.Add(1)
	return entry.Profile, true
}

// Unpin decrements the reference count.
// If the profile is marked PendingDelete and refCount reaches 0, it is actually deleted.
func (m *CacheManager) Unpin(key string) {
	val, ok := m.entries.Load(key)
	if !ok {
		return
	}
	entry := val.(*ProfileEntry)
	newCount := atomic.AddInt32(&entry.RefCount, -1)

	// If pending delete and no more users, actually delete.
	if newCount <= 0 && entry.State == ProfilePendingDelete {
		if m.entries.CompareAndDelete(key, val) {
			m.stats.ProfileInvalidated.Add(1)
			m.dirty.Store(true)
		}
	}
}

// PinCount returns the current reference count for a key.
func (m *CacheManager) PinCount(key string) int32 {
	val, ok := m.entries.Load(key)
	if !ok {
		return 0
	}
	return atomic.LoadInt32(&val.(*ProfileEntry).RefCount)
}

// --- Store / Hot-swap ---

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

// HotSwapProfile replaces a profile while preserving pinned connections.
// Old profile is marked PendingDelete; new profile is stored.
// Old profile is actually deleted when all pinned connections release it.
func (m *CacheManager) HotSwapProfile(key string, newProfile *RealityProfile) {
	newEntry := &ProfileEntry{
		Profile: newProfile,
		State:   ProfileValid,
		TTL:     m.baseTTL,
	}

	// Step 1: Load old entry before storing new one.
	oldVal, hadOld := m.entries.Load(key)

	// Step 2: Store new entry.
	m.entries.Store(key, newEntry)
	m.stats.HotSwaps.Add(1)
	m.dirty.Store(true)

	// Step 3: Mark old entry for deferred deletion.
	if hadOld {
		oldEntry := oldVal.(*ProfileEntry)
		if oldEntry != newEntry {
			oldEntry.mu.Lock()
			oldEntry.State = ProfilePendingDelete
			oldEntry.PendingSince = time.Now()
			oldEntry.mu.Unlock()
			// If nothing is using it, delete immediately.
			if atomic.LoadInt32(&oldEntry.RefCount) <= 0 {
				m.entries.CompareAndDelete(key, oldVal)
				m.stats.ProfileInvalidated.Add(1)
			}
		}
	}
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

// InvalidateProfile marks a profile for deletion.
// If refCount=0, deletes immediately. Otherwise marks PendingDelete.
func (m *CacheManager) InvalidateProfile(key string) {
	val, ok := m.entries.Load(key)
	if !ok {
		return
	}
	entry := val.(*ProfileEntry)
	if atomic.LoadInt32(&entry.RefCount) <= 0 {
		// No connections using it — delete now.
		if m.entries.CompareAndDelete(key, val) {
			m.stats.ProfileInvalidated.Add(1)
			m.dirty.Store(true)
		}
	} else {
		// Connections still using it — defer deletion.
		entry.mu.Lock()
		entry.State = ProfilePendingDelete
		entry.PendingSince = time.Now()
		entry.mu.Unlock()
	}
}

func (m *CacheManager) InvalidateFingerprint() {
	m.stats.FingerprintChanged.Add(1)
}

func (m *CacheManager) StoreFingerprint(key string, fp *targetFingerprintCache) {
	m.fingerprints.Store(key, fp)
}

// FindCachedProfileByDest searches for a cached profile matching the given dest prefix
// and cipher suite. Returns the profile's RecordLens and TLSVersion if found and valid.
// This is used by Server() to skip target probing when a cached profile is available.
func (m *CacheManager) FindCachedProfileByDest(dest string, cipherSuite uint16) (lens [7]int, tlsVersion uint16, ok bool) {
	m.entries.Range(func(key, val any) bool {
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.State == ProfilePendingDelete || entry.State == ProfileNegative {
			return true
		}
		if time.Since(entry.Profile.CapturedAt) >= entry.TTL {
			return true
		}
		if DestFromKey(key.(string)) != dest {
			return true
		}
		if entry.Profile.CipherSuite != cipherSuite {
			return true
		}
		lens = entry.Profile.RecordLens
		tlsVersion = entry.Profile.TLSVersion
		ok = true
		return false
	})
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
		// Don't evict pinned or pending-delete entries.
		if atomic.LoadInt32(&entry.RefCount) > 0 {
			return true
		}
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

func (m *CacheManager) SnapshotProfiles() map[string]*RealityProfile {
	snap := make(map[string]*RealityProfile)
	now := time.Now()
	m.entries.Range(func(key, val any) bool {
		entry := val.(*ProfileEntry)
		if entry.State == ProfileNegative || entry.State == ProfilePendingDelete {
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
	pins := m.stats.Pins.Load()

	return fmt.Sprintf(`REALITY cache report:
  active profiles:  %d
  invalidated:      %d
  stale served:     %d
  negative hits:    %d
  hot swaps:        %d
  total pins:       %d`, entries, invalidated, stale, negative, hotSwaps, pins)
}

func (m *CacheManager) IsDirty() bool {
	return m.dirty.Load()
}

func (m *CacheManager) ClearDirty() {
	m.dirty.Store(false)
}

// CleanupPending removes PendingDelete entries older than maxAge.
// This is a safety net for leaked Pin/Unpin (e.g., panic without defer).
// Should be called periodically (e.g., every 5 minutes).
func (m *CacheManager) CleanupPending(maxAge time.Duration) {
	now := time.Now()
	m.entries.Range(func(key, val any) bool {
		entry := val.(*ProfileEntry)
		if entry.State == ProfilePendingDelete {
			if now.Sub(entry.PendingSince) > maxAge {
				// Force delete regardless of refCount (safety net).
				if m.entries.CompareAndDelete(key, val) {
					m.stats.ProfileInvalidated.Add(1)
					m.dirty.Store(true)
				}
			}
		}
		return true
	})
}

// startCleanupLoop runs CleanupPending every interval in the background.
func (m *CacheManager) startCleanupLoop(interval time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.CleanupPending(10 * time.Minute)
			case <-stop:
				return
			}
		}
	}()
}

var globalCacheManager = NewCacheManager()

var cleanupStop = make(chan struct{})

func init() {
	// Start background cleanup for leaked Pin/Unpin.
	globalCacheManager.startCleanupLoop(5*time.Minute, cleanupStop)
}

// StopCleanupLoop stops the background cleanup goroutine. For test cleanup.
func StopCleanupLoop() {
	select {
	case <-cleanupStop:
	default:
		close(cleanupStop)
	}
}
