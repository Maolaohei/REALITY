package reality

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// alpnToInt converts an ALPN string to the integer index used by ProbeTargetViaUTLS.
func alpnToInt(alpn string) int {
	switch alpn {
	case "http/1.1":
		return 1
	case "h2":
		return 2
	default:
		return 0
	}
}

// intToALPN converts an ALPN index back to the protocol string.
func intToALPN(index int) string {
	switch index {
	case 1:
		return "http/1.1"
	case 2:
		return "h2"
	default:
		return ""
	}
}

// probeTarget connects to the target using a real uTLS ClientHello and compares
// the captured record lengths against the cached profile.
// Two-phase approach: Phase A checks only CipherSuite from ServerHello,
// Phase B reads full 7 records only if Phase A detects changes.
// Returns true if probe succeeded, false on error.
// Debouncing: requires 2 consecutive identical probe results before triggering HotSwap.
func (m *RefreshManager) probeTarget(dest, serverName string, entry *refreshEntry) bool {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()

	globalCacheManager.stats.ProbeAttempts.Add(1)

	// Determine serverName: use entry's if set, otherwise fall back to dest host.
	sn := serverName
	if sn == "" {
		sn = entry.serverName
	}

	result, err := ProbeTargetViaUTLS(ctx, dest, sn, alpnToInt(entry.alpn), 0)
	if err != nil {
		globalCacheManager.MarkNegative(entry.cacheKey)
		return false
	}

	globalCacheManager.stats.ProbeSuccesses.Add(1)

	// Check cached profile for comparison.
	profile, _ := globalCacheManager.GetProfile(entry.cacheKey)

	// Phase A: Quick CipherSuite check.
	if profile != nil && !profile.IsExpired() && profile.CipherSuite == result.CipherSuite {
		// CipherSuite matches — quick check records 1-2 (CCS + EE).
		if result.RecordLens[1] == profile.RecordLens[1] && result.RecordLens[2] == profile.RecordLens[2] {
			// CCS + EE lengths match cached values — confident no change.
			globalCacheManager.MarkStale(entry.cacheKey)
			return true
		}
		// Quick check failed — fall through to full comparison.
	}

	// Phase B: Full profile comparison.
	if profile != nil && !profile.IsExpired() {
		if profile.CipherSuite != result.CipherSuite || !recordLensMatch(profile.RecordLens, result.RecordLens) {
			// Target appears to have changed. Apply debouncing: only
			// HotSwap after 2 consecutive identical probe results to
			// filter out transient network jitter.
			if entry.lastProbeCipherSuite == result.CipherSuite && entry.lastProbeLens == result.RecordLens {
				entry.stableCount++
			} else {
				entry.stableCount = 1
				entry.lastProbeCipherSuite = result.CipherSuite
				entry.lastProbeLens = result.RecordLens
			}
			if entry.stableCount >= 2 {
				// Confirmed stable change — safe to swap.
				entry.stableCount = 0
				if !ValidateRecordLens(result.RecordLens) {
					globalCacheManager.MarkNegative(entry.cacheKey)
					return false
				}
				newProfile := &RealityProfile{
					RecordLens:   result.RecordLens,
					Fingerprint:  computeFingerprint(result.CipherSuite, entry.alpn, result.RecordLens[0], result.RecordLens[2]),
					CipherSuite:  result.CipherSuite,
					ALPN:         entry.alpn,
					RecordCount:  result.RecordCount,
					CapturedAt:   time.Now(),
				}
				globalCacheManager.HotSwapProfile(entry.cacheKey, newProfile)
				globalCacheManager.InvalidateFingerprint()
			}
			return true
		}
	}

	// Profile unchanged — reset debouncing state.
	entry.stableCount = 0

	globalCacheManager.MarkStale(entry.cacheKey)
	return true
}

// RefreshManager is a unified scheduler for background target probing.
// Instead of per-target goroutines, it uses a single scheduler that
// manages all targets with independent timers.
type RefreshManager struct {
	mu      sync.Mutex
	targets map[string]*refreshEntry
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
	sem     chan struct{} // concurrency limiter for probes
}

// refreshEntry tracks refresh state for a single target.
type refreshEntry struct {
	dest       string
	serverName string
	alpn       string // ALPN for building full cache key
	cacheKey   string // precomputed CacheKey(dest, serverName, alpn, VersionTLS13)
	timer      *time.Timer
	stopCh     chan struct{}
	failCount  int // consecutive probe failures

	// Debouncing: only HotSwap after consecutive identical probe results.
	lastProbeLens      [7]int
	lastProbeCipherSuite uint16
	stableCount        int
}

var (
	globalRefreshManager     *RefreshManager
	globalRefreshManagerOnce sync.Once
)

// refreshMin/Max define the random range for refresh intervals.
// Randomized to avoid predictable timing patterns.
var (
	refreshMin = 20 * time.Minute
	refreshMax = 30 * time.Minute
)

// refreshTimeout is the maximum time for a single probe operation.
const refreshTimeout = 10 * time.Second

// randomRefreshInterval returns a random duration between refreshMin and refreshMax.
func randomRefreshInterval() time.Duration {
	return refreshMin + time.Duration(rand.Int63n(int64(refreshMax-refreshMin)))
}

// GetRefreshManager returns the global refresh manager, initializing if needed.
func GetRefreshManager() *RefreshManager {
	globalRefreshManagerOnce.Do(func() {
		globalRefreshManager = &RefreshManager{
			targets: make(map[string]*refreshEntry),
			sem:     make(chan struct{}, 8), // max 8 concurrent probes
		}
	})
	return globalRefreshManager
}

// Start begins the background refresh scheduler.
func (m *RefreshManager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return
	}
	m.started = true
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	// Background goroutine that waits for context cancellation.
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-ctx.Done()
		m.mu.Lock()
		for key, entry := range m.targets {
			entry.timer.Stop()
			close(entry.stopCh)
			delete(m.targets, key)
		}
		m.mu.Unlock()
	}()
}

// Stop stops all background refresh goroutines and waits for them to exit.
func (m *RefreshManager) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// AddTarget registers a target for background refresh. If already registered,
// this is a no-op. The target will be probed periodically.
func (m *RefreshManager) AddTarget(dest, serverName, alpn string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Use dest as primary key (serverName may be empty at probe time).
	key := dest
	if _, exists := m.targets[key]; exists {
		return
	}

	entry := &refreshEntry{
		dest:     dest,
		serverName: serverName,
		alpn:     alpn,
		cacheKey: CacheKey(serverName, alpn, VersionTLS13),
		stopCh:   make(chan struct{}),
	}
	entry.timer = time.AfterFunc(randomRefreshInterval(), func() {
		m.probeAndReschedule(entry)
	})
	m.targets[key] = entry
}

// RemoveTarget stops refresh for a single target.
func (m *RefreshManager) RemoveTarget(dest, serverName, alpn string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := dest
	if entry, exists := m.targets[key]; exists {
		entry.timer.Stop()
		close(entry.stopCh)
		delete(m.targets, key)
	}
}

// probeAndReschedule probes the target and reschedules the next refresh.
func (m *RefreshManager) probeAndReschedule(entry *refreshEntry) {
	select {
	case <-entry.stopCh:
		return
	default:
	}

	// Acquire semaphore to limit concurrent probes.
	m.sem <- struct{}{}
	defer func() { <-m.sem }()

	success := m.probeTarget(entry.dest, entry.serverName, entry)

	// Reschedule with adaptive interval.
	m.mu.Lock()
	defer m.mu.Unlock()
	key := entry.dest
	if _, exists := m.targets[key]; exists {
		if success {
			entry.failCount = 0
			entry.timer.Reset(randomRefreshInterval())
		} else {
			entry.failCount++
			// Exponential backoff: 1min, 2min, 4min, max 10min
			backoff := time.Duration(1<<min(entry.failCount-1, 3)) * time.Minute
			if backoff > 10*time.Minute {
				backoff = 10 * time.Minute
			}
			entry.timer.Reset(backoff)
		}
	}
}

// GetStats returns statistics about the refresh manager.
func (m *RefreshManager) GetStats() (activeTargets int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.targets)
}

// FormatStats returns a human-readable string of refresh statistics.
func (m *RefreshManager) FormatStats() string {
	active := m.GetStats()
	return fmt.Sprintf("Background refresh: %d active targets", active)
}

// invalidateCache removes cached profiles for a target.
func invalidateCache(dest, serverName, alpn string) {
	profileKey := CacheKey(serverName, alpn, VersionTLS13)
	globalCacheManager.InvalidateProfile(profileKey)
}

// recordLensMatch compares two record lens arrays with tolerance for record[6]
// (NewSessionTicket), which can vary between connections.
func recordLensMatch(a, b [7]int) bool {
	for i := 0; i < 6; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	// record[6] (NewSessionTicket) — allow ±64 bytes tolerance.
	diff := a[6] - b[6]
	if diff < 0 {
		diff = -diff
	}
	return diff <= 64
}

// StartBackgroundRefreshForProfile is called when a new profile is cached.
func StartBackgroundRefreshForProfile(dest, serverName, alpn string) {
	m := GetRefreshManager()
	if !m.started {
		m.Start()
	}
	m.AddTarget(dest, serverName, alpn)
}

// StopBackgroundRefreshForProfile is called when a profile is invalidated.
func StopBackgroundRefreshForProfile(dest, serverName, alpn string) {
	if globalRefreshManager != nil {
		globalRefreshManager.RemoveTarget(dest, serverName, alpn)
	}
}

// FormatRefreshStats returns a human-readable string of refresh statistics.
func FormatRefreshStats() string {
	if globalRefreshManager == nil {
		return "Background refresh: not initialized"
	}
	return globalRefreshManager.FormatStats()
}

// ResetForTesting clears all internal state for unit test isolation.
// Must only be called from test code.
func (m *RefreshManager) ResetForTesting() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.mu.Unlock()
	m.wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range m.targets {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		select {
		case <-entry.stopCh:
		default:
			close(entry.stopCh)
		}
	}
	m.targets = make(map[string]*refreshEntry)
	m.started = false

	for len(m.sem) > 0 {
		<-m.sem
	}
}

// ResetGlobalRefreshManagerForTesting resets the package-level singleton
// so each test gets a fresh manager. Only for use in tests.
func ResetGlobalRefreshManagerForTesting() {
	if globalRefreshManager != nil {
		globalRefreshManager.ResetForTesting()
	}
}
