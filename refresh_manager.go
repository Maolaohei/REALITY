package reality

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

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
	timer      *time.Timer
	stopCh     chan struct{}
	failCount  int // consecutive probe failures
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
func (m *RefreshManager) AddTarget(dest, serverName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Use dest as primary key (serverName may be empty at probe time).
	key := dest
	if _, exists := m.targets[key]; exists {
		return
	}

	entry := &refreshEntry{
		dest:       dest,
		serverName: serverName,
		stopCh:     make(chan struct{}),
	}
	entry.timer = time.AfterFunc(randomRefreshInterval(), func() {
		m.probeAndReschedule(entry)
	})
	m.targets[key] = entry
}

// RemoveTarget stops refresh for a single target.
func (m *RefreshManager) RemoveTarget(dest, serverName string) {
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

	success := m.probeTarget(entry.dest, entry.serverName)

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

// probeTarget connects to the target and compares against cached profile.
// Two-phase approach: Phase A reads only ServerHello (fast path),
// Phase B reads all 7 records only if Phase A detects changes.
// Returns true if probe succeeded, false on error.
func (m *RefreshManager) probeTarget(dest, serverName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return false
	}
	defer conn.Close()

	buf := make([]byte, maxRecordSize)
	s2cSaved := make([]byte, 0, maxRecordSize)

	// Phase A: Read only ServerHello.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadAtLeast(conn, buf, recordHeaderLen+1)
	if err != nil {
		return false
	}
	s2cSaved = append(s2cSaved, buf[:n]...)

	// Validate ServerHello record.
	if bigEndianUint16(s2cSaved[1:3]) != VersionTLS12 {
		return false
	}
	if recordType(s2cSaved[0]) != recordTypeHandshake || s2cSaved[5] != typeServerHello {
		return false
	}
	serverHelloLen := recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
	if serverHelloLen > maxTLSRecordPayload || serverHelloLen > len(s2cSaved) {
		return false
	}

	hello := new(serverHelloMsg)
	if !hello.unmarshal(s2cSaved[recordHeaderLen:serverHelloLen]) {
		return false
	}

	// Quick check: compare cipherSuite only.
	key := dest
	profile := globalCacheManager.GetProfile(key)
	if profile != nil && !profile.IsExpired() {
		if profile.CipherSuite == hello.cipherSuite {
			// CipherSuite unchanged — skip Phase B (fast path).
			return true
		}
		// CipherSuite changed — need Phase B to confirm.
	}

	// Phase B: Read remaining records to get full record lengths.
	var recordLens [7]int
	recordLens[0] = serverHelloLen
	recordIndex := 1
	s2cSaved = s2cSaved[serverHelloLen:]

	for recordIndex < 7 {
		for recordIndex < 7 && len(s2cSaved) > recordHeaderLen {
			handshakeLen := recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
			if handshakeLen > maxTLSRecordPayload {
				return false
			}
			if len(s2cSaved) < handshakeLen {
				break
			}
			recordLens[recordIndex] = handshakeLen
			s2cSaved = s2cSaved[handshakeLen:]
			recordIndex++
		}
		if recordIndex >= 7 {
			break
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := io.ReadAtLeast(conn, buf, recordHeaderLen+1)
		if err != nil {
			break
		}
		s2cSaved = append(s2cSaved, buf[:n]...)
	}

	// Compare full profile.
	if profile != nil && !profile.IsExpired() {
		if profile.CipherSuite != hello.cipherSuite {
			globalCacheManager.InvalidateProfile(key)
			globalCacheManager.InvalidateFingerprint()
			return true
		}
		if !recordLensMatch(profile.RecordLens, recordLens) {
			globalCacheManager.InvalidateProfile(key)
			return true
		}
	}

	return true
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
func invalidateCache(dest, serverName string) {
	profileKey := dest + "|" + serverName
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
func StartBackgroundRefreshForProfile(dest, serverName string) {
	m := GetRefreshManager()
	if !m.started {
		m.Start()
	}
	m.AddTarget(dest, serverName)
}

// StopBackgroundRefreshForProfile is called when a profile is invalidated.
func StopBackgroundRefreshForProfile(dest, serverName string) {
	if globalRefreshManager != nil {
		globalRefreshManager.RemoveTarget(dest, serverName)
	}
}

// FormatRefreshStats returns a human-readable string of refresh statistics.
func FormatRefreshStats() string {
	if globalRefreshManager == nil {
		return "Background refresh: not initialized"
	}
	return globalRefreshManager.FormatStats()
}
