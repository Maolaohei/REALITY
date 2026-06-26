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
}

// refreshEntry tracks refresh state for a single target.
type refreshEntry struct {
	dest       string
	serverName string
	timer      *time.Timer
	stopCh     chan struct{}
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

	m.probeTarget(entry.dest, entry.serverName)

	// Reschedule with a new random interval.
	m.mu.Lock()
	defer m.mu.Unlock()
	key := entry.dest
	if _, exists := m.targets[key]; exists {
		entry.timer.Reset(randomRefreshInterval())
	}
}

// probeTarget connects to the target, reads its full TLS handshake
// (all 7 records), and compares against the cached profile.
// Invalidates cache if the target changed (cipher suite, record lengths, etc.).
func (m *RefreshManager) probeTarget(dest, serverName string) {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		invalidateCache(dest, serverName)
		return
	}
	defer conn.Close()

	// Read the target's full TLS handshake to capture record lengths.
	buf := make([]byte, maxRecordSize)
	s2cSaved := make([]byte, 0, maxRecordSize)
	handshakeLen := 0
	var recordLens [7]int
	var cipherSuite uint16

	recordIndex := 0
	for recordIndex < 7 {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := io.ReadAtLeast(conn, buf, recordHeaderLen+1)
		if err != nil {
			break
		}
		s2cSaved = append(s2cSaved, buf[:n]...)

		for recordIndex < 7 && len(s2cSaved) > recordHeaderLen {
			if handshakeLen == 0 {
				if bigEndianUint16(s2cSaved[1:3]) != VersionTLS12 {
					invalidateCache(dest, serverName)
					return
				}
				rt := recordType(s2cSaved[0])
				switch recordIndex {
				case 0: // ServerHello
					if rt != recordTypeHandshake || s2cSaved[5] != typeServerHello {
						invalidateCache(dest, serverName)
						return
					}
				case 1: // ChangeCipherSpec
					if rt != recordTypeChangeCipherSpec || s2cSaved[5] != 1 {
						invalidateCache(dest, serverName)
						return
					}
				default: // ApplicationData records
					if rt != recordTypeApplicationData {
						invalidateCache(dest, serverName)
						return
					}
				}
				handshakeLen = recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
			}
			if handshakeLen > maxTLSRecordPayload {
				invalidateCache(dest, serverName)
				return
			}
			if len(s2cSaved) < handshakeLen {
				break // need more data
			}
			recordLens[recordIndex] = handshakeLen

			// Parse ServerHello to extract cipher suite.
			if recordIndex == 0 {
				hello := new(serverHelloMsg)
				if !hello.unmarshal(s2cSaved[recordHeaderLen:handshakeLen]) {
					invalidateCache(dest, serverName)
					return
				}
				cipherSuite = hello.cipherSuite
			}

			s2cSaved = s2cSaved[handshakeLen:]
			handshakeLen = 0
			recordIndex++
		}
	}

	if recordIndex == 0 {
		invalidateCache(dest, serverName)
		return
	}

	// Compare against cached profile.
	key := dest
	if profile := globalCacheManager.GetProfile(key); profile != nil {
		if !profile.IsExpired() {
			// Check if cipher suite or record lengths changed.
			if profile.CipherSuite != cipherSuite {
				globalCacheManager.InvalidateProfile(key)
				globalCacheManager.InvalidateFingerprint()
				return
			}
			// Check if record lengths differ (target may have changed certificates).
			if profile.RecordLens != recordLens {
				globalCacheManager.InvalidateProfile(key)
				return
			}
		}
	}

	// Target alive and unchanged — save cache.
	if profileStore != nil {
		go profileStore.Save()
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
func invalidateCache(dest, serverName string) {
	profileKey := dest + "|" + serverName
	globalCacheManager.InvalidateProfile(profileKey)
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
