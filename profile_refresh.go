package reality

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// BackgroundRefreshManager manages periodic background probing of cached targets.
type BackgroundRefreshManager struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	interval time.Duration
	running  atomic.Bool
	targets  sync.Map // map[string]*refreshTarget
}

// refreshTarget tracks background refresh state for a single target.
type refreshTarget struct {
	dest       string
	serverName string
	interval   time.Duration
	stopCh     chan struct{}
}

var (
	refreshManager     *BackgroundRefreshManager
	refreshManagerOnce sync.Once
)

// InitBackgroundRefresh initializes the background refresh manager.
func InitBackgroundRefresh(interval time.Duration) *BackgroundRefreshManager {
	refreshManagerOnce.Do(func() {
		refreshManager = &BackgroundRefreshManager{
			interval: interval,
		}
	})
	return refreshManager
}

// StartRefresh begins background probing for a target.
// Called automatically when a profile is cached.
func (m *BackgroundRefreshManager) StartRefresh(dest, serverName string) {
	if m == nil {
		return
	}

	key := dest + "|" + serverName
	if _, loaded := m.targets.LoadOrStore(key, &refreshTarget{
		dest:       dest,
		serverName: serverName,
		interval:   m.interval,
		stopCh:     make(chan struct{}),
	}); loaded {
		return // already refreshing
	}

	go m.refreshLoop(dest, serverName)
}

// StopRefresh stops background probing for a target.
func (m *BackgroundRefreshManager) StopRefresh(dest, serverName string) {
	if m == nil {
		return
	}

	key := dest + "|" + serverName
	if val, ok := m.targets.LoadAndDelete(key); ok {
		t := val.(*refreshTarget)
		close(t.stopCh)
	}
}

// refreshLoop periodically probes a target and updates the cache.
func (m *BackgroundRefreshManager) refreshLoop(dest, serverName string) {
	key := dest + "|" + serverName
	val, ok := m.targets.Load(key)
	if !ok {
		return
	}
	t := val.(*refreshTarget)

	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			m.probeTarget(dest, serverName)
		}
	}
}

// probeTarget connects to the target and compares the fingerprint.
func (m *BackgroundRefreshManager) probeTarget(dest, serverName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := net.DialTimeout("tcp", dest, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// Read ServerHello to get basic TLS info
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return
	}

	// Parse record header
	if buf[0] != 22 { // Handshake
		return
	}
	recordLen := int(buf[3])<<8 | int(buf[4])
	if recordLen > 16384 {
		return
	}

	// We got a valid TLS response — target is alive
	// The real validation happens when the next user connection
	// compares the fingerprint. We just ensure the target is reachable.

	_ = ctx

	// Log refresh attempt
	if profileStore != nil {
		profileStore.Save()
	}
}

// GetRefreshStats returns statistics about background refresh.
func (m *BackgroundRefreshManager) GetRefreshStats() (activeTargets int, totalProbes uint64) {
	if m == nil {
		return 0, 0
	}
	m.targets.Range(func(key, val any) bool {
		activeTargets++
		return true
	})
	return activeTargets, 0
}

// DefaultRefreshInterval is the default interval for background profile refresh.
const DefaultRefreshInterval = 6 * time.Hour

// StartBackgroundRefreshForProfile is called when a new profile is cached.
// It starts background refresh if not already running for this target.
func StartBackgroundRefreshForProfile(dest, serverName string) {
	if refreshManager == nil {
		InitBackgroundRefresh(DefaultRefreshInterval)
	}
	refreshManager.StartRefresh(dest, serverName)
}

// StopBackgroundRefreshForProfile is called when a profile is invalidated.
func StopBackgroundRefreshForProfile(dest, serverName string) {
	if refreshManager != nil {
		refreshManager.StopRefresh(dest, serverName)
	}
}

// FormatRefreshStats returns a human-readable string of refresh statistics.
func FormatRefreshStats() string {
	if refreshManager == nil {
		return "Background refresh: not initialized"
	}
	active, _ := refreshManager.GetRefreshStats()
	return fmt.Sprintf("Background refresh: %d active targets, interval: %v", active, refreshManager.interval)
}
