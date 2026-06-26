package reality

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

// BackgroundRefreshManager manages periodic background probing of cached targets.
type BackgroundRefreshManager struct {
	interval time.Duration
	targets  sync.Map // map[string]*refreshTarget
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// refreshTarget tracks background refresh state for a single target.
type refreshTarget struct {
	dest       string
	serverName string
	stopCh     chan struct{}
}

var (
	refreshManager     *BackgroundRefreshManager
	refreshManagerOnce sync.Once
)

// refreshInterval returns a random duration between 20 and 30 minutes.
// Reuses prebuild.go's range to avoid predictable timing patterns.
func refreshInterval() time.Duration {
	return probeRefreshMin + time.Duration(rand.Int63n(int64(probeRefreshMax-probeRefreshMin)))
}

// InitBackgroundRefresh initializes the background refresh manager.
func InitBackgroundRefresh() *BackgroundRefreshManager {
	refreshManagerOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		refreshManager = &BackgroundRefreshManager{
			interval: refreshInterval(),
			cancel:   cancel,
		}
		// Start a goroutine that watches for context cancellation.
		go func() {
			<-ctx.Done()
			refreshManager.wg.Wait()
		}()
	})
	return refreshManager
}

// StartRefresh begins background probing for a target.
func (m *BackgroundRefreshManager) StartRefresh(dest, serverName string) {
	if m == nil {
		return
	}

	key := dest + "|" + serverName
	if _, loaded := m.targets.LoadOrStore(key, &refreshTarget{
		dest:       dest,
		serverName: serverName,
		stopCh:     make(chan struct{}),
	}); loaded {
		return
	}

	m.wg.Add(1)
	go m.refreshLoop(dest, serverName)
}

// StopRefresh stops background probing for a single target.
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

// StopAll stops all background goroutines and waits for them to exit.
func (m *BackgroundRefreshManager) StopAll() {
	if m == nil {
		return
	}

	// Signal all goroutines to stop.
	m.targets.Range(func(key, val any) bool {
		t := val.(*refreshTarget)
		close(t.stopCh)
		m.targets.Delete(key)
		return true
	})

	// Cancel context and wait for all goroutines to finish.
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

// refreshLoop periodically probes a target.
func (m *BackgroundRefreshManager) refreshLoop(dest, serverName string) {
	defer m.wg.Done()

	val, ok := m.targets.Load(dest + "|" + serverName)
	if !ok {
		return
	}
	t := val.(*refreshTarget)

	timer := time.NewTimer(refreshInterval())
	defer timer.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-timer.C:
			m.probeTarget(dest, serverName)
			timer.Reset(refreshInterval())
		}
	}
}

// probeTarget connects to the target, reads its ServerHello, and compares
// the fingerprint against the cached profile. If the target changed
// (e.g. certificate rotation), the cache is invalidated.
func (m *BackgroundRefreshManager) probeTarget(dest, serverName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		invalidateCache(dest, serverName)
		return
	}
	defer conn.Close()

	// Read ServerHello to capture TLS record length.
	buf := make([]byte, maxRecordSize)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadAtLeast(conn, buf, recordHeaderLen+1)
	if err != nil {
		invalidateCache(dest, serverName)
		return
	}

	// Validate record header.
	if recordType(buf[0]) != recordTypeHandshake || buf[5] != typeServerHello {
		invalidateCache(dest, serverName)
		return
	}
	if bigEndianUint16(buf[1:3]) != VersionTLS12 {
		invalidateCache(dest, serverName)
		return
	}
	serverHelloLen := recordHeaderLen + int(binary.BigEndian.Uint16(buf[3:5]))
	if serverHelloLen > maxTLSRecordPayload || serverHelloLen > n {
		invalidateCache(dest, serverName)
		return
	}

	// Parse ServerHello to extract cipher suite.
	hello := new(serverHelloMsg)
	if !hello.unmarshal(buf[recordHeaderLen:serverHelloLen]) {
		invalidateCache(dest, serverName)
		return
	}

	// Compare against cached profile.
	key := dest + "|" + serverName
	if profile := globalCacheManager.GetProfile(key); profile != nil {
		if !profile.IsExpired() && profile.CipherSuite != hello.cipherSuite {
			// Cipher suite changed — invalidate.
			globalCacheManager.InvalidateProfile(key)
			globalCacheManager.InvalidateFingerprint()
			return
		}
	}

	// Target alive and unchanged — save cache.
	if profileStore != nil {
		go profileStore.Save()
	}
}

// invalidateCache removes cached profiles for a target.
func invalidateCache(dest, serverName string) {
	profileKey := dest + "|" + serverName
	globalCacheManager.InvalidateProfile(profileKey)
}

// GetRefreshStats returns statistics about background refresh.
func (m *BackgroundRefreshManager) GetRefreshStats() (activeTargets int) {
	if m == nil {
		return 0
	}
	m.targets.Range(func(key, val any) bool {
		activeTargets++
		return true
	})
	return activeTargets
}

// StartBackgroundRefreshForProfile is called when a new profile is cached.
func StartBackgroundRefreshForProfile(dest, serverName string) {
	if refreshManager == nil {
		InitBackgroundRefresh()
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
	active := refreshManager.GetRefreshStats()
	return fmt.Sprintf("Background refresh: %d active targets", active)
}
