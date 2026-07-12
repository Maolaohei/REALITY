package reality

import (
	"sync"
	"sync/atomic"
	"time"
)

const defaultReplayGuardMaxEntries = 100000

// ReplayGuard deduplicates ClientHello.random prefixes within a time window.
// Prevents resource-wasting replays within the MaxTimeDiff window.
type ReplayGuard struct {
	seen       sync.Map    // key: [20]byte (random prefix), value: time.Time
	window     time.Duration
	maxEntries int64
	count      atomic.Int64
	stopCh     chan struct{}
}

// NewReplayGuard creates a ReplayGuard with the given window and capacity limit.
func NewReplayGuard(window time.Duration, maxEntries int) *ReplayGuard {
	if maxEntries <= 0 {
		maxEntries = defaultReplayGuardMaxEntries
	}
	g := &ReplayGuard{
		window:     window,
		maxEntries: int64(maxEntries),
		stopCh:     make(chan struct{}),
	}
	go g.gcLoop()
	return g
}

// CheckAndMark returns true if this random prefix is seen for the first time
// within the window (allow), or false if it's a duplicate (reject).
func (g *ReplayGuard) CheckAndMark(randomPrefix [20]byte) bool {
	if g.count.Load() >= g.maxEntries {
		// At or near capacity: do an inline sweep to evict expired entries
		// before deciding. This prevents an attacker from filling the guard
		// with unique randoms and blocking all legitimate connections.
		g.sweepExpired()
		// If still at capacity after sweep, reject to bound memory usage.
		if g.count.Load() >= g.maxEntries {
			return false
		}
	}

	now := time.Now()
	existing, loaded := g.seen.LoadOrStore(randomPrefix, now)
	if !loaded {
		g.count.Add(1)
		return true
	}
	// Key exists -- check if it has expired. If so, replace it and allow.
	if now.Sub(existing.(time.Time)) > g.window {
		g.seen.Store(randomPrefix, now)
		return true
	}
	return false
}

// sweepExpired removes all entries older than the window. Called inline when
// the guard is near capacity and periodically by gcLoop.
func (g *ReplayGuard) sweepExpired() {
	now := time.Now()
	g.seen.Range(func(k, v any) bool {
		if now.Sub(v.(time.Time)) > g.window {
			g.seen.Delete(k)
			g.count.Add(-1)
		}
		return true
	})
}

// gcLoop periodically removes expired entries from the seen map.
// Runs at window/4 interval for faster recovery after a burst.
func (g *ReplayGuard) gcLoop() {
	gcInterval := g.window / 4
	if gcInterval < 5*time.Second {
		gcInterval = 5 * time.Second
	}
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			g.sweepExpired()
		case <-g.stopCh:
			return
		}
	}
}

// Stop terminates the background GC goroutine.
func (g *ReplayGuard) Stop() {
	close(g.stopCh)
}

// replayGuardInit provides safe concurrent initialization of globalReplayGuard.
var replayGuardInit sync.Once

// InitGlobalReplayGuard initializes the global replay guard exactly once
// with the given window. Subsequent calls are no-ops.
func InitGlobalReplayGuard(window time.Duration) {
	replayGuardInit.Do(func() {
		if window <= 0 {
			window = 90 * time.Second
		}
		globalReplayGuard = NewReplayGuard(window, 0)
	})
}

// GetGlobalReplayGuard returns the initialized replay guard, or nil if not yet initialized.
func GetGlobalReplayGuard() *ReplayGuard {
	return globalReplayGuard
}
