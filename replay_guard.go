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
	// Check capacity before storing.
	if g.count.Load() >= g.maxEntries {
		// At capacity — reject to prevent memory exhaustion.
		// The GC loop will clean up expired entries shortly.
		return false
	}

	now := time.Now()
	_, loaded := g.seen.LoadOrStore(randomPrefix, now)
	if !loaded {
		g.count.Add(1)
	}
	return !loaded
}

// gcLoop periodically removes expired entries from the seen map.
func (g *ReplayGuard) gcLoop() {
	ticker := time.NewTicker(g.window)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			g.seen.Range(func(k, v any) bool {
				if now.Sub(v.(time.Time)) > g.window {
					g.seen.Delete(k)
					g.count.Add(-1)
				}
				return true
			})
		case <-g.stopCh:
			return
		}
	}
}

// Stop terminates the background GC goroutine.
func (g *ReplayGuard) Stop() {
	close(g.stopCh)
}
