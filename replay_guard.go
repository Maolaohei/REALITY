package reality

import (
	"sync"
	"sync/atomic"
	"time"
)

const defaultReplayGuardMaxEntries = 100000

// replayShardCount partitions the replay map so the hot path only touches 1/N
// of the entries and near-capacity sweeps rotate one shard at a time instead
// of traversing the whole table (the single big sync.Map made every
// capacity-triggered scan O(N) and the atomic count drifted under load).
const replayShardCount = 16

// ReplayGuard deduplicates ClientHello.random prefixes within a time window.
// Prevents resource-wasting replays within the MaxTimeDiff window.
type ReplayGuard struct {
	shards      [replayShardCount]*replayShard
	window      time.Duration
	maxEntries  int64
	count       atomic.Int64 // global live-entry count (exact capacity gate)
	evictCursor atomic.Uint64
	evictSeed   atomic.Uint64
	stopCh      chan struct{}
}

// replayShard is one partition of the seen map, guarded by its own mutex.
type replayShard struct {
	mu   sync.Mutex
	seen map[[20]byte]int64 // key: random prefix, value: unix nano
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
	for i := range g.shards {
		g.shards[i] = &replayShard{seen: make(map[[20]byte]int64)}
	}
	g.evictSeed.Store(uint64(time.Now().UnixNano()))
	go g.gcLoop()
	return g
}

// shardFor maps a random prefix to its shard. ClientHello.random is
// effectively random, so the first 4 bytes distribute well.
func (g *ReplayGuard) shardFor(randomPrefix [20]byte) *replayShard {
	h := uint32(randomPrefix[0])<<24 | uint32(randomPrefix[1])<<16 | uint32(randomPrefix[2])<<8 | uint32(randomPrefix[3])
	return g.shards[h%replayShardCount]
}

// CheckAndMark returns true if this random prefix is seen for the first time
// within the window (allow), or false if it's a duplicate (reject).
func (g *ReplayGuard) CheckAndMark(randomPrefix [20]byte) bool {
	if g.count.Load() >= g.maxEntries {
		// At capacity: free one shard (round-robin) before admitting. Rotating
		// one shard per call keeps the scan cost bounded instead of walking
		// the entire table on every hot-path arrival.
		g.evictOneShard()
		if g.count.Load() >= g.maxEntries {
			// Still full after eviction: reject this one (memory hard bound).
			return false
		}
	}

	s := g.shardFor(randomPrefix)
	s.mu.Lock()
	nowNano := time.Now().UnixNano()
	existing, ok := s.seen[randomPrefix]
	if !ok {
		s.seen[randomPrefix] = nowNano
		g.count.Add(1)
		s.mu.Unlock()
		return true
	}
	// Key exists -- check if it has expired. If so, replace it and allow.
	if nowNano-existing > int64(g.window) {
		s.seen[randomPrefix] = nowNano
		s.mu.Unlock()
		return true
	}
	s.mu.Unlock()
	return false
}

// evictOneShard sweeps expired entries from one shard (round-robin) and, if
// that did not free room, randomly drops ~10% of the shard. Availability is
// preferred over strict capacity: an attacker filling the guard with unique
// randoms must not permanently block legitimate connections.
func (g *ReplayGuard) evictOneShard() {
	idx := g.evictCursor.Add(1) % replayShardCount
	s := g.shards[idx]
	s.mu.Lock()
	defer s.mu.Unlock()

	nowNano := time.Now().UnixNano()
	for k, v := range s.seen {
		if nowNano-v > int64(g.window) {
			delete(s.seen, k)
			g.count.Add(-1)
		}
	}
	if g.count.Load() < g.maxEntries {
		return
	}
	// Still full: random-evict ~10% of this shard.
	stride := 10
	seed := g.evictSeed.Add(0x9e3779b97f4a7c15)
	var i int
	for k := range s.seen {
		i++
		// pseudo-random bucket from seed+i
		h := seed + uint64(i)*0x85ebca6b
		if int(h%uint64(stride)) == 0 {
			delete(s.seen, k)
			g.count.Add(-1)
		}
	}
}

// gcLoop periodically removes expired entries from all shards, one shard per
// tick (rotating), so bursts are recovered without a full-table stall.
func (g *ReplayGuard) gcLoop() {
	gcInterval := g.window / 4
	if gcInterval < 5*time.Second {
		gcInterval = 5 * time.Second
	}
	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()
	var cursor uint64
	for {
		select {
		case <-ticker.C:
			idx := cursor % replayShardCount
			cursor++
			s := g.shards[idx]
			s.mu.Lock()
			nowNano := time.Now().UnixNano()
			for k, v := range s.seen {
				if nowNano-v > int64(g.window) {
					delete(s.seen, k)
					g.count.Add(-1)
				}
			}
			s.mu.Unlock()
		case <-g.stopCh:
			return
		}
	}
}

// Stop terminates the background GC goroutine.
func (g *ReplayGuard) Stop() {
	close(g.stopCh)
}

// Count returns the total number of live entries across all shards
// (statistics/debug helper).
func (g *ReplayGuard) Count() int64 {
	return g.count.Load()
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
