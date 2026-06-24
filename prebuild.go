package reality

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"
)

// TargetProfile holds cached TLS record lengths captured from a target
// server during a probe. These lengths are used to construct the fake
// handshake without connecting to the target in real-time.
type TargetProfile struct {
	// HandshakeLen mirrors hs.c.out.handshakeLen — the exact byte lengths
	// of each TLS 1.3 record the target sends:
	//   [0] ServerHello
	//   [1] ChangeCipherSpec (always 6)
	//   [2] EncryptedExtensions
	//   [3] Certificate
	//   [4] CertificateVerify
	//   [5] Finished
	//   [6] NewSessionTicket (0 if not sent)
	HandshakeLen [7]int

	// CipherSuite is the TLS 1.3 cipher suite from the target's ServerHello.
	// Needed to construct a compatible fake ServerHello.
	CipherSuite uint16

	// KeyGroup is the key exchange group from the target's ServerHello
	// (X25519 or X25519MLKEM768).
	KeyGroup CurveID

	CapturedAt time.Time
	TTL        time.Duration
}

// PrebuildCache stores per-serverName target profiles with automatic
// expiration and LRU eviction. Safe for concurrent use.
type PrebuildCache struct {
	mu       sync.RWMutex
	profiles map[string]*TargetProfile
	access   map[string]int64 // monotonic counter for LRU ordering
	counter  int64
	capacity int
	ttl      time.Duration
}

// NewPrebuildCache creates a new cache with the given per-entry TTL
// and maximum capacity. When the cache is full, the least recently
// accessed entry is evicted on Store(). A capacity of 0 means unlimited.
func NewPrebuildCache(ttl time.Duration, capacity int) *PrebuildCache {
	return &PrebuildCache{
		profiles: make(map[string]*TargetProfile),
		access:   make(map[string]int64),
		capacity: capacity,
		ttl:      ttl,
	}
}

// Get returns the cached profile for serverName, or nil if expired/missing.
// Updates LRU access timestamp on hit.
func (pc *PrebuildCache) Get(serverName string) *TargetProfile {
	pc.mu.RLock()
	p, ok := pc.profiles[serverName]
	pc.mu.RUnlock()
	if !ok || p == nil {
		return nil
	}
	if time.Since(p.CapturedAt) >= p.TTL {
		pc.mu.Lock()
		delete(pc.profiles, serverName)
		delete(pc.access, serverName)
		pc.mu.Unlock()
		return nil
	}
	// Update LRU timestamp.
	pc.mu.Lock()
	pc.counter++
	pc.access[serverName] = pc.counter
	pc.mu.Unlock()
	return p
}

// Store adds or replaces a profile for serverName.
// A shallow copy is made to prevent callers from mutating cached data.
// If the cache is at capacity, the least recently accessed entry is evicted.
func (pc *PrebuildCache) Store(serverName string, p *TargetProfile) {
	if p == nil {
		return
	}
	cp := *p
	pc.mu.Lock()
	// Evict LRU entry if at capacity (and capacity > 0) and this is a new key.
	if pc.capacity > 0 {
		if _, exists := pc.profiles[serverName]; !exists && len(pc.profiles) >= pc.capacity {
			pc.evictLRU()
		}
	}
	pc.counter++
	pc.access[serverName] = pc.counter
	pc.profiles[serverName] = &cp
	pc.mu.Unlock()
}

// evictLRU removes the least recently accessed entry. Must be called with mu held.
func (pc *PrebuildCache) evictLRU() {
	var oldestKey string
	var oldestAccess int64 = math.MaxInt64
	for k, v := range pc.access {
		if v < oldestAccess {
			oldestAccess = v
			oldestKey = k
		}
	}
	if oldestKey != "" {
		delete(pc.profiles, oldestKey)
		delete(pc.access, oldestKey)
	}
}

// Len returns the current number of entries in the cache.
func (pc *PrebuildCache) Len() int {
	pc.mu.RLock()
	n := len(pc.profiles)
	pc.mu.RUnlock()
	return n
}

// ProbeTarget connects to the target server, captures its TLS record
// lengths, and caches the result. This is the core "pre-build" operation.
// It should be called periodically (e.g., every 30 minutes) to refresh
// cached data before expiration.
func ProbeTarget(ctx context.Context, config *Config) error {
	target, err := config.DialContext(ctx, config.Type, config.Dest)
	if err != nil {
		return err
	}
	defer target.Close()

	// Read the target's TLS response to capture record lengths.
	buf := make([]byte, maxRecordSize)
	s2cSaved := make([]byte, 0, maxRecordSize)
	handshakeLen := 0
	profile := &TargetProfile{
		CapturedAt: time.Now(),
		TTL:        30 * time.Minute,
	}

	recordIndex := 0
	for recordIndex < 7 {
		n, err := target.Read(buf)
		if err != nil {
			break
		}
		s2cSaved = append(s2cSaved, buf[:n]...)

		for recordIndex < 7 && len(s2cSaved) > recordHeaderLen {
			if handshakeLen == 0 {
				if bigEndianUint16(s2cSaved[1:3]) != VersionTLS12 {
					return nil
				}
				recordType := recordType(s2cSaved[0])
				switch recordIndex {
				case 0: // ServerHello
					if recordType != recordTypeHandshake || s2cSaved[5] != typeServerHello {
						return nil
					}
				case 1: // ChangeCipherSpec
					if recordType != recordTypeChangeCipherSpec || s2cSaved[5] != 1 {
						return nil
					}
				default: // ApplicationData records
					if recordType != recordTypeApplicationData {
						return nil
					}
				}
				handshakeLen = recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
			}
			if handshakeLen > maxTLSRecordPayload {
				return nil
			}
			if len(s2cSaved) < handshakeLen {
				break // need more data
			}
			profile.HandshakeLen[recordIndex] = handshakeLen
			s2cSaved = s2cSaved[handshakeLen:]
			handshakeLen = 0
			recordIndex++
		}
	}

	if recordIndex > 0 {
		defaultPrebuildCache.Store(config.Dest, profile)
	}
	return nil
}

// ============================================================================
// Auto-start infrastructure
// ============================================================================

var (
	// probeOnces tracks per-destination sync.Once to ensure the initial
	// probe runs exactly once.
	probeOnces sync.Map // map[string]*sync.Once
	// probeStops tracks cancel functions for background refresh goroutines.
	probeStops sync.Map // map[string]context.CancelFunc
	// probeRefreshMin/Max define the random range for refresh intervals.
	// Randomized to avoid predictable timing patterns that could be
	// detected by traffic analysis. Must stay within the 30-min TTL.
	probeRefreshMin = 20 * time.Minute
	probeRefreshMax = 30 * time.Minute
	// probeTimeout is the maximum time for a single probe operation.
	probeTimeout = 10 * time.Second
)

// probeRefreshInterval returns a random duration between probeRefreshMin
// and probeRefreshMax. Each call produces a different value.
func probeRefreshInterval() time.Duration {
	return probeRefreshMin + time.Duration(rand.Int63n(int64(probeRefreshMax-probeRefreshMin)))
}

// probeConfig holds the values needed to probe a target, copied from
// Config to avoid retaining a pointer to the caller's mutable Config.
type probeConfig struct {
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
	show        bool
	dest        string
	typ         string
}

func newProbeConfig(config *Config) probeConfig {
	return probeConfig{
		dialContext: config.DialContext,
		show:        config.Show,
		dest:        config.Dest,
		typ:         config.Type,
	}
}

// ensureAutoProbe ensures that the target is probed on first connection
// and a background refresh goroutine is running. Called from Server().
func ensureAutoProbe(config *Config) {
	dest := config.Dest
	if dest == "" {
		return // skip auto-probe for empty destinations
	}

	// Copy config values to avoid capturing a mutable pointer.
	pc := newProbeConfig(config)

	onceVal, _ := probeOnces.LoadOrStore(dest, &sync.Once{})
	once := onceVal.(*sync.Once)

	once.Do(func() {
		// Synchronous initial probe — the first connection benefits
		// immediately from the cache without waiting for a goroutine.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
			defer cancel()
			if err := ProbeTarget(ctx, &Config{
				DialContext: pc.dialContext,
				Show:        pc.show,
				Dest:        pc.dest,
				Type:        pc.typ,
			}); err != nil && pc.show {
				fmt.Printf("REALITY prebuild: initial probe for %v failed: %v\n", pc.dest, err)
			}
		}()

		// Start background refresh goroutine.
		ctx, cancel := context.WithCancel(context.Background())
		probeStops.Store(dest, cancel)
		go func() {
			defer func() {
				// Clean up sync.Map entries to prevent memory leak.
				probeStops.Delete(dest)
				probeOnces.Delete(dest)
			}()
			// Use manual timer with random intervals to avoid
			// predictable timing patterns.
			timer := time.NewTimer(probeRefreshInterval())
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					probeCtx, probeCancel := context.WithTimeout(context.Background(), probeTimeout)
					if err := ProbeTarget(probeCtx, &Config{
						DialContext: pc.dialContext,
						Show:        pc.show,
						Dest:        pc.dest,
						Type:        pc.typ,
					}); err != nil && pc.show {
						fmt.Printf("REALITY prebuild: refresh probe for %v failed: %v\n", pc.dest, err)
					}
					probeCancel()
					// Reset with a new random interval.
					timer.Reset(probeRefreshInterval())
				}
			}
		}()
	})
}

// StopAutoProbe cancels the background refresh goroutine for the given
// destination. Useful for graceful shutdown.
func StopAutoProbe(dest string) {
	if cancel, ok := probeStops.Load(dest); ok {
		cancel.(context.CancelFunc)()
		probeStops.Delete(dest)
		probeOnces.Delete(dest)
	}
}
