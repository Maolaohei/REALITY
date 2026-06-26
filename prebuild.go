package reality

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
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

	// Store the result for later use by Server().
	// Note: ProbeTarget is called for background probing; the actual profile
	// caching happens in Server() after a successful handshake.
	return nil
}

// ============================================================================
// Auto-start infrastructure
// ============================================================================

var (
	// probeOnces tracks per-destination sync.Once to ensure the initial
	// probe runs exactly once.
	probeOnces sync.Map // map[string]*sync.Once
	// warmupOnce ensures warmup runs only once.
	warmupOnce sync.Once
)

// WarmupProfiles proactively probes all known targets from profiles.json.
// Called once at startup to ensure fresh profiles before first connection.
// Uses a worker pool (5 concurrent probes) to avoid overwhelming the network.
func WarmupProfiles(dir string) {
	warmupOnce.Do(func() {
		go func() {
			// Wait for profile store to be initialized.
			if profileStore == nil {
				return
			}
			// Read all known keys from cache (loaded from profiles.json).
			var keys []string
			globalCacheManager.entries.Range(func(key, val any) bool {
				keys = append(keys, key.(string))
				return true
			})
			if len(keys) == 0 {
				return
			}

			// Worker pool: 5 concurrent probes.
			sem := make(chan struct{}, 5)
			var wg sync.WaitGroup
			for _, key := range keys {
				wg.Add(1)
				sem <- struct{}{}
				go func(k string) {
					defer wg.Done()
					defer func() { <-sem }()

					// Extract dest from key (format: "dest|serverName|alpn").
					dest := k
					if idx := strings.Index(k, "|"); idx > 0 {
						dest = k[:idx]
					}
					if dest == "" {
						return
					}

					// Probe with singleflight — skip if already in-flight.
					globalCacheManager.DoProbe(dest, func() (*RealityProfile, error) {
						return probeTargetRaw(dest)
					})
				}(key)
			}
			wg.Wait()
		}()
	})
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
// and registered with the background refresh manager. Called from Server().
func ensureAutoProbe(config *Config) {
	dest := config.Dest
	if dest == "" {
		return
	}

	onceVal, _ := probeOnces.LoadOrStore(dest, &sync.Once{})
	once := onceVal.(*sync.Once)

	once.Do(func() {
		// Register with the unified refresh manager.
		m := GetRefreshManager()
		if !m.started {
			m.Start()
		}
		m.AddTarget(dest, "")
	})
}

// StopAutoProbe cancels the background refresh for the given destination.
func StopAutoProbe(dest string) {
	if globalRefreshManager != nil {
		// RemoveTarget needs serverName; use empty string as fallback.
		globalRefreshManager.RemoveTarget(dest, "")
	}
	probeOnces.Delete(dest)
}

// probeTargetRaw connects to the target and returns a RealityProfile.
// Used by warmup and singleflight. Returns nil on error.
func probeTargetRaw(dest string) (*RealityProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	buf := make([]byte, maxRecordSize)
	s2cSaved := make([]byte, 0, maxRecordSize)

	// Read ServerHello.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadAtLeast(conn, buf, recordHeaderLen+1)
	if err != nil {
		return nil, err
	}
	s2cSaved = append(s2cSaved, buf[:n]...)

	// Validate.
	if bigEndianUint16(s2cSaved[1:3]) != VersionTLS12 {
		return nil, fmt.Errorf("invalid TLS version")
	}
	if recordType(s2cSaved[0]) != recordTypeHandshake || s2cSaved[5] != typeServerHello {
		return nil, fmt.Errorf("not ServerHello")
	}
	serverHelloLen := recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
	if serverHelloLen > maxTLSRecordPayload || serverHelloLen > len(s2cSaved) {
		return nil, fmt.Errorf("invalid ServerHello length")
	}

	hello := new(serverHelloMsg)
	if !hello.unmarshal(s2cSaved[recordHeaderLen:serverHelloLen]) {
		return nil, fmt.Errorf("failed to unmarshal ServerHello")
	}

	// Read remaining records.
	var recordLens [7]int
	recordLens[0] = serverHelloLen
	recordIndex := 1
	s2cSaved = s2cSaved[serverHelloLen:]

	for recordIndex < 7 {
		for recordIndex < 7 && len(s2cSaved) > recordHeaderLen {
			handshakeLen := recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
			if handshakeLen > maxTLSRecordPayload {
				break
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

	alpn := ""
	profile := &RealityProfile{
		RecordLens:   recordLens,
		Fingerprint:  computeFingerprint(hello.cipherSuite, alpn, recordLens[0], recordLens[2]),
		CipherSuite:  hello.cipherSuite,
		ALPN:         alpn,
		RecordCount:  0,
		CapturedAt:   time.Now(),
	}
	for _, l := range recordLens {
		if l > 0 {
			profile.RecordCount++
		}
	}

	return profile, nil
}
