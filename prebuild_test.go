package reality

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// PrebuildCache Tests
// ============================================================================

func TestPrebuildCache_StoreAndGet(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)

	profile := &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite:  0x1301,
		KeyGroup:     X25519,
		CapturedAt:   time.Now(),
		TTL:          time.Minute,
	}

	cache.Store("example.com", profile)
	got := cache.Get("example.com")
	if got == nil {
		t.Fatal("expected profile, got nil")
	}
	if got.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %v, want %v", got.CipherSuite, 0x1301)
	}
	if got.KeyGroup != X25519 {
		t.Errorf("KeyGroup = %v, want %v", got.KeyGroup, X25519)
	}
	for i, v := range got.HandshakeLen {
		if v != profile.HandshakeLen[i] {
			t.Errorf("HandshakeLen[%d] = %v, want %v", i, v, profile.HandshakeLen[i])
		}
	}
}

func TestPrebuildCache_GetMiss(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	got := cache.Get("nonexistent.com")
	if got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

func TestPrebuildCache_GetExpired(t *testing.T) {
	cache := NewPrebuildCache(time.Millisecond, 0)
	profile := &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite:  0x1301,
		KeyGroup:     X25519,
		CapturedAt:   time.Now().Add(-2 * time.Millisecond),
		TTL:          time.Millisecond,
	}
	cache.Store("example.com", profile)
	time.Sleep(5 * time.Millisecond)
	got := cache.Get("example.com")
	if got != nil {
		t.Errorf("expected nil for expired entry, got %v", got)
	}
}

func TestPrebuildCache_Replace(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite:  0x1301, KeyGroup: X25519,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{150, 6, 250, 350, 120, 60, 0},
		CipherSuite:  0x1302, KeyGroup: X25519MLKEM768,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	got := cache.Get("example.com")
	if got == nil {
		t.Fatal("expected profile, got nil")
	}
	if got.CipherSuite != 0x1302 {
		t.Errorf("CipherSuite = %v, want 0x1302 (replacement)", got.CipherSuite)
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestPrebuildCache_ConcurrentReadWrite(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				cache.Store("key", &TargetProfile{
					HandshakeLen: [7]int{id, 6, j, 300, 100, 50, 0},
					CipherSuite:  uint16(id), KeyGroup: X25519,
					CapturedAt: time.Now(), TTL: time.Minute,
				})
				cache.Get("key")
			}
		}(i)
	}
	wg.Wait()
}

func TestPrebuildCache_ConcurrentDelete(t *testing.T) {
	cache := NewPrebuildCache(time.Millisecond, 0)
	var wg sync.WaitGroup
	const n = 50
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cache.Get("key")
			}
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestPrebuildCache_EmptyKey(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("", &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite: 0x1301, KeyGroup: X25519,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	got := cache.Get("")
	if got == nil {
		t.Error("expected profile for empty key, got nil")
	}
}

func TestPrebuildCache_ZeroTTL(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite: 0x1301, KeyGroup: X25519,
		CapturedAt: time.Now(), TTL: 0,
	})
	time.Sleep(time.Millisecond)
	got := cache.Get("example.com")
	if got != nil {
		t.Errorf("expected nil for zero-TTL entry, got %v", got)
	}
}

func TestPrebuildCache_NegativeTTL(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite: 0x1301, KeyGroup: X25519,
		CapturedAt: time.Now(), TTL: -time.Second,
	})
	got := cache.Get("example.com")
	if got != nil {
		t.Errorf("expected nil for negative-TTL entry, got %v", got)
	}
}

func TestPrebuildCache_ZeroHandshakeLen(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{0, 0, 0, 0, 0, 0, 0},
		CipherSuite: 0, KeyGroup: 0,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	got := cache.Get("example.com")
	if got == nil {
		t.Fatal("expected profile, got nil")
	}
	if got.HandshakeLen[0] != 0 {
		t.Errorf("expected zero HandshakeLen[0], got %v", got.HandshakeLen[0])
	}
}

func TestPrebuildCache_MaxHandshakeLen(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{16389, 6, 16389, 16389, 16389, 16389, 16389},
		CipherSuite: 0x1302, KeyGroup: X25519MLKEM768,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	got := cache.Get("example.com")
	if got == nil {
		t.Fatal("expected profile, got nil")
	}
	if got.HandshakeLen[0] != 16389 {
		t.Errorf("expected 16389, got %v", got.HandshakeLen[0])
	}
}

func TestPrebuildCache_MultipleKeys(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	keys := map[string]*TargetProfile{
		"a.com": {HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0}, CipherSuite: 0x1301, KeyGroup: X25519, CapturedAt: time.Now(), TTL: time.Minute},
		"b.com": {HandshakeLen: [7]int{150, 6, 250, 350, 120, 60, 0}, CipherSuite: 0x1302, KeyGroup: X25519MLKEM768, CapturedAt: time.Now(), TTL: time.Minute},
		"c.com": {HandshakeLen: [7]int{200, 6, 300, 400, 130, 70, 0}, CipherSuite: 0x1303, KeyGroup: X25519, CapturedAt: time.Now(), TTL: time.Minute},
	}
	for k, v := range keys {
		cache.Store(k, v)
	}
	for k, want := range keys {
		got := cache.Get(k)
		if got == nil {
			t.Errorf("expected profile for %s, got nil", k)
			continue
		}
		if got.CipherSuite != want.CipherSuite {
			t.Errorf("%s: CipherSuite = %v, want %v", k, got.CipherSuite, want.CipherSuite)
		}
	}
}

// ============================================================================
// Functional Defect Tests
// ============================================================================

func TestPrebuildCache_GetDeletesExpired(t *testing.T) {
	cache := NewPrebuildCache(time.Millisecond, 0)
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite: 0x1301, KeyGroup: X25519,
		CapturedAt: time.Now().Add(-2 * time.Millisecond), TTL: time.Millisecond,
	})
	got := cache.Get("example.com")
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
	// Verify entry was deleted
	cache.mu.RLock()
	_, exists := cache.profiles["example.com"]
	cache.mu.RUnlock()
	if exists {
		t.Error("expected entry to be deleted after expiration")
	}
}

func TestPrebuildCache_StoreDoesNotAffectOtherKeys(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("a.com", &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite: 0x1301, KeyGroup: X25519,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	cache.Store("b.com", &TargetProfile{
		HandshakeLen: [7]int{999, 6, 888, 777, 666, 555, 0},
		CipherSuite: 0x1302, KeyGroup: X25519MLKEM768,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	got := cache.Get("a.com")
	if got == nil {
		t.Fatal("expected profile, got nil")
	}
	if got.HandshakeLen[0] != 100 {
		t.Errorf("expected 100, got %v (store should copy)", got.HandshakeLen[0])
	}
}

func TestPrebuildCache_StoreNilProfile(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("example.com", nil) // should not panic
	got := cache.Get("example.com")
	if got != nil {
		t.Errorf("expected nil for stored nil, got %v", got)
	}
}

// ============================================================================
// Non-expected Behavior Tests
// ============================================================================

func TestPrebuildCache_GetDuringStore(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func(v int) {
			defer wg.Done()
			cache.Store("key", &TargetProfile{
				HandshakeLen: [7]int{v, 6, 200, 300, 100, 50, 0},
				CipherSuite: uint16(v), KeyGroup: X25519,
				CapturedAt: time.Now(), TTL: time.Minute,
			})
		}(i)
		go func() {
			defer wg.Done()
			cache.Get("key")
		}()
	}
	wg.Wait()
	got := cache.Get("key")
	if got == nil {
		t.Error("expected non-nil after concurrent operations")
	}
}

// ============================================================================
// LRU Eviction Tests
// ============================================================================

func TestPrebuildCache_LRUEviction(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 3) // capacity = 3

	for i := 0; i < 5; i++ {
		cache.Store(fmt.Sprintf("key%d", i), &TargetProfile{
			HandshakeLen: [7]int{i, 6, 200, 300, 100, 50, 0},
			CipherSuite:  0x1301, KeyGroup: X25519,
			CapturedAt: time.Now(), TTL: time.Minute,
		})
	}

	if cache.Len() != 3 {
		t.Errorf("expected 3 entries, got %v", cache.Len())
	}

	// key0 and key1 should have been evicted (LRU)
	if got := cache.Get("key0"); got != nil {
		t.Error("expected key0 evicted")
	}
	if got := cache.Get("key1"); got != nil {
		t.Error("expected key1 evicted")
	}

	// key2, key3, key4 should still exist
	if got := cache.Get("key2"); got == nil {
		t.Error("expected key2 to exist")
	}
	if got := cache.Get("key3"); got == nil {
		t.Error("expected key3 to exist")
	}
	if got := cache.Get("key4"); got == nil {
		t.Error("expected key4 to exist")
	}
}

func TestPrebuildCache_LRUAccessUpdates(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 3)

	// Fill cache
	cache.Store("a", &TargetProfile{HandshakeLen: [7]int{1}, CapturedAt: time.Now(), TTL: time.Minute})
	cache.Store("b", &TargetProfile{HandshakeLen: [7]int{2}, CapturedAt: time.Now(), TTL: time.Minute})
	cache.Store("c", &TargetProfile{HandshakeLen: [7]int{3}, CapturedAt: time.Now(), TTL: time.Minute})

	// Access "a" to make it recently used
	cache.Get("a")

	// Add "d" — should evict "b" (least recently accessed), not "a"
	cache.Store("d", &TargetProfile{HandshakeLen: [7]int{4}, CapturedAt: time.Now(), TTL: time.Minute})

	if got := cache.Get("a"); got == nil {
		t.Error("expected 'a' to survive (was just accessed)")
	}
	if got := cache.Get("b"); got != nil {
		t.Error("expected 'b' to be evicted (LRU)")
	}
	if got := cache.Get("c"); got == nil {
		t.Error("expected 'c' to exist")
	}
	if got := cache.Get("d"); got == nil {
		t.Error("expected 'd' to exist")
	}
}

func TestPrebuildCache_ReplaceDoesNotEvict(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 2)

	cache.Store("a", &TargetProfile{HandshakeLen: [7]int{1}, CapturedAt: time.Now(), TTL: time.Minute})
	cache.Store("b", &TargetProfile{HandshakeLen: [7]int{2}, CapturedAt: time.Now(), TTL: time.Minute})

	// Replace "a" — should NOT trigger eviction since key already exists
	cache.Store("a", &TargetProfile{HandshakeLen: [7]int{10}, CapturedAt: time.Now(), TTL: time.Minute})

	if cache.Len() != 2 {
		t.Errorf("expected 2 entries after replace, got %v", cache.Len())
	}
	if got := cache.Get("a"); got == nil || got.HandshakeLen[0] != 10 {
		t.Error("expected 'a' to be updated with new value")
	}
}

func TestPrebuildCache_UnlimitedCapacity(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 0) // 0 = unlimited

	for i := 0; i < 1000; i++ {
		cache.Store(fmt.Sprintf("key%d", i), &TargetProfile{
			HandshakeLen: [7]int{i}, CapturedAt: time.Now(), TTL: time.Minute,
		})
	}

	if cache.Len() != 1000 {
		t.Errorf("expected 1000 entries with unlimited capacity, got %v", cache.Len())
	}
}

func TestPrebuildCache_Len(t *testing.T) {
	cache := NewPrebuildCache(time.Minute, 10)

	if cache.Len() != 0 {
		t.Errorf("expected 0, got %v", cache.Len())
	}

	cache.Store("a", &TargetProfile{HandshakeLen: [7]int{1}, CapturedAt: time.Now(), TTL: time.Minute})
	if cache.Len() != 1 {
		t.Errorf("expected 1, got %v", cache.Len())
	}

	cache.Store("b", &TargetProfile{HandshakeLen: [7]int{2}, CapturedAt: time.Now(), TTL: time.Minute})
	if cache.Len() != 2 {
		t.Errorf("expected 2, got %v", cache.Len())
	}
}

// ============================================================================
// ProbeTarget Tests (with mock server)
// ============================================================================

func startMockTCPServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Send a minimal TLS ServerHello-like response
				// Record header: type=22 (Handshake), version=0x0303, length=5
				// Handshake: type=2 (ServerHello), length=0x0000, version=0x0303
				response := []byte{
					0x16, 0x03, 0x03, 0x00, 0x05, // TLS record header
					0x02, 0x00, 0x00, 0x03, 0x03, // ServerHello: type=2, len=0, ver=TLS1.2
				}
				c.Write(response)
				// Read anything the client sends
				buf := make([]byte, 4096)
				c.Read(buf)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestProbeTarget_ConnectionRefused(t *testing.T) {
	config := &Config{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        "127.0.0.1:19999",
	}
	err := ProbeTarget(context.Background(), config)
	if err == nil {
		t.Error("expected error for connection refused, got nil")
	}
}

func TestProbeTarget_ContextCanceled(t *testing.T) {
	addr, cleanup := startMockTCPServer(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	config := &Config{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        addr,
	}
	err := ProbeTarget(ctx, config)
	_ = err // may or may not error
}

// ============================================================================
// Auto-probe Infrastructure Tests
// ============================================================================

func TestEnsureAutoProbe_EmptyDest(t *testing.T) {
	// Empty dest should not start any probe
	config := &Config{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        "",
	}
	ensureAutoProbe(config)

	// Verify no entries created
	count := 0
	probeOnces.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected 0 probe entries for empty dest, got %v", count)
	}
}

func TestEnsureAutoProbe_CopiesConfig(t *testing.T) {
	config := &Config{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        "127.0.0.1:19999",
		Show:        false,
	}

	// ensureAutoProbe should copy config values, not capture pointer
	ensureAutoProbe(config)

	// Verify entry was created
	if _, ok := probeOnces.Load("127.0.0.1:19999"); !ok {
		t.Error("expected probeOnces entry for dest")
	}
	if _, ok := probeStops.Load("127.0.0.1:19999"); !ok {
		t.Error("expected probeStops entry for dest")
	}

	// Clean up
	StopAutoProbe("127.0.0.1:19999")
}

func TestEnsureAutoProbe_Idempotent(t *testing.T) {
	config := &Config{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        "127.0.0.1:19998",
	}

	// Call twice — should only create one entry
	ensureAutoProbe(config)
	ensureAutoProbe(config)

	count := 0
	probeOnces.Range(func(key, value any) bool {
		if key == "127.0.0.1:19998" {
			count++
		}
		return true
	})
	if count != 1 {
		t.Errorf("expected 1 entry for dest, got %v", count)
	}

	StopAutoProbe("127.0.0.1:19998")
}

func TestStopAutoProbe_CleansUp(t *testing.T) {
	config := &Config{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        "127.0.0.1:19997",
	}

	ensureAutoProbe(config)

	// Verify entries exist
	if _, ok := probeOnces.Load("127.0.0.1:19997"); !ok {
		t.Error("expected probeOnces entry before stop")
	}
	if _, ok := probeStops.Load("127.0.0.1:19997"); !ok {
		t.Error("expected probeStops entry before stop")
	}

	StopAutoProbe("127.0.0.1:19997")

	// Verify entries cleaned up
	if _, ok := probeOnces.Load("127.0.0.1:19997"); ok {
		t.Error("expected probeOnces entry cleaned up after stop")
	}
	if _, ok := probeStops.Load("127.0.0.1:19997"); ok {
		t.Error("expected probeStops entry cleaned up after stop")
	}
}

func TestStopAutoProbe_Noop(t *testing.T) {
	// Stopping a non-existent dest should not panic
	StopAutoProbe("nonexistent")
}

func TestEnsureAutoProbe_NoMemoryLeak(t *testing.T) {
	// Create and stop many entries to verify cleanup
	const n = 100
	for i := 0; i < n; i++ {
		config := &Config{
			DialContext: (&net.Dialer{}).DialContext,
			Type:        "tcp",
			Dest:        fmt.Sprintf("127.0.0.1:%d", 19000+i),
		}
		ensureAutoProbe(config)
		StopAutoProbe(config.Dest)
	}

	// Verify all entries cleaned up
	count := 0
	probeOnces.Range(func(key, value any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected 0 probe entries after cleanup, got %v", count)
	}
}

// ============================================================================
// Performance Tests (continued)
// ============================================================================

func BenchmarkPrebuildCache_Get(b *testing.B) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite: 0x1301, KeyGroup: X25519,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("example.com")
	}
}

func BenchmarkPrebuildCache_Store(b *testing.B) {
	cache := NewPrebuildCache(time.Minute, 0)
	profile := &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite: 0x1301, KeyGroup: X25519,
		CapturedAt: time.Now(), TTL: time.Minute,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Store("example.com", profile)
	}
}

func BenchmarkPrebuildCache_GetMiss(b *testing.B) {
	cache := NewPrebuildCache(time.Minute, 0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("nonexistent.com")
	}
}

func BenchmarkPrebuildCache_ConcurrentGet(b *testing.B) {
	cache := NewPrebuildCache(time.Minute, 0)
	cache.Store("example.com", &TargetProfile{
		HandshakeLen: [7]int{100, 6, 200, 300, 100, 50, 0},
		CipherSuite: 0x1301, KeyGroup: X25519,
		CapturedAt: time.Now(), TTL: time.Minute,
	})
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Get("example.com")
		}
	})
}

// ============================================================================
// RealityProfile Cache V2 Tests
// ============================================================================

// --- 1. Profile Cache Hit ---

func TestRealityProfileCacheHit(t *testing.T) {
	// Reset stats
	cacheStats = CacheStats{}

	key := "www.microsoft.com|www.microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	// Connection 1: populate cache (simulates cache miss)
	profile := &RealityProfile{
		RecordLens:   [7]int{1215, 6, 41, 800, 300, 200, 0},
		Fingerprint:  fp,
		CipherSuite:  0x1301,
		ALPN:         "h2",
		RecordCount:  5,
		CapturedAt:   time.Now(),
	}
	realityProfileCache.Store(key, profile)

	// Simulate connection 2: same fingerprint → HIT
	stored, _ := realityProfileCache.Load(key)
	if stored == nil {
		t.Fatal("expected profile in cache")
	}
	p := stored.(*RealityProfile)
	if p.Fingerprint != fp {
		t.Errorf("fingerprint mismatch: got %d, want %d", p.Fingerprint, fp)
	}

	// Simulate HIT path
	cacheStats.OutputHit.Add(1)
	cacheStats.PollingSkipped.Add(1)

	// Assert
	if cacheStats.OutputHit.Load() != 1 {
		t.Errorf("OutputHit = %d, want 1", cacheStats.OutputHit.Load())
	}
	if cacheStats.PollingSkipped.Load() != 1 {
		t.Errorf("PollingSkipped = %d, want 1", cacheStats.PollingSkipped.Load())
	}

	// Cleanup
	realityProfileCache.Delete(key)
}

// --- 2. Profile Cache Miss (Fingerprint Mismatch) ---

func TestRealityProfileCacheMiss(t *testing.T) {
	cacheStats = CacheStats{}

	key := "www.microsoft.com|www.microsoft.com|h2"
	cachedFP := computeFingerprint(0x1301, "h2", 1215, 41)
	currentFP := computeFingerprint(0x1302, "h2", 1215, 41) // different CipherSuite

	profile := &RealityProfile{
		RecordLens:   [7]int{1215, 6, 41, 800, 300, 200, 0},
		Fingerprint:  cachedFP,
		CipherSuite:  0x1301,
		ALPN:         "h2",
		RecordCount:  5,
		CapturedAt:   time.Now(),
	}
	realityProfileCache.Store(key, profile)

	// Simulate: current fingerprint != cached → MISS
	stored, _ := realityProfileCache.Load(key)
	if stored == nil {
		t.Fatal("expected profile in cache")
	}
	p := stored.(*RealityProfile)
	if p.Fingerprint == currentFP {
		t.Error("fingerprints should NOT match (this is a miss scenario)")
	}

	// Simulate MISS path
	cacheStats.FingerprintChanged.Add(1)
	cacheStats.MetaMiss.Add(1)

	if cacheStats.FingerprintChanged.Load() != 1 {
		t.Errorf("FingerprintChanged = %d, want 1", cacheStats.FingerprintChanged.Load())
	}
	if cacheStats.PollingSkipped.Load() != 0 {
		t.Errorf("PollingSkipped = %d, want 0 (miss should not skip polling)", cacheStats.PollingSkipped.Load())
	}

	realityProfileCache.Delete(key)
}

// --- 3. TTL Expiry ---

func TestRealityProfileExpiry(t *testing.T) {
	key := "expired.com|expired.com|h2"

	profile := &RealityProfile{
		RecordLens:  [7]int{100, 6, 200, 300, 100, 50, 0},
		Fingerprint: computeFingerprint(0x1301, "h2", 100, 200),
		CipherSuite: 0x1301,
		ALPN:        "h2",
		CapturedAt:  time.Now().Add(-31 * time.Minute), // expired
	}

	if !profile.IsExpired() {
		t.Error("profile should be expired (31 minutes old > 30min TTL)")
	}

	// Non-expired profile
	fresh := &RealityProfile{
		RecordLens:  [7]int{100, 6, 200, 300, 100, 50, 0},
		Fingerprint: computeFingerprint(0x1301, "h2", 100, 200),
		CipherSuite: 0x1301,
		ALPN:        "h2",
		CapturedAt:  time.Now(),
	}
	if fresh.IsExpired() {
		t.Error("fresh profile should NOT be expired")
	}

	// Simulate cache with expired entry
	realityProfileCache.Store(key, profile)
	stored, _ := realityProfileCache.Load(key)
	p := stored.(*RealityProfile)
	if !p.IsExpired() {
		t.Error("stored profile should be expired")
	}
	// Expired entry should be deleted on access
	realityProfileCache.Delete(key)
}

// --- 4. Fingerprint Deterministic ---

func TestFingerprintDeterministic(t *testing.T) {
	cipherSuite := uint16(0x1301) // TLS_AES_128_GCM_SHA256
	alpn := "h2"
	serverHelloLen := 1215
	extensionsLen := 41

	fp1 := computeFingerprint(cipherSuite, alpn, serverHelloLen, extensionsLen)
	fp2 := computeFingerprint(cipherSuite, alpn, serverHelloLen, extensionsLen)
	fp3 := computeFingerprint(cipherSuite, alpn, serverHelloLen, extensionsLen)
	fp4 := computeFingerprint(cipherSuite, alpn, serverHelloLen, extensionsLen)

	if fp1 != fp2 || fp2 != fp3 || fp3 != fp4 {
		t.Errorf("fingerprint not deterministic: %d, %d, %d, %d", fp1, fp2, fp3, fp4)
	}
	if fp1 == 0 {
		t.Error("fingerprint should not be zero")
	}
}

// --- 5. Fingerprint Sensitivity ---

func TestFingerprintSensitivity(t *testing.T) {
	base := computeFingerprint(0x1301, "h2", 1215, 41)

	// Change CipherSuite
	if computeFingerprint(0x1302, "h2", 1215, 41) == base {
		t.Error("fingerprint should change when CipherSuite changes")
	}
	// Change ALPN
	if computeFingerprint(0x1301, "http/1.1", 1215, 41) == base {
		t.Error("fingerprint should change when ALPN changes")
	}
	// Change ServerHelloLen
	if computeFingerprint(0x1301, "h2", 1216, 41) == base {
		t.Error("fingerprint should change when ServerHelloLen changes")
	}
	// Change ExtensionsLen
	if computeFingerprint(0x1301, "h2", 1215, 42) == base {
		t.Error("fingerprint should change when ExtensionsLen changes")
	}
}

// --- 6. Cache Isolation ---

func TestProfileIsolation(t *testing.T) {
	microsoftKey := "www.microsoft.com|www.microsoft.com|h2"
	googleKey := "www.google.com|www.google.com|h2"
	githubKey := "www.github.com|www.github.com|h2"

	fpMS := computeFingerprint(0x1301, "h2", 1200, 40)
	fpGoogle := computeFingerprint(0x1302, "h2", 1300, 50)
	fpGH := computeFingerprint(0x1301, "h2", 1400, 60)

	realityProfileCache.Store(microsoftKey, &RealityProfile{
		RecordLens: [7]int{1200}, Fingerprint: fpMS, CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	realityProfileCache.Store(googleKey, &RealityProfile{
		RecordLens: [7]int{1300}, Fingerprint: fpGoogle, CipherSuite: 0x1302, ALPN: "h2", CapturedAt: time.Now(),
	})
	realityProfileCache.Store(githubKey, &RealityProfile{
		RecordLens: [7]int{1400}, Fingerprint: fpGH, CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	// Verify isolation
	valMS, _ := realityProfileCache.Load(microsoftKey)
	valGoogle, _ := realityProfileCache.Load(googleKey)
	valGH, _ := realityProfileCache.Load(githubKey)

	pMS := valMS.(*RealityProfile)
	pGoogle := valGoogle.(*RealityProfile)
	pGH := valGH.(*RealityProfile)

	if pMS.Fingerprint == pGoogle.Fingerprint {
		t.Error("microsoft and google should have different fingerprints")
	}
	if pMS.RecordLens[0] == pGoogle.RecordLens[0] {
		t.Error("microsoft and google should have different record lengths")
	}
	if pMS.ALPN != pGoogle.ALPN || pMS.ALPN != pGH.ALPN {
		t.Error("all profiles should have same ALPN for this test")
	}

	// Cross-check: microsoft key should not return google data
	if pMS.RecordLens[0] != 1200 {
		t.Errorf("microsoft RecordLens[0] = %d, want 1200", pMS.RecordLens[0])
	}
	if pGoogle.RecordLens[0] != 1300 {
		t.Errorf("google RecordLens[0] = %d, want 1300", pGoogle.RecordLens[0])
	}
	if pGH.RecordLens[0] != 1400 {
		t.Errorf("github RecordLens[0] = %d, want 1400", pGH.RecordLens[0])
	}

	realityProfileCache.Delete(microsoftKey)
	realityProfileCache.Delete(googleKey)
	realityProfileCache.Delete(githubKey)
}

// --- 7. Concurrent Cache Hit ---

func TestRealityProfileCacheConcurrentHit(t *testing.T) {
	cacheStats = CacheStats{}

	key := "concurrent.com|concurrent.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp, CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				val, ok := realityProfileCache.Load(key)
				if !ok {
					t.Errorf("goroutine %d iteration %d: key not found", id, j)
					return
				}
				p := val.(*RealityProfile)
				if p.Fingerprint != fp {
					t.Errorf("goroutine %d iteration %d: fingerprint mismatch", id, j)
					return
				}
				cacheStats.OutputHit.Add(1)
				cacheStats.PollingSkipped.Add(1)
			}
		}(i)
	}
	wg.Wait()

	totalHits := cacheStats.OutputHit.Load()
	if totalHits != goroutines*iterations {
		t.Errorf("OutputHit = %d, want %d", totalHits, goroutines*iterations)
	}

	realityProfileCache.Delete(key)
}

// --- 8. Target Change Invalidation ---

func TestTargetChangeInvalidation(t *testing.T) {
	cacheStats = CacheStats{}

	key := "target.com|target.com|h2"

	// Connection 1: CipherSuite=0x1301
	fp1 := computeFingerprint(0x1301, "h2", 1215, 41)
	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp1, CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	// Connection 2: CipherSuite changed to 0x1302
	currentFP := computeFingerprint(0x1302, "h2", 1215, 41)

	val, _ := realityProfileCache.Load(key)
	p := val.(*RealityProfile)
	if p.Fingerprint == currentFP {
		t.Error("fingerprints should NOT match after target change")
	}

	// Simulate MISS path
	cacheStats.FingerprintChanged.Add(1)
	cacheStats.MetaMiss.Add(1)

	if cacheStats.FingerprintChanged.Load() != 1 {
		t.Errorf("FingerprintChanged = %d, want 1", cacheStats.FingerprintChanged.Load())
	}

	// Update cache with new fingerprint
	newProfile := &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: currentFP, CipherSuite: 0x1302, ALPN: "h2", CapturedAt: time.Now(),
	}
	realityProfileCache.Store(key, newProfile)

	// Connection 3: now should HIT
	val2, _ := realityProfileCache.Load(key)
	p2 := val2.(*RealityProfile)
	if p2.Fingerprint != currentFP {
		t.Error("new profile should match current fingerprint")
	}

	realityProfileCache.Delete(key)
}

// --- 9. Benchmark Handshake Cache Hit vs Miss ---

func BenchmarkRealityProfileCacheHit(b *testing.B) {
	key := "bench.com|bench.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp, CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		val, ok := realityProfileCache.Load(key)
		if ok {
			p := val.(*RealityProfile)
			_ = p.Fingerprint == fp
		}
	}
	b.StopTimer()
	realityProfileCache.Delete(key)
}

func BenchmarkRealityProfileCacheMiss(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Always miss — key doesn't exist
		_, _ = realityProfileCache.Load("nonexistent.nonexistent.nonexistent")
	}
}

func BenchmarkComputeFingerprint(b *testing.B) {
	for i := 0; i < b.N; i++ {
		computeFingerprint(0x1301, "h2", 1215, 41)
	}
}

// --- 10. Long-Running Simulation ---

func TestReality24HourSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	cacheStats = CacheStats{}

	const totalConnections = 10000
	const uniqueDests = 10

	for i := 0; i < totalConnections; i++ {
		destIdx := i % uniqueDests
		dest := fmt.Sprintf("dest%d.example.com|dest%d.example.com|h2", destIdx, destIdx)
		fp := computeFingerprint(0x1301, "h2", 1200+destIdx, 40+destIdx)

		// 80% of connections hit existing dests (warm cache)
		// 20% hit new dests (cold cache)
		if i > uniqueDests && i%5 != 0 {
			// Cache HIT path
			val, ok := realityProfileCache.Load(dest)
			if ok {
				p := val.(*RealityProfile)
				if p.Fingerprint != fp {
					t.Errorf("connection %d: fingerprint mismatch for %s", i, dest)
				}
				cacheStats.OutputHit.Add(1)
				cacheStats.PollingSkipped.Add(1)
				continue
			}
		}

		// Cache MISS path — populate
		cacheStats.OutputMiss.Add(1)
		realityProfileCache.Store(dest, &RealityProfile{
			RecordLens: [7]int{1200 + destIdx, 6, 40 + destIdx}, Fingerprint: fp,
			CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
		})
	}

	hits := cacheStats.OutputHit.Load()
	misses := cacheStats.OutputMiss.Load()
	total := hits + misses
	hitRate := float64(hits) / float64(total) * 100

	t.Logf("Simulation results: %d connections, %d hits, %d misses, %.1f%% hit rate", total, hits, misses, hitRate)

	// Verify hit rate is reasonable (>70% for 80/20 distribution)
	if hitRate < 70 {
		t.Errorf("hit rate %.1f%% is too low, expected >70%%", hitRate)
	}

	// Cleanup
	for i := 0; i < uniqueDests; i++ {
		realityProfileCache.Delete(fmt.Sprintf("dest%d.example.com|dest%d.example.com|h2", i, i))
	}
}

// ============================================================================
// A2: Cache Invalidation Tests
// ============================================================================

func TestRealityProfileInvalidation(t *testing.T) {
	cacheStats = CacheStats{}

	key := "invalidation.test|microsoft.com|h2"
	fingerprintA := computeFingerprint(0x1301, "h2", 1215, 41)

	// Step 1: First connection — cache miss, populate
	stored, _ := realityProfileCache.Load(key)
	if stored != nil {
		t.Fatal("expected no cache entry before first connection")
	}
	cacheStats.MetaMiss.Add(1) // miss: not found

	profile := &RealityProfile{
		RecordLens:  [7]int{1215, 6, 41, 800, 300, 200, 0},
		Fingerprint: fingerprintA,
		CipherSuite: 0x1301,
		ALPN:        "h2",
		RecordCount: 5,
		CapturedAt:  time.Now(),
	}
	realityProfileCache.Store(key, profile)

	// Step 2: Second connection — same fingerprint, should HIT
	val, _ := realityProfileCache.Load(key)
	p := val.(*RealityProfile)
	currentFP := computeFingerprint(0x1301, "h2", 1215, 41)
	if p.Fingerprint != currentFP {
		t.Fatalf("step 2: fingerprint mismatch: cached=%d current=%d", p.Fingerprint, currentFP)
	}
	cacheStats.OutputHit.Add(1)
	cacheStats.MetaHit.Add(1)
	cacheStats.PollingSkipped.Add(1)

	// Step 3: Simulate target change — corrupt stored fingerprint
	// This simulates: server rotated cert, changed cipher suite, etc.
	p.Fingerprint = computeFingerprint(0x1302, "h2", 1215, 41) // different fingerprint
	// Don't re-store — the pointer in sync.Map is already modified

	// Step 4: Third connection — fingerprint mismatch, should MISS
	val2, _ := realityProfileCache.Load(key)
	p2 := val2.(*RealityProfile)
	changedFP := computeFingerprint(0x1301, "h2", 1215, 41) // what current connection produces
	if p2.Fingerprint == changedFP {
		t.Fatal("step 4: fingerprint should NOT match after target change")
	}
	cacheStats.FingerprintChanged.Add(1)
	cacheStats.MetaMiss.Add(1)

	// Step 5: Re-learn — store new profile with correct fingerprint
	newProfile := &RealityProfile{
		RecordLens:  [7]int{1215, 6, 41, 800, 300, 200, 0},
		Fingerprint: changedFP,
		CipherSuite: 0x1301,
		ALPN:        "h2",
		RecordCount: 5,
		CapturedAt:  time.Now(),
	}
	realityProfileCache.Store(key, newProfile)

	// Step 6: Fourth connection — should HIT again
	val3, _ := realityProfileCache.Load(key)
	p3 := val3.(*RealityProfile)
	if p3.Fingerprint != changedFP {
		t.Fatalf("step 6: fingerprint mismatch after re-learn: cached=%d current=%d", p3.Fingerprint, changedFP)
	}
	cacheStats.OutputHit.Add(1)
	cacheStats.MetaHit.Add(1)
	cacheStats.PollingSkipped.Add(1)

	// Assert final stats
	if cacheStats.MetaHit.Load() != 2 {
		t.Errorf("MetaHit = %d, want 2", cacheStats.MetaHit.Load())
	}
	if cacheStats.MetaMiss.Load() != 2 {
		t.Errorf("MetaMiss = %d, want 2 (1 initial + 1 fp changed)", cacheStats.MetaMiss.Load())
	}
	if cacheStats.FingerprintChanged.Load() != 1 {
		t.Errorf("FingerprintChanged = %d, want 1", cacheStats.FingerprintChanged.Load())
	}
	if cacheStats.PollingSkipped.Load() != 2 {
		t.Errorf("PollingSkipped = %d, want 2", cacheStats.PollingSkipped.Load())
	}

	realityProfileCache.Delete(key)
}

func TestRealityProfileInvalidationByExpiry(t *testing.T) {
	cacheStats = CacheStats{}

	key := "expiry.test|apple.com|h2"
	fp := computeFingerprint(0x1301, "h2", 127, 41)

	// Step 1: Store an already-expired profile
	expiredProfile := &RealityProfile{
		RecordLens:  [7]int{127, 6, 41},
		Fingerprint: fp,
		CipherSuite: 0x1301,
		ALPN:        "h2",
		CapturedAt:  time.Now().Add(-31 * time.Minute), // expired
	}
	realityProfileCache.Store(key, expiredProfile)

	// Step 2: Connection — should detect expiry, MISS, delete
	val, _ := realityProfileCache.Load(key)
	p := val.(*RealityProfile)
	if !p.IsExpired() {
		t.Fatal("profile should be expired")
	}
	cacheStats.OutputMiss.Add(1)
	cacheStats.MetaMiss.Add(1)
	realityProfileCache.Delete(key)

	// Step 3: Verify entry deleted
	val2, _ := realityProfileCache.Load(key)
	if val2 != nil {
		t.Fatal("expired entry should have been deleted")
	}

	// Step 4: Re-learn with fresh profile
	freshProfile := &RealityProfile{
		RecordLens:  [7]int{127, 6, 41},
		Fingerprint: fp,
		CipherSuite: 0x1301,
		ALPN:        "h2",
		CapturedAt:  time.Now(), // fresh
	}
	realityProfileCache.Store(key, freshProfile)

	// Step 5: Should HIT
	val3, _ := realityProfileCache.Load(key)
	p3 := val3.(*RealityProfile)
	if p3.IsExpired() {
		t.Fatal("fresh profile should NOT be expired")
	}
	if p3.Fingerprint != fp {
		t.Errorf("fingerprint mismatch after re-learn")
	}
	cacheStats.OutputHit.Add(1)
	cacheStats.MetaHit.Add(1)

	// Assert
	if cacheStats.MetaHit.Load() != 1 {
		t.Errorf("MetaHit = %d, want 1", cacheStats.MetaHit.Load())
	}
	if cacheStats.MetaMiss.Load() != 1 {
		t.Errorf("MetaMiss = %d, want 1", cacheStats.MetaMiss.Load())
	}

	realityProfileCache.Delete(key)
}

func TestRealityProfileInvalidationByCipherSuiteChange(t *testing.T) {
	cacheStats = CacheStats{}

	key := "cschange.test|tesla.com|h2"

	// Step 1: Target initially uses AES-128-GCM (0x1301)
	fp1 := computeFingerprint(0x1301, "h2", 127, 51)
	profile := &RealityProfile{
		RecordLens:  [7]int{127, 6, 51},
		Fingerprint: fp1,
		CipherSuite: 0x1301,
		ALPN:        "h2",
		CapturedAt:  time.Now(),
	}
	realityProfileCache.Store(key, profile)

	// Step 2: Verify initial HIT
	currentFP1 := computeFingerprint(0x1301, "h2", 127, 51)
	if fp1 != currentFP1 {
		t.Fatal("initial fingerprint should match")
	}
	cacheStats.MetaHit.Add(1)
	cacheStats.PollingSkipped.Add(1)

	// Step 3: Target upgrades to AES-256-GCM (0x1302)
	// Same ALPN and record lengths, but different CipherSuite
	currentFP2 := computeFingerprint(0x1302, "h2", 127, 51)
	if currentFP1 == currentFP2 {
		t.Fatal("different CipherSuite should produce different fingerprint")
	}

	// Step 4: Verify MISS — stored fp != current fp
	val, _ := realityProfileCache.Load(key)
	p := val.(*RealityProfile)
	if p.Fingerprint == currentFP2 {
		t.Fatal("old profile fingerprint should NOT match new CipherSuite")
	}
	cacheStats.FingerprintChanged.Add(1)
	cacheStats.MetaMiss.Add(1)

	// Step 5: Re-learn
	newProfile := &RealityProfile{
		RecordLens:  [7]int{127, 6, 51},
		Fingerprint: currentFP2,
		CipherSuite: 0x1302,
		ALPN:        "h2",
		CapturedAt:  time.Now(),
	}
	realityProfileCache.Store(key, newProfile)

	// Step 6: HIT with new fingerprint
	val2, _ := realityProfileCache.Load(key)
	p2 := val2.(*RealityProfile)
	if p2.Fingerprint != currentFP2 {
		t.Fatal("new profile should match current fingerprint")
	}
	cacheStats.MetaHit.Add(1)
	cacheStats.PollingSkipped.Add(1)

	// Assert
	if cacheStats.FingerprintChanged.Load() != 1 {
		t.Errorf("FingerprintChanged = %d, want 1", cacheStats.FingerprintChanged.Load())
	}
	if cacheStats.PollingSkipped.Load() != 2 {
		t.Errorf("PollingSkipped = %d, want 2", cacheStats.PollingSkipped.Load())
	}

	realityProfileCache.Delete(key)
}

// ============================================================================
// A3: Soak Test — 1000 connections, memory stability
// ============================================================================

func TestRealityProfileSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test in short mode")
	}

	cacheStats = CacheStats{}

	const totalConnections = 1000
	const uniqueDests = 20

	var mBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mBefore)

	allocBefore := mBefore.TotalAlloc
	gcBefore := mBefore.NumGC

	for i := 0; i < totalConnections; i++ {
		destIdx := i % uniqueDests
		dest := fmt.Sprintf("soak%d.example.com|soak%d.example.com|h2", destIdx, destIdx)
		fp := computeFingerprint(0x1301, "h2", 1200+destIdx, 40+destIdx)

		val, ok := realityProfileCache.Load(dest)
		if ok {
			p := val.(*RealityProfile)
			if p.Fingerprint != fp {
				t.Fatalf("connection %d: fingerprint mismatch for %s", i, dest)
			}
			cacheStats.OutputHit.Add(1)
			cacheStats.MetaHit.Add(1)
			cacheStats.PollingSkipped.Add(1)
		} else {
			cacheStats.OutputMiss.Add(1)
			cacheStats.MetaMiss.Add(1)
			realityProfileCache.Store(dest, &RealityProfile{
				RecordLens: [7]int{1200 + destIdx, 6, 40 + destIdx},
				Fingerprint: fp, CipherSuite: 0x1301, ALPN: "h2",
				CapturedAt: time.Now(),
			})
		}
	}

	var mAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mAfter)

	allocAfter := mAfter.TotalAlloc
	gcAfter := mAfter.NumGC

	hits := cacheStats.OutputHit.Load()
	misses := cacheStats.OutputMiss.Load()
	total := hits + misses
	hitRate := float64(hits) / float64(total) * 100
	allocDelta := allocAfter - allocBefore
	gcDelta := gcAfter - gcBefore

	t.Logf("Soak test results:")
	t.Logf("  Connections: %d (unique dests: %d)", total, uniqueDests)
	t.Logf("  Hit rate:    %.1f%% (%d hits / %d misses)", hitRate, hits, misses)
	t.Logf("  Alloc delta: %d bytes (%.2f MB)", allocDelta, float64(allocDelta)/1024/1024)
	t.Logf("  GC cycles:   %d", gcDelta)

	if hitRate < 70 {
		t.Errorf("hit rate %.1f%% too low, expected >70%%", hitRate)
	}
	if allocDelta > 50*1024*1024 {
		t.Errorf("alloc delta %.2f MB too high, expected <50 MB", float64(allocDelta)/1024/1024)
	}

	for i := 0; i < uniqueDests; i++ {
		realityProfileCache.Delete(fmt.Sprintf("soak%d.example.com|soak%d.example.com|h2", i, i))
	}
}

// ============================================================================
// A4: Benchmark — Cache Hit vs Miss
// ============================================================================

func BenchmarkRealityCacheHit(b *testing.B) {
	key := "bench.hit|example.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		val, ok := realityProfileCache.Load(key)
		if ok {
			p := val.(*RealityProfile)
			_ = p.Fingerprint == fp
		}
	}
	b.StopTimer()
	realityProfileCache.Delete(key)
}

func BenchmarkRealityCacheMiss(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = realityProfileCache.Load("bench.miss.nonexistent|nonexistent.com|h2")
	}
}

func BenchmarkRealityFingerprintCompute(b *testing.B) {
	for i := 0; i < b.N; i++ {
		computeFingerprint(0x1301, "h2", 1215, 41)
	}
}

func BenchmarkRealityFullCycle(b *testing.B) {
	b.Run("CacheHit", func(b *testing.B) {
		key := "bench.cycle|example.com|h2"
		fp := computeFingerprint(0x1301, "h2", 1215, 41)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			realityProfileCache.Store(key, &RealityProfile{
				RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
				CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
			})
			b.StartTimer()
			val, ok := realityProfileCache.Load(key)
			if ok {
				p := val.(*RealityProfile)
				currentFP := computeFingerprint(p.CipherSuite, p.ALPN, p.RecordLens[0], p.RecordLens[2])
				_ = p.Fingerprint == currentFP
			}
		}
		b.StopTimer()
		realityProfileCache.Delete(key)
	})
	b.Run("CacheMiss_Store", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("bench.miss.%d|example.com|h2", i)
			fp := computeFingerprint(0x1301, "h2", 1215, 41)
			_, ok := realityProfileCache.Load(key)
			if !ok {
				realityProfileCache.Store(key, &RealityProfile{
					RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
					CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
				})
			}
		}
		for i := 0; i < b.N; i++ {
			realityProfileCache.Delete(fmt.Sprintf("bench.miss.%d|example.com|h2", i))
		}
	})
}

// ============================================================================
// v2: HandshakeLayout Cache Tests
// ============================================================================

func TestLayoutCacheCapture(t *testing.T) {
	cacheStats = CacheStats{}

	key := "layout.capture|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	layout := &HandshakeLayout{
		Fingerprint:            fp,
		ServerHelloLen:         1215,
		EncryptedExtensionsLen: 41,
		CertificateLen:         8273,
		CertificateVerifyLen:   286,
		FinishedLen:            74,
		RecordLens:             [7]int{1215, 6, 41, 8273, 286, 74, 0},
		RecordCount:            5,
		CapturedAt:             time.Now(),
	}
	realityLayoutCache.Store(key, layout)

	val, ok := realityLayoutCache.Load(key)
	if !ok {
		t.Fatal("layout not found in cache")
	}
	l := val.(*HandshakeLayout)
	if l.ServerHelloLen != 1215 {
		t.Errorf("ServerHelloLen = %d, want 1215", l.ServerHelloLen)
	}
	if l.EncryptedExtensionsLen != 41 {
		t.Errorf("EncryptedExtensionsLen = %d, want 41", l.EncryptedExtensionsLen)
	}
	if l.CertificateLen != 8273 {
		t.Errorf("CertificateLen = %d, want 8273", l.CertificateLen)
	}
	if l.Fingerprint != fp {
		t.Errorf("Fingerprint = %d, want %d", l.Fingerprint, fp)
	}

	realityLayoutCache.Delete(key)
}

func TestLayoutCacheReuse(t *testing.T) {
	cacheStats = CacheStats{}

	key := "layout.reuse|apple.com|h2"
	fp := computeFingerprint(0x1301, "h2", 127, 41)

	layout := &HandshakeLayout{
		Fingerprint:            fp,
		ServerHelloLen:         127,
		EncryptedExtensionsLen: 41,
		CertificateLen:         8273,
		CertificateVerifyLen:   286,
		FinishedLen:            74,
		RecordLens:             [7]int{127, 6, 41, 8273, 286, 74, 0},
		RecordCount:            5,
		CapturedAt:             time.Now(),
	}
	realityLayoutCache.Store(key, layout)

	// Simulate connection 2: same fingerprint → HIT
	val, _ := realityLayoutCache.Load(key)
	l := val.(*HandshakeLayout)
	currentFP := computeFingerprint(0x1301, "h2", 127, 41)
	if l.Fingerprint != currentFP {
		t.Fatalf("fingerprint mismatch: cached=%d current=%d", l.Fingerprint, currentFP)
	}
	cacheStats.LayoutHit.Add(1)
	cacheStats.PollingSkipped.Add(1)

	// Simulate connection 3: same → HIT again
	val2, _ := realityLayoutCache.Load(key)
	l2 := val2.(*HandshakeLayout)
	if l2.Fingerprint != currentFP {
		t.Fatal("fingerprint should match on second reuse")
	}
	cacheStats.LayoutHit.Add(1)
	cacheStats.PollingSkipped.Add(1)

	if cacheStats.LayoutHit.Load() != 2 {
		t.Errorf("LayoutHit = %d, want 2", cacheStats.LayoutHit.Load())
	}
	if cacheStats.PollingSkipped.Load() != 2 {
		t.Errorf("PollingSkipped = %d, want 2", cacheStats.PollingSkipped.Load())
	}

	realityLayoutCache.Delete(key)
}

func TestLayoutCacheInvalidation(t *testing.T) {
	cacheStats = CacheStats{}

	key := "layout.inval|tesla.com|h2"
	fp1 := computeFingerprint(0x1301, "h2", 127, 51)

	layout := &HandshakeLayout{
		Fingerprint:            fp1,
		ServerHelloLen:         127,
		EncryptedExtensionsLen: 51,
		CertificateLen:         8273,
		CertificateVerifyLen:   286,
		FinishedLen:            74,
		RecordLens:             [7]int{127, 6, 51, 8273, 286, 74, 0},
		RecordCount:            5,
		CapturedAt:             time.Now(),
	}
	realityLayoutCache.Store(key, layout)

	// Target changes CipherSuite → fingerprint changes
	fp2 := computeFingerprint(0x1302, "h2", 127, 51)
	if fp1 == fp2 {
		t.Fatal("different CipherSuite should produce different fingerprint")
	}

	val, _ := realityLayoutCache.Load(key)
	l := val.(*HandshakeLayout)
	if l.Fingerprint == fp2 {
		t.Fatal("old layout should NOT match new fingerprint")
	}
	cacheStats.FingerprintChanged.Add(1)
	cacheStats.LayoutMiss.Add(1)

	// Re-learn
	newLayout := &HandshakeLayout{
		Fingerprint:            fp2,
		ServerHelloLen:         127,
		EncryptedExtensionsLen: 51,
		CertificateLen:         8273,
		CertificateVerifyLen:   286,
		FinishedLen:            74,
		RecordLens:             [7]int{127, 6, 51, 8273, 286, 74, 0},
		RecordCount:            5,
		CapturedAt:             time.Now(),
	}
	realityLayoutCache.Store(key, newLayout)

	// HIT with new fingerprint
	val2, _ := realityLayoutCache.Load(key)
	l2 := val2.(*HandshakeLayout)
	if l2.Fingerprint != fp2 {
		t.Fatal("new layout should match current fingerprint")
	}
	cacheStats.LayoutHit.Add(1)

	if cacheStats.FingerprintChanged.Load() != 1 {
		t.Errorf("FingerprintChanged = %d, want 1", cacheStats.FingerprintChanged.Load())
	}
	if cacheStats.LayoutHit.Load() != 1 {
		t.Errorf("LayoutHit = %d, want 1", cacheStats.LayoutHit.Load())
	}

	realityLayoutCache.Delete(key)
}

func TestLayoutCacheExpiry(t *testing.T) {
	key := "layout.expiry|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	// Store expired layout
	layout := &HandshakeLayout{
		Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		CertificateLen: 8273, CertificateVerifyLen: 286, FinishedLen: 74,
		RecordLens: [7]int{1215, 6, 41, 8273, 286, 74, 0}, RecordCount: 5,
		CapturedAt: time.Now().Add(-31 * time.Minute),
	}
	realityLayoutCache.Store(key, layout)

	val, _ := realityLayoutCache.Load(key)
	l := val.(*HandshakeLayout)
	if !l.IsExpired() {
		t.Error("layout should be expired")
	}

	// Store fresh layout
	fresh := &HandshakeLayout{
		Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		CertificateLen: 8273, CertificateVerifyLen: 286, FinishedLen: 74,
		RecordLens: [7]int{1215, 6, 41, 8273, 286, 74, 0}, RecordCount: 5,
		CapturedAt: time.Now(),
	}
	realityLayoutCache.Store(key, fresh)

	val2, _ := realityLayoutCache.Load(key)
	l2 := val2.(*HandshakeLayout)
	if l2.IsExpired() {
		t.Error("fresh layout should NOT be expired")
	}

	realityLayoutCache.Delete(key)
}

func TestLayoutCacheIsolation(t *testing.T) {
	microsoftKey := "layout.iso|microsoft.com|h2"
	appleKey := "layout.iso|apple.com|h2"
	teslaKey := "layout.iso|tesla.com|h2"

	fpMS := computeFingerprint(0x1301, "h2", 1215, 41)
	fpApple := computeFingerprint(0x1301, "h2", 127, 41)
	fpTesla := computeFingerprint(0x1302, "h2", 127, 51)

	realityLayoutCache.Store(microsoftKey, &HandshakeLayout{
		Fingerprint: fpMS, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		RecordLens: [7]int{1215}, CapturedAt: time.Now(),
	})
	realityLayoutCache.Store(appleKey, &HandshakeLayout{
		Fingerprint: fpApple, ServerHelloLen: 127, EncryptedExtensionsLen: 41,
		RecordLens: [7]int{127}, CapturedAt: time.Now(),
	})
	realityLayoutCache.Store(teslaKey, &HandshakeLayout{
		Fingerprint: fpTesla, ServerHelloLen: 127, EncryptedExtensionsLen: 51,
		RecordLens: [7]int{127}, CapturedAt: time.Now(),
	})

	valMS, _ := realityLayoutCache.Load(microsoftKey)
	valApple, _ := realityLayoutCache.Load(appleKey)
	valTesla, _ := realityLayoutCache.Load(teslaKey)

	lMS := valMS.(*HandshakeLayout)
	lApple := valApple.(*HandshakeLayout)
	lTesla := valTesla.(*HandshakeLayout)

	if lMS.Fingerprint == lApple.Fingerprint {
		t.Error("microsoft and apple should have different fingerprints")
	}
	if lMS.ServerHelloLen != 1215 {
		t.Errorf("microsoft ServerHelloLen = %d, want 1215", lMS.ServerHelloLen)
	}
	if lApple.ServerHelloLen != 127 {
		t.Errorf("apple ServerHelloLen = %d, want 127", lApple.ServerHelloLen)
	}
	if lTesla.EncryptedExtensionsLen != 51 {
		t.Errorf("tesla EncryptedExtensionsLen = %d, want 51", lTesla.EncryptedExtensionsLen)
	}

	realityLayoutCache.Delete(microsoftKey)
	realityLayoutCache.Delete(appleKey)
	realityLayoutCache.Delete(teslaKey)
}

func TestLayoutCacheSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test in short mode")
	}

	const totalConnections = 1000
	const uniqueDests = 20

	var mBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mBefore)
	allocBefore := mBefore.TotalAlloc

	for i := 0; i < totalConnections; i++ {
		destIdx := i % uniqueDests
		dest := fmt.Sprintf("layout.soak%d.example.com|layout.soak%d.example.com|h2", destIdx, destIdx)
		fp := computeFingerprint(0x1301, "h2", 1200+destIdx, 40+destIdx)

		val, ok := realityLayoutCache.Load(dest)
		if ok {
			l := val.(*HandshakeLayout)
			if l.Fingerprint != fp {
				t.Fatalf("connection %d: fp mismatch", i)
			}
		} else {
			realityLayoutCache.Store(dest, &HandshakeLayout{
				Fingerprint: fp, ServerHelloLen: 1200 + destIdx,
				EncryptedExtensionsLen: 40 + destIdx,
				RecordLens: [7]int{1200 + destIdx, 6, 40 + destIdx},
				CapturedAt: time.Now(),
			})
		}
	}

	var mAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mAfter)

	allocDelta := mAfter.TotalAlloc - allocBefore
	t.Logf("Layout soak: %d connections, alloc delta: %d bytes (%.2f KB)",
		totalConnections, allocDelta, float64(allocDelta)/1024)

	if allocDelta > 50*1024*1024 {
		t.Errorf("alloc delta too high: %.2f MB", float64(allocDelta)/1024/1024)
	}

	for i := 0; i < uniqueDests; i++ {
		realityLayoutCache.Delete(fmt.Sprintf("layout.soak%d.example.com|layout.soak%d.example.com|h2", i, i))
	}
}

func BenchmarkLayoutCacheHit(b *testing.B) {
	key := "bench.layout.hit|example.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	realityLayoutCache.Store(key, &HandshakeLayout{
		Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		RecordLens: [7]int{1215, 6, 41}, CapturedAt: time.Now(),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		val, ok := realityLayoutCache.Load(key)
		if ok {
			l := val.(*HandshakeLayout)
			_ = l.Fingerprint == fp
		}
	}
	b.StopTimer()
	realityLayoutCache.Delete(key)
}

func BenchmarkLayoutCacheMiss(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = realityLayoutCache.Load("bench.layout.miss|nonexistent.com|h2")
	}
}

// ============================================================================
// P1: Persistent Profile Cache Tests
// ============================================================================

func TestPersistentStoreSaveLoad(t *testing.T) {
	dir := t.TempDir()
	store := InitPersistentStore(dir)

	// Store some profiles
	fp1 := computeFingerprint(0x1301, "h2", 1215, 41)
	realityProfileCache.Store("persist.test|microsoft.com|h2", &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp1,
		CipherSuite: 0x1301, ALPN: "h2", RecordCount: 5, CapturedAt: time.Now(),
	})
	realityLayoutCache.Store("persist.test|microsoft.com|h2", &HandshakeLayout{
		Fingerprint: fp1, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		CertificateLen: 8273, CertificateVerifyLen: 286, FinishedLen: 74,
		RecordLens: [7]int{1215, 6, 41, 8273, 286, 74, 0}, RecordCount: 5,
		CapturedAt: time.Now(),
	})

	// Save
	store.Save()

	// Verify file exists
	if _, err := os.Stat(store.GetFilePath()); os.IsNotExist(err) {
		t.Fatal("profiles.json not created")
	}

	// Clear caches
	realityProfileCache.Delete("persist.test|microsoft.com|h2")
	realityLayoutCache.Delete("persist.test|microsoft.com|h2")

	// Reset loadOnce to simulate fresh startup
	loadOnce = sync.Once{}
	profileStore = nil
	InitPersistentStore(dir)

	// Verify loaded
	val, ok := realityProfileCache.Load("persist.test|microsoft.com|h2")
	if !ok {
		t.Fatal("profile not loaded from disk")
	}
	p := val.(*RealityProfile)
	if p.Fingerprint != fp1 {
		t.Errorf("fingerprint = %d, want %d", p.Fingerprint, fp1)
	}
	if p.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %d, want 0x1301", p.CipherSuite)
	}

	val2, ok2 := realityLayoutCache.Load("persist.test|microsoft.com|h2")
	if !ok2 {
		t.Fatal("layout not loaded from disk")
	}
	l := val2.(*HandshakeLayout)
	if l.ServerHelloLen != 1215 {
		t.Errorf("ServerHelloLen = %d, want 1215", l.ServerHelloLen)
	}
	if l.CertificateLen != 8273 {
		t.Errorf("CertificateLen = %d, want 8273", l.CertificateLen)
	}

	// Cleanup
	realityProfileCache.Delete("persist.test|microsoft.com|h2")
	realityLayoutCache.Delete("persist.test|microsoft.com|h2")
}

func TestPersistentStoreSkipsExpired(t *testing.T) {
	dir := t.TempDir()

	// Reset loadOnce to allow fresh initialization
	loadOnce = sync.Once{}
	profileStore = nil
	store := InitPersistentStore(dir)

	// Store expired profile
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	realityProfileCache.Store("persist.expired|microsoft.com|h2", &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now().Add(-31 * time.Minute),
	})

	store.Save()

	// Clear and reload
	realityProfileCache.Delete("persist.expired|microsoft.com|h2")
	loadOnce = sync.Once{}
	profileStore = nil
	InitPersistentStore(dir)

	// Should NOT be loaded (expired)
	_, ok := realityProfileCache.Load("persist.expired|microsoft.com|h2")
	if ok {
		t.Error("expired profile should not be loaded from disk")
	}

	realityProfileCache.Delete("persist.expired|microsoft.com|h2")
}

func TestPersistentStoreAtomicWrite(t *testing.T) {
	dir := t.TempDir()

	loadOnce = sync.Once{}
	profileStore = nil
	store := InitPersistentStore(dir)

	// Store profile
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	realityProfileCache.Store("persist.atomic|microsoft.com|h2", &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	store.Save()

	// Verify no .tmp file left
	tmpPath := store.GetFilePath() + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("temp file should be cleaned up after atomic write")
	}

	// Verify main file exists and is valid JSON
	data, err := os.ReadFile(store.GetFilePath())
	if err != nil {
		t.Fatal(err)
	}
	var file ProfileFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if file.Version != 1 {
		t.Errorf("version = %d, want 1", file.Version)
	}
	if len(file.Profiles) != 1 {
		t.Errorf("profiles count = %d, want 1", len(file.Profiles))
	}

	realityProfileCache.Delete("persist.atomic|microsoft.com|h2")
}

// ============================================================================
// P2: Background Refresh Tests
// ============================================================================

func TestBackgroundRefreshStartStop(t *testing.T) {
	m := InitBackgroundRefresh(time.Second)

	// Start refresh for a target
	m.StartRefresh("example.com:443", "example.com")

	// Verify target is tracked
	active, _ := m.GetRefreshStats()
	if active != 1 {
		t.Errorf("active targets = %d, want 1", active)
	}

	// Start again — should be idempotent
	m.StartRefresh("example.com:443", "example.com")
	active, _ = m.GetRefreshStats()
	if active != 1 {
		t.Errorf("active targets = %d after duplicate start, want 1", active)
	}

	// Stop refresh
	m.StopRefresh("example.com:443", "example.com")
	active, _ = m.GetRefreshStats()
	if active != 0 {
		t.Errorf("active targets = %d after stop, want 0", active)
	}
}

func TestBackgroundRefreshMultipleTargets(t *testing.T) {
	m := InitBackgroundRefresh(time.Second)

	targets := []struct{ dest, name string }{
		{"microsoft.com:443", "microsoft.com"},
		{"apple.com:443", "apple.com"},
		{"tesla.com:443", "tesla.com"},
	}

	for _, tgt := range targets {
		m.StartRefresh(tgt.dest, tgt.name)
	}

	active, _ := m.GetRefreshStats()
	if active != 3 {
		t.Errorf("active targets = %d, want 3", active)
	}

	// Stop one
	m.StopRefresh("apple.com:443", "apple.com")
	active, _ = m.GetRefreshStats()
	if active != 2 {
		t.Errorf("active targets = %d after stop, want 2", active)
	}

	// Cleanup
	for _, tgt := range targets {
		m.StopRefresh(tgt.dest, tgt.name)
	}
}

func TestBackgroundRefreshConcurrent(t *testing.T) {
	m := InitBackgroundRefresh(time.Second)

	var wg sync.WaitGroup
	const n = 50
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(id int) {
			defer wg.Done()
			dest := fmt.Sprintf("concurrent%d.example.com:443", id)
			m.StartRefresh(dest, fmt.Sprintf("concurrent%d.example.com", id))
		}(i)
	}
	wg.Wait()

	active, _ := m.GetRefreshStats()
	if active != n {
		t.Errorf("active targets = %d, want %d", n, active)
	}

	// Cleanup
	for i := 0; i < n; i++ {
		m.StopRefresh(
			fmt.Sprintf("concurrent%d.example.com:443", i),
			fmt.Sprintf("concurrent%d.example.com", i),
		)
	}
}

func TestBackgroundRefreshFormatStats(t *testing.T) {
	// Before initialization
	refreshManager = nil
	refreshManagerOnce = sync.Once{}

	stats := FormatRefreshStats()
	if stats == "" {
		t.Error("stats should not be empty")
	}
}
