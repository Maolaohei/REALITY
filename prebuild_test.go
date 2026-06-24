package reality

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// PrebuildCache Tests
// ============================================================================

func TestPrebuildCache_StoreAndGet(t *testing.T) {
	cache := NewPrebuildCache(time.Minute)

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
	cache := NewPrebuildCache(time.Minute)
	got := cache.Get("nonexistent.com")
	if got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

func TestPrebuildCache_GetExpired(t *testing.T) {
	cache := NewPrebuildCache(time.Millisecond)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Millisecond)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Millisecond)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
// Performance Tests
// ============================================================================

func BenchmarkPrebuildCache_Get(b *testing.B) {
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
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
	cache := NewPrebuildCache(time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("nonexistent.com")
	}
}

func BenchmarkPrebuildCache_ConcurrentGet(b *testing.B) {
	cache := NewPrebuildCache(time.Minute)
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
