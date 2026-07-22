package reality

import (
	"sync"
	"testing"
	"time"
)

func TestReplayGuard_AllowFirst(t *testing.T) {
	g := NewReplayGuard(time.Minute, 1000)
	defer g.Stop()

	var key [20]byte
	key[0] = 1
	if !g.CheckAndMark(key) {
		t.Fatal("first occurrence should be allowed")
	}
}

func TestReplayGuard_RejectDuplicate(t *testing.T) {
	g := NewReplayGuard(time.Minute, 1000)
	defer g.Stop()

	var key [20]byte
	key[0] = 1
	g.CheckAndMark(key)
	if g.CheckAndMark(key) {
		t.Fatal("duplicate should be rejected")
	}
}

func TestReplayGuard_DifferentKeysAllowed(t *testing.T) {
	g := NewReplayGuard(time.Minute, 1000)
	defer g.Stop()

	var k1, k2 [20]byte
	k1[0] = 1
	k2[0] = 2
	if !g.CheckAndMark(k1) {
		t.Fatal("k1 should be allowed")
	}
	if !g.CheckAndMark(k2) {
		t.Fatal("k2 should be allowed")
	}
}

func TestReplayGuard_WindowExpiry(t *testing.T) {
	g := NewReplayGuard(50*time.Millisecond, 1000)
	defer g.Stop()

	var key [20]byte
	key[0] = 1
	g.CheckAndMark(key)

	// Wait for window to expire
	time.Sleep(100 * time.Millisecond)

	// After window expiry, the same key should be allowed again
	if !g.CheckAndMark(key) {
		t.Fatal("should be allowed after window expiry")
	}
}

func TestReplayGuard_CapacityLimit(t *testing.T) {
	g := NewReplayGuard(time.Minute, 3)
	defer g.Stop()

	for i := 0; i < 3; i++ {
		var key [20]byte
		key[0] = byte(i)
		if !g.CheckAndMark(key) {
			t.Fatalf("key %d should be allowed", i)
		}
	}

	// At capacity: may either reject or succeed after random ~10% eviction.
	// Hard bound still holds: map never grows unbounded without eviction path.
	var key [20]byte
	key[0] = 99
	_ = g.CheckAndMark(key)
	if g.count.Load() > 3 {
		// After admit, count may briefly equal 4 before next sweep; ensure
		// we never stay far above max without eviction (evict runs first).
		// Allow +1 only if eviction did not delete enough of 3 entries.
		if g.count.Load() > int64(4) {
			t.Fatalf("count %d exceeds max+1", g.count.Load())
		}
	}
}

func TestReplayGuard_EvictsUnderPressure(t *testing.T) {
	g := NewReplayGuard(time.Minute, 20)
	defer g.Stop()
	// Fill beyond capacity many times; at least some new keys should succeed
	// thanks to random eviction (not permanent full reject).
	allowed := 0
	for i := 0; i < 200; i++ {
		var key [20]byte
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		if g.CheckAndMark(key) {
			allowed++
		}
	}
	if allowed < 20 {
		t.Fatalf("expected eviction to admit >=20 unique keys over time, got %d", allowed)
	}
	if g.count.Load() > 30 {
		t.Fatalf("count should stay near capacity, got %d", g.count.Load())
	}
}

func TestReplayGuard_Concurrent(t *testing.T) {
	g := NewReplayGuard(time.Minute, 10000)
	defer g.Stop()

	var wg sync.WaitGroup
	allowed := make([]bool, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var key [20]byte
			key[0] = byte(idx % 10) // 10 unique keys, each hit 10 times
			allowed[idx] = g.CheckAndMark(key)
		}(i)
	}
	wg.Wait()

	// Count how many were allowed (should be exactly 10 unique keys)
	allowedCount := 0
	for _, a := range allowed {
		if a {
			allowedCount++
		}
	}
	if allowedCount != 10 {
		t.Fatalf("expected 10 allowed, got %d", allowedCount)
	}
}
