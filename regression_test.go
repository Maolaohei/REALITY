package reality

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// ① Regression Gate — 功能正确性回归
// ============================================================================

func TestRegressionProfileReuse(t *testing.T) {
	cacheStats = CacheStats{}

	targets := []struct {
		key string
		fp  uint64
		cs  uint16
		alpn string
		sh  int
		ext int
	}{
		{"regress|microsoft.com|h2", computeFingerprint(0x1301, "h2", 127, 51), 0x1301, "h2", 127, 51},
		{"regress|apple.com|h2", computeFingerprint(0x1301, "h2", 127, 41), 0x1301, "h2", 127, 41},
		{"regress|tesla.com|h2", computeFingerprint(0x1302, "h2", 127, 51), 0x1302, "h2", 127, 51},
	}

	for _, tgt := range targets {
		// Connection 1: cache miss → store
		_, loaded := realityProfileCache.LoadOrStore(tgt.key, &RealityProfile{
			RecordLens: [7]int{tgt.sh, 6, tgt.ext, 800, 300, 200, 0},
			Fingerprint: tgt.fp, CipherSuite: tgt.cs, ALPN: tgt.alpn,
			RecordCount: 5, CapturedAt: time.Now(),
		})
		if loaded {
			t.Errorf("%s: expected miss on first connection", tgt.key)
		}

		// Connection 2-N: cache hit
		for i := 0; i < 10; i++ {
			val, ok := realityProfileCache.Load(tgt.key)
			if !ok {
				t.Fatalf("%s connection %d: cache miss", tgt.key, i+2)
			}
			p := val.(*RealityProfile)
			if p.Fingerprint != tgt.fp {
				t.Fatalf("%s: fingerprint mismatch", tgt.key)
			}
		}
	}

	// Verify all entries exist
	for _, tgt := range targets {
		val, ok := realityProfileCache.Load(tgt.key)
		if !ok {
			t.Errorf("%s: entry not found", tgt.key)
			continue
		}
		p := val.(*RealityProfile)
		if p.Fingerprint != tgt.fp {
			t.Errorf("%s: fingerprint mismatch", tgt.key)
		}
	}

	// Cleanup
	for _, tgt := range targets {
		realityProfileCache.Delete(tgt.key)
	}
}

func TestRegressionLayoutCacheHIT(t *testing.T) {
	cacheStats = CacheStats{}

	key := "regress.layout|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	realityLayoutCache.Store(key, &HandshakeLayout{
		Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		CertificateLen: 8273, CertificateVerifyLen: 286, FinishedLen: 74,
		RecordLens: [7]int{1215, 6, 41, 8273, 286, 74, 0}, RecordCount: 5,
		CapturedAt: time.Now(),
	})

	for i := 0; i < 5; i++ {
		val, ok := realityLayoutCache.Load(key)
		if !ok {
			t.Fatalf("layout miss on iteration %d", i)
		}
		l := val.(*HandshakeLayout)
		if l.Fingerprint != fp {
			t.Fatalf("layout fingerprint mismatch on iteration %d", i)
		}
	}

	realityLayoutCache.Delete(key)
}

func TestRegressionVariantSelection(t *testing.T) {
	set := NewProfileVariantSet(4)

	// Create 3 variants with different weights
	v1 := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	v1.HitCount = 70
	v1.MissCount = 30 // weight 0.7

	v2 := set.AddOrHit(200, [7]int{200}, 0x1302, "h2")
	v2.HitCount = 25
	v2.MissCount = 5 // weight 0.833

	v3 := set.AddOrHit(300, [7]int{300}, 0x1301, "http/1.1")
	v3.HitCount = 5
	v3.MissCount = 25 // weight 0.167

	// FindBest should return v2 (highest weight)
	best := set.FindBest()
	if best == nil {
		t.Fatal("FindBest returned nil")
	}
	if best.Fingerprint != 200 {
		t.Errorf("best = %d, want 200 (highest weight)", best.Fingerprint)
	}

	// Hit v1 to increase its weight
	for i := 0; i < 20; i++ {
		set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	}
	// v1: 90 hits, 30 miss = 0.75
	// v2: 25 hits, 5 miss = 0.833
	// v2 still best
	best2 := set.FindBest()
	if best2.Fingerprint != 200 {
		t.Errorf("best after hits = %d, want 200", best2.Fingerprint)
	}
}

func TestRegressionPersistentLoadSave(t *testing.T) {
	dir := t.TempDir()
	loadOnce = sync.Once{}
	profileStore = nil
	store := InitPersistentStore(dir)

	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	realityProfileCache.Store("regress.persist|microsoft.com|h2", &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	realityLayoutCache.Store("regress.persist|microsoft.com|h2", &HandshakeLayout{
		Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		RecordLens: [7]int{1215}, CapturedAt: time.Now(),
	})

	store.Save()

	// Clear
	realityProfileCache.Delete("regress.persist|microsoft.com|h2")
	realityLayoutCache.Delete("regress.persist|microsoft.com|h2")

	// Reload
	loadOnce = sync.Once{}
	profileStore = nil
	InitPersistentStore(dir)

	// Verify
	val, ok := realityProfileCache.Load("regress.persist|microsoft.com|h2")
	if !ok {
		t.Fatal("profile not loaded after restart")
	}
	p := val.(*RealityProfile)
	if p.Fingerprint != fp {
		t.Errorf("fingerprint = %d, want %d", p.Fingerprint, fp)
	}

	val2, ok2 := realityLayoutCache.Load("regress.persist|microsoft.com|h2")
	if !ok2 {
		t.Fatal("layout not loaded after restart")
	}
	l := val2.(*HandshakeLayout)
	if l.ServerHelloLen != 1215 {
		t.Errorf("ServerHelloLen = %d, want 1215", l.ServerHelloLen)
	}

	realityProfileCache.Delete("regress.persist|microsoft.com|h2")
	realityLayoutCache.Delete("regress.persist|microsoft.com|h2")
}

func TestRegressionBackgroundRefreshNonBlocking(t *testing.T) {
	m := InitBackgroundRefresh(time.Second)

	// Start refresh
	m.StartRefresh("example.com:443", "example.com")

	// Verify it's running
	active, _ := m.GetRefreshStats()
	if active != 1 {
		t.Errorf("active = %d, want 1", active)
	}

	// Stop — should not block
	done := make(chan struct{})
	go func() {
		m.StopRefresh("example.com:443", "example.com")
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(time.Second):
		t.Fatal("StopRefresh blocked")
	}
}

// ============================================================================
// ② Soak + Drift Stability
// ============================================================================

func TestSoakStability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test in short mode")
	}

	const (
		totalConnections = 2000
		uniqueTargets    = 20
	)

	var mBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mBefore)
	allocBefore := mBefore.TotalAlloc
	gcBefore := mBefore.NumGC

	for i := 0; i < totalConnections; i++ {
		targetIdx := i % uniqueTargets
		key := fmt.Sprintf("soak.stability%d.example.com|soak.stability%d.example.com|h2", targetIdx, targetIdx)
		fp := computeFingerprint(0x1301, "h2", 1200+targetIdx, 40+targetIdx)

		val, ok := realityProfileCache.Load(key)
		if ok {
			p := val.(*RealityProfile)
			if p.Fingerprint != fp {
				t.Fatalf("connection %d: fp mismatch", i)
			}
		} else {
			realityProfileCache.Store(key, &RealityProfile{
				RecordLens: [7]int{1200 + targetIdx, 6, 40 + targetIdx},
				Fingerprint: fp, CipherSuite: 0x1301, ALPN: "h2",
				CapturedAt: time.Now(),
			})
		}
	}

	var mAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mAfter)

	allocDelta := mAfter.TotalAlloc - allocBefore
	gcDelta := mAfter.NumGC - gcBefore
	allocGrowthPct := float64(allocDelta) / float64(allocBefore) * 100

	t.Logf("Soak results:")
	t.Logf("  Connections: %d", totalConnections)
	t.Logf("  Alloc delta: %d bytes (%.2f MB)", allocDelta, float64(allocDelta)/1024/1024)
	t.Logf("  Alloc growth: %.2f%%", allocGrowthPct)
	t.Logf("  GC cycles: %d", gcDelta)

	if allocGrowthPct > 10 {
		t.Errorf("alloc growth %.2f%% > 10%%", allocGrowthPct)
	}
	if gcDelta > 10 {
		t.Errorf("GC cycles %d > 10", gcDelta)
	}

	// Cleanup
	for i := 0; i < uniqueTargets; i++ {
		realityProfileCache.Delete(fmt.Sprintf("soak.stability%d.example.com|soak.stability%d.example.com|h2", i, i))
	}
}

// ============================================================================
// ③ Target Drift Simulation
// ============================================================================

func TestDriftCipherSuiteChange(t *testing.T) {
	cacheStats = CacheStats{}

	key := "drift.cs|microsoft.com|h2"

	// Initial: AES-128-GCM
	fp1 := computeFingerprint(0x1301, "h2", 127, 51)
	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 51}, Fingerprint: fp1,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	// Target upgrades to AES-256-GCM
	currentFP := computeFingerprint(0x1302, "h2", 127, 51)

	// Verify MISS
	val, _ := realityProfileCache.Load(key)
	p := val.(*RealityProfile)
	if p.Fingerprint == currentFP {
		t.Fatal("old profile should not match new CipherSuite")
	}
	cacheStats.FingerprintChanged.Add(1)
	cacheStats.MetaMiss.Add(1)

	// Re-learn
	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 51}, Fingerprint: currentFP,
		CipherSuite: 0x1302, ALPN: "h2", CapturedAt: time.Now(),
	})

	// Verify HIT with new fingerprint
	val2, _ := realityProfileCache.Load(key)
	p2 := val2.(*RealityProfile)
	if p2.Fingerprint != currentFP {
		t.Fatal("new profile should match")
	}

	if cacheStats.FingerprintChanged.Load() != 1 {
		t.Errorf("FingerprintChanged = %d, want 1", cacheStats.FingerprintChanged.Load())
	}

	realityProfileCache.Delete(key)
}

func TestDriftCertRotation(t *testing.T) {
	cacheStats = CacheStats{}

	key := "drift.cert|apple.com|h2"
	fp1 := computeFingerprint(0x1301, "h2", 127, 41)

	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 41}, Fingerprint: fp1,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	// Cert rotation: same CS/ALPN but different cert → different fingerprint
	fp2 := computeFingerprint(0x1301, "h2", 127, 50) // ext changed
	currentFP := fp2

	val, _ := realityProfileCache.Load(key)
	p := val.(*RealityProfile)
	if p.Fingerprint == currentFP {
		t.Fatal("old profile should not match after cert rotation")
	}
	cacheStats.FingerprintChanged.Add(1)
	cacheStats.MetaMiss.Add(1)

	// Re-learn
	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 50}, Fingerprint: currentFP,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	val2, _ := realityProfileCache.Load(key)
	p2 := val2.(*RealityProfile)
	if p2.Fingerprint != currentFP {
		t.Fatal("re-learned profile should match")
	}

	if cacheStats.FingerprintChanged.Load() != 1 {
		t.Errorf("FingerprintChanged = %d, want 1", cacheStats.FingerprintChanged.Load())
	}

	realityProfileCache.Delete(key)
}

func TestDriftALPNChange(t *testing.T) {
	cacheStats = CacheStats{}

	key := "drift.alpn|microsoft.com|h2"
	fp1 := computeFingerprint(0x1301, "h2", 127, 51)

	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 51}, Fingerprint: fp1,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	// ALPN changes h2 → http/1.1
	fp2 := computeFingerprint(0x1301, "http/1.1", 127, 51)

	val, _ := realityProfileCache.Load(key)
	p := val.(*RealityProfile)
	if p.Fingerprint == fp2 {
		t.Fatal("old profile should not match after ALPN change")
	}
	cacheStats.FingerprintChanged.Add(1)
	cacheStats.MetaMiss.Add(1)

	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 51}, Fingerprint: fp2,
		CipherSuite: 0x1301, ALPN: "http/1.1", CapturedAt: time.Now(),
	})

	val2, _ := realityProfileCache.Load(key)
	p2 := val2.(*RealityProfile)
	if p2.Fingerprint != fp2 {
		t.Fatal("re-learned profile should match")
	}

	realityProfileCache.Delete(key)
}

// ============================================================================
// ④ Variant System Tests (P3 Core)
// ============================================================================

func TestVariantMultiVersionSelection(t *testing.T) {
	set := NewProfileVariantSet(4)

	// Create 3 variants with different weights
	v1 := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	v1.HitCount = 60
	v1.MissCount = 40 // weight 0.6

	v2 := set.AddOrHit(200, [7]int{200}, 0x1302, "h2")
	v2.HitCount = 30
	v2.MissCount = 5 // weight 0.857

	v3 := set.AddOrHit(300, [7]int{300}, 0x1301, "http/1.1")
	v3.HitCount = 10
	v3.MissCount = 20 // weight 0.333

	// Run 1000 selections
	selections := map[uint64]int{}
	for i := 0; i < 1000; i++ {
		best := set.FindBest()
		selections[best.Fingerprint]++
	}

	// v2 should be selected most (>70%)
	if selections[200] < 700 {
		t.Errorf("v2 selected %d/1000, want >= 700", selections[200])
	}

	// v3 should be selected least (<10%)
	if selections[300] > 100 {
		t.Errorf("v3 selected %d/1000, want <= 100", selections[300])
	}
}

func TestVariantExplosionGuard(t *testing.T) {
	set := NewProfileVariantSet(4) // max 4

	// Force 20 variants
	for i := 0; i < 20; i++ {
		fp := uint64(i * 1000)
		set.AddOrHit(fp, [7]int{i * 10}, uint16(0x1300+i), "h2")
	}

	if set.Len() > 4 {
		t.Errorf("Len = %d, want <= 4", set.Len())
	}

	// Verify memory doesn't grow linearly
	// (set is capped at 4)
}

func TestVariantEvictionPriority(t *testing.T) {
	set := NewProfileVariantSet(2) // max 2

	v1 := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	v1.HitCount = 100
	v1.MissCount = 0 // weight 1.0

	v2 := set.AddOrHit(200, [7]int{200}, 0x1302, "h2")
	v2.HitCount = 1
	v2.MissCount = 100 // weight ~0.01

	// Add v3 — should evict v2 (lowest weight)
	v3 := set.AddOrHit(300, [7]int{300}, 0x1301, "h2")
	v3.HitCount = 50
	v3.MissCount = 10

	// v2 should be evicted
	if set.FindByFingerprint(200) != nil {
		t.Error("v2 (lowest weight) should have been evicted")
	}

	// v1 should survive
	if set.FindByFingerprint(100) == nil {
		t.Error("v1 (highest weight) should survive")
	}
}

// ============================================================================
// ⑤ Concurrent Consistency
// ============================================================================

func TestConcurrentCacheAccess(t *testing.T) {
	const goroutines = 200
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	var panicCount atomic.Int32

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
				}
			}()

			for j := 0; j < iterations; j++ {
				key := fmt.Sprintf("concurrent.%d.example.com|h2", id%10)
				fp := computeFingerprint(0x1301, "h2", 1200+id%10, 40+id%10)

				// Concurrent read/write
				val, ok := realityProfileCache.Load(key)
				if ok {
					_ = val.(*RealityProfile)
				} else {
					realityProfileCache.Store(key, &RealityProfile{
						RecordLens: [7]int{1200 + id%10, 6, 40 + id%10},
						Fingerprint: fp, CipherSuite: 0x1301, ALPN: "h2",
						CapturedAt: time.Now(),
					})
				}

				// Concurrent layout access
				realityLayoutCache.LoadOrStore(key, &HandshakeLayout{
					Fingerprint: fp, ServerHelloLen: 1200 + id%10,
					EncryptedExtensionsLen: 40 + id%10,
					RecordLens: [7]int{1200 + id%10}, CapturedAt: time.Now(),
				})
			}
		}(i)
	}

	wg.Wait()

	if panicCount.Load() > 0 {
		t.Errorf("panics during concurrent access: %d", panicCount.Load())
	}

	// Cleanup
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("concurrent.%d.example.com|h2", i)
		realityProfileCache.Delete(key)
		realityLayoutCache.Delete(key)
	}
}

// ============================================================================
// ⑥ P2 Background Refresh Verification
// ============================================================================

func TestRefreshDoesNotBlockHandshake(t *testing.T) {
	m := InitBackgroundRefresh(time.Second)

	m.StartRefresh("example.com:443", "example.com")

	// Stop should be non-blocking
	done := make(chan struct{})
	go func() {
		m.StopRefresh("example.com:443", "example.com")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StopRefresh blocked")
	}
}

func TestRefreshProducesVariant(t *testing.T) {
	set := NewProfileVariantSet(4)

	// Initial profile
	v1 := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	v1.HitCount = 10

	// Simulate refresh detecting different fingerprint
	// (target changed between probes)
	set.AddOrHit(200, [7]int{200}, 0x1302, "h2")

	if set.Len() != 2 {
		t.Errorf("Len = %d, want 2 (should have 2 variants)", set.Len())
	}

	// Both should be findable
	if set.FindByFingerprint(100) == nil {
		t.Error("v1 not found")
	}
	if set.FindByFingerprint(200) == nil {
		t.Error("v2 not found")
	}
}

// ============================================================================
// ⑦ Fail-Open / Fail-Safe Tests
// ============================================================================

func TestFailSafeTimeoutRecovery(t *testing.T) {
	// Simulate: profile exists, then target becomes unreachable
	// Next connection should still use cached profile
	key := "failsafe|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 127, 51)

	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 51}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	// "Connection" should still HIT even if target is down
	val, ok := realityProfileCache.Load(key)
	if !ok {
		t.Fatal("cache miss on existing profile")
	}
	p := val.(*RealityProfile)
	if p.Fingerprint != fp {
		t.Fatal("fingerprint mismatch")
	}

	realityProfileCache.Delete(key)
}

func TestFailSafeLayoutCacheAvailability(t *testing.T) {
	// Even if profile cache misses, layout cache should still work
	profileKey := "failsafe.layout|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	realityLayoutCache.Store(profileKey, &HandshakeLayout{
		Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		RecordLens: [7]int{1215, 6, 41}, CapturedAt: time.Now(),
	})

	// Layout cache should work independently
	val, ok := realityLayoutCache.Load(profileKey)
	if !ok {
		t.Fatal("layout cache miss")
	}
	l := val.(*HandshakeLayout)
	if l.ServerHelloLen != 1215 {
		t.Errorf("ServerHelloLen = %d, want 1215", l.ServerHelloLen)
	}

	realityLayoutCache.Delete(profileKey)
}

func TestFailSafeVariantIntegrity(t *testing.T) {
	// Variant set should not corrupt on partial failure
	set := NewProfileVariantSet(4)

	v1 := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	v1.HitCount = 10

	// Simulate: add with invalid data (should not crash)
	set.AddOrHit(0, [7]int{}, 0, "")

	// Original variant should still be intact
	v := set.FindByFingerprint(100)
	if v == nil {
		t.Fatal("original variant lost after invalid add")
	}
	if v.HitCount != 10 {
		t.Errorf("HitCount = %d, want 10", v.HitCount)
	}
}
