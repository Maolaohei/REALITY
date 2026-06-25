//go:build l1 || l1unit

package reality

import (
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Level 1：单元测试 — 缓存逻辑、Fingerprint、Variant
// 要求：PASS 率 100%
// ============================================================================

// --- Cache: Profile ---

func TestL1_ProfileStoreAndGet(t *testing.T) {
	cacheStats = CacheStats{}
	key := "l1|ms.com|h2"
	fp := computeFingerprint(0x1301, "h2", 100, 50)

	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{100, 6, 50}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	defer realityProfileCache.Delete(key)

	val, ok := realityProfileCache.Load(key)
	if !ok {
		t.Fatal("cache miss")
	}
	p := val.(*RealityProfile)
	if p.Fingerprint != fp {
		t.Errorf("fp = %d, want %d", p.Fingerprint, fp)
	}
	if p.CipherSuite != 0x1301 {
		t.Errorf("cs = 0x%04X, want 0x1301", p.CipherSuite)
	}
}

func TestL1_ProfileExpiry(t *testing.T) {
	p := &RealityProfile{CapturedAt: time.Now()}
	if p.IsExpired() {
		t.Fatal("fresh profile should not be expired")
	}

	p.CapturedAt = time.Now().Add(-ProfileTTL - time.Minute)
	if !p.IsExpired() {
		t.Fatal("old profile should be expired")
	}
}

func TestL1_ProfileInvalidation(t *testing.T) {
	cacheStats = CacheStats{}
	key := "l1.inv|ms.com|h2"

	realityProfileCache.Store(key, &RealityProfile{
		RecordLens: [7]int{100, 6, 50}, Fingerprint: 111,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	realityProfileCache.Delete(key)
	if _, ok := realityProfileCache.Load(key); ok {
		t.Fatal("should be deleted")
	}
}

func TestL1_ProfileIsolation(t *testing.T) {
	cacheStats = CacheStats{}
	k1 := "l1.iso|ms.com|h2"
	k2 := "l1.iso|apple.com|h2"

	realityProfileCache.Store(k1, &RealityProfile{Fingerprint: 100, CapturedAt: time.Now()})
	realityProfileCache.Store(k2, &RealityProfile{Fingerprint: 200, CapturedAt: time.Now()})
	defer realityProfileCache.Delete(k1)
	defer realityProfileCache.Delete(k2)

	v1, _ := realityProfileCache.Load(k1)
	v2, _ := realityProfileCache.Load(k2)
	if v1.(*RealityProfile).Fingerprint == v2.(*RealityProfile).Fingerprint {
		t.Fatal("profiles should be isolated")
	}
}

// --- Cache: Layout ---

func TestL1_LayoutCaptureAndReuse(t *testing.T) {
	cacheStats = CacheStats{}
	key := "l1.lay|ms.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	l := &HandshakeLayout{
		Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
		CertificateLen: 8273, CertificateVerifyLen: 286, FinishedLen: 74,
		RecordLens: [7]int{1215, 6, 41, 8273, 286, 74, 0}, RecordCount: 5,
		CapturedAt: time.Now(),
	}

	realityLayoutCache.Store(key, l)
	defer realityLayoutCache.Delete(key)

	val, ok := realityLayoutCache.Load(key)
	if !ok {
		t.Fatal("layout miss")
	}
	got := val.(*HandshakeLayout)
	if got.ServerHelloLen != 1215 {
		t.Errorf("ServerHelloLen = %d, want 1215", got.ServerHelloLen)
	}
	if got.CertificateLen != 8273 {
		t.Errorf("CertificateLen = %d, want 8273", got.CertificateLen)
	}
}

func TestL1_LayoutInvalidation(t *testing.T) {
	cacheStats = CacheStats{}
	key := "l1.linv|ms.com|h2"

	realityLayoutCache.Store(key, &HandshakeLayout{
		ServerHelloLen: 100, CapturedAt: time.Now(),
	})
	realityLayoutCache.Delete(key)
	if _, ok := realityLayoutCache.Load(key); ok {
		t.Fatal("should be deleted")
	}
}

// --- Variant ---

func TestL1_VariantAddAndFindBest(t *testing.T) {
	set := NewProfileVariantSet(4)

	v1 := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	v1.HitCount = 70
	v1.MissCount = 30

	v2 := set.AddOrHit(200, [7]int{200}, 0x1302, "h2")
	v2.HitCount = 25
	v2.MissCount = 5

	best := set.FindBest()
	if best == nil || best.Fingerprint != 200 {
		t.Errorf("best = %v, want fp=200 (highest weight)", best)
	}
}

func TestL1_VariantEvictLowest(t *testing.T) {
	set := NewProfileVariantSet(2)

	v1 := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	v1.HitCount = 100
	v1.MissCount = 0

	v2 := set.AddOrHit(200, [7]int{200}, 0x1302, "h2")
	v2.HitCount = 1
	v2.MissCount = 100

	set.AddOrHit(300, [7]int{300}, 0x1301, "h2")

	if set.FindByFingerprint(200) != nil {
		t.Error("v2 (lowest weight) should be evicted")
	}
	if set.FindByFingerprint(100) == nil {
		t.Error("v1 (highest weight) should survive")
	}
}

func TestL1_VariantCleanExpired(t *testing.T) {
	set := NewProfileVariantSet(4)
	v := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
	v.CapturedAt = time.Now().Add(-ProfileTTL - time.Minute)

	removed := set.CleanExpired()
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if set.Len() != 0 {
		t.Errorf("len = %d, want 0", set.Len())
	}
}

// --- Fingerprint ---

func TestL1_FingerprintDeterministic(t *testing.T) {
	f1 := computeFingerprint(0x1301, "h2", 1215, 41)
	f2 := computeFingerprint(0x1301, "h2", 1215, 41)
	if f1 != f2 {
		t.Errorf("deterministic check failed: %d != %d", f1, f2)
	}
}

func TestL1_FingerprintCipherSuiteChange(t *testing.T) {
	f1 := computeFingerprint(0x1301, "h2", 127, 51)
	f2 := computeFingerprint(0x1302, "h2", 127, 51)
	if f1 == f2 {
		t.Error("different CipherSuite should produce different fingerprint")
	}
}

func TestL1_FingerprintALPNChange(t *testing.T) {
	f1 := computeFingerprint(0x1301, "h2", 127, 51)
	f2 := computeFingerprint(0x1301, "http/1.1", 127, 51)
	if f1 == f2 {
		t.Error("different ALPN should produce different fingerprint")
	}
}

func TestL1_FingerprintRecordLenChange(t *testing.T) {
	f1 := computeFingerprint(0x1301, "h2", 127, 51)
	f2 := computeFingerprint(0x1301, "h2", 200, 51)
	if f1 == f2 {
		t.Error("different ServerHelloLen should produce different fingerprint")
	}
}

// --- Concurrent ---

func TestL1_ConcurrentCacheAccess(t *testing.T) {
	const goroutines = 200
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	var panics sync.Map

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Store(id, r)
				}
			}()
			for j := 0; j < iterations; j++ {
				key := "l1.c." + string(rune('A'+id%10)) + "|" + string(rune('0'+j%10)) + "|h2"
				fp := computeFingerprint(0x1301, "h2", 1200+id%10, 40+j%10)

				realityProfileCache.LoadOrStore(key, &RealityProfile{
					RecordLens: [7]int{1200 + id%10, 6, 40 + j%10},
					Fingerprint: fp, CipherSuite: 0x1301, ALPN: "h2",
					CapturedAt: time.Now(),
				})
				realityProfileCache.Delete(key)
			}
		}(i)
	}
	wg.Wait()

	panics.Range(func(_, _ any) bool {
		t.Error("panic during concurrent access")
		return true
	})

	for i := 0; i < 10; i++ {
		key := "l1.c." + string(rune('A'+i)) + "|0|h2"
		realityProfileCache.Delete(key)
	}
}

// --- Cache Report ---

func TestL1_CacheReport(t *testing.T) {
	cacheStats = CacheStats{}
	cacheStats.LayoutHit.Add(10)
	cacheStats.LayoutMiss.Add(2)
	cacheStats.MetaHit.Add(8)
	cacheStats.MetaMiss.Add(3)
	cacheStats.VariantHit.Add(5)
	cacheStats.VariantMiss.Add(1)

	report := cacheStats.CacheReport()
	if len(report) == 0 {
		t.Fatal("report should not be empty")
	}
	t.Logf("Cache report:\n%s", report)
}
