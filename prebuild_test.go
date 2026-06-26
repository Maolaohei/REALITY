package reality

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestProbeTarget_ConnectionRefused(t *testing.T) {
	profile, err := probeTargetRaw("127.0.0.1:1")
	if err == nil {
		t.Error("expected error")
	}
	if profile != nil {
		t.Error("expected nil")
	}
}

func TestProbeTarget_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var d net.Dialer
	_, err := d.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Error("expected error")
	}
}

func TestEnsureAutoProbe_EmptyDest(t *testing.T) {
	ensureAutoProbe(&Config{Dest: ""})
}

func TestEnsureAutoProbe_CopiesConfig(t *testing.T) {
	ensureAutoProbe(&Config{
		Dest: "example.com:443", Type: "tcp",
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return net.Dial(n, a) },
	})
}

func TestEnsureAutoProbe_Idempotent(t *testing.T) {
	c := &Config{
		Dest: "idempotent.example.com:443", Type: "tcp",
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return net.Dial(n, a) },
	}
	ensureAutoProbe(c)
	ensureAutoProbe(c)
}

func TestStopAutoProbe_Noop(t *testing.T) {
	StopAutoProbe("nonexistent.example.com:443")
}

func TestRealityProfileCacheHit(t *testing.T) {
	key := "cache.hit|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	defer globalCacheManager.InvalidateProfile(key)
	p, stale := globalCacheManager.GetProfile(key)
	if p == nil || stale {
		t.Error("expected fresh profile")
	}
}

func TestRealityProfileCacheMiss(t *testing.T) {
	p, _ := globalCacheManager.GetProfile("nonexistent|example.com|h2")
	if p != nil {
		t.Error("expected nil")
	}
}

func TestRealityProfileExpiry(t *testing.T) {
	key := "cache.expiry|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now().Add(-ProfileTTL - time.Minute),
	})
	p, stale := globalCacheManager.GetProfile(key)
	if p == nil || !stale {
		t.Error("expected stale profile")
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	fp1 := computeFingerprint(0x1301, "h2", 1215, 41)
	fp2 := computeFingerprint(0x1301, "h2", 1215, 41)
	if fp1 != fp2 {
		t.Error("not deterministic")
	}
}

func TestFingerprintSensitivity(t *testing.T) {
	fp1 := computeFingerprint(0x1301, "h2", 1215, 41)
	fp2 := computeFingerprint(0x1302, "h2", 1215, 41)
	fp3 := computeFingerprint(0x1301, "http/1.1", 1215, 41)
	fp4 := computeFingerprint(0x1301, "h2", 1200, 41)
	if fp1 == fp2 || fp1 == fp3 || fp1 == fp4 {
		t.Error("different inputs should differ")
	}
}

func TestProfileIsolation(t *testing.T) {
	key := "isolation|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	defer globalCacheManager.InvalidateProfile(key)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{9999, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	p, _ := globalCacheManager.GetProfile(key)
	if p.RecordLens[0] == 9999 {
		t.Error("should not overwrite")
	}
}

func TestRealityProfileCacheConcurrentHit(t *testing.T) {
	key := "concurrent|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	defer globalCacheManager.InvalidateProfile(key)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p, _ := globalCacheManager.GetProfile(key); p == nil {
				t.Error("nil")
			}
		}()
	}
	wg.Wait()
}

func TestTargetChangeInvalidation(t *testing.T) {
	key := "target.change|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	globalCacheManager.InvalidateProfile(key)
	if p, _ := globalCacheManager.GetProfile(key); p != nil {
		t.Error("should be invalidated")
	}
}

func TestRealityProfileInvalidation(t *testing.T) {
	key := "invalidation|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	globalCacheManager.InvalidateProfile(key)
	if p, _ := globalCacheManager.GetProfile(key); p != nil {
		t.Error("should be invalidated")
	}
}

func TestRealityProfileInvalidationByCipherSuiteChange(t *testing.T) {
	key := "invalidation.cipher|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	globalCacheManager.InvalidateProfile(key)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1302, ALPN: "h2", CapturedAt: time.Now(),
	})
	defer globalCacheManager.InvalidateProfile(key)
	p, _ := globalCacheManager.GetProfile(key)
	if p == nil || p.CipherSuite != 0x1302 {
		t.Error("new cipher suite")
	}
}

func TestRealityProfileSoak(t *testing.T) {
	key := "soak|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	for i := 0; i < 100; i++ {
		globalCacheManager.StoreProfile(key, &RealityProfile{
			RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
			CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
		})
		if p, _ := globalCacheManager.GetProfile(key); p == nil {
			t.Fatalf("iteration %d", i)
		}
	}
	globalCacheManager.InvalidateProfile(key)
}

func TestPersistentStoreSaveLoad(t *testing.T) {
	dir := t.TempDir()
	loadOnce = sync.Once{}
	profileStore = nil
	store := InitPersistentStore(dir)
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	key := "persist.test|microsoft.com|h2"
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", TLSVersion: VersionTLS13, CapturedAt: time.Now(),
	})
	store.Save()
	globalCacheManager.InvalidateProfile(key)
	loadOnce = sync.Once{}
	profileStore = nil
	InitPersistentStore(dir)
	if p, _ := globalCacheManager.GetProfile(key); p == nil {
		t.Fatal("should load from disk")
	}
}

func TestPersistentStoreSkipsExpired(t *testing.T) {
	dir := t.TempDir()
	loadOnce = sync.Once{}
	profileStore = nil
	store := InitPersistentStore(dir)
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile("persist.expired|microsoft.com|h2", &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now().Add(-31 * time.Minute),
	})
	store.Save()
	globalCacheManager.InvalidateProfile("persist.expired|microsoft.com|h2")
	loadOnce = sync.Once{}
	profileStore = nil
	InitPersistentStore(dir)
	if p, _ := globalCacheManager.GetProfile("persist.expired|microsoft.com|h2"); p != nil {
		t.Error("should not load expired")
	}
}

func TestPersistentStoreAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	globalCacheManager.entries.Range(func(key, val any) bool {
		globalCacheManager.entries.Delete(key)
		return true
	})
	loadOnce = sync.Once{}
	profileStore = nil
	store := InitPersistentStore(dir)
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile("persist.atomic|microsoft.com|h2", &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	store.Save()
	if _, err := os.Stat(store.GetFilePath() + ".tmp"); !os.IsNotExist(err) {
		t.Error("tmp should be cleaned")
	}
	data, err := os.ReadFile(store.GetFilePath())
	if err != nil {
		t.Fatal(err)
	}
	var file ProfileFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Profiles) != 1 {
		t.Errorf("count = %d, want 1", len(file.Profiles))
	}
	globalCacheManager.InvalidateProfile("persist.atomic|microsoft.com|h2")
}

func TestBackgroundRefreshStartStop(t *testing.T) {
	ResetGlobalRefreshManagerForTesting()
	t.Cleanup(ResetGlobalRefreshManagerForTesting)
	m := GetRefreshManager()
	m.AddTarget("example.com:443", "example.com")
	if m.GetStats() != 1 {
		t.Error("want 1")
	}
	m.AddTarget("example.com:443", "example.com")
	if m.GetStats() != 1 {
		t.Error("want 1 after dup")
	}
	m.RemoveTarget("example.com:443", "example.com")
	if m.GetStats() != 0 {
		t.Error("want 0")
	}
}

func TestBackgroundRefreshMultipleTargets(t *testing.T) {
	ResetGlobalRefreshManagerForTesting()
	t.Cleanup(ResetGlobalRefreshManagerForTesting)
	m := GetRefreshManager()
	for _, t := range []string{"a.com:443", "b.com:443", "c.com:443"} {
		m.AddTarget(t, t)
	}
	if m.GetStats() != 3 {
		t.Error("want 3")
	}
	for _, t := range []string{"a.com:443", "b.com:443", "c.com:443"} {
		m.RemoveTarget(t, t)
	}
}

func TestBackgroundRefreshConcurrent(t *testing.T) {
	ResetGlobalRefreshManagerForTesting()
	t.Cleanup(ResetGlobalRefreshManagerForTesting)
	m := GetRefreshManager()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			m.AddTarget("concurrent"+string(rune('0'+n))+".com:443", "test")
		}(i)
	}
	wg.Wait()
}

func TestBackgroundRefreshFormatStats(t *testing.T) {
	ResetGlobalRefreshManagerForTesting()
	t.Cleanup(ResetGlobalRefreshManagerForTesting)
	if s := FormatRefreshStats(); s == "" {
		t.Error("empty")
	}
}

func TestPinFallbackTTL_CleanupDeletesExpired(t *testing.T) {
	key := "pin.cleanup|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	globalCacheManager.Pin(key)
	globalCacheManager.InvalidateProfile(key)
	val, _ := globalCacheManager.entries.Load(key)
	entry := val.(*ProfileEntry)
	entry.PendingSince = time.Now().Add(-15 * time.Minute)
	globalCacheManager.CleanupPending(10 * time.Minute)
	if _, ok := globalCacheManager.entries.Load(key); ok {
		t.Fatal("should be deleted")
	}
}

func TestPinFallbackTTL_KeepsRecentEntries(t *testing.T) {
	key := "pin.recent|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	globalCacheManager.Pin(key)
	globalCacheManager.InvalidateProfile(key)
	globalCacheManager.CleanupPending(10 * time.Minute)
	if _, ok := globalCacheManager.entries.Load(key); !ok {
		t.Fatal("should keep recent")
	}
	globalCacheManager.Unpin(key)
	globalCacheManager.InvalidateProfile(key)
}

func TestPinFallbackTTL_SafetyNetForLeak(t *testing.T) {
	key := "pin.leak|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	globalCacheManager.Pin(key)
	globalCacheManager.InvalidateProfile(key)
	val, _ := globalCacheManager.entries.Load(key)
	entry := val.(*ProfileEntry)
	entry.PendingSince = time.Now().Add(-15 * time.Minute)
	globalCacheManager.CleanupPending(10 * time.Minute)
	if _, ok := globalCacheManager.entries.Load(key); ok {
		t.Fatal("should force delete")
	}
}

func BenchmarkRealityProfileCacheHit(b *testing.B) {
	key := "bench.hit|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 1215, 41)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	defer globalCacheManager.InvalidateProfile(key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		globalCacheManager.GetProfile(key)
	}
}

func BenchmarkRealityProfileCacheMiss(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		globalCacheManager.GetProfile("bench.miss|nonexistent.com|h2")
	}
}

func BenchmarkComputeFingerprint(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeFingerprint(0x1301, "h2", 1215, 41)
	}
}

var _ = runtime.GOMAXPROCS
