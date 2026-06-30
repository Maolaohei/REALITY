package reality

import (
	"testing"
	"time"
)

// BenchmarkCacheInvalidateByDest measures the old invalidation path.
func BenchmarkCacheInvalidateByDest(b *testing.B) {
	m := NewCacheManager()
	for i := 0; i < 100; i++ {
		key := CacheKey("1.2.3.4:443", "example.com", "h2", VersionTLS13)
		m.StoreProfile(key, &RealityProfile{
			RecordLens:  [7]int{1215, 6, 41, 8273, 286, 74, 0},
			CipherSuite: 0x1301,
			ALPN:        "h2",
			TLSVersion:  VersionTLS13,
			CapturedAt:  time.Now(),
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.InvalidateByDest("1.2.3.4:443")
	}
}

// BenchmarkCacheGetProfile measures cache lookup latency.
func BenchmarkCacheGetProfile(b *testing.B) {
	m := NewCacheManager()
	key := CacheKey("1.2.3.4:443", "example.com", "h2", VersionTLS13)
	m.StoreProfile(key, &RealityProfile{
		RecordLens:  [7]int{1215, 6, 41, 8273, 286, 74, 0},
		CipherSuite: 0x1301,
		ALPN:        "h2",
		TLSVersion:  VersionTLS13,
		CapturedAt:  time.Now(),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.GetProfile(key)
	}
}

// BenchmarkFindCachedProfileByDest measures the cache fast path lookup.
func BenchmarkFindCachedProfileByDest(b *testing.B) {
	m := NewCacheManager()
	key := CacheKey("1.2.3.4:443", "example.com", "h2", VersionTLS13)
	m.StoreProfile(key, &RealityProfile{
		RecordLens:  [7]int{1215, 6, 41, 8273, 286, 74, 0},
		CipherSuite: 0x1301,
		ALPN:        "h2",
		TLSVersion:  VersionTLS13,
		CapturedAt:  time.Now(),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.FindCachedProfileByDest("1.2.3.4:443", 0x1301, "h2", VersionTLS13)
	}
}

// BenchmarkAuthFailedChannel measures the overhead of the authFailed channel check.
func BenchmarkAuthFailedChannel(b *testing.B) {
	ch := make(chan struct{}, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		select {
		case <-ch:
		default:
		}
	}
}

// BenchmarkRecordLensMatch measures the quick-check comparison.
func BenchmarkRecordLensMatch(b *testing.B) {
	a := [7]int{1215, 6, 41, 8273, 286, 74, 100}
	b2 := [7]int{1215, 6, 41, 8273, 286, 74, 160}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recordLensMatch(a, b2)
	}
}

// BenchmarkQuickCheckCompare measures the two-level quick check comparison.
func BenchmarkQuickCheckCompare(b *testing.B) {
	cached := [7]int{1215, 6, 41, 8273, 286, 74, 0}
	quickLens := [2]int{6, 41}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = quickLens[0] == cached[1] && quickLens[1] == cached[2]
	}
}
