package reality

import (
	"testing"
	"time"
)

// BenchmarkCacheInvalidateByServerName measures the invalidation path.
func BenchmarkCacheInvalidateByServerName(b *testing.B) {
	m := NewCacheManager()
	for i := 0; i < 100; i++ {
		key := CacheKey("example.com", "h2", VersionTLS13)
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
		m.InvalidateProfile(CacheKey("example.com", "h2", VersionTLS13))
	}
}

// BenchmarkCacheGetProfile measures cache lookup latency.
func BenchmarkCacheGetProfile(b *testing.B) {
	m := NewCacheManager()
	key := CacheKey("example.com", "h2", VersionTLS13)
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

// BenchmarkFindCachedProfile measures the cache fast path lookup.
func BenchmarkFindCachedProfile(b *testing.B) {
	m := NewCacheManager()
	key := CacheKey("example.com", "h2", VersionTLS13)
	m.StoreProfile(key, &RealityProfile{
		RecordLens:  [7]int{1215, 6, 41, 8273, 286, 74, 0},
		CipherSuite: 0x1301,
		ALPN:        "h2",
		TLSVersion:  VersionTLS13,
		CapturedAt:  time.Now(),
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.FindCachedProfile("example.com", 0x1301, "h2", VersionTLS13) //nolint:errcheck
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
	a := [7]int{1215, 6, 200, 300, 400, 500, 600}
	b2 := [7]int{1215, 6, 200, 300, 400, 500, 660}
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
