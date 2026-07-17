package reality

import (
	"testing"
	"time"
)

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

// BenchmarkFindCachedProfileByDest measures the cache fast path lookup.
func BenchmarkFindCachedProfileByDest(b *testing.B) {
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
		m.FindCachedProfileByDest("1.2.3.4:443", "example.com", 0x1301, "h2", VersionTLS13)
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


func BenchmarkLookupAmortizeHit(b *testing.B) {
	m := NewCacheManager()
	chClass := "class1"
	key := CacheKeyV2("10.0.0.1:443", "sni.example", "h2", VersionTLS13, chClass)
	m.StoreProfile(key, &RealityProfile{
		RecordLens:          [7]int{200, 6, 40, 1000, 200, 50, 0},
		CipherSuite:         0x1301,
		ALPN:                "h2",
		TLSVersion:          VersionTLS13,
		CapturedAt:          time.Now(),
		Dest:                "10.0.0.1:443",
		ServerName:          "sni.example",
		CHClass:             chClass,
		KeyShareGroup:       X25519,
		ShapeHash:           42,
		ServerHelloTemplate: make([]byte, 80),
		Evidence:            MinL2Evidence + 2,
		LiveEvidence:        MinL2Evidence + 2,
		Source:              "live",
		CHClassVer:          CHClassVersion,
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := m.LookupAmortize(AmortizeAuto, "10.0.0.1:443", "sni.example", "h2", VersionTLS13, chClass, 0, 0)
		if res.Profile == nil {
			b.Fatal("miss")
		}
	}
}

func BenchmarkClassifyClientHello(b *testing.B) {
	ch := &clientHelloMsg{
		cipherSuites:      []uint16{0x1301, 0x1302, 0x1303},
		supportedCurves:   []CurveID{X25519, CurveP256},
		keyShares:         []keyShare{{group: X25519, data: make([]byte, 32)}},
		supportedVersions: []uint16{VersionTLS13},
		alpnProtocols:     []string{"h2"},
		serverName:        "example.com",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ClassifyClientHello(ch) == "" {
			b.Fatal("empty")
		}
	}
}

func BenchmarkCacheKeyV2(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CacheKeyV2("10.0.0.1:443", "sni.example", "h2", VersionTLS13, "abcd1234")
	}
}
