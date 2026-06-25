package reality

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkComparison compares original vs optimized paths.
func BenchmarkComparison(b *testing.B) {
	b.Run("Original_WithoutCache", func(b *testing.B) {
		// Simulate original path: always miss, always probe
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("target%d.example.com|h2", i%100)
			fp := computeFingerprint(0x1301, "h2", 1215, 41)

			// Simulate: always store new (no cache hit)
			realityProfileCache.Store(key, &RealityProfile{
				RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
				CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
			})
			realityProfileCache.Delete(key)
		}
	})

	b.Run("Optimized_WithCache", func(b *testing.B) {
		// Pre-populate cache
		for i := 0; i < 100; i++ {
			key := fmt.Sprintf("target%d.example.com|h2", i)
			fp := computeFingerprint(0x1301, "h2", 1215, 41)
			realityProfileCache.Store(key, &RealityProfile{
				RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
				CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
			})
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("target%d.example.com|h2", i%100)
			val, ok := realityProfileCache.Load(key)
			if ok {
				p := val.(*RealityProfile)
				_ = p.Fingerprint
			}
		}
		b.StopTimer()
		for i := 0; i < 100; i++ {
			realityProfileCache.Delete(fmt.Sprintf("target%d.example.com|h2", i))
		}
	})

	b.Run("Original_LayoutMiss", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("layout%d.example.com|h2", i%100)
			fp := computeFingerprint(0x1301, "h2", 1215, 41)
			realityLayoutCache.Store(key, &HandshakeLayout{
				Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
				RecordLens: [7]int{1215, 6, 41}, CapturedAt: time.Now(),
			})
			realityLayoutCache.Delete(key)
		}
	})

	b.Run("Optimized_LayoutHit", func(b *testing.B) {
		for i := 0; i < 100; i++ {
			key := fmt.Sprintf("layout%d.example.com|h2", i)
			fp := computeFingerprint(0x1301, "h2", 1215, 41)
			realityLayoutCache.Store(key, &HandshakeLayout{
				Fingerprint: fp, ServerHelloLen: 1215, EncryptedExtensionsLen: 41,
				RecordLens: [7]int{1215, 6, 41}, CapturedAt: time.Now(),
			})
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("layout%d.example.com|h2", i%100)
			val, ok := realityLayoutCache.Load(key)
			if ok {
				l := val.(*HandshakeLayout)
				_ = l.Fingerprint
			}
		}
		b.StopTimer()
		for i := 0; i < 100; i++ {
			realityLayoutCache.Delete(fmt.Sprintf("layout%d.example.com|h2", i))
		}
	})

	b.Run("Optimized_VariantSelect", func(b *testing.B) {
		set := NewProfileVariantSet(4)
		v1 := set.AddOrHit(100, [7]int{100}, 0x1301, "h2")
		v1.HitCount = 80
		v1.MissCount = 20
		v2 := set.AddOrHit(200, [7]int{200}, 0x1302, "h2")
		v2.HitCount = 60
		v2.MissCount = 10
		v3 := set.AddOrHit(300, [7]int{300}, 0x1301, "http/1.1")
		v3.HitCount = 20
		v3.MissCount = 30

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = set.FindBest()
		}
	})

	b.Run("Optimized_ScoringEngine", func(b *testing.B) {
		engine := NewScoringEngine()
		for i := 0; i < 10; i++ {
			fv := engine.GetOrCreate(uint64(i * 1000))
			for j := 0; j < 20; j++ {
				fv.RecordSuccess(time.Millisecond * time.Duration(10+j))
			}
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = engine.Ranked()
		}
	})
}
