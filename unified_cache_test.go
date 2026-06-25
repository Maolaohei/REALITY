package reality

import (
	"testing"
	"time"
)

func TestUnifiedCacheHardFilter(t *testing.T) {
	cache := NewUnifiedCache(10)
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	cache.Store("test|microsoft.com|h2", &UnifiedCacheEntry{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	// Stage 1: exact match
	entry, hit := cache.Stage1_HardFilter("test|microsoft.com|h2", fp)
	if !hit {
		t.Fatal("expected HIT")
	}
	if entry.Fingerprint != fp {
		t.Errorf("fingerprint = %d, want %d", entry.Fingerprint, fp)
	}

	// Stage 1: wrong fingerprint
	_, hit2 := cache.Stage1_HardFilter("test|microsoft.com|h2", 999)
	if hit2 {
		t.Error("expected MISS for wrong fingerprint")
	}

	// Stage 1: wrong key
	_, hit3 := cache.Stage1_HardFilter("wrong|key|h2", fp)
	if hit3 {
		t.Error("expected MISS for wrong key")
	}
}

func TestUnifiedCacheHardFilterExpiry(t *testing.T) {
	cache := NewUnifiedCache(10)
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	cache.Store("test|expired.com|h2", &UnifiedCacheEntry{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2",
		CapturedAt: time.Now().Add(-31 * time.Minute), // expired
	})

	_, hit := cache.Stage1_HardFilter("test|expired.com|h2", fp)
	if hit {
		t.Error("expected MISS for expired entry")
	}
}

func TestUnifiedCacheSoftSelect(t *testing.T) {
	cache := NewUnifiedCache(10)

	// Add entries with different weights
	e1 := &UnifiedCacheEntry{
		RecordLens: [7]int{100}, Fingerprint: 100, CipherSuite: 0x1301, ALPN: "h2",
		CapturedAt: time.Now(),
	}
	e1.HitCount.Store(80)
	e1.MissCount.Store(20) // weight 0.8

	e2 := &UnifiedCacheEntry{
		RecordLens: [7]int{200}, Fingerprint: 200, CipherSuite: 0x1302, ALPN: "h2",
		CapturedAt: time.Now(),
	}
	e2.HitCount.Store(30)
	e2.MissCount.Store(10) // weight 0.75

	e3 := &UnifiedCacheEntry{
		RecordLens: [7]int{300}, Fingerprint: 300, CipherSuite: 0x1301, ALPN: "http/1.1",
		CapturedAt: time.Now(),
	}
	e3.HitCount.Store(10)
	e3.MissCount.Store(30) // weight 0.25

	cache.Store("a|target.com|h2", e1)
	cache.Store("b|target.com|h2", e2)
	cache.Store("c|target.com|h2", e3)

	// Stage 2: select best by weight
	best := cache.Stage2_SoftSelect("nonexistent|target.com|h2")
	if best == nil {
		t.Fatal("expected best entry")
	}
	if best.Fingerprint != 100 {
		t.Errorf("best fingerprint = %d, want 100 (highest weight)", best.Fingerprint)
	}
}

func TestUnifiedCacheEviction(t *testing.T) {
	cache := NewUnifiedCache(2) // max 2

	e1 := &UnifiedCacheEntry{
		RecordLens: [7]int{100}, Fingerprint: 100, CipherSuite: 0x1301, ALPN: "h2",
		CapturedAt: time.Now(),
	}
	e1.HitCount.Store(100)
	e1.MissCount.Store(0) // weight 1.0

	e2 := &UnifiedCacheEntry{
		RecordLens: [7]int{200}, Fingerprint: 200, CipherSuite: 0x1302, ALPN: "h2",
		CapturedAt: time.Now(),
	}
	e2.HitCount.Store(1)
	e2.MissCount.Store(100) // weight ~0.01

	cache.Store("a|target.com|h2", e1)
	cache.Store("b|target.com|h2", e2)

	// Add third — should evict e2 (lowest weight)
	e3 := &UnifiedCacheEntry{
		RecordLens: [7]int{300}, Fingerprint: 300, CipherSuite: 0x1301, ALPN: "h2",
		CapturedAt: time.Now(),
	}
	cache.Store("c|target.com|h2", e3)

	if cache.Len() > 2 {
		t.Errorf("Len = %d, want <= 2", cache.Len())
	}

	// e2 should be evicted
	_, hit := cache.Stage1_HardFilter("b|target.com|h2", 200)
	if hit {
		t.Error("e2 (lowest weight) should have been evicted")
	}
}

func TestSimplifiedScoring(t *testing.T) {
	scoring := NewSimplifiedScoring()

	e1 := &UnifiedCacheEntry{
		RecordLens: [7]int{100}, Fingerprint: 100, CipherSuite: 0x1301, ALPN: "h2",
		CapturedAt: time.Now(), LastHit: time.Now(),
	}
	e1.HitCount.Store(80)
	e1.MissCount.Store(20)

	e2 := &UnifiedCacheEntry{
		RecordLens: [7]int{200}, Fingerprint: 200, CipherSuite: 0x1302, ALPN: "h2",
		CapturedAt: time.Now(), LastHit: time.Now(),
	}
	e2.HitCount.Store(30)
	e2.MissCount.Store(10)

	score1 := scoring.Score(e1)
	score2 := scoring.Score(e2)

	if score1 <= score2 {
		t.Errorf("e1 score %v should be > e2 score %v", score1, score2)
	}
}

func TestTwoStageDecision(t *testing.T) {
	cache := NewUnifiedCache(10)
	fp := computeFingerprint(0x1301, "h2", 1215, 41)

	// Store entry
	cache.Store("target|microsoft.com|h2", &UnifiedCacheEntry{
		RecordLens: [7]int{1215, 6, 41}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	// Stage 1: exact match → HIT
	entry, hit := cache.Stage1_HardFilter("target|microsoft.com|h2", fp)
	if !hit {
		t.Fatal("Stage 1 should HIT")
	}
	if entry.ServerHelloLen != 0 {
		t.Error("entry should have correct data")
	}

	// Stage 1: wrong fp → MISS
	_, hit2 := cache.Stage1_HardFilter("target|microsoft.com|h2", 999)
	if hit2 {
		t.Error("Stage 1 should MISS for wrong fp")
	}

	// Stage 2: fallback selection
	best := cache.Stage2_SoftSelect("target|microsoft.com|h2")
	if best == nil {
		t.Fatal("Stage 2 should find entry")
	}
}

func TestUnifiedCacheCleanExpired(t *testing.T) {
	cache := NewUnifiedCache(10)

	cache.Store("fresh|target.com|h2", &UnifiedCacheEntry{
		RecordLens: [7]int{100}, Fingerprint: 100, CipherSuite: 0x1301, ALPN: "h2",
		CapturedAt: time.Now(),
	})

	cache.Store("expired|target.com|h2", &UnifiedCacheEntry{
		RecordLens: [7]int{200}, Fingerprint: 200, CipherSuite: 0x1302, ALPN: "h2",
		CapturedAt: time.Now().Add(-31 * time.Minute),
	})

	removed := cache.CleanExpired()
	if removed != 1 {
		t.Errorf("CleanExpired removed %d, want 1", removed)
	}
	if cache.Len() != 1 {
		t.Errorf("Len = %d after clean, want 1", cache.Len())
	}
}

func TestUnifiedCacheConcurrent(t *testing.T) {
	cache := NewUnifiedCache(10)

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func(id int) {
			fp := uint64(id % 10)
			key := "concurrent" + string(rune('A'+id%10)) + "|target.com|h2"
			entry := &UnifiedCacheEntry{
				RecordLens: [7]int{id}, Fingerprint: fp,
				CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
			}
			cache.Store(key, entry)
			cache.Stage1_HardFilter(key, fp)
			cache.Stage2_SoftSelect(key)
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}
