package reality

import (
	"testing"
	"time"
)

func TestFeatureVectorScore(t *testing.T) {
	fv := &FeatureVector{}

	// Fresh variant: neutral scores
	score := fv.Score()
	if score < 0.2 || score > 0.8 {
		t.Errorf("fresh score = %v, want ~0.5", score)
	}

	// After successes
	for i := 0; i < 10; i++ {
		fv.RecordSuccess(time.Millisecond * 10)
	}
	score = fv.Score()
	if score < 0.5 {
		t.Errorf("after 10 successes: score = %v, want >= 0.5", score)
	}

	// Success rate should be 1.0
	if fv.SuccessRate() != 1.0 {
		t.Errorf("SuccessRate = %v, want 1.0", fv.SuccessRate())
	}
}

func TestFeatureVectorScoreWithFailures(t *testing.T) {
	fv := &FeatureVector{}

	// 7 successes, 3 failures
	for i := 0; i < 7; i++ {
		fv.RecordSuccess(time.Millisecond * 10)
	}
	for i := 0; i < 3; i++ {
		fv.RecordMiss()
	}

	score := fv.Score()
	// Should be lower than all-success
	allSuccess := &FeatureVector{}
	for i := 0; i < 10; i++ {
		allSuccess.RecordSuccess(time.Millisecond * 10)
	}

	if score >= allSuccess.Score() {
		t.Errorf("mixed score %v should be < all-success score %v", score, allSuccess.Score())
	}
}

func TestFeatureVectorRTT(t *testing.T) {
	fv := &FeatureVector{}

	// Fast RTT
	fv.RecordSuccess(time.Millisecond * 5)
	fv.RecordSuccess(time.Millisecond * 10)

	avgRTT := fv.AvgRTT()
	if avgRTT < 5 || avgRTT > 15 {
		t.Errorf("AvgRTT = %v, want ~7.5ms", avgRTT)
	}

	// Slow RTT should lower score
	slow := &FeatureVector{}
	slow.RecordSuccess(time.Millisecond * 500)
	slow.RecordSuccess(time.Millisecond * 1000)

	if fv.Score() <= slow.Score() {
		t.Error("fast RTT should score higher than slow RTT")
	}
}

func TestFeatureVectorStability(t *testing.T) {
	fv := &FeatureVector{}

	// Consecutive successes
	for i := 0; i < 20; i++ {
		fv.RecordSuccess(time.Millisecond * 10)
	}

	stability := fv.StabilityScore()
	if stability < 0.7 {
		t.Errorf("stability after 20 consecutive = %v, want >= 0.7", stability)
	}

	// Reset and add failures
	fv2 := &FeatureVector{}
	for i := 0; i < 5; i++ {
		fv2.RecordSuccess(time.Millisecond * 10)
	}
	fv2.RecordMiss()
	fv2.RecordMiss()
	fv2.RecordMiss()

	stability2 := fv2.StabilityScore()
	if stability2 >= stability {
		t.Error("variant with failures should be less stable")
	}
}

func TestScoringEngineRanked(t *testing.T) {
	engine := NewScoringEngine()

	// Add variants with different performance
	fv1 := engine.GetOrCreate(100)
	for i := 0; i < 10; i++ {
		fv1.RecordSuccess(time.Millisecond * 5)
	}

	fv2 := engine.GetOrCreate(200)
	for i := 0; i < 10; i++ {
		fv2.RecordSuccess(time.Millisecond * 50)
	}

	fv3 := engine.GetOrCreate(300)
	for i := 0; i < 5; i++ {
		fv3.RecordSuccess(time.Millisecond * 10)
	}
	for i := 0; i < 5; i++ {
		fv3.RecordMiss()
	}

	ranked := engine.Ranked()
	if len(ranked) != 3 {
		t.Fatalf("Ranked returned %d items, want 3", len(ranked))
	}

	// fv1 (fast RTT, all success) should be #1
	if ranked[0] != 100 {
		t.Errorf("ranked[0] = %d, want 100", ranked[0])
	}
}

func TestScoringEngineTop(t *testing.T) {
	engine := NewScoringEngine()

	fv := engine.GetOrCreate(42)
	for i := 0; i < 5; i++ {
		fv.RecordSuccess(time.Millisecond * 10)
	}

	top := engine.Top()
	if top != 42 {
		t.Errorf("Top() = %d, want 42", top)
	}
}

func TestScoringEngineRemove(t *testing.T) {
	engine := NewScoringEngine()

	engine.GetOrCreate(100)
	engine.GetOrCreate(200)

	if engine.Len() != 2 {
		t.Errorf("Len = %d, want 2", engine.Len())
	}

	engine.Remove(100)
	if engine.Len() != 1 {
		t.Errorf("Len after remove = %d, want 1", engine.Len())
	}

	if engine.Get(100) != nil {
		t.Error("removed fingerprint still accessible")
	}
}

func TestScoringEngineConcurrent(t *testing.T) {
	engine := NewScoringEngine()

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func(id int) {
			fp := uint64(id % 10)
			fv := engine.GetOrCreate(fp)
			fv.RecordSuccess(time.Millisecond * time.Duration(id))
			engine.Ranked()
			engine.Top()
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}
