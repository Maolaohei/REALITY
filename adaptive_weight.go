package reality

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// v4 Adaptive Weight Engine
// ============================================================================

// FeatureVector captures per-variant runtime signals.
type FeatureVector struct {
	SuccessCount   atomic.Uint64
	FailCount      atomic.Uint64
	LayoutHitCount atomic.Uint64
	TotalRequests  atomic.Uint64
	RTTSum          atomic.Int64  // cumulative RTT in microseconds
	RTTCount        atomic.Uint64
	LastSuccess     atomic.Int64  // unix nano
	LastFail        atomic.Int64  // unix nano
	LastSeen        atomic.Int64  // unix nano
	ConsecutiveOK   atomic.Uint64
	ConsecutiveFail atomic.Uint64
}

// RecordSuccess records a successful use of this variant.
func (f *FeatureVector) RecordSuccess(rtt time.Duration) {
	f.SuccessCount.Add(1)
	f.TotalRequests.Add(1)
	f.LayoutHitCount.Add(1)
	f.RTTSum.Add(int64(rtt.Microseconds()))
	f.RTTCount.Add(1)
	f.LastSuccess.Store(time.Now().UnixNano())
	f.LastSeen.Store(time.Now().UnixNano())
	f.ConsecutiveOK.Add(1)
	f.ConsecutiveFail.Store(0)
}

// RecordMiss records a cache miss for this variant.
func (f *FeatureVector) RecordMiss() {
	f.FailCount.Add(1)
	f.TotalRequests.Add(1)
	f.LastFail.Store(time.Now().UnixNano())
	f.LastSeen.Store(time.Now().UnixNano())
	f.ConsecutiveFail.Add(1)
	f.ConsecutiveOK.Store(0)
}

// RecordLayoutHit records a layout cache hit.
func (f *FeatureVector) RecordLayoutHit() {
	f.LayoutHitCount.Add(1)
}

// SuccessRate returns the ratio of successes to total requests.
func (f *FeatureVector) SuccessRate() float64 {
	total := f.TotalRequests.Load()
	if total == 0 {
		return 0.5 // neutral prior
	}
	return float64(f.SuccessCount.Load()) / float64(total)
}

// AvgRTT returns the average RTT in milliseconds.
func (f *FeatureVector) AvgRTT() float64 {
	count := f.RTTCount.Load()
	if count == 0 {
		return 100 // default 100ms
	}
	return float64(f.RTTSum.Load()) / float64(count) / 1000.0
}

// LayoutHitRate returns the ratio of layout hits to total requests.
func (f *FeatureVector) LayoutHitRate() float64 {
	total := f.TotalRequests.Load()
	if total == 0 {
		return 0.5
	}
	return float64(f.LayoutHitCount.Load()) / float64(total)
}

// StabilityScore returns how stable this variant is.
// Higher = more stable (consecutive successes, low fail rate).
func (f *FeatureVector) StabilityScore() float64 {
	total := f.TotalRequests.Load()
	if total == 0 {
		return 0.5
	}

	// Consecutive success bonus
	consec := f.ConsecutiveOK.Load()
	consecBonus := math.Min(float64(consec)/10.0, 1.0) // max bonus at 10 consecutive

	// Recency penalty (old data is less reliable)
	lastSeen := f.LastSeen.Load()
	if lastSeen == 0 {
		return 0.3
	}
	age := time.Since(time.Unix(0, lastSeen)).Hours()
	recencyPenalty := math.Max(0, 1.0-age/168.0) // linear decay over 1 week

	// Fail penalty
	failRate := float64(f.FailCount.Load()) / float64(total)
	failPenalty := 1.0 - failRate

	return (consecBonus*0.4 + recencyPenalty*0.3 + failPenalty*0.3)
}

// Score computes the adaptive weight for this variant.
// Formula: 0.35 * success_rate + 0.25 * rtt_score + 0.20 * layout_rate + 0.20 * stability
func (f *FeatureVector) Score() float64 {
	successRate := f.SuccessRate()

	// RTT score: normalized (lower RTT = higher score)
	avgRTT := f.AvgRTT()
	rttScore := 1.0 / (1.0 + avgRTT/100.0) // 100ms = 0.5, 0ms = 1.0, 1000ms = 0.09

	layoutRate := f.LayoutHitRate()
	stability := f.StabilityScore()

	return 0.35*successRate + 0.25*rttScore + 0.20*layoutRate + 0.20*stability
}

// ScoringEngine manages scoring for all variants of a target.
type ScoringEngine struct {
	mu       sync.RWMutex
	variants map[uint64]*FeatureVector // fingerprint → features
}

// NewScoringEngine creates a new scoring engine.
func NewScoringEngine() *ScoringEngine {
	return &ScoringEngine{
		variants: make(map[uint64]*FeatureVector),
	}
}

// GetOrCreate returns the feature vector for a fingerprint, creating if needed.
func (e *ScoringEngine) GetOrCreate(fp uint64) *FeatureVector {
	e.mu.Lock()
	defer e.mu.Unlock()
	if fv, ok := e.variants[fp]; ok {
		return fv
	}
	fv := &FeatureVector{}
	e.variants[fp] = fv
	return fv
}

// Get returns the feature vector for a fingerprint, or nil.
func (e *ScoringEngine) Get(fp uint64) *FeatureVector {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.variants[fp]
}

// Ranked returns fingerprints sorted by score (highest first).
func (e *ScoringEngine) Ranked() []uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	type scored struct {
		fp    uint64
		score float64
	}
	var items []scored
	for fp, fv := range e.variants {
		items = append(items, scored{fp, fv.Score()})
	}

	// Simple insertion sort (small N)
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].score > items[j-1].score; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}

	result := make([]uint64, len(items))
	for i, item := range items {
		result[i] = item.fp
	}
	return result
}

// Top returns the fingerprint with the highest score.
func (e *ScoringEngine) Top() uint64 {
	ranked := e.Ranked()
	if len(ranked) == 0 {
		return 0
	}
	return ranked[0]
}

// Remove removes a fingerprint from scoring.
func (e *ScoringEngine) Remove(fp uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.variants, fp)
}

// Len returns the number of tracked fingerprints.
func (e *ScoringEngine) Len() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.variants)
}

// ScoreReport returns a human-readable breakdown of scores.
func (e *ScoringEngine) ScoreReport() string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := "Scoring Engine Report:\n"
	for fp, fv := range e.variants {
		result += formatScoringLine(fp, fv)
	}
	return result
}

func formatScoringLine(fp uint64, fv *FeatureVector) string {
	successRate := fv.SuccessRate()
	avgRTT := fv.AvgRTT()
	layoutRate := fv.LayoutHitRate()
	stability := fv.StabilityScore()
	score := fv.Score()

	rttScore := 1.0 / (1.0 + avgRTT/100.0)

	return formatScoreEntry(fp, successRate, rttScore, layoutRate, stability, score)
}

func formatScoreEntry(fp uint64, successRate, rttScore, layoutRate, stability, score float64) string {
	return formatLine(
		fp,
		successRate*100,
		rttScore*100,
		layoutRate*100,
		stability*100,
		score*100,
	)
}

func formatLine(fp uint64, success, rtt, layout, stability, total float64) string {
	return formatFP(fp) + ": success=" + formatPct(success) +
		" rtt=" + formatPct(rtt) +
		" layout=" + formatPct(layout) +
		" stability=" + formatPct(stability) +
		" total=" + formatPct(total) + "\n"
}

func formatFP(fp uint64) string {
	return "fp=" + formatUint64(fp)
}

func formatPct(val float64) string {
	return formatFloat(val) + "%"
}

func formatFloat(val float64) string {
	return formatInt(int(val))
}

func formatInt(val int) string {
	if val < 0 {
		return "-" + formatUint(uint(-val))
	}
	return formatUint(uint(val))
}

func formatUint(val uint) string {
	if val == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	for val > 0 {
		digits = append([]byte{byte('0' + val%10)}, digits...)
		val /= 10
	}
	return string(digits)
}

func formatUint64(val uint64) string {
	return formatUint(uint(val))
}
