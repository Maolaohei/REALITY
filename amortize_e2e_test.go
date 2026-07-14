//go:build l2

package reality

import (
	"testing"
	"time"
)

// TestL2_AuthorizedPaths_L0L1L2 is kept as a focused regression for the
// amortize progression (dials: +1,+1,0,0 under default L2 mode).
func TestL2_AuthorizedPaths_L0L1L2(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })

	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})

	var deltas []int64
	for i := 0; i < 4; i++ {
		before := h.Dials()
		c := h.mustDialAuthorized(t)
		// Handshake success is sufficient; best-effort tiny echo.
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Write([]byte("x"))
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		c.Close()
		time.Sleep(40 * time.Millisecond)
		deltas = append(deltas, h.Dials()-before)
		h.report(t, "legacy-conn")
	}
	if h.AuthOK() < 4 {
		t.Fatalf("authOK=%d want 4", h.AuthOK())
	}
	if deltas[0] < 1 || deltas[1] < 1 {
		t.Fatalf("first two should dial, deltas=%v", deltas)
	}
	if deltas[2] != 0 || deltas[3] != 0 {
		t.Fatalf("conn3/4 should zero-dial, deltas=%v l2=%d", deltas, globalCacheManager.stats.L2Hits.Load())
	}
	if globalCacheManager.stats.L2Hits.Load() < 2 {
		t.Fatalf("l2 hits=%d want >=2", globalCacheManager.stats.L2Hits.Load())
	}
}
