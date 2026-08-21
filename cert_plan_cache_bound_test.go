package reality

import "testing"

func TestCertPlanCacheBoundedAcrossBudgets(t *testing.T) {
	ResetCertPlanCacheForTesting()
	t.Cleanup(ResetCertPlanCacheForTesting)

	for budget := 512; budget < 512+certPlanCacheMaxEntries*4; budget++ {
		if p := GetCertPlan(budget, false, RecordModeSplit); p == nil {
			t.Fatalf("nil plan for budget %d", budget)
		}
	}
	certPlanMu.RLock()
	n := len(certPlanCache)
	certPlanMu.RUnlock()
	if n > certPlanCacheMaxEntries {
		t.Fatalf("cert plan cache entries=%d exceeds bound=%d", n, certPlanCacheMaxEntries)
	}
}
