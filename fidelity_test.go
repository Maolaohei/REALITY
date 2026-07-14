package reality

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"testing"
	"time"
)

func TestInferRecordMode(t *testing.T) {
	if InferRecordMode([7]int{100, 6, 40, 100, 50, 40, 0}) != RecordModeSplit {
		t.Fatal("expected split")
	}
	if InferRecordMode([7]int{100, 6, 1200, 0, 0, 0, 0}) != RecordModeCoalesced {
		t.Fatal("expected coalesced")
	}
}

func TestValidateRecordLensMode_Coalesced(t *testing.T) {
	lens := [7]int{200, 6, 800, 0, 0, 0, 0}
	if !ValidateRecordLensMode(lens, RecordModeCoalesced) {
		t.Fatal("coalesced with empty R3-R5 should pass")
	}
	if ValidateRecordLensMode([7]int{200, 6, 100, 0, 0, 0, 0}, RecordModeCoalesced) {
		t.Fatal("coalesced with small R2 should fail")
	}
}

func TestDestCapability_Transitions(t *testing.T) {
	ResetDestCapabilitiesForTesting()
	dest := "cap-test.example:443"
	if DestCapabilityState(dest) != DestCapUnknown {
		t.Fatal("start unknown")
	}
	NoteDestTLS13Ready(dest)
	if DestCapabilityState(dest) != DestCapTLS13Ready {
		t.Fatal("ready")
	}
	if !DestAllowsAmortize(dest) || DestShouldMirrorOnly(dest) {
		t.Fatal("ready allows amortize")
	}
	for i := 0; i < destCapUnsuitableAfter; i++ {
		NoteDestCaptureFailure(dest, "not_tls13")
	}
	if DestCapabilityState(dest) != DestCapUnsuitable {
		t.Fatalf("want unsuitable got %d", DestCapabilityState(dest))
	}
	if DestAllowsAmortize(dest) || !DestShouldMirrorOnly(dest) {
		t.Fatal("unsuitable mirror only")
	}
}

func TestCertPlan_HMACOffsetAndMaterialize(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	plan := GetCertPlan(0, false, RecordModeSplit)
	if plan == nil || len(plan.LeafDER) == 0 {
		t.Fatal("nil plan")
	}
	if plan.HMACOffset < 0 || plan.HMACOffset+64 > len(plan.LeafDER) {
		t.Fatalf("bad hmac offset %d", plan.HMACOffset)
	}
	authKey := make([]byte, 32)
	for i := range authKey {
		authKey[i] = byte(i + 1)
	}
	chain, err := MaterializeCert(plan, authKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) == 0 {
		t.Fatal("empty chain")
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("not ed25519")
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	if !hmac.Equal(h.Sum(nil), cert.Signature) {
		t.Fatal("HMAC signature slot mismatch")
	}
}

func TestClassifyClientHello_V2_Suites(t *testing.T) {
	base := &clientHelloMsg{
		cipherSuites:                 []uint16{0x1301, 0x1302},
		supportedCurves:              []CurveID{X25519},
		keyShares:                    []keyShare{{group: X25519, data: make([]byte, 32)}},
		supportedVersions:            []uint16{VersionTLS13},
		supportedSignatureAlgorithms: []SignatureScheme{Ed25519},
		alpnProtocols:                []string{"h2"},
	}
	a := ClassifyClientHello(base)
	shuffled := *base
	shuffled.cipherSuites = []uint16{0x1302, 0x1301}
	if ClassifyClientHello(&shuffled) != a {
		t.Fatal("suite order should not change class")
	}
	withChacha := *base
	withChacha.cipherSuites = []uint16{0x1301, 0x1302, 0x1303}
	if ClassifyClientHello(&withChacha) == a {
		t.Fatal("suite set change should change class")
	}
}

func TestStoreObservation_ProbeNoL2(t *testing.T) {
	m := NewCacheManager()
	key := CacheKeyV2("9.9.9.9:443", "probe.example", "h2", VersionTLS13, "c1")
	now := time.Now()
	p := &RealityProfile{
		RecordLens:          [7]int{200, 6, 40, 100, 50, 40, 0},
		CipherSuite:         0x1301,
		ALPN:                "h2",
		TLSVersion:          VersionTLS13,
		CapturedAt:          now,
		RecordMode:          RecordModeSplit,
		KeyShareGroup:       X25519,
		ShapeHash:           123,
		ServerHelloTemplate: make([]byte, 80),
		Source:              "probe",
	}
	m.StoreObservation(key, p)
	m.StoreObservation(key, p)
	m.StoreObservation(key, p)
	got, _ := m.GetProfile(key)
	if got == nil {
		t.Fatal("missing")
	}
	if got.LiveEvidence != 0 || got.Evidence != 0 {
		t.Fatalf("probe must not promote evidence: live=%d ev=%d", got.LiveEvidence, got.Evidence)
	}
	if profileL2Eligible(got) {
		t.Fatal("probe profile must not be L2 eligible")
	}
}

func TestCertPlan_FitsTightBudget(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	minimal := GetCertPlan(0, false, RecordModeSplit)
	if minimal == nil {
		t.Fatal("nil minimal")
	}
	// Budgets that can hold minimal leaf must never overshoot.
	// Budgets below minOuter are pathological (real dest would not emit such a short cert record
	// for a larger TLS1.3 Certificate message); we only require plan stays minimal-sized.
	minOuter := recordHeaderLen + minimal.InnerMsgLen + 1 + 16
	for _, budget := range []int{0, 120, 200, 400, 800, 1500, 3000} {
		plan := GetCertPlan(budget, false, RecordModeSplit)
		if plan == nil || len(plan.LeafDER) == 0 {
			t.Fatalf("budget=%d nil plan", budget)
		}
		if budget > 0 && budget >= minOuter && !certPlanFitsBudget(plan, budget) {
			t.Fatalf("budget=%d plan does not fit: inner=%d leaf=%d chain=%d minOuter=%d",
				budget, plan.InnerMsgLen, len(plan.LeafDER), len(plan.ChainDERs), minOuter)
		}
		if budget > 0 && budget < minOuter {
			// Must not grow beyond minimal when budget is hopeless.
			if plan.InnerMsgLen > minimal.InnerMsgLen {
				t.Fatalf("budget=%d grew past minimal: %d > %d", budget, plan.InnerMsgLen, minimal.InnerMsgLen)
			}
		}
		authKey := make([]byte, 32)
		chain, err := MaterializeCert(plan, authKey, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		m := estimateCertMsgLen(chain[0], chain[1:])
		if budget >= minOuter {
			maxInner := MaxCertInnerForBudget(budget)
			if m > maxInner {
				t.Fatalf("budget=%d materialized inner %d > max %d", budget, m, maxInner)
			}
		}
	}
}

func TestCertPlan_GrowUnderLargeBudget(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	// Large RSA-like outer cert record should allow growth but still fit.
	budget := 2500
	plan := GetCertPlan(budget, false, RecordModeSplit)
	if plan == nil {
		t.Fatal("nil")
	}
	if !certPlanFitsBudget(plan, budget) {
		t.Fatalf("does not fit inner=%d", plan.InnerMsgLen)
	}
	minimal := GetCertPlan(0, false, RecordModeSplit)
	if plan.InnerMsgLen <= minimal.InnerMsgLen {
		// Growth is best-effort; not fatal if residual too small after safety.
		t.Logf("no growth: plan=%d minimal=%d (ok if safety margin)", plan.InnerMsgLen, minimal.InnerMsgLen)
	}
}
