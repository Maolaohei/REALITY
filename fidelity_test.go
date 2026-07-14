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
	minimal := GetCertPlan(0, false, RecordModeSplit)
	if minimal == nil {
		t.Fatal("nil minimal")
	}

	// Large RSA-like outer cert records must grow and still fit budget.
	for _, budget := range []int{1500, 2500, 4000} {
		ResetCertPlanCacheForTesting()
		plan := GetCertPlan(budget, false, RecordModeSplit)
		if plan == nil {
			t.Fatalf("budget=%d nil", budget)
		}
		if !certPlanFitsBudget(plan, budget) {
			t.Fatalf("budget=%d does not fit inner=%d", budget, plan.InnerMsgLen)
		}
		maxInner := MaxCertInnerForBudget(budget)
		if plan.InnerMsgLen <= minimal.InnerMsgLen {
			t.Fatalf("budget=%d expected growth: plan=%d minimal=%d", budget, plan.InnerMsgLen, minimal.InnerMsgLen)
		}
		// Fill at least 70% of usable inner capacity (safety margin is 32 bytes).
		// Residual may remain for AEAD record padding; do not require 100%.
		minFill := (maxInner * 7) / 10
		if plan.InnerMsgLen < minFill {
			t.Fatalf("budget=%d underfilled: inner=%d minFill=%d maxInner=%d",
				budget, plan.InnerMsgLen, minFill, maxInner)
		}
		// Materialized length must match estimate and stay under maxInner.
		authKey := make([]byte, 32)
		chain, err := MaterializeCert(plan, authKey, nil, nil, nil)
		if err != nil {
			t.Fatalf("budget=%d materialize: %v", budget, err)
		}
		m := estimateCertMsgLen(chain[0], chain[1:])
		if m > maxInner {
			t.Fatalf("budget=%d materialized %d > max %d", budget, m, maxInner)
		}
		if m != plan.InnerMsgLen {
			t.Fatalf("budget=%d materialize len %d != plan.InnerMsgLen %d", budget, m, plan.InnerMsgLen)
		}
	}
}

func TestCertPlan_AuthInvariantEd25519HMAC(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	// Grown chain still authenticates via leaf Ed25519 HMAC only.
	plan := GetCertPlan(3000, false, RecordModeSplit)
	authKey := make([]byte, 32)
	for i := range authKey {
		authKey[i] = byte(i + 3)
	}
	chain, err := MaterializeCert(plan, authKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) < 1 {
		t.Fatal("empty chain")
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("leaf must remain Ed25519")
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	if !hmac.Equal(h.Sum(nil), cert.Signature) {
		t.Fatal("HMAC slot mismatch on grown cert")
	}
	// P2 metadata: not bare Serial=1 / zero times.
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		t.Fatal("expected non-trivial serial")
	}
	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() || !cert.NotAfter.After(cert.NotBefore) {
		t.Fatal("expected realistic validity window")
	}
	if len(cert.DNSNames) == 0 && cert.Subject.CommonName == "" {
		t.Fatal("expected SAN or CN")
	}
	// Fillers (if any) are not auth material; ensure they parse.
	for i := 1; i < len(chain); i++ {
		if _, err := x509.ParseCertificate(chain[i]); err != nil {
			t.Fatalf("filler[%d] parse: %v", i, err)
		}
	}
}

func TestCoalescedCertBudget_Math(t *testing.T) {
	if CoalescedCertBudget(400) != 0 {
		t.Fatal("small R2 must yield 0 residual")
	}
	if CoalescedCertBudget(512) != 0 {
		t.Fatal("boundary R2 must yield 0 residual")
	}
	// Large coalesced R2 must leave room for a non-trivial cert after EE+CV+Finished.
	b := CoalescedCertBudget(2500)
	if b < 500 {
		t.Fatalf("expected residual cert budget, got %d", b)
	}
	// Invariant: residual + overhead + framing <= R2 outer.
	const aeadTag = 16
	const contentType = 1
	maxPlain := 2500 - recordHeaderLen - contentType - aeadTag
	if b+coalescedEECVFinishedOverhead+coalescedSafetyInner > maxPlain {
		t.Fatalf("budget overshoots plain capacity: cert=%d overhead=%d safety=%d maxPlain=%d",
			b, coalescedEECVFinishedOverhead, coalescedSafetyInner, maxPlain)
	}
}

func TestCertPlan_CoalescedResidualGrowth(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	r2 := 3000
	budget := CoalescedCertBudget(r2)
	if budget <= 0 {
		t.Fatalf("no residual for r2=%d", r2)
	}
	plan := GetCertPlan(budget, false, RecordModeCoalesced)
	if plan == nil {
		t.Fatal("nil plan")
	}
	if !certPlanFitsInnerBudget(plan, budget) {
		t.Fatalf("plan inner %d exceeds residual %d", plan.InnerMsgLen, budget)
	}
	minimal := GetCertPlan(0, false, RecordModeCoalesced)
	if plan.InnerMsgLen <= minimal.InnerMsgLen {
		t.Fatalf("expected coalesced residual growth: plan=%d min=%d budget=%d",
			plan.InnerMsgLen, minimal.InnerMsgLen, budget)
	}
	// Outer coalesced padding must remain non-negative with conservative overhead.
	const aeadTag = 16
	const contentType = 1
	plain := plan.InnerMsgLen + coalescedEECVFinishedOverhead
	outerNeed := recordHeaderLen + plain + contentType + aeadTag
	if outerNeed > r2 {
		t.Fatalf("would overshoot R2: need=%d r2=%d (padding would be negative)", outerNeed, r2)
	}
}

func TestClassifyClientHello_V3_ExtensionBits(t *testing.T) {
	if CHClassVersion != 3 {
		t.Fatalf("expected CHClassVersion=3 got %d", CHClassVersion)
	}
	base := &clientHelloMsg{
		cipherSuites:                 []uint16{0x1301, 0x1302},
		supportedCurves:              []CurveID{X25519},
		keyShares:                    []keyShare{{group: X25519, data: make([]byte, 32)}},
		supportedVersions:            []uint16{VersionTLS13},
		supportedSignatureAlgorithms: []SignatureScheme{Ed25519},
		alpnProtocols:                []string{"h2"},
		serverName:                   "a.example",
	}
	a := ClassifyClientHello(base)
	// SCT presence should change class (coarse bit).
	withSCT := *base
	withSCT.scts = true
	if ClassifyClientHello(&withSCT) == a {
		t.Fatal("scts bit should change class")
	}
	// OCSP presence should change class.
	withOCSP := *base
	withOCSP.ocspStapling = true
	if ClassifyClientHello(&withOCSP) == a {
		t.Fatal("ocsp bit should change class")
	}
	// Extension order is not modeled; only presence. Same fields => same class.
	if ClassifyClientHello(base) != a {
		t.Fatal("stable class expected")
	}
}

func BenchmarkMaterializeCert(b *testing.B) {
	if initErr != nil {
		b.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	plan := GetCertPlan(2500, false, RecordModeSplit)
	authKey := make([]byte, 32)
	for i := range authKey {
		authKey[i] = byte(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := MaterializeCert(plan, authKey, nil, nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}


func TestDestCertMeta_MaterializeLeafFields(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	ResetDestCertMetaForTesting()
	meta := &DestCertMeta{
		CN:           "cdn.example.net",
		DNSNames:     []string{"cdn.example.net", "www.cdn.example.net"},
		Organization: "Example Org",
		NotBefore:    time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		ChainDepth:   2,
		ChainLens:    []int{900, 1100},
		LeafLen:      900,
	}
	NoteDestCertMeta("cdn.example.net:443", meta)
	plan := GetCertPlanFor(0, false, RecordModeSplit, "cdn.example.net:443", nil)
	if plan == nil {
		t.Fatal("nil plan")
	}
	authKey := make([]byte, 32)
	for i := range authKey {
		authKey[i] = byte(i + 3)
	}
	chain, err := MaterializeCert(plan, authKey, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "cdn.example.net" {
		t.Fatalf("CN=%q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Example Org" {
		t.Fatalf("Org=%v", cert.Subject.Organization)
	}
	found := false
	for _, d := range cert.DNSNames {
		if d == "cdn.example.net" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("SAN missing: %v", cert.DNSNames)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("not ed25519")
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	if !hmac.Equal(h.Sum(nil), cert.Signature) {
		t.Fatal("HMAC auth broken under dest meta")
	}
}

func TestCertShapeHint_PrefersDestDepth(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	ResetDestCertMetaForTesting()
	meta := &DestCertMeta{CN: "leafonly.example", ChainDepth: 1, ChainLens: []int{800}}
	NoteDestCertMeta("leafonly.example:443", meta)
	budget := 4000
	plan := GetCertPlanFor(budget, false, RecordModeSplit, "leafonly.example:443", ShapeHintFromMeta(meta))
	if plan == nil {
		t.Fatal("nil plan")
	}
	if len(plan.ChainDERs) > 0 {
		t.Fatalf("expected no intermediates under depth=1, got %d", len(plan.ChainDERs))
	}
}

func TestSoftClassifyClientHello_DualKey(t *testing.T) {
	base := &clientHelloMsg{
		cipherSuites:                 []uint16{0x1301, 0x1302},
		supportedCurves:              []CurveID{X25519},
		keyShares:                    []keyShare{{group: X25519, data: make([]byte, 32)}},
		supportedVersions:            []uint16{VersionTLS13},
		supportedSignatureAlgorithms: []SignatureScheme{Ed25519},
		alpnProtocols:                []string{"h2"},
		serverName:                   "soft.example",
	}
	exactNone := ClassifyClientHello(base)
	softNone := SoftClassifyClientHello(base)
	if softNone == "" || softNone[:2] != "s:" {
		t.Fatalf("soft class missing s: prefix: %q", softNone)
	}
	if softNone == exactNone {
		t.Fatal("soft class must differ from exact (prefix)")
	}
	withSCT := *base
	withSCT.scts = true
	withOCSP := *base
	withOCSP.ocspStapling = true
	if ClassifyClientHello(&withSCT) == exactNone {
		t.Fatal("exact SCT should differ")
	}
	if ClassifyClientHello(&withOCSP) == exactNone {
		t.Fatal("exact OCSP should differ")
	}
	softSCT := SoftClassifyClientHello(&withSCT)
	softOCSP := SoftClassifyClientHello(&withOCSP)
	if softSCT != softOCSP {
		t.Fatalf("soft should collapse SCT/OCSP: %q vs %q", softSCT, softOCSP)
	}
	if softSCT == softNone {
		t.Fatal("soft with SCT/OCSP should differ from no-status soft")
	}
	key := CacheKeyV2("d:443", "sni", "h2", VersionTLS13, softSCT)
	if !isSoftCacheKey(key) {
		t.Fatal("expected soft cache key")
	}
	exactKey := CacheKeyV2("d:443", "sni", "h2", VersionTLS13, exactNone)
	if isSoftCacheKey(exactKey) {
		t.Fatal("exact key must not be soft")
	}
}

func TestLookupAmortizeSoft_L1OnlyNeverL2(t *testing.T) {
	m := NewCacheManager()
	dest := "soft-l2.example:443"
	sni := "soft-l2.example"
	alpn := "h2"
	exact := "c:exact-test"
	soft := "s:soft-test"
	p := &RealityProfile{
		RecordLens:          [7]int{200, 6, 40, 500, 100, 60, 0},
		CipherSuite:         0x1301,
		KeyShareGroup:       X25519,
		TLSVersion:          VersionTLS13,
		ALPN:                alpn,
		Dest:                dest,
		ServerName:          sni,
		CHClass:             soft,
		Evidence:            10,
		LiveEvidence:        10,
		Stability:           10,
		ServerHelloTemplate: []byte{0x01, 0x02},
		Source:              "live",
		CapturedAt:          time.Now(),
		RecordMode:          RecordModeSplit,
	}
	softKey := CacheKeyV2(dest, sni, alpn, VersionTLS13, soft)
	m.StoreObservation(softKey, p)
	res := m.LookupAmortizeSoft(AmortizeAuto, dest, sni, alpn, VersionTLS13, exact, soft, 0x1301, X25519)
	if res.Path != PathL1 {
		t.Fatalf("soft dual-key want L1 got %v", res.Path)
	}
	if res.Profile == nil {
		t.Fatal("nil profile on soft hit")
	}
	res2 := m.LookupAmortize(AmortizeAuto, dest, sni, alpn, VersionTLS13, soft, 0x1301, X25519)
	if res2.Path == PathL2 {
		t.Fatal("soft cache key must never promote L2")
	}
}

func TestMeasureCoalescedFlightOverhead_Constants(t *testing.T) {
	ee, cv, fin, head, total, safety := MeasureCoalescedFlightOverhead()
	if ee != 40 || cv != 72 || fin != 36 || head != 40 {
		t.Fatalf("components ee=%d cv=%d fin=%d head=%d", ee, cv, fin, head)
	}
	if total != 188 {
		t.Fatalf("total=%d want 188", total)
	}
	if safety != 48 {
		t.Fatalf("safety=%d want 48", safety)
	}
	if total != ee+cv+fin+head {
		t.Fatal("total mismatch sum")
	}
}

func TestCertPlan_MLDSAGrowthPastMinimal(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	minimal := GetCertPlan(0, true, RecordModeSplit)
	if minimal == nil {
		t.Fatal("nil minimal mldsa")
	}
	if minimal.MLDSAOffset < 0 {
		t.Fatal("minimal mldsa offset missing")
	}
	plan := GetCertPlan(4500, true, RecordModeSplit)
	if plan == nil {
		t.Fatal("nil grown mldsa")
	}
	if plan.InnerMsgLen <= minimal.InnerMsgLen {
		t.Fatalf("expected ML-DSA growth under large budget: plan=%d min=%d", plan.InnerMsgLen, minimal.InnerMsgLen)
	}
	if plan.MLDSAOffset < 0 {
		t.Fatal("grown plan lost MLDSA offset")
	}
	if !certPlanFitsBudget(plan, 4500) {
		t.Fatalf("grown plan overshoots budget: inner=%d", plan.InnerMsgLen)
	}
	authKey := make([]byte, 32)
	chain, err := MaterializeCert(plan, authKey, nil, []byte{1}, []byte{2})
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
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatal("not ed25519 after ML-DSA growth")
	}
}

func TestWarmCertPlansForDest_PopulatesCache(t *testing.T) {
	if initErr != nil {
		t.Fatalf("init: %v", initErr)
	}
	ResetCertPlanCacheForTesting()
	ResetDestCertMetaForTesting()
	NoteDestCertMeta("warm.example:443", &DestCertMeta{CN: "warm.example", ChainDepth: 2})
	before := certPlanWarmCount.Load()
	WarmCertPlansForDest("warm.example:443")
	after := certPlanWarmCount.Load()
	if after <= before {
		t.Fatal("warm counter did not advance")
	}
	p1 := GetCertPlanFor(1500, false, RecordModeSplit, "warm.example:443", nil)
	p2 := GetCertPlanFor(1500, false, RecordModeSplit, "warm.example:443", nil)
	if p1 == nil || p2 == nil {
		t.Fatal("nil plan after warm")
	}
	if p1 != p2 {
		t.Fatal("expected cached plan pointer reuse")
	}
}

func TestTruncatedPlanTime_MinuteStable(t *testing.T) {
	old := certPlanTimeNow
	defer func() { certPlanTimeNow = old }()
	certPlanTimeNow = func() time.Time {
		return time.Date(2026, 7, 15, 12, 34, 56, 789, time.UTC)
	}
	got := truncatedPlanTime()
	want := time.Date(2026, 7, 15, 12, 34, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
