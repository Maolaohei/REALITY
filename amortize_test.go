package reality

import (
	"testing"
	"time"
)

func TestClassifyClientHello_Stable(t *testing.T) {
	ch := &clientHelloMsg{
		cipherSuites:      []uint16{0x1301, 0x1302},
		supportedCurves:   []CurveID{X25519, CurveP256},
		keyShares:         []keyShare{{group: X25519, data: make([]byte, 32)}},
		supportedVersions: []uint16{VersionTLS13},
		alpnProtocols:     []string{"h2"},
	}
	a := ClassifyClientHello(ch)
	b := ClassifyClientHello(ch)
	if a == "" || a != b {
		t.Fatalf("unstable class: %q vs %q", a, b)
	}
	ch2 := *ch
	ch2.alpnProtocols = []string{"http/1.1"}
	if ClassifyClientHello(&ch2) == a {
		t.Fatal("ALPN change should change chClass")
	}
}

func TestCacheKeyV2_Parse(t *testing.T) {
	k := CacheKeyV2("1.2.3.4:443", "www.example.com", "h2", VersionTLS13, "abcd")
	d, sn, alpn, ver, ch, ok := ParseCacheKeyV2(k)
	if !ok {
		t.Fatal("expected v2 parse ok")
	}
	if d != "1.2.3.4:443" || sn != "www.example.com" || alpn != "h2" || ver != VersionTLS13 || ch != "abcd" {
		t.Fatalf("parse mismatch: %v %v %v %x %v", d, sn, alpn, ver, ch)
	}
	if IsLegacyCacheKey(k) {
		t.Fatal("v2 should not be legacy")
	}
	legacy := CacheKey("www.example.com", "h2", VersionTLS13)
	if !IsLegacyCacheKey(legacy) {
		t.Fatal("expected legacy")
	}
}

func TestLookupAmortize_L1AndL2(t *testing.T) {
	m := NewCacheManager()
	chClass := "class1"
	key := CacheKeyV2("10.0.0.1:443", "sni.example", "h2", VersionTLS13, chClass)
	tpl := make([]byte, 80)
	tpl[0] = typeServerHello
	p := &RealityProfile{
		RecordLens:          [7]int{100, 6, 40, 1000, 200, 50, 0},
		CipherSuite:         0x1301,
		ALPN:                "h2",
		TLSVersion:          VersionTLS13,
		CapturedAt:          time.Now(),
		Dest:                "10.0.0.1:443",
		ServerName:          "sni.example",
		CHClass:             chClass,
		KeyShareGroup:       X25519,
		ServerHelloTemplate: tpl,
		ShapeHash:           computeShapeHash(0x1301, X25519, 100, len(tpl)),
		Evidence:            MinL2Evidence,
		Source:              "live",
	}
	m.StoreObservation(key, p)

	res := m.LookupAmortize(AmortizeAuto, "10.0.0.1:443", "sni.example", "h2", VersionTLS13, chClass, 0, 0)
	if res.Path != PathL2 {
		t.Fatalf("want L2, got %s", res.Path)
	}

	res = m.LookupAmortize(AmortizeL1, "10.0.0.1:443", "sni.example", "h2", VersionTLS13, chClass, 0x1301, X25519)
	if res.Path != PathL1 {
		t.Fatalf("want L1, got %s", res.Path)
	}

	res = m.LookupAmortize(AmortizeL0, "10.0.0.1:443", "sni.example", "h2", VersionTLS13, chClass, 0x1301, X25519)
	if res.Path != PathL0 {
		t.Fatalf("want L0, got %s", res.Path)
	}

	p2 := *p
	p2.Evidence = 1
	m.HotSwapProfile(key, &p2)
	res = m.LookupAmortize(AmortizeAuto, "10.0.0.1:443", "sni.example", "h2", VersionTLS13, chClass, 0, 0)
	if res.Path == PathL2 {
		t.Fatal("low evidence must not L2")
	}
}

func TestStoreObservation_EvidenceAndMismatch(t *testing.T) {
	m := NewCacheManager()
	key := CacheKeyV2("1.1.1.1:443", "a.com", "h2", VersionTLS13, "c")
	base := &RealityProfile{
		RecordLens:    [7]int{100, 6, 40, 1000, 200, 50, 0},
		CipherSuite:   0x1301,
		ALPN:          "h2",
		TLSVersion:    VersionTLS13,
		CapturedAt:    time.Now(),
		KeyShareGroup: X25519,
		Evidence:      1,
	}
	m.StoreObservation(key, base)
	got, _ := m.GetProfile(key)
	if got == nil || got.Evidence != 1 {
		t.Fatalf("evidence1=%v", got)
	}
	m.StoreObservation(key, base)
	got, _ = m.GetProfile(key)
	if got == nil || got.Evidence < 2 {
		t.Fatalf("evidence should grow, got %#v", got)
	}
	bad := *base
	bad.CipherSuite = 0x1302
	m.StoreObservation(key, &bad)
	if p, _ := m.GetProfile(key); p != nil {
		t.Fatal("suspect should not serve")
	}
}

func TestQuarantine_BlocksLookup(t *testing.T) {
	m := NewCacheManager()
	key := CacheKeyV2("2.2.2.2:443", "b.com", "h2", VersionTLS13, "c")
	p := &RealityProfile{
		RecordLens:          [7]int{100, 6, 40, 1000, 200, 50, 0},
		CipherSuite:         0x1301,
		ALPN:                "h2",
		TLSVersion:          VersionTLS13,
		CapturedAt:          time.Now(),
		KeyShareGroup:       X25519,
		ServerHelloTemplate: make([]byte, 40),
		ShapeHash:           computeShapeHash(0x1301, X25519, 100, 40),
		Evidence:            5,
	}
	m.StoreObservation(key, p)
	m.Quarantine(key, "test")
	res := m.LookupAmortize(AmortizeAuto, "2.2.2.2:443", "b.com", "h2", VersionTLS13, "c", 0, 0)
	if res.Path != PathL0 {
		t.Fatalf("quarantined should force L0, got %s", res.Path)
	}
}

func TestFindCachedProfileByDest_LegacyStillWorks(t *testing.T) {
	m := NewCacheManager()
	key := CacheKey("www.microsoft.com", "h2", VersionTLS13)
	m.StoreProfile(key, &RealityProfile{
		RecordLens:  [7]int{1215, 6, 41, 8273, 286, 74, 0},
		CipherSuite: 0x1301,
		ALPN:        "h2",
		TLSVersion:  VersionTLS13,
		CapturedAt:  time.Now(),
	})
	lens, ver, ok := m.FindCachedProfileByDest("1.2.3.4:443", "www.microsoft.com", 0x1301, "h2", VersionTLS13)
	if !ok {
		t.Fatal("expected legacy hit")
	}
	if lens[0] != 1215 || ver != VersionTLS13 {
		t.Fatalf("bad result %v %x", lens, ver)
	}
}

func TestInvalidateAndReprobe_DoesNotWipeUnrelated(t *testing.T) {
	m := NewCacheManager()
	k1 := CacheKey("a.com", "h2", VersionTLS13)
	k2 := CacheKey("b.com", "h2", VersionTLS13)
	m.StoreProfile(k1, &RealityProfile{RecordLens: [7]int{100, 6, 40}, CipherSuite: 0x1301, ALPN: "h2", TLSVersion: VersionTLS13, CapturedAt: time.Now()})
	m.StoreProfile(k2, &RealityProfile{RecordLens: [7]int{110, 6, 40}, CipherSuite: 0x1301, ALPN: "h2", TLSVersion: VersionTLS13, CapturedAt: time.Now()})
	m.InvalidateAndReprobe("1.1.1.1:443", "a.com", "h2")
	if p, _ := m.GetProfile(k1); p != nil {
		t.Fatal("a.com should be invalidated")
	}
	if p, _ := m.GetProfile(k2); p == nil {
		t.Fatal("b.com should remain")
	}
}

func TestProfileL2Eligible_Gates(t *testing.T) {
	p := &RealityProfile{
		RecordLens:          [7]int{100, 6, 40, 1000, 200, 50, 0},
		CipherSuite:         0x1301,
		KeyShareGroup:       X25519,
		ServerHelloTemplate: make([]byte, 20),
		Evidence:            MinL2Evidence,
		ShapeHash:           computeShapeHash(0x1301, X25519, 100, 20),
		CapturedAt:          time.Now(),
	}
	if !profileL2Eligible(p) {
		t.Fatal("should be eligible")
	}
	p.AcceptsHRR = true
	if profileL2Eligible(p) {
		t.Fatal("HRR not eligible")
	}
	p.AcceptsHRR = false
	p.ShapeHash = 0
	if profileL2Eligible(p) {
		t.Fatal("missing ShapeHash not eligible")
	}
	p.ShapeHash = computeShapeHash(0x1301, X25519, 100, 20)
	p.CapturedAt = time.Now().Add(-MaxL2ProfileAge - time.Minute)
	if profileL2Eligible(p) {
		t.Fatal("stale CapturedAt not eligible for L2")
	}
}

func TestWrapHandshakeRecord(t *testing.T) {
	msg := []byte{1, 2, 3, 4}
	rec := wrapHandshakeRecord(msg, VersionTLS10)
	if len(rec) != recordHeaderLen+len(msg) {
		t.Fatalf("len=%d", len(rec))
	}
	if rec[0] != byte(recordTypeHandshake) {
		t.Fatal("type")
	}
	if bigEndianUint16(rec[1:3]) != VersionTLS10 {
		t.Fatal("vers")
	}
}

func TestResolveAmortizeMode_Default(t *testing.T) {
	if ResolveAmortizeMode(0) != AmortizeL2 {
		t.Fatalf("zero mode should resolve to L2, got %v", ResolveAmortizeMode(0))
	}
	if ResolveAmortizeMode(AmortizeDefault) != AmortizeL2 {
		t.Fatal("AmortizeDefault should resolve to L2")
	}
	if ResolveAmortizeMode(AmortizeL0) != AmortizeL0 {
		t.Fatal("explicit L0 must stay L0")
	}
	if ResolveAmortizeMode(AmortizeL1) != AmortizeL1 {
		t.Fatal("explicit L1 must stay L1")
	}
}

func TestQuarantine_CalibrationLadder(t *testing.T) {
	m := NewCacheManager()
	key := CacheKeyV2("3.3.3.3:443", "c.com", "h2", VersionTLS13, "c")
	tpl := make([]byte, 40)
	tpl[0] = typeServerHello
	base := &RealityProfile{
		RecordLens:          [7]int{100, 6, 40, 1000, 200, 50, 0},
		CipherSuite:         0x1301,
		ALPN:                "h2",
		TLSVersion:          VersionTLS13,
		CapturedAt:          time.Now(),
		Dest:                "3.3.3.3:443",
		ServerName:          "c.com",
		CHClass:             "c",
		KeyShareGroup:       X25519,
		ServerHelloTemplate: tpl,
		ShapeHash:           computeShapeHash(0x1301, X25519, 100, len(tpl)),
		Evidence:            5,
		Source:              "live",
	}
	m.StoreObservation(key, base)
	m.Quarantine(key, "test-ladder")

	// Still in cooldown: observation ignored, lookup L0.
	obs := *base
	obs.CapturedAt = time.Now()
	obs.Evidence = 1
	m.StoreObservation(key, &obs)
	res := m.LookupAmortize(AmortizeAuto, "3.3.3.3:443", "c.com", "h2", VersionTLS13, "c", 0, 0)
	if res.Path != PathL0 {
		t.Fatalf("in-cooldown want L0, got %s", res.Path)
	}

	// Expire cooldown and calibrate with live observation.
	val, _ := m.entries.Load(key)
	entry := val.(*ProfileEntry)
	entry.mu.Lock()
	entry.NextRetry = time.Now().Add(-time.Second)
	entry.mu.Unlock()

	obs2 := *base
	obs2.CapturedAt = time.Now()
	obs2.Evidence = 1
	m.StoreObservation(key, &obs2)
	if m.stats.Calibrations.Load() < 1 {
		t.Fatal("expected calibration counter")
	}
	// GetProfile returns (profile, isStale); valid fresh profiles yield isStale=false.
	got, _ := m.GetProfile(key)
	if got == nil || got.Evidence != 1 {
		t.Fatalf("after calibrate evidence want 1, got %#v", got)
	}
	res = m.LookupAmortize(AmortizeAuto, "3.3.3.3:443", "c.com", "h2", VersionTLS13, "c", 0, 0)
	if res.Path == PathL2 {
		t.Fatal("single calibration observation must not L2")
	}
	if res.Path != PathL1 {
		t.Fatalf("want L1 after calibration, got %s", res.Path)
	}

	// Second matching live observation rebuilds L2 eligibility.
	obs3 := *base
	obs3.CapturedAt = time.Now()
	m.StoreObservation(key, &obs3)
	res = m.LookupAmortize(AmortizeAuto, "3.3.3.3:443", "c.com", "h2", VersionTLS13, "c", 0, 0)
	if res.Path != PathL2 {
		t.Fatalf("want L2 after rebuild evidence, got %s", res.Path)
	}
}

func TestProfileL2Eligible_AgeGate_LookupFallsToL1(t *testing.T) {
	m := NewCacheManager()
	chClass := "age1"
	key := CacheKeyV2("9.9.9.9:443", "age.example", "h2", VersionTLS13, chClass)
	tpl := make([]byte, 80)
	tpl[0] = typeServerHello
	p := &RealityProfile{
		RecordLens:          [7]int{100, 6, 40, 1000, 200, 50, 0},
		CipherSuite:         0x1301,
		ALPN:                "h2",
		TLSVersion:          VersionTLS13,
		CapturedAt:          time.Now().Add(-MaxL2ProfileAge - time.Minute),
		Dest:                "9.9.9.9:443",
		ServerName:          "age.example",
		CHClass:             chClass,
		KeyShareGroup:       X25519,
		ServerHelloTemplate: tpl,
		ShapeHash:           computeShapeHash(0x1301, X25519, 100, len(tpl)),
		Evidence:            MinL2Evidence + 3,
		Source:              "live",
	}
	m.StoreObservation(key, p)
	// Force age after store (StoreObservation uses obs.CapturedAt).
	if gp, _ := m.GetProfile(key); gp != nil {
		gp.CapturedAt = time.Now().Add(-MaxL2ProfileAge - time.Minute)
		m.HotSwapProfile(key, gp)
	}
	res := m.LookupAmortize(AmortizeAuto, "9.9.9.9:443", "age.example", "h2", VersionTLS13, chClass, 0, 0)
	if res.Path == PathL2 {
		t.Fatal("aged profile must not L2")
	}
	if res.Path != PathL1 {
		t.Fatalf("want L1 for aged but otherwise valid profile, got %s", res.Path)
	}
}