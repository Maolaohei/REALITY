package reality

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// genTestCert generates a unique TLS certificate for mock servers.
func genTestCert(org string) tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{Organization: []string{org}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// startMockTLSServer starts a TLS server that accepts connections and discards data.
func startMockTLSServer(t *testing.T, cert tls.Certificate) (string, func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 65536)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func tCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestRefreshProbe_Success verifies that probeTarget succeeds against a
// reachable target and does not MarkNegative.
func TestRefreshProbe_Success(t *testing.T) {
	cert := genTestCert("ProbeSuccess")
	addr, closeServer := startMockTLSServer(t, cert)
	defer closeServer()

	cacheKey := CacheKey(addr, "localhost", "h2", VersionTLS13)
	result, err := ProbeTargetViaUTLS(tCtx(t), addr, "localhost", 2, 0)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	fp := computeFingerprint(result.CipherSuite, "h2", result.RecordLens[0], result.RecordLens[2])
	globalCacheManager.StoreProfile(cacheKey, &RealityProfile{
		RecordLens:   result.RecordLens,
		Fingerprint:  fp,
		CipherSuite:  result.CipherSuite,
		ALPN:         "h2",
		TLSVersion:   VersionTLS13,
		RecordCount:  result.RecordCount,
		CapturedAt:   time.Now(),
	})
	t.Cleanup(func() { globalCacheManager.InvalidateProfile(cacheKey) })

	negBefore := globalCacheManager.stats.NegativeHits.Load()

	m := &RefreshManager{
		targets: make(map[string]*refreshEntry),
		sem:     make(chan struct{}, 8),
	}
	entry := &refreshEntry{
		dest:     addr,
		alpn:     "h2",
		cacheKey: cacheKey,
		stopCh:   make(chan struct{}),
	}
	ok := m.probeTarget(addr, "localhost", entry)
	if !ok {
		t.Fatal("probeTarget should succeed against reachable server")
	}
	if globalCacheManager.stats.NegativeHits.Load() > negBefore {
		t.Fatal("probeTarget should not MarkNegative for reachable server")
	}
}

// TestRefreshProbe_UnreachableTarget verifies that probing an unreachable
// target calls MarkNegative and returns false.
func TestRefreshProbe_UnreachableTarget(t *testing.T) {
	dest := "127.0.0.1:1"
	cacheKey := CacheKey(dest, "test", "h2", VersionTLS13)

	m := &RefreshManager{
		targets: make(map[string]*refreshEntry),
		sem:     make(chan struct{}, 8),
	}
	entry := &refreshEntry{
		dest:     dest,
		alpn:     "h2",
		cacheKey: cacheKey,
		stopCh:   make(chan struct{}),
	}

	ok := m.probeTarget(dest, "test", entry)
	if ok {
		t.Fatal("probeTarget should fail against unreachable target")
	}
	// MarkNegative creates a ProfileNegative entry (doesn't increment NegativeHits
	// directly — that happens in GetProfile). Verify the entry state.
	val, exists := globalCacheManager.entries.Load(cacheKey)
	if !exists {
		t.Fatal("MarkNegative should create a cache entry")
	}
	pe := val.(*ProfileEntry)
	pe.mu.Lock()
	state := pe.State
	pe.mu.Unlock()
	if state != ProfileNegative {
		t.Fatalf("entry state = %d, want ProfileNegative (%d)", state, ProfileNegative)
	}
}

// TestRefreshProbe_Debouncing verifies that HotSwap only triggers after
// 2 consecutive identical probe results that differ from cached profile.
// Strategy: pre-populate cache with a fake profile so the real probe always
// enters Phase B debouncing logic.
func TestRefreshProbe_Debouncing(t *testing.T) {
	cert := genTestCert("DebounceServer")
	addr, closeServer := startMockTLSServer(t, cert)
	defer closeServer()

	// Probe the real server to get its actual profile.
	result, err := ProbeTargetViaUTLS(tCtx(t), addr, "localhost", 2, 0)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	// Pre-populate cache with a FAKE profile that differs from the real one.
	// This ensures every probe enters Phase B (change detection).
	cacheKey := CacheKey(addr, "localhost", "h2", VersionTLS13)
	fakeRecordLens := result.RecordLens
	fakeRecordLens[3] = result.RecordLens[3] + 999 // Cert record length guaranteed different
	fakeCS := result.CipherSuite
	if fakeCS == 0x1301 {
		fakeCS = 0x1302 // Use different cipher suite
	} else {
		fakeCS = 0x1301
	}
	fpFake := computeFingerprint(fakeCS, "h2", fakeRecordLens[0], fakeRecordLens[2])
	globalCacheManager.StoreProfile(cacheKey, &RealityProfile{
		RecordLens:   fakeRecordLens,
		Fingerprint:  fpFake,
		CipherSuite:  fakeCS,
		ALPN:         "h2",
		TLSVersion:   VersionTLS13,
		RecordCount:  4,
		CapturedAt:   time.Now(),
	})
	t.Cleanup(func() { globalCacheManager.InvalidateProfile(cacheKey) })

	initialSwaps := globalCacheManager.stats.HotSwaps.Load()

	m := &RefreshManager{
		targets: make(map[string]*refreshEntry),
		sem:     make(chan struct{}, 8),
	}
	entry := &refreshEntry{
		dest:     addr,
		alpn:     "h2",
		cacheKey: cacheKey,
		stopCh:   make(chan struct{}),
	}

	// First probe: real result differs from fake cache → enters Phase B.
	// stableCount = 1, no HotSwap yet.
	ok := m.probeTarget(addr, "localhost", entry)
	if !ok {
		t.Fatal("probe should succeed")
	}
	if entry.stableCount != 1 {
		t.Fatalf("stableCount after first probe: %d, want 1", entry.stableCount)
	}
	if globalCacheManager.stats.HotSwaps.Load() != initialSwaps {
		t.Fatal("HotSwap should NOT trigger after only 1 different probe")
	}

	// Second probe: same real result again → stableCount = 2 → HotSwap.
	ok = m.probeTarget(addr, "localhost", entry)
	if !ok {
		t.Fatal("probe should succeed")
	}
	if globalCacheManager.stats.HotSwaps.Load() <= initialSwaps {
		t.Fatal("HotSwap should trigger after 2 consecutive identical different probes")
	}

	// Verify profile updated to real server's profile.
	p, _ := globalCacheManager.GetProfile(cacheKey)
	if p == nil {
		t.Fatal("profile missing after HotSwap")
	}
	if p.CipherSuite != result.CipherSuite {
		t.Errorf("CipherSuite = %x, want %x", p.CipherSuite, result.CipherSuite)
	}
	if p.RecordLens != result.RecordLens {
		t.Errorf("RecordLens = %v, want %v", p.RecordLens, result.RecordLens)
	}
}

// TestRefreshManager_DetectsTargetChange is the full integration test:
// RefreshManager timer → probeAndReschedule → probeTarget → detect change → HotSwap.
// This verifies the complete background refresh lifecycle end-to-end.
func TestRefreshManager_DetectsTargetChange(t *testing.T) {
	cert := genTestCert("FullCycleServer")
	addr, closeServer := startMockTLSServer(t, cert)
	defer closeServer()

	// Probe the real server to get its actual profile.
	result, err := ProbeTargetViaUTLS(tCtx(t), addr, "localhost", 2, 0)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	// Pre-populate cache with a fake profile that differs from the real one.
	cacheKey := CacheKey(addr, "localhost", "h2", VersionTLS13)
	fakeRecordLens := result.RecordLens
	fakeRecordLens[3] = result.RecordLens[3] + 999
	fakeCS := result.CipherSuite
	if fakeCS == 0x1301 {
		fakeCS = 0x1302
	} else {
		fakeCS = 0x1301
	}
	fpFake := computeFingerprint(fakeCS, "h2", fakeRecordLens[0], fakeRecordLens[2])
	globalCacheManager.StoreProfile(cacheKey, &RealityProfile{
		RecordLens:   fakeRecordLens,
		Fingerprint:  fpFake,
		CipherSuite:  fakeCS,
		ALPN:         "h2",
		TLSVersion:   VersionTLS13,
		RecordCount:  4,
		CapturedAt:   time.Now(),
	})
	t.Cleanup(func() { globalCacheManager.InvalidateProfile(cacheKey) })

	initialSwaps := globalCacheManager.stats.HotSwaps.Load()

	// Override refresh intervals for fast cycling.
	oldMin, oldMax := refreshMin, refreshMax
	refreshMin = 100 * time.Millisecond
	refreshMax = 200 * time.Millisecond
	t.Cleanup(func() {
		refreshMin = oldMin
		refreshMax = oldMax
	})

	// Create a fresh RefreshManager (not the global one) for test isolation.
	m := &RefreshManager{
		targets: make(map[string]*refreshEntry),
		sem:     make(chan struct{}, 8),
	}
	m.Start()
	t.Cleanup(m.Stop)

	// Register the target — timer fires in 100-200ms.
	m.AddTarget(addr, "localhost", "h2")

	// Poll for HotSwap. Need 2 probe cycles: first sets stableCount=1,
	// second sets stableCount=2 and triggers HotSwap. Allow 10s for
	// the full cycle (probe + timer reset + second probe).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if globalCacheManager.stats.HotSwaps.Load() > initialSwaps {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if globalCacheManager.stats.HotSwaps.Load() <= initialSwaps {
		t.Fatal("RefreshManager did not trigger HotSwap after target change")
	}

	// Verify the cached profile now matches the real server.
	p, _ := globalCacheManager.GetProfile(cacheKey)
	if p == nil {
		t.Fatal("profile missing after HotSwap")
	}
	if p.CipherSuite != result.CipherSuite {
		t.Errorf("CipherSuite = %x, want %x", p.CipherSuite, result.CipherSuite)
	}
	if p.RecordLens != result.RecordLens {
		t.Errorf("RecordLens = %v, want %v", p.RecordLens, result.RecordLens)
	}

	// Verify probe counters were incremented.
	attempts := globalCacheManager.stats.ProbeAttempts.Load()
	successes := globalCacheManager.stats.ProbeSuccesses.Load()
	if attempts == 0 {
		t.Error("ProbeAttempts should be > 0 after background refresh")
	}
	if successes == 0 {
		t.Error("ProbeSuccesses should be > 0 after successful refresh")
	}
	t.Logf("probe attempts: %d, successes: %d", attempts, successes)
}

// TestRecordLensMatch verifies the tolerance logic for record[6] comparison.
func TestRecordLensMatch(t *testing.T) {
	a := [7]int{100, 6, 200, 300, 400, 500, 600}

	if !recordLensMatch(a, a) {
		t.Fatal("identical should match")
	}

	b := a
	b[6] = 630
	if !recordLensMatch(a, b) {
		t.Fatal("record[6] within tolerance should match")
	}

	c := a
	c[6] = 700
	if recordLensMatch(a, c) {
		t.Fatal("record[6] exceeding tolerance should not match")
	}

	d := a
	d[0] = 99
	if recordLensMatch(a, d) {
		t.Fatal("record[0] difference should not match")
	}
}
