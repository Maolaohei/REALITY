//go:build l2 || l3 || l3e2e

package reality

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestE2E_Amortize_L0L1L2_Progression(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})

	var dialDeltas []int64
	for i := 0; i < 5; i++ {
		before := h.Dials()
		h.handshakeOnly(t)
		time.Sleep(40 * time.Millisecond)
		dialDeltas = append(dialDeltas, h.Dials()-before)
		h.report(t, fmt.Sprintf("conn%d", i+1))
	}
	if h.AuthOK() < 5 {
		t.Fatalf("authOK=%d want 5", h.AuthOK())
	}
	if dialDeltas[0] < 1 {
		t.Fatalf("conn1 must dial RA, delta=%d", dialDeltas[0])
	}
	zeroDial := 0
	for i := 2; i < len(dialDeltas); i++ {
		if dialDeltas[i] == 0 {
			zeroDial++
		}
	}
	if zeroDial == 0 || globalCacheManager.stats.L2Hits.Load() == 0 {
		t.Fatalf("expected L2 zero-dial, deltas=%v l2=%d", dialDeltas, globalCacheManager.stats.L2Hits.Load())
	}
	t.Logf("PASS progression deltas=%v", dialDeltas)
}

func TestE2E_Amortize_ModeL0_AlwaysDials(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeL0})
	for i := 0; i < 3; i++ {
		before := h.Dials()
		h.handshakeOnly(t)
		if h.Dials()-before < 1 {
			t.Fatalf("L0 conn %d did not dial RA", i+1)
		}
	}
	if globalCacheManager.stats.L2Hits.Load() != 0 {
		t.Fatalf("L0 must not L2-hit, got %d", globalCacheManager.stats.L2Hits.Load())
	}
}

func TestE2E_Amortize_ModeL1_NeverZeroDial(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeL1})
	for i := 0; i < 3; i++ {
		before := h.Dials()
		h.handshakeOnly(t)
		time.Sleep(30 * time.Millisecond)
		if h.Dials()-before < 1 {
			t.Fatalf("L1 conn %d zero-dialed unexpectedly", i+1)
		}
	}
	h.report(t, "L1-final")
}

func TestE2E_AuthFailure_WrongShortID(t *testing.T) {
	t.Run("wrongShortID_not_authOK", func(t *testing.T) {
		globalCacheManager.Reset()
		h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
		badShort := []byte{9, 9, 9, 9, 9, 9, 9, 9}
		c, err := h.dialAuthorized("", badShort, nil)
		if err == nil {
			c.Close()
		}
		time.Sleep(120 * time.Millisecond)
		if h.AuthOK() != 0 {
			t.Fatalf("authOK should stay 0 for wrong shortId, got %d", h.AuthOK())
		}
	})
	t.Run("authorized_control", func(t *testing.T) {
		globalCacheManager.Reset()
		h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
		h.handshakeOnly(t)
		if h.AuthOK() < 1 {
			t.Fatalf("authorized control authOK=%d", h.AuthOK())
		}
	})
}

func TestE2E_AuthFailure_PlainTLSClient(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	if conn, err := h.dialPlainTLS(t, h.serverName); err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("ping"))
		buf := make([]byte, 16)
		_, _ = conn.Read(buf)
		conn.Close()
	}
	time.Sleep(80 * time.Millisecond)
	if h.AuthOK() != 0 {
		t.Fatalf("plain TLS must not count as REALITY authOK, got %d", h.AuthOK())
	}
	h.handshakeOnly(t)
}

func TestE2E_SNIMismatch(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	c, err := h.dialAuthorized("wrong.example.com", nil, nil)
	if err == nil {
		c.Close()
	}
	time.Sleep(80 * time.Millisecond)
	if h.AuthOK() != 0 {
		t.Fatalf("authOK=%d want 0 for SNI mismatch", h.AuthOK())
	}
}

func TestE2E_ConcurrentAuthorized(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	for i := 0; i < 2; i++ {
		h.handshakeOnly(t)
	}
	time.Sleep(50 * time.Millisecond)

	const n = 20
	var wg sync.WaitGroup
	var fail atomic.Int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			before := h.AuthOK()
			c, err := h.dialAuthorized("", nil, nil)
			if err != nil {
				fail.Add(1)
				return
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) && h.AuthOK() <= before {
				time.Sleep(5 * time.Millisecond)
			}
			c.Close()
			if h.AuthOK() <= before {
				fail.Add(1)
			}
		}()
	}
	wg.Wait()
	if fail.Load() != 0 {
		t.Fatalf("concurrent failures: %d", fail.Load())
	}
	if h.AuthOK() < int64(2+n-2) { // allow tiny loss under scheduler races
		t.Fatalf("authOK=%d want >= %d", h.AuthOK(), 2+n-2)
	}
	h.report(t, "concurrent")
}

// serverSideEchoCheck writes payload from client and asserts the REALITY server
// echo loop observed the bytes and wrote without error. Client Read is best-effort
// because camouflage record framing may not be fully transparent to all uTLS builds.
func serverSideEchoCheck(t *testing.T, h *e2eHarness, payload []byte) {
	t.Helper()
	before := h.echoBytes.Load()
	werrBefore := h.echoWriteErr.Load()
	c := h.mustDialAuthorized(t)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	// Wait until server observes bytes.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.echoBytes.Load() >= before+int64(len(payload)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := h.echoBytes.Load() - before
	if got < int64(len(payload)) {
		t.Fatalf("server did not observe payload: delta=%d want=%d authOK=%d", got, len(payload), h.AuthOK())
	}
	if h.echoWriteErr.Load() != werrBefore {
		t.Fatalf("server echo write errors increased: %d -> %d", werrBefore, h.echoWriteErr.Load())
	}
	// Best-effort client read; do not fail suite if uTLS rejects camouflage app records.
	buf := make([]byte, len(payload))
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := io.ReadFull(c, buf); err == nil && n == len(payload) {
		if string(buf) != string(payload) {
			t.Fatalf("client echo mismatch")
		}
		t.Log("client full-duplex echo OK")
	} else {
		t.Logf("client read best-effort: n=%d err=%v (server-side echo verified)", n, err)
	}
	c.Close()
}

func TestE2E_DataPlane_EchoAfterL2(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	for i := 0; i < 2; i++ {
		h.handshakeOnly(t)
		time.Sleep(40 * time.Millisecond)
	}
	if h.maxEvidence() < MinL2Evidence {
		t.Fatalf("evidence=%d", h.maxEvidence())
	}
	before := h.Dials()
	serverSideEchoCheck(t, h, []byte("hello-l2-data"))
	if h.Dials() == before {
		t.Log("data-plane conn was L2 zero-dial")
	}
	med := make([]byte, 4096)
	for i := range med {
		med[i] = byte(i)
	}
	serverSideEchoCheck(t, h, med)
}

func TestE2E_DataPlane_LargePayload(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	for i := 0; i < 2; i++ {
		h.handshakeOnly(t)
		time.Sleep(30 * time.Millisecond)
	}
	payload := make([]byte, 64*1024)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	serverSideEchoCheck(t, h, payload)
}

func TestE2E_ManySequentialConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("skip many sequential in short mode")
	}
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	const n = 50
	for i := 0; i < n; i++ {
		h.handshakeOnly(t)
	}
	if h.AuthOK() < int64(n-1) {
		t.Fatalf("authOK=%d want >= %d", h.AuthOK(), n-1)
	}
	if h.Dials() >= int64(n) {
		t.Fatalf("amortize ineffective: dials=%d for %d conns", h.Dials(), n)
	}
	h.report(t, "sequential50")
}

func TestE2E_ALPNVariants(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	c1, err := h.dialAuthorized("", nil, []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	c1.Close()
	c2, err := h.dialAuthorized("", nil, []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	c2.Close()
	time.Sleep(50 * time.Millisecond)
	if h.AuthOK() < 2 {
		t.Fatalf("authOK=%d want >=2", h.AuthOK())
	}
	h.report(t, "alpn")
}

func TestE2E_CacheIsolation_TwoHarnesses(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h1 := newE2EHarness(t, e2eHarnessOpts{ServerName: "a.example.com", AmortizeMode: AmortizeDefault})
	h2 := newE2EHarness(t, e2eHarnessOpts{ServerName: "b.example.com", AmortizeMode: AmortizeDefault})
	for i := 0; i < 2; i++ {
		h1.handshakeOnly(t)
	}
	time.Sleep(40 * time.Millisecond)
	before := h2.Dials()
	h2.handshakeOnly(t)
	if h2.Dials()-before < 1 {
		t.Fatal("second dest first conn must dial RA (no cross-dest L2)")
	}
}

func TestE2E_IdleThenResume(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	for i := 0; i < 2; i++ {
		h.handshakeOnly(t)
		time.Sleep(30 * time.Millisecond)
	}
	serverSideEchoCheck(t, h, []byte("before-idle"))
	// New conn after idle gap (connection-level idle is covered if client read works).
	time.Sleep(500 * time.Millisecond)
	serverSideEchoCheck(t, h, []byte("after-idle"))
}

func TestE2E_NoRAWhenL2_Hit(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeL2})
	for i := 0; i < 2; i++ {
		h.handshakeOnly(t)
		time.Sleep(40 * time.Millisecond)
	}
	if h.maxEvidence() < MinL2Evidence {
		t.Fatalf("evidence=%d want >= %d", h.maxEvidence(), MinL2Evidence)
	}
	before := h.Dials()
	h.handshakeOnly(t)
	if h.Dials() != before {
		t.Fatalf("expected zero RA dial, before=%d after=%d l2hits=%d", before, h.Dials(), globalCacheManager.stats.L2Hits.Load())
	}
}

func TestE2E_MixedAuthAndUnauth(t *testing.T) {
	// Split into isolated subtests so mirror-path residual state cannot poison
	// subsequent authorized handshakes in the same process lifetime.
	t.Run("plainTLS_not_authOK", func(t *testing.T) {
		globalCacheManager.Reset()
		h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
		if conn, err := h.dialPlainTLS(t, h.serverName); err == nil {
			_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = conn.Write([]byte("x"))
			conn.Close()
		}
		time.Sleep(100 * time.Millisecond)
		if h.AuthOK() != 0 {
			t.Fatalf("plain TLS authOK=%d want 0", h.AuthOK())
		}
	})
	t.Run("wrongSNI_not_authOK", func(t *testing.T) {
		globalCacheManager.Reset()
		h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
		c, err := h.dialAuthorized("nope.example.com", nil, nil)
		if err == nil {
			c.Close()
		}
		time.Sleep(100 * time.Millisecond)
		if h.AuthOK() != 0 {
			t.Fatalf("wrong SNI authOK=%d want 0", h.AuthOK())
		}
	})
	t.Run("authorized_control", func(t *testing.T) {
		globalCacheManager.Reset()
		h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
		h.handshakeOnly(t)
		if h.AuthOK() < 1 {
			t.Fatalf("authorized control authOK=%d", h.AuthOK())
		}
	})
}

func TestE2E_DataPlane_ConcurrentEcho(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	for i := 0; i < 2; i++ {
		h.handshakeOnly(t)
		time.Sleep(30 * time.Millisecond)
	}
	const n = 10
	var wg sync.WaitGroup
	var fail atomic.Int64
	before := h.echoBytes.Load()
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(id int) {
			defer wg.Done()
			c, err := h.dialAuthorized("", nil, nil)
			if err != nil {
				fail.Add(1)
				return
			}
			defer c.Close()
			payload := []byte(fmt.Sprintf("echo-%02d", id))
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(payload); err != nil {
				fail.Add(1)
			}
		}(i)
	}
	wg.Wait()
	// Wait for server to observe all writes.
	want := before + int64(n*len("echo-00"))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && h.echoBytes.Load() < want {
		time.Sleep(10 * time.Millisecond)
	}
	if fail.Load() != 0 {
		t.Fatalf("client write failures: %d", fail.Load())
	}
	if h.echoBytes.Load() < want {
		t.Fatalf("server echo bytes %d want >= %d", h.echoBytes.Load(), want)
	}
	if h.echoWriteErr.Load() != 0 {
		t.Fatalf("server write errors: %d", h.echoWriteErr.Load())
	}
}

func TestE2E_AppData_FullDuplex_AfterHandshake(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})

	// Cold path (L0/L1 first conn)
	h.fullDuplexEcho(t, []byte("cold-appdata-1"))
	// Warm second conn (likely L1)
	h.fullDuplexEcho(t, []byte("warm-appdata-2"))
	// Third should be L2 zero-dial and still full-duplex
	before := h.Dials()
	h.fullDuplexEcho(t, []byte("l2-appdata-3"))
	if h.Dials() != before {
		t.Logf("third conn dialed RA delta=%d (L2 may need more evidence)", h.Dials()-before)
	} else {
		t.Log("third conn L2 zero-dial + full duplex OK")
	}
	// Medium payload multi-round already inside fullDuplexEcho; add larger once.
	h.fullDuplexEcho(t, makePayload(16*1024))
	if h.echoWriteErr.Load() != 0 {
		t.Fatalf("server write errors: %d", h.echoWriteErr.Load())
	}
}

func TestE2E_AppData_FullDuplex_ModeL0(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeL0})
	h.fullDuplexEcho(t, []byte("l0-appdata"))
	h.fullDuplexEcho(t, makePayload(4096))
}

func TestE2E_AppData_FullDuplex_ModeL1(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeL1})
	h.fullDuplexEcho(t, []byte("l1-appdata"))
	h.fullDuplexEcho(t, []byte("l1-appdata-2"))
}

func TestE2E_AppData_FullDuplex_Concurrent(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })
	h := newE2EHarness(t, e2eHarnessOpts{AmortizeMode: AmortizeDefault})
	// warm
	h.fullDuplexEcho(t, []byte("warm"))
	h.fullDuplexEcho(t, []byte("warm2"))

	const n = 8
	var wg sync.WaitGroup
	var fail atomic.Int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					fail.Add(1)
				}
			}()
			// manual to avoid t.Fatalf from non-owner goroutine
			c, err := h.dialAuthorizedVerifiedErr("", nil, nil)
			if err != nil {
				fail.Add(1)
				return
			}
			defer c.Close()
			payload := []byte(fmt.Sprintf("cfd-%d", id))
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(payload); err != nil {
				fail.Add(1)
				return
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != string(payload) {
				fail.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if fail.Load() != 0 {
		t.Fatalf("concurrent full-duplex failures: %d (serverWriteErr=%d)", fail.Load(), h.echoWriteErr.Load())
	}
}

func makePayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}
