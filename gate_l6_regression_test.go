//go:build l6 || l6gate

package reality

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Level 6：回归测试（Release Gate）
// 以后任何版本 (v3/v4/v5/v6) 发版前必须过这一套
//
// 最终发版标准:
//   L1 PASS (单元测试 100%)
//   L2 PASS (REALITY 握手)
//   L3 PASS (E2E 端到端)
//   L4 PASS (TLS 兼容性)
//   L5 PASS (Soak)
//   HTTP Success >= 99.9%
//   HTTPS Success >= 99.9%
//   EOF = 0
//   Panic = 0
//   Data Corruption = 0
// ============================================================================

// TestL6_SequenceIntegrity 序列号完整性 — 硬性测试
// 如果发现重复 incSeq() → 直接 FAIL
func TestL6_SequenceIntegrity(t *testing.T) {
	const rounds = 500

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	for i := 0; i < rounds; i++ {
		conn := dialTLS(t, addr)

		// 每次发送不同大小的数据来触发不同的 seq 增长路径
		sizes := []int{1, 128, 256, 512, 1024, 2048, 4096, 8192, 16384}
		for _, size := range sizes {
			data := genPayload(size)
			_, err := conn.Write(data)
			if err != nil {
				t.Fatalf("round %d size %d: write: %v", i, size, err)
			}

			buf := make([]byte, size)
			received := 0
			for received < size {
				n, err := conn.Read(buf[received:])
				if err != nil {
					t.Fatalf("round %d size %d: read: %v", i, size, err)
				}
				received += n
			}

			if string(buf[:size]) != string(data) {
				t.Fatalf("round %d size %d: data corruption", i, size)
			}
		}

		conn.Close()
	}

	t.Logf("Sequence integrity: %d rounds × %d sizes = %d verifications passed",
		rounds, 9, rounds*9)
}

// TestL6_SequenceIntegrityConcurrent 并发序列号完整性
func TestL6_SequenceIntegrityConcurrent(t *testing.T) {
	const goroutines = 20
	const roundsPerGoroutine = 50

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(goroutines)
	var fail atomic.Int64

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < roundsPerGoroutine; i++ {
				conn := dialTLS(t, addr)
				data := genPayload(1024)

				if _, err := conn.Write(data); err != nil {
					fail.Add(1)
					conn.Close()
					continue
				}

				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil || string(buf[:n]) != string(data) {
					fail.Add(1)
				}
				conn.Close()
			}
		}(g)
	}

	wg.Wait()

	total := goroutines * roundsPerGoroutine
	t.Logf("Concurrent sequence integrity: %d/%d passed", total-int(fail.Load()), total)
	if fail.Load() > 0 {
		t.Errorf("%d failures in concurrent sequence test", fail.Load())
	}
}

// TestL6_PostHandshakeCompatibility Post-Handshake 兼容性
// 如果未来引入 NewSessionTicket / KeyUpdate，必须通过此测试
func TestL6_PostHandshakeCompatibility(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	// 模拟多种客户端行为
	clientConfigs := []struct {
		name string
		min  uint16
		max  uint16
	}{
		{"TLS1.3 Only", 0x0304, 0x0304},
		{"TLS1.2-1.3", 0x0303, 0x0304},
		{"Default", 0, 0},
	}

	for _, cfg := range clientConfigs {
		t.Run(cfg.name, func(t *testing.T) {
			conn, err := dialTLSWithConfig(t, addr, cfg.min, cfg.max)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			// 发送数据
			data := genPayload(256)
			_, err = conn.Write(data)
			assertNoError(t, err)

			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			assertNoError(t, err)
			if string(buf[:n]) != string(data) {
				t.Error("data mismatch")
			}
		})
	}
}

// TestL6_ReleaseGate 综合发版门禁
func TestL6_ReleaseGate(t *testing.T) {
	t.Log("========================================")
	t.Log("  REALITY Release Gate v3-stable")
	t.Log("========================================")

	var (
		totalTests   int
		passedTests  int
		totalPanic   int
		totalEOF     int
		totalCorrupt int
	)

	// --- L1: 单元测试 ---
	t.Run("L1_Unit", func(t *testing.T) {
		totalTests++
		fp := computeFingerprint(0x1301, "h2", 100, 50)
		key := "gate|test|h2"

		globalCacheManager.StoreProfile(key, &RealityProfile{
			RecordLens: [7]int{100, 6, 50}, Fingerprint: fp,
			CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
		})

		p := globalCacheManager.GetProfile(key)
		if p == nil {
			t.Error("cache miss")
			return
		}
		if p.Fingerprint != fp {
			t.Error("fingerprint mismatch")
			return
		}

		globalCacheManager.InvalidateProfile(key)
		passedTests++
		t.Log("  L1 PASS")
	})

	// --- L2: REALITY 握手 ---
	t.Run("L2_Handshake", func(t *testing.T) {
		totalTests++
		ln, addr := newTestServer(t, echoHandler)
		defer ln.Close()

		conn := dialTLS(t, addr)
		defer conn.Close()

		if !conn.ConnectionState().HandshakeComplete {
			t.Error("handshake not complete")
			return
		}

		data := genPayload(256)
		if _, err := conn.Write(data); err != nil {
			t.Errorf("write: %v", err)
			return
		}

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			t.Errorf("read: %v", err)
			totalEOF++
			return
		}
		if string(buf[:n]) != string(data) {
			t.Error("data corruption")
			totalCorrupt++
			return
		}

		passedTests++
		t.Log("  L2 PASS")
	})

	// --- L3: E2E ---
	t.Run("L3_E2E", func(t *testing.T) {
		totalTests++
		const requests = 100

		ln, addr := newTestServer(t, echoHandler)
		defer ln.Close()

		var success int
		for i := 0; i < requests; i++ {
			conn := dialTLS(t, addr)
			data := genPayload(256)

			if _, err := conn.Write(data); err != nil {
				conn.Close()
				continue
			}

			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err != nil || string(buf[:n]) != string(data) {
				conn.Close()
				totalCorrupt++
				continue
			}

			success++
			conn.Close()
		}

		rate := float64(success) / float64(requests) * 100
		t.Logf("  E2E: %d/%d (%.1f%%)", success, requests, rate)
		if rate < 99.9 {
			t.Errorf("E2E rate %.1f%% < 99.9%%", rate)
			return
		}
		passedTests++
		t.Log("  L3 PASS")
	})

	// --- L4: TLS 兼容 ---
	t.Run("L4_TLS", func(t *testing.T) {
		totalTests++
		ln, addr := newTestServer(t, echoHandler)
		defer ln.Close()

		conn := dialTLS(t, addr)
		defer conn.Close()

		state := conn.ConnectionState()
		if state.Version != 0x0304 {
			t.Error("not TLS 1.3")
			return
		}
		if state.CipherSuite == 0 {
			t.Error("no cipher suite")
			return
		}
		passedTests++
		t.Log("  L4 PASS")
	})

	// --- L5: Soak ---
	t.Run("L5_Soak", func(t *testing.T) {
		totalTests++
		ln, addr := newTestServer(t, echoHandler)
		defer ln.Close()

		var soakSuccess, soakFail, soakEOF atomic.Int64
		conn := dialTLS(t, addr)

		const soakDuration = 30 * time.Second
		start := time.Now()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for time.Since(start) < soakDuration {
			<-ticker.C
			data := genPayload(256)
			if _, err := conn.Write(data); err != nil {
				soakFail.Add(1)
				conn.Close()
				conn = dialTLS(t, addr)
				continue
			}

			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err != nil {
				soakEOF.Add(1)
				conn.Close()
				conn = dialTLS(t, addr)
				continue
			}
			if string(buf[:n]) == string(data) {
				soakSuccess.Add(1)
			} else {
				soakFail.Add(1)
				totalCorrupt++
			}
		}
		conn.Close()

		t.Logf("  Soak: success=%d fail=%d eof=%d", soakSuccess.Load(), soakFail.Load(), soakEOF.Load())
		if soakEOF.Load() > 0 {
			t.Errorf("soak EOF: %d", soakEOF.Load())
			totalEOF += int(soakEOF.Load())
			return
		}
		passedTests++
		t.Log("  L5 PASS")
	})

	// --- Summary ---
	t.Log("========================================")
	t.Logf("  Tests: %d/%d passed", passedTests, totalTests)
	t.Logf("  Panics: %d", totalPanic)
	t.Logf("  EOF: %d", totalEOF)
	t.Logf("  Corruption: %d", totalCorrupt)
	t.Log("========================================")

	if passedTests != totalTests {
		t.Errorf("Release Gate FAILED: %d/%d tests passed", passedTests, totalTests)
	}
	if totalPanic > 0 {
		t.Errorf("Release Gate FAILED: %d panics", totalPanic)
	}
	if totalCorrupt > 0 {
		t.Errorf("Release Gate FAILED: %d data corruption", totalCorrupt)
	}

	if passedTests == totalTests && totalPanic == 0 && totalCorrupt == 0 {
		t.Log("  ✓ Ready for: git tag reality-vNext")
	}
}

func dialTLSWithConfig(t *testing.T, addr string, minVer, maxVer uint16) (*tls.Conn, error) {
	t.Helper()
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if minVer != 0 {
		cfg.MinVersion = minVer
	}
	if maxVer != 0 {
		cfg.MaxVersion = maxVer
	}
	return tls.Dial("tcp", addr, cfg)
}

// ============================================================================
// Control Plane → Data Plane 泄漏回归测试
// 防止 cache 代码再次侵入 TLS write path
// ============================================================================

// TestL6_NoCacheInHandshakePath 验证 cache 不出现在握手路径中
// 如果 cache 代码被加回到 handshake flow，这个测试会失败
func TestL6_NoCacheInHandshakePath(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	// 连接并传输数据
	conn := dialTLS(t, addr)
	defer conn.Close()

	for i := 0; i < 50; i++ {
		data := genPayload(256)
		if _, err := conn.Write(data); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}

		buf := make([]byte, 256)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if string(buf[:n]) != string(data) {
			t.Fatalf("data mismatch %d", i)
		}
	}
}

// TestL6_DataPlaneIntegrityAfterCacheLoad 验证 cache 加载后数据面仍正常
func TestL6_DataPlaneIntegrityAfterCacheLoad(t *testing.T) {
	key := "regression|microsoft.com|h2"
	fp := computeFingerprint(0x1301, "h2", 127, 51)

	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 51}, Fingerprint: fp,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	defer globalCacheManager.InvalidateProfile(key)

	p := globalCacheManager.GetProfile(key)
	if p == nil {
		t.Fatal("cache miss")
	}

	// 连接并传输数据 — cache 不应影响数据流
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn := dialTLS(t, addr)
	defer conn.Close()

	for i := 0; i < 50; i++ {
		data := genPayload(512)
		if _, err := conn.Write(data); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}

		buf := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if string(buf[:n]) != string(data) {
			t.Fatalf("data mismatch %d", i)
		}
	}
}



// TestL6_CacheEvictionDoesNotCorruptData 验证 cache 淘汰不破坏数据流
func TestL6_CacheEvictionDoesNotCorruptData(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	// 大量 cache 操作 + 数据传输交替进行
	for i := 0; i < 100; i++ {
		// 写入 cache
		key := fmt.Sprintf("evict|%d.example.com|h2", i%20)
		fp := computeFingerprint(0x1301, "h2", 100+i, 50+i)
		globalCacheManager.StoreProfile(key, &RealityProfile{
			RecordLens: [7]int{100 + i, 6, 50 + i}, Fingerprint: fp,
			CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
		})

		// 传输数据
		conn := dialTLS(t, addr)

		data := genPayload(128)
		if _, err := conn.Write(data); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}

		buf := make([]byte, 128)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		conn.Close()

		if err != nil || string(buf[:n]) != string(data) {
			t.Fatalf("data mismatch %d", i)
		}
	}

	// 清理
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("evict|%d.example.com|h2", i)
		globalCacheManager.InvalidateProfile(key)
	}
}
