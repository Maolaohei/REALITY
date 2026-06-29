//go:build l4 || l4tls

package reality

import (
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Level 4：TLS 兼容性测试
// 目标：防止 post-handshake 类问题
// ============================================================================

// TestL4_TLS13Handshake TLS 1.3 握手
func TestL4_TLS13Handshake(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	for i := 0; i < 20; i++ {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("iteration %d: dial: %v", i, err)
		}

		state := conn.ConnectionState()
		if state.Version != tls.VersionTLS13 {
			t.Errorf("version = 0x%04X, want TLS 1.3", state.Version)
		}
		conn.Close()
	}
}

// TestL4_ALPNNegotiation ALPN 协商
func TestL4_ALPNNegotiation(t *testing.T) {
	protos := []string{"h2", "http/1.1"}

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	for _, proto := range protos {
		t.Run(proto, func(t *testing.T) {
			conn, err := tls.Dial("tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{proto},
				MinVersion:         tls.VersionTLS13,
			})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			state := conn.ConnectionState()
			if state.NegotiatedProtocol != proto {
				t.Errorf("negotiated = %q, want %q", state.NegotiatedProtocol, proto)
			}
		})
	}
}

// TestL4_CipherSuiteSelection 密码套件选择
func TestL4_CipherSuiteSelection(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.CipherSuite == 0 {
		t.Error("cipher suite not negotiated")
	}
	t.Logf("Cipher suite: 0x%04X", state.CipherSuite)
}

// TestL4_SessionResumptionNoPostHandshake 不依赖 post-handshake 的会话
func TestL4_SessionResumptionNoPostHandshake(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	// 第一次连接
	conn1 := dialTLS(t, addr)
	data := genPayload(128)
	_, err := conn1.Write(data)
	assertNoError(t, err)

	buf := make([]byte, 128)
	n, err := conn1.Read(buf)
	assertNoError(t, err)
	if string(buf[:n]) != string(data) {
		t.Fatal("first connection data mismatch")
	}
	conn1.Close()

	// 第二次连接（全新握手）
	conn2 := dialTLS(t, addr)
	_, err = conn2.Write(data)
	assertNoError(t, err)

	n, err = conn2.Read(buf)
	assertNoError(t, err)
	if string(buf[:n]) != string(data) {
		t.Fatal("second connection data mismatch")
	}
	conn2.Close()
}

// TestL4_CertRotation 等效证书轮换 — 同 key 再次 store 不覆盖（LoadOrStore 语义）
func TestL4_CertRotation(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })

	key := "l4.rot|ms.com|h2"
	fp1 := computeFingerprint(0x1301, "h2", 127, 51)

	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 51}, Fingerprint: fp1,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})
	defer globalCacheManager.InvalidateProfile(key)

	fp2 := computeFingerprint(0x1301, "h2", 127, 60)

	val := globalCacheManager.GetProfileOrExpired(key)
	if val == nil {
		t.Fatal("first store should be retrievable")
	}
	if val.Fingerprint != fp1 {
		t.Fatal("first store fingerprint mismatch")
	}

	// Second store with same key is a no-op (LoadOrStore).
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens: [7]int{127, 6, 60}, Fingerprint: fp2,
		CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now(),
	})

	val2 := globalCacheManager.GetProfileOrExpired(key)
	if val2 == nil {
		t.Fatal("profile should still be retrievable after no-op store")
	}
	if val2.Fingerprint != fp1 {
		t.Fatal("second store should not overwrite existing entry")
	}
}

// TestL4_ServerHelloRecordParsing Server Hello 记录解析
func TestL4_ServerHelloRecordParsing(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn := dialTLS(t, addr)
	defer conn.Close()

	state := conn.ConnectionState()

	// 验证所有关键字段
	if state.Version == 0 {
		t.Error("version not set")
	}
	if !state.HandshakeComplete {
		t.Error("handshake not complete")
	}
	if state.CipherSuite == 0 {
		t.Error("cipher suite not set")
	}
	t.Logf("Handshake: ver=0x%04X cs=0x%04X proto=%s", state.Version, state.CipherSuite, state.NegotiatedProtocol)
}

// TestL4_ConcurrentHandshakeStress 并发握手压力
func TestL4_ConcurrentHandshakeStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping handshake stress in short mode")
	}

	const goroutines = 50

	ln, addr := newTestServer(t, drainHandler)
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(goroutines)
	var success atomic.Int64

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			conn := dialTLS(t, addr)
			defer conn.Close()

			if conn.ConnectionState().HandshakeComplete {
				success.Add(1)
			}
		}()
	}
	wg.Wait()

	t.Logf("Handshake stress: %d/%d succeeded", success.Load(), goroutines)
	if success.Load() != goroutines {
		t.Errorf("handshake success rate: %.2f%%", float64(success.Load())/float64(goroutines)*100)
	}
}

// TestL4_ConnectionStateConsistency 连接状态一致性
func TestL4_ConnectionStateConsistency(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn := dialTLS(t, addr)
	defer conn.Close()

	// 多次查询 ConnectionState 应一致
	for i := 0; i < 10; i++ {
		s1 := conn.ConnectionState()
		s2 := conn.ConnectionState()
		if s1.Version != s2.Version {
			t.Errorf("version changed between reads")
		}
		if s1.CipherSuite != s2.CipherSuite {
			t.Errorf("cipher suite changed between reads")
		}
	}
}

// TestL4_MultipleRecords 大量记录发送
func TestL4_MultipleRecords(t *testing.T) {
	const messages = 200

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn := dialTLS(t, addr)
	defer conn.Close()

	for i := 0; i < messages; i++ {
		data := genPayload(64)
		_, err := conn.Write(data)
		assertNoError(t, err)

		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		assertNoError(t, err)
		if string(buf[:n]) != string(data) {
			t.Fatalf("message %d: mismatch", i)
		}
	}
}
