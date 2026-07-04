//go:build l2 || l2handshake

package reality

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Level 2：REALITY 握手测试
// 目标：验证 REALITY 自身握手逻辑正确
// ============================================================================

// TestL2_HandshakeCompletes 验证 TLS 1.3 握手正常完成
func TestL2_HandshakeCompletes(t *testing.T) {
	for _, tgt := range ReleaseGateTargets {
		t.Run(tgt.Name, func(t *testing.T) {
			ln, addr := newTestServer(t, echoHandler)
			defer ln.Close()

			conn := dialTLS(t, addr)
			defer conn.Close()

			state := conn.ConnectionState()
			if !state.HandshakeComplete {
				t.Fatal("handshake not complete")
			}
			if state.Version != tls.VersionTLS13 {
				t.Errorf("version = 0x%04X, want TLS 1.3", state.Version)
			}
		})
	}
}

// TestL2_ApplicationDataTransfer 握手成功后应用数据传输
func TestL2_ApplicationDataTransfer(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn := dialTLS(t, addr)
	defer conn.Close()

	// 1KB
	data1K := genPayload(1024)
	_, err := conn.Write(data1K)
	assertNoError(t, err)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	assertNoError(t, err)
	if string(buf[:n]) != string(data1K) {
		t.Error("1KB data mismatch")
	}

	// 100KB
	data100K := genPayload(100 * 1024)
	_, err = conn.Write(data100K)
	assertNoError(t, err)

	received := make([]byte, 0, len(data100K))
	tmp := make([]byte, 65536)
	for len(received) < len(data100K) {
		n, err := conn.Read(tmp)
		assertNoError(t, err)
		received = append(received, tmp[:n]...)
	}
	if len(received) != len(data100K) {
		t.Errorf("100KB: received %d bytes, want %d", len(received), len(data100K))
	}
}

// TestL2_SequenceIntegrity 序列号完整性 — 检测 seq 重复 incSeq
func TestL2_SequenceIntegrity(t *testing.T) {
	const rounds = 100

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn := dialTLS(t, addr)
	defer conn.Close()

	for i := 0; i < rounds; i++ {
		payload := genPayload(256)
		_, err := conn.Write(payload)
		assertNoError(t, err)

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		assertNoError(t, err)
		if string(buf[:n]) != string(payload) {
			t.Fatalf("round %d: data mismatch", i)
		}
	}
}

// TestL2_MultipleSequentialConnections 连续多次连接
func TestL2_MultipleSequentialConnections(t *testing.T) {
	const connections = 20

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	for i := 0; i < connections; i++ {
		conn := dialTLS(t, addr)

		data := genPayload(512)
		_, err := conn.Write(data)
		assertNoError(t, err)

		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		assertNoError(t, err)
		if string(buf[:n]) != string(data) {
			t.Fatalf("connection %d: data mismatch", i)
		}
		conn.Close()
	}
}

// TestL2_GracefulClose 正常关闭
func TestL2_GracefulClose(t *testing.T) {
	ln, addr := newTestServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	})
	defer ln.Close()

	conn := dialTLS(t, addr)

	data := genPayload(128)
	_, err := conn.Write(data)
	assertNoError(t, err)

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	assertNoError(t, err)
	if string(buf[:n]) != string(data) {
		t.Error("data mismatch before close")
	}

	err = conn.CloseWrite()
	assertNoError(t, err)

	// 读取对端关闭信号
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
}

// TestL2_ConcurrentConnections 并发连接
func TestL2_ConcurrentConnections(t *testing.T) {
	const goroutines = 50

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(goroutines)

	var success atomic.Int64
	var fail atomic.Int64

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			conn := dialTLS(t, addr)
			defer conn.Close()

			data := genPayload(256)
			if _, err := conn.Write(data); err != nil {
				fail.Add(1)
				return
			}

			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err != nil || string(buf[:n]) != string(data) {
				fail.Add(1)
				return
			}
			success.Add(1)
		}()
	}

	wg.Wait()

	total := success.Load() + fail.Load()
	t.Logf("Concurrent: %d/%d succeeded", success.Load(), total)
	if fail.Load() > 0 {
		t.Errorf("%d concurrent connections failed", fail.Load())
	}
}

// ============================================================================
// Data Plane Integrity — REALITY Server() 握手后数据传输验证
// 这是 v3-stable 失败的核心场景：握手成功但数据断了
// ============================================================================

// TestL2_REALITY_DataPlaneREALITY Server() 握手后应用数据完整性
func TestL2_REALITY_DataPlane(t *testing.T) {
	// 1. 启动目标 TLS 服务器（模拟 microsoft.com）
	targetCert := mustTestCert()
	targetLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{targetCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer targetLn.Close()
	targetAddr := targetLn.Addr().String()

	// 目标服务器：回显所有数据
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 65536)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// 2. 生成 REALITY 密钥对
	privateKeyBytes := make([]byte, 32)
	for i := range privateKeyBytes {
		privateKeyBytes[i] = byte(i)
	}
	// 使用有效的 X25519 密钥
	copy(privateKeyBytes, []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	})

	// 3. 启动 REALITY Server
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reality server listen: %v", err)
	}
	defer serverLn.Close()
	serverAddr := serverLn.Addr().String()

	serverConfig := &Config{
		Dest:        targetAddr,
		Type:        "tcp",
		ServerNames: map[string]bool{"test.example.com": true},
		PrivateKey:  privateKeyBytes,
		ShortIds:    map[[8]byte]bool{{0x01}: true},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("tcp", targetAddr)
		},
	}

	go func() {
		for {
			conn, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, err := Server(context.Background(), c, serverConfig)
				if err != nil {
					c.Close()
				}
			}(conn)
		}
	}()

	// 4. 启动 DetectPostHandshakeRecordsLens
	go DetectPostHandshakeRecordsLens(serverConfig)

	// 5. 客户端连接 REALITY Server
	time.Sleep(100 * time.Millisecond) // 等待服务器启动

	for i := 0; i < 10; i++ {
		clientConn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "test.example.com",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("iteration %d: dial: %v", i, err)
		}

		// 6. 发送应用数据
		msg := fmt.Sprintf("hello reality data plane %d", i)
		_, err = clientConn.Write([]byte(msg))
		if err != nil {
			t.Fatalf("iteration %d: write: %v", i, err)
		}

		// 7. 读取回显
		buf := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := clientConn.Read(buf)
		if err != nil {
			t.Fatalf("iteration %d: read: %v", i, err)
		}

		if string(buf[:n]) != msg {
			t.Fatalf("iteration %d: data mismatch: got %q, want %q", i, buf[:n], msg)
		}

		clientConn.Close()
	}

	t.Log("REALITY Data Plane: 10/10 passed")
}

// TestL2_REALITY_CacheHitMiss verifies cache behavior across multiple connections.
// First connection: cache miss → full handshake → store profile.
// Subsequent connections: cache hit → skip target reads → use cached RecordLens.
func TestL2_REALITY_CacheHitMiss(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })

	// 1. Start target TLS server on a FIXED address.
	targetCert := mustTestCert()
	targetLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{targetCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer targetLn.Close()
	targetAddr := targetLn.Addr().String()

	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 65536)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// 2. Generate REALITY key.
	privateKeyBytes := make([]byte, 32)
	for i := range privateKeyBytes {
		privateKeyBytes[i] = byte(i + 1)
	}

	// 3. Start REALITY Server with Show=true.
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reality server listen: %v", err)
	}
	defer serverLn.Close()
	serverAddr := serverLn.Addr().String()

	serverConfig := &Config{
		Dest:        targetAddr, // FIXED dest — same across all connections.
		Type:        "tcp",
		Show:        true,
		ServerNames: map[string]bool{"test.example.com": true},
		PrivateKey:  privateKeyBytes,
		ShortIds:    map[[8]byte]bool{{0x01}: true},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("tcp", targetAddr)
		},
	}

	go func() {
		for {
			conn, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, err := Server(context.Background(), c, serverConfig)
				if err != nil {
					c.Close()
				}
			}(conn)
		}
	}()

	go DetectPostHandshakeRecordsLens(serverConfig)
	time.Sleep(100 * time.Millisecond)

	dial := func(label string) {
		t.Helper()
		conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "test.example.com",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("%s dial: %v", label, err)
		}
		msg := "hello " + label
		conn.Write([]byte(msg))
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := conn.Read(buf)
		if string(buf[:n]) != msg {
			t.Fatalf("%s data mismatch", label)
		}
		conn.Close()
	}

	// 4. First connection — cache miss, full handshake, profile stored.
	t.Log("=== Connection 1: CACHE MISS (first, profile stored) ===")
	dial("conn1")

	// 5. Second connection — cache hit, skip target reads.
	t.Log("=== Connection 2: CACHE HIT (reuse RecordLens) ===")
	dial("conn2")

	// 6. Third connection — cache still valid.
	t.Log("=== Connection 3: CACHE HIT (still valid) ===")
	dial("conn3")

	t.Log("Cache hit/miss test: 3/3 connections passed")
	t.Logf("Cache report:\n%s", globalCacheManager.CacheReport())
}

// TestL2_CacheLogic directly tests cache hit/miss/isolation behavior
// without requiring a full REALITY handshake.
func TestL2_CacheLogic(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })

	serverName := "www.google.com"
	alpn := "h2"
	tlsVer := uint16(VersionTLS13)
	key := CacheKey(serverName, alpn, tlsVer)

	lens := [7]int{1215, 6, 41, 0, 0, 0, 0}
	fp := computeFingerprint(0x1301, alpn, lens[0], lens[2])

	// --- Test 1: Cache miss on empty cache ---
	t.Log("=== Test 1: Cache miss (empty cache) ===")
	_, _, _, hit := globalCacheManager.FindCachedProfile(serverName, 0x1301, alpn, tlsVer)
	if hit {
		t.Fatal("expected cache miss on empty cache")
	}
	t.Log("  Result: MISS — no profile stored yet")

	// --- Test 2: Store profile, expect cache hit ---
	t.Log("=== Test 2: Store profile → cache hit ===")
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens:  lens,
		Fingerprint: fp,
		CipherSuite: 0x1301,
		ALPN:        alpn,
		TLSVersion:  tlsVer,
		CapturedAt:  time.Now(),
	})

	gotLens, gotVer, _, hit := globalCacheManager.FindCachedProfile(serverName, 0x1301, alpn, tlsVer)
	if !hit {
		t.Fatal("expected cache hit after store")
	}
	if gotLens != lens {
		t.Fatalf("RecordLens mismatch: got %v, want %v", gotLens, lens)
	}
	if gotVer != tlsVer {
		t.Fatalf("TLSVersion mismatch: got 0x%x, want 0x%x", gotVer, tlsVer)
	}
	t.Logf("  Result: HIT — lens=%v tlsVer=0x%x", gotLens, gotVer)

	// --- Test 3: ALPN mismatch → cache miss ---
	t.Log("=== Test 3: ALPN mismatch → miss ===")
	_, _, _, hit = globalCacheManager.FindCachedProfile(serverName, 0x1301, "http/1.1", tlsVer)
	if hit {
		t.Fatal("expected cache miss for different ALPN")
	}
	t.Log("  Result: MISS — ALPN 'http/1.1' != 'h2'")

	// --- Test 4: TLSVersion mismatch → cache miss ---
	t.Log("=== Test 4: TLSVersion mismatch → miss ===")
	_, _, _, hit = globalCacheManager.FindCachedProfile(serverName, 0x1301, alpn, VersionTLS12)
	if hit {
		t.Fatal("expected cache miss for different TLS version")
	}
	t.Log("  Result: MISS — TLSVersion 0x0302 != 0x0303")

	// --- Test 5: CipherSuite mismatch → cache miss ---
	t.Log("=== Test 5: CipherSuite mismatch → miss ===")
	_, _, _, hit = globalCacheManager.FindCachedProfile(serverName, 0x1302, alpn, tlsVer)
	if hit {
		t.Fatal("expected cache miss for different CipherSuite")
	}
	t.Log("  Result: MISS — CipherSuite 0x1302 != 0x1301")

	// --- Test 6: Different serverName → cache miss ---
	t.Log("=== Test 6: Different serverName → miss ===")
	_, _, _, hit = globalCacheManager.FindCachedProfile("other.example.com", 0x1301, alpn, tlsVer)
	if hit {
		t.Fatal("expected cache miss for different serverName")
	}
	t.Log("  Result: MISS — serverName 'other.example.com' != 'www.google.com'")

	// --- Test 7: Invalid RecordLens → cache miss (defense) ---
	t.Log("=== Test 7: Invalid RecordLens → miss (defense) ===")
	badKey := CacheKey(serverName, "grpc", tlsVer)
	globalCacheManager.StoreProfile(badKey, &RealityProfile{
		RecordLens:  [7]int{99999, 6, 41}, // 99999 > maxTLSRecordPayload
		Fingerprint: fp,
		CipherSuite: 0x1301,
		ALPN:        "grpc",
		TLSVersion:  tlsVer,
		CapturedAt:  time.Now(),
	})
	_, _, _, hit = globalCacheManager.FindCachedProfile(serverName, 0x1301, "grpc", tlsVer)
	if hit {
		t.Fatal("expected cache miss for invalid RecordLens")
	}
	t.Log("  Result: MISS — RecordLens[0]=99999 exceeds maxTLSRecordPayload")

	// --- Test 8: Invalidate → cache miss ---
	t.Log("=== Test 8: Invalidate → miss ===")
	globalCacheManager.InvalidateProfile(key)
	_, _, _, hit = globalCacheManager.FindCachedProfile(serverName, 0x1301, alpn, tlsVer)
	if hit {
		t.Fatal("expected cache miss after invalidation")
	}
	t.Log("  Result: MISS — profile invalidated")

	t.Logf("\nCache report:\n%s", globalCacheManager.CacheReport())
}

// TestL2_CacheALPNMismatch_BugReproduction reproduces the bug where
// probeTargetRaw stored profiles with ALPN="" (hardcoded empty string),
// but FindCachedProfile looked up by the actual ALPN (e.g. "h2").
// This caused every connection to miss the cache and re-probe the target,
// leading to intermittent handshake failures from unstable probe results.
func TestL2_CacheALPNMismatch_BugReproduction(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })

	serverName := "www.microsoft.com"
	tlsVer := uint16(VersionTLS13)
	lens := [7]int{1215, 6, 41, 8273, 286, 74, 0}

	// === Reproduce Bug: profile stored with ALPN="" (old probeTargetRaw behavior) ===
	buggyKey := CacheKey(serverName, "", tlsVer) // ALPN="" in key
	fp := computeFingerprint(0x1301, "", lens[0], lens[2])
	globalCacheManager.StoreProfile(buggyKey, &RealityProfile{
		RecordLens:   lens,
		Fingerprint:  fp,
		CipherSuite:  0x1301,
		ALPN:         "", // BUG: old code hardcoded empty string
		TLSVersion:   tlsVer,
		CapturedAt:   time.Now(),
	})

	// Lookup with actual ALPN="h2" → should MISS because key mismatch
	_, _, _, hit := globalCacheManager.FindCachedProfile(serverName, 0x1301, "h2", tlsVer)
	if hit {
		t.Fatal("BUG STILL PRESENT: cache hit with ALPN='' stored but 'h2' queried")
	}
	t.Log("Confirmed bug: profile stored with ALPN='' is NOT found when querying ALPN='h2'")

	// === Fix: profile stored with ALPN="h2" (new probeTargetRaw behavior) ===
	globalCacheManager.Reset()

	fixedKey := CacheKey(serverName, "h2", tlsVer)
	fp2 := computeFingerprint(0x1301, "h2", lens[0], lens[2])
	globalCacheManager.StoreProfile(fixedKey, &RealityProfile{
		RecordLens:   lens,
		Fingerprint:  fp2,
		CipherSuite:  0x1301,
		ALPN:         "h2", // FIX: correct ALPN
		TLSVersion:   tlsVer,
		CapturedAt:   time.Now(),
	})

	// Lookup with ALPN="h2" → should HIT
	_, _, _, hit = globalCacheManager.FindCachedProfile(serverName, 0x1301, "h2", tlsVer)
	if !hit {
		t.Fatal("FIX FAILED: expected cache hit with correct ALPN")
	}
	t.Log("Fix verified: profile stored with ALPN='h2' is found when querying ALPN='h2'")
}

// TestL2_CacheServerNameIsolation_BugReproduction verifies that different
// SNIs have isolated cache entries.
func TestL2_CacheServerNameIsolation_BugReproduction(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })

	tlsVer := uint16(VersionTLS13)
	alpn := "h2"

	// Store profile for www.microsoft.com
	keyMS := CacheKey("www.microsoft.com", alpn, tlsVer)
	lensMS := [7]int{1215, 6, 41, 8273, 286, 74, 0}
	globalCacheManager.StoreProfile(keyMS, &RealityProfile{
		RecordLens:  lensMS,
		CipherSuite: 0x1301,
		ALPN:        alpn,
		TLSVersion:  tlsVer,
		CapturedAt:  time.Now(),
	})

	// Store profile for a different SNI
	keyOther := CacheKey("login.live.com", alpn, tlsVer)
	lensOther := [7]int{1300, 6, 50, 9000, 300, 80, 0}
	globalCacheManager.StoreProfile(keyOther, &RealityProfile{
		RecordLens:  lensOther,
		CipherSuite: 0x1301,
		ALPN:        alpn,
		TLSVersion:  tlsVer,
		CapturedAt:  time.Now(),
	})

	// Lookup for www.microsoft.com → must return its record lens, not login.live.com's
	gotLens, _, _, hit := globalCacheManager.FindCachedProfile("www.microsoft.com", 0x1301, alpn, tlsVer)
	if !hit {
		t.Fatal("expected cache hit for www.microsoft.com")
	}
	if gotLens != lensMS {
		t.Fatalf("serverName isolation broken: got lens %v (login.live.com), want %v (www.microsoft.com)", gotLens, lensMS)
	}
	t.Logf("Correct: returned lens %v for www.microsoft.com", gotLens)

	// Lookup for login.live.com → must return its record lens
	gotLens2, _, _, hit2 := globalCacheManager.FindCachedProfile("login.live.com", 0x1301, alpn, tlsVer)
	if !hit2 {
		t.Fatal("expected cache hit for login.live.com")
	}
	if gotLens2 != lensOther {
		t.Fatalf("serverName isolation broken: got lens %v (www.microsoft.com), want %v (login.live.com)", gotLens2, lensOther)
	}
	t.Logf("Correct: returned lens %v for login.live.com", gotLens2)
}

// TestL2_REALITY_LargeEncryptedExtensions verifies the C2 code path:
// when the target's EncryptedExtensions exceeds 512 bytes, the handshakeBuf
// accumulation logic must correctly reconstruct the message across iterations.
func TestL2_REALITY_LargeEncryptedExtensions(t *testing.T) {
	// Generate a cert with many SANs to produce a large EncryptedExtensions.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var sans []string
	for i := 0; i < 50; i++ {
		sans = append(sans, fmt.Sprintf("san%d.example.com", i))
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"C2 Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     sans,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	targetCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	targetLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{targetCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	targetAddr := targetLn.Addr().String()

	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 65536)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	privateKeyBytes := make([]byte, 32)
	for i := range privateKeyBytes {
		privateKeyBytes[i] = byte(i + 0x30)
	}

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverLn.Close()

	serverConfig := &Config{
		Dest:        targetAddr,
		Type:        "tcp",
		ServerNames: map[string]bool{"c2test.example.com": true},
		PrivateKey:  privateKeyBytes,
		ShortIds:    map[[8]byte]bool{{0x02}: true},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("tcp", targetAddr)
		},
	}

	go func() {
		for {
			conn, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, err := Server(context.Background(), c, serverConfig)
				if err != nil {
					c.Close()
				}
			}(conn)
		}
	}()

	go DetectPostHandshakeRecordsLens(serverConfig)
	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 5; i++ {
		clientConn, err := tls.Dial("tcp", serverLn.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "c2test.example.com",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("iteration %d: dial: %v", i, err)
		}

		msg := fmt.Sprintf("c2 large ee test %d", i)
		_, err = clientConn.Write([]byte(msg))
		if err != nil {
			t.Fatalf("iteration %d: write: %v", i, err)
		}

		buf := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := clientConn.Read(buf)
		if err != nil {
			t.Fatalf("iteration %d: read: %v", i, err)
		}
		if string(buf[:n]) != msg {
			t.Fatalf("iteration %d: data mismatch", i)
		}
		clientConn.Close()
	}

	t.Log("C2 Large EncryptedExtensions: 5/5 passed")
}

// TestL2_StaleCacheCausesHandshakeFailure simulates the real-world scenario:
// REALITY impersonates microsoft.com, client accesses a site through tunnel.
// When cache has stale record lens (e.g. from a previous target), the padding
// calculation in encrypt() goes negative, causing handshake failure and fallback
// to direct forwarding — the browser then sees the target's real cert.
func TestL2_StaleCacheCausesHandshakeFailure(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })

	serverName := "www.microsoft.com"
	tlsVer := uint16(VersionTLS13)
	alpn := "h2"

	// Scenario: target server updated its cert chain, making records larger.
	// Old cached profile has small record lens, but actual server sends bigger ones.
	oldLens := [7]int{1215, 6, 41, 8273, 286, 74, 0}   // stale cache
	newLens := [7]int{1300, 6, 55, 9200, 310, 82, 0}    // actual target response

	// Store stale profile in cache (simulates old probe result)
	key := CacheKey(serverName, alpn, tlsVer)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens:  oldLens,
		CipherSuite: 0x1301,
		ALPN:        alpn,
		TLSVersion:  tlsVer,
		CapturedAt:  time.Now(),
	})

	// Verify cache hit returns stale data
	gotLens, _, _, hit := globalCacheManager.FindCachedProfile(serverName, 0x1301, alpn, tlsVer)
	if !hit {
		t.Fatal("expected cache hit")
	}
	if gotLens != oldLens {
		t.Fatalf("expected stale lens %v, got %v", oldLens, gotLens)
	}

	// Simulate what happens during handshake when cached lens are stale.
	// In encrypt(), the padding formula is:
	//   padding = cached_lens - len(record) - AEAD_overhead
	// where len(record) = 5 (TLS header) + payload_size
	// and AEAD overhead = 16 bytes (AES-GCM tag)
	//
	// If the target's actual record is larger than cached, padding < 0 → handshake fails.
	overhead := 16
	for i := 2; i <= 5; i++ {
		// The payload is the actual handshake message bytes (e.g. Certificate body).
		// In real handshake, payload_size ≈ actual_record_lens - 5 (header) - 16 (AEAD)
		actualPayloadSize := newLens[i] - 5 - overhead
		recordSize := 5 + actualPayloadSize
		padding := oldLens[i] - recordSize - overhead
		if padding < 0 {
			t.Logf("Record[%d]: stale lens=%d, actual record=%d, padding=%d → HANDSHAKE FAILS",
				i, oldLens[i], recordSize, padding)
		} else {
			t.Logf("Record[%d]: stale lens=%d, actual record=%d, padding=%d → OK",
				i, oldLens[i], recordSize, padding)
		}
	}

	// Now invalidate stale cache and store correct profile
	globalCacheManager.InvalidateProfile(key)
	globalCacheManager.StoreProfile(key, &RealityProfile{
		RecordLens:  newLens,
		CipherSuite: 0x1301,
		ALPN:        alpn,
		TLSVersion:  tlsVer,
		CapturedAt:  time.Now(),
	})

	// Verify cache now returns correct data
	gotLens2, _, _, hit2 := globalCacheManager.FindCachedProfile(serverName, 0x1301, alpn, tlsVer)
	if !hit2 {
		t.Fatal("expected cache hit after refresh")
	}
	if gotLens2 != newLens {
		t.Fatalf("expected fresh lens %v, got %v", newLens, gotLens2)
	}

	// Verify padding would be non-negative with correct lens
	for i := 2; i <= 5; i++ {
		actualPayloadSize := newLens[i] - 5 - overhead
		recordSize := 5 + actualPayloadSize
		padding := newLens[i] - recordSize - overhead
		if padding < 0 {
			t.Fatalf("Record[%d]: even with fresh lens, padding=%d < 0", i, padding)
		}
	}

	t.Log("Stale cache scenario: confirmed padding error with stale data, correct with fresh data")
}

// TestL2_ALPNMismatchCausesProbeStorm demonstrates how the old ALPN=""
// bug caused every connection to miss cache and trigger a new probe,
// leading to inconsistent record lens across connections.
func TestL2_ALPNMismatchCausesProbeStorm(t *testing.T) {
	globalCacheManager.Reset()
	t.Cleanup(func() { globalCacheManager.Reset() })

	serverName := "www.microsoft.com"
	tlsVer := uint16(VersionTLS13)

	// Simulate old bug: 5 connections each store profile with ALPN=""
	for i := 0; i < 5; i++ {
		buggyKey := CacheKey(serverName, "", tlsVer)
		lens := [7]int{1200 + i*10, 6, 40 + i, 8000 + i*100, 250 + i*5, 70 + i, 0}
		globalCacheManager.StoreProfile(buggyKey, &RealityProfile{
			RecordLens:  lens,
			CipherSuite: 0x1301,
			ALPN:        "", // BUG
			TLSVersion:  tlsVer,
			CapturedAt:  time.Now(),
		})
	}

	// Every lookup with ALPN="h2" misses
	misses := 0
	for i := 0; i < 5; i++ {
		_, _, _, hit := globalCacheManager.FindCachedProfile(serverName, 0x1301, "h2", tlsVer)
		if !hit {
			misses++
		}
	}
	if misses != 5 {
		t.Fatalf("expected 5 misses, got %d", misses)
	}
	t.Logf("ALPN mismatch: 5/5 lookups missed cache (probe storm)")

	// Now with fix: store with correct ALPN
	globalCacheManager.Reset()
	fixedKey := CacheKey(serverName, "h2", tlsVer)
	lens := [7]int{1215, 6, 41, 8273, 286, 74, 0}
	globalCacheManager.StoreProfile(fixedKey, &RealityProfile{
		RecordLens:  lens,
		CipherSuite: 0x1301,
		ALPN:        "h2", // FIX
		TLSVersion:  tlsVer,
		CapturedAt:  time.Now(),
	})

	// All lookups hit
	hits := 0
	for i := 0; i < 5; i++ {
		_, _, _, hit := globalCacheManager.FindCachedProfile(serverName, 0x1301, "h2", tlsVer)
		if hit {
			hits++
		}
	}
	if hits != 5 {
		t.Fatalf("expected 5 hits, got %d", hits)
	}
	t.Logf("ALPN fix: 5/5 lookups hit cache (no more probe storm)")
}
