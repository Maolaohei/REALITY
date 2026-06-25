//go:build l2 || l2handshake

package reality

import (
	"context"
	"crypto/tls"
	"fmt"
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
