//go:build l3 || l3e2e

package reality

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Level 3：最小 E2E 测试
// 核心目标：验证握手后业务数据能正常传输
// 不需要公网，不需要编译 Xray
// ============================================================================

// --- Plan A: Echo 回环测试 ---

// TestL3A_EchoLoopback Echo 回环：发 hello → 收 hello，循环 1000 次
func TestL3A_EchoLoopback(t *testing.T) {
	const iterations = 1000

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	for i := 0; i < iterations; i++ {
		conn := dialTLS(t, addr)

		msg := fmt.Sprintf("hello reality %d", i)
		_, err := conn.Write([]byte(msg))
		if err != nil {
			t.Fatalf("iteration %d: write: %v", i, err)
		}

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("iteration %d: read: %v", i, err)
		}

		if string(buf[:n]) != msg {
			t.Fatalf("iteration %d: got %q, want %q", i, buf[:n], msg)
		}
		conn.Close()
	}

	t.Logf("Echo loopback: %d/%d passed", iterations, iterations)
}

// --- Plan B: HTTP 回环测试 ---

// TestL3B_HTTPLoopback HTTP 回环：连续 100 次 curl 式请求
func TestL3B_HTTPLoopback(t *testing.T) {
	const requests = 100

	ln, addr := newTestServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 65536)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_ = n
			resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
			conn.Write([]byte(resp))
		}
	})
	defer ln.Close()

	var success atomic.Int64
	var eof atomic.Int64

	for i := 0; i < requests; i++ {
		conn := dialTLS(t, addr)

		req := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
		_, err := conn.Write([]byte(req))
		if err != nil {
			eof.Add(1)
			conn.Close()
			continue
		}

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			eof.Add(1)
			conn.Close()
			continue
		}

		resp := string(buf[:n])
		if len(resp) > 0 {
			success.Add(1)
		}
		conn.Close()
	}

	t.Logf("HTTP loopback: %d/%d succeeded, EOF: %d", success.Load(), requests, eof.Load())
	if eof.Load() > 0 {
		t.Errorf("EOF detected: %d", eof.Load())
	}
	if success.Load() != requests {
		t.Errorf("success rate: %.2f%% < 100%%", float64(success.Load())/float64(requests)*100)
	}
}

// --- Plan C: Idle 测试（抓 post-handshake 问题）---

// TestL3C_IdleResume 空闲后恢复：30s/60s 空闲再发数据
func TestL3C_IdleResume(t *testing.T) {
	idleDurations := []time.Duration{
		5 * time.Second,
		30 * time.Second,
		60 * time.Second,
	}

	for _, idle := range idleDurations {
		t.Run(idle.String(), func(t *testing.T) {
			ln, addr := newTestServer(t, echoHandler)
			defer ln.Close()

			conn := dialTLS(t, addr)
			defer conn.Close()

			// 第一包
			msg1 := "before idle"
			_, err := conn.Write([]byte(msg1))
			assertNoError(t, err)

			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			assertNoError(t, err)
			if string(buf[:n]) != msg1 {
				t.Fatalf("first msg: got %q, want %q", buf[:n], msg1)
			}

			// 空闲
			time.Sleep(idle)

			// 空闲后发数据
			msg2 := "after idle"
			_, err = conn.Write([]byte(msg2))
			assertNoError(t, err)

			n, err = conn.Read(buf)
			if err != nil {
				t.Fatalf("after %v idle: read failed: %v", idle, err)
			}
			if string(buf[:n]) != msg2 {
				t.Fatalf("after idle: got %q, want %q", buf[:n], msg2)
			}
		})
	}
}

// --- Plan D: 大文件 SHA256 校验 ---

// TestL3D_LargeTransferSHA256 大数据传输 + SHA256 完整性验证
func TestL3D_LargeTransferSHA256(t *testing.T) {
	sizes := []struct {
		name string
		size int
	}{
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"50MB", 50 * 1024 * 1024},
	}

	for _, sz := range sizes {
		t.Run(sz.name, func(t *testing.T) {
			original := genPayload(sz.size)
			origHash := sha256.Sum256(original)

			ln, addr := newTestServer(t, func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4096)
				conn.Read(buf) // 读取请求
				conn.Write(original)
			})
			defer ln.Close()

			conn := dialTLS(t, addr)
			defer conn.Close()

			_, err := conn.Write([]byte("GET /big HTTP/1.1\r\n\r\n"))
			assertNoError(t, err)

			h := sha256.New()
			received := 0
			buf := make([]byte, 65536)
			for received < sz.size {
				n, err := conn.Read(buf)
				if err != nil {
					t.Fatalf("read at byte %d: %v", received, err)
				}
				h.Write(buf[:n])
				received += n
			}

			gotHash := h.Sum(nil)
			if hex.EncodeToString(gotHash) != hex.EncodeToString(origHash[:]) {
				t.Errorf("SHA256 mismatch")
			}
		})
	}
}

// --- Plan E: 1000 连接测试 ---

// TestL3E_1000Connections 1000 次 connect → send → recv → disconnect
func TestL3E_1000Connections(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1000 connection test in short mode")
	}

	const total = 1000

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	var success atomic.Int64
	var eof atomic.Int64
	var timeout atomic.Int64
	var panicCount atomic.Int64

	for i := 0; i < total; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
				}
			}()

			conn := dialTLS(t, addr)

			msg := fmt.Sprintf("test-%d", i)
			if _, err := conn.Write([]byte(msg)); err != nil {
				eof.Add(1)
				conn.Close()
				return
			}

			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					timeout.Add(1)
				} else {
					eof.Add(1)
				}
				conn.Close()
				return
			}

			if string(buf[:n]) == msg {
				success.Add(1)
			}
			conn.Close()
		}()
	}

	t.Logf("1000 connections: success=%d EOF=%d timeout=%d panic=%d",
		success.Load(), eof.Load(), timeout.Load(), panicCount.Load())

	if panicCount.Load() > 0 {
		t.Errorf("panics: %d", panicCount.Load())
	}
	if eof.Load() > 0 {
		t.Errorf("EOF: %d", eof.Load())
	}
	if timeout.Load() > 0 {
		t.Errorf("timeout: %d", timeout.Load())
	}
	if success.Load() != total {
		t.Errorf("success rate: %.2f%%", float64(success.Load())/float64(total)*100)
	}
}

// --- 并发 Echo ---

// TestL3E_ConcurrentEcho 100 并发 echo
func TestL3E_ConcurrentEcho(t *testing.T) {
	const goroutines = 100

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(goroutines)

	var success atomic.Int64
	var fail atomic.Int64

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			conn := dialTLS(t, addr)
			defer conn.Close()

			msg := fmt.Sprintf("concurrent-%d", id)
			if _, err := conn.Write([]byte(msg)); err != nil {
				fail.Add(1)
				return
			}

			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil || string(buf[:n]) != msg {
				fail.Add(1)
				return
			}
			success.Add(1)
		}(i)
	}

	wg.Wait()

	t.Logf("Concurrent echo: %d/%d succeeded", success.Load(), goroutines)
	if fail.Load() > 0 {
		t.Errorf("failures: %d", fail.Load())
	}
}

// --- 连续小包 + 大包混合 ---

// TestL3E_MixedPacketSize 混合大小数据包
func TestL3E_MixedPacketSize(t *testing.T) {
	const iterations = 200

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	sizes := []int{1, 10, 100, 256, 512, 1024, 4096, 8192, 16384}

	for i := 0; i < iterations; i++ {
		conn := dialTLS(t, addr)

		for _, size := range sizes {
			data := genPayload(size)
			if _, err := conn.Write(data); err != nil {
				t.Fatalf("iter %d size %d: write: %v", i, size, err)
			}

			received := make([]byte, 0, size)
			buf := make([]byte, 65536)
			for len(received) < size {
				n, err := conn.Read(buf)
				if err != nil {
					t.Fatalf("iter %d size %d: read: %v", i, size, err)
				}
				received = append(received, buf[:n]...)
			}

			if string(received) != string(data) {
				t.Fatalf("iter %d size %d: data corruption", i, size)
			}
		}

		conn.Close()
	}
}
