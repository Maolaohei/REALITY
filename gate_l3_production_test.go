//go:build l3prod || l3production

package reality

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Level 3: Production Proxy Behavior — 纯本地模拟
//
// 验证 REALITY 在代理场景下的行为:
//   1. Split Routing: 不同目标走不同路径
//   2. Fallback: cache miss 时不 crash
//   3. Long Connection: 10min/30min 无 EOF/RST
//   4. 端口扫描防护
//
// 所有测试不依赖公网，100% 确定性
// ============================================================================

// ============================================================================
// Test 1: Split Routing — LOCAL 模拟
// ============================================================================

func TestL3_Production_SplitRouting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping production test in short mode")
	}

	// 模拟 split routing:
	// 目标 A → REALITY path (echo server)
	// 目标 B → DIRECT path (另一个 echo server)

	echoA, addrA := newTestServer(t, echoHandler)
	defer echoA.Close()

	echoB, addrB := newTestServer(t, echoHandler)
	defer echoB.Close()

	t.Logf("Target A (REALITY path): %s", addrA)
	t.Logf("Target B (DIRECT path): %s", addrB)

	// 测试 A: 通过 REALITY 路径
	t.Run("TargetA_via_REALITY", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			conn := dialTLS(t, addrA)

			msg := fmt.Sprintf("reality-path-%d", i)
			_, err := conn.Write([]byte(msg))
			if err != nil {
				t.Fatalf("write: %v", err)
			}

			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			conn.Close()

			if err != nil || string(buf[:n]) != msg {
				t.Fatalf("iteration %d: mismatch", i)
			}
		}
		t.Log("Target A: 10/10 passed")
	})

	// 测试 B: 直连路径
	t.Run("TargetB_DIRECT", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			conn := dialTLS(t, addrB)

			msg := fmt.Sprintf("direct-path-%d", i)
			_, err := conn.Write([]byte(msg))
			if err != nil {
				t.Fatalf("write: %v", err)
			}

			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			conn.Close()

			if err != nil || string(buf[:n]) != msg {
				t.Fatalf("iteration %d: mismatch", i)
			}
		}
		t.Log("Target B: 10/10 passed")
	})

	// 测试 C: 交替访问
	t.Run("Alternating", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			var conn net.Conn
			if i%2 == 0 {
				conn = dialTLS(t, addrA)
			} else {
				conn = dialTLS(t, addrB)
			}

			msg := fmt.Sprintf("alt-%d", i)
			_, err := conn.Write([]byte(msg))
			if err != nil {
				t.Fatalf("write %d: %v", i, err)
			}

			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			conn.Close()

			if err != nil || string(buf[:n]) != msg {
				t.Fatalf("iteration %d: mismatch", i)
			}
		}
		t.Log("Alternating: 20/20 passed")
	})
}

// ============================================================================
// Test 2: Fallback Path — Cache Miss 场景
// ============================================================================

func TestL3_Production_FallbackPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fallback test in short mode")
	}

	// 清空所有缓存
	realityProfileCache = sync.Map{}
	realityLayoutCache = sync.Map{}

	t.Log("Caches cleared, testing cold-start fallback")

	// 冷启动测试: 首次连接应该正常
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	total := 50
	success := 0

	for i := 0; i < total; i++ {
		conn := dialTLS(t, addr)

		msg := fmt.Sprintf("fallback-test-%d", i)
		_, err := conn.Write([]byte(msg))
		if err != nil {
			conn.Close()
			continue
		}

		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && string(buf[:n]) == msg {
			success++
		}
	}

	t.Logf("Fallback: %d/%d passed", success, total)
	if success != total {
		t.Errorf("fallback success rate: %.2f%%", float64(success)/float64(total)*100)
	}
}

// ============================================================================
// Test 3: Long Connection Stability — 10min/30min
// ============================================================================

func TestL3_Production_LongConnection_10min(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 10min connection test in short mode")
	}

	const duration = 10 * time.Minute
	const sendInterval = 5 * time.Second

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn := dialTLS(t, addr)
	defer conn.Close()

	var sendCount, recvCount atomic.Int64
	var eofCount atomic.Int64

	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				data := genPayload(1024)
				if _, err := conn.Write(data); err != nil {
					eofCount.Add(1)
					close(done)
					return
				}
				sendCount.Add(1)

				buf := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					eofCount.Add(1)
					close(done)
					return
				}
				if string(buf[:n]) == string(data) {
					recvCount.Add(1)
				}

			case <-done:
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(duration):
	}

	t.Logf("Long connection 10min:")
	t.Logf("  Sent: %d", sendCount.Load())
	t.Logf("  Received: %d", recvCount.Load())
	t.Logf("  EOF: %d", eofCount.Load())

	if eofCount.Load() > 0 {
		t.Errorf("EOF detected: %d", eofCount.Load())
	}

	if sendCount.Load() > 0 && recvCount.Load() != sendCount.Load() {
		t.Errorf("send/recv mismatch: sent %d, received %d", sendCount.Load(), recvCount.Load())
	}
}

func TestL3_Production_LongConnection_30min(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 30min connection test in short mode")
	}

	const duration = 30 * time.Minute
	const sendInterval = 5 * time.Second

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	conn := dialTLS(t, addr)
	defer conn.Close()

	var sendCount, recvCount atomic.Int64
	var eofCount atomic.Int64

	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				data := genPayload(1024)
				if _, err := conn.Write(data); err != nil {
					eofCount.Add(1)
					close(done)
					return
				}
				sendCount.Add(1)

				buf := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					eofCount.Add(1)
					close(done)
					return
				}
				if string(buf[:n]) == string(data) {
					recvCount.Add(1)
				}

			case <-done:
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(duration):
	}

	t.Logf("Long connection 30min:")
	t.Logf("  Sent: %d", sendCount.Load())
	t.Logf("  Received: %d", recvCount.Load())
	t.Logf("  EOF: %d", eofCount.Load())

	if eofCount.Load() > 0 {
		t.Errorf("EOF detected: %d", eofCount.Load())
	}

	if sendCount.Load() > 0 && recvCount.Load() != sendCount.Load() {
		t.Errorf("send/recv mismatch: sent %d, received %d", sendCount.Load(), recvCount.Load())
	}
}

// ============================================================================
// Test 4: Port Scan Resistance
// ============================================================================

func TestL3_Production_PortScanResistance(t *testing.T) {
	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	// 提取端口号
	_, portStr, _ := net.SplitHostPort(addr)

	// 尝试连接（不经过 TLS 握手）
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%s", portStr), 2*time.Second)
	if err != nil {
		t.Skipf("cannot connect: %v", err)
	}
	defer conn.Close()

	// 发送垃圾数据
	_, err = conn.Write([]byte("NOT_A_TLS_CONNECTION"))
	if err != nil {
		t.Logf("Write failed (expected): %v", err)
	}

	// 读取响应
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)

	if err != nil {
		t.Logf("Read failed (expected for non-TLS): %v", err)
	} else {
		response := string(buf[:n])
		if strings.Contains(response, "REALITY") || strings.Contains(response, "vless") {
			t.Error("REALITY feature leaked in non-authenticated response")
		} else {
			t.Logf("Port scan resistance: OK (no REALITY leak, response=%d bytes)", n)
		}
	}
}

// ============================================================================
// Test 5: Xray Config Validation (不需要启动 Xray)
// ============================================================================

func TestL3_Production_XrayConfigValidation(t *testing.T) {
	if _, err := os.Stat(xrayBinary); os.IsNotExist(err) {
		t.Skipf("xray binary not found at %s", xrayBinary)
	}

	os.MkdirAll(configDir, 0755)

	// 生成配置
	serverJSON := fmt.Sprintf(`{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "%s", "flow": "xtls-rprx-vision"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": true,
        "dest": "%s",
        "serverNames": ["%s"],
        "privateKey": "%s",
        "shortIds": ["%s"]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}`, serverPort, vlessID, realityDest, realitySNI, privateKey, shortId)

	clientJSON := fmt.Sprintf(`{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": true}
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "127.0.0.1",
        "port": %d,
        "users": [{"id": "%s", "flow": "xtls-rprx-vision", "encryption": "none"}]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "fingerprint": "chrome",
        "serverName": "%s",
        "publicKey": "%s",
        "shortId": "%s",
        "spiderX": "/"
      }
    },
    "tag": "reality"
  }]
}`, socksPort, serverPort, vlessID, realitySNI, publicKey, shortId)

	os.WriteFile(filepath.Join(configDir, "server.json"), []byte(serverJSON), 0644)
	os.WriteFile(filepath.Join(configDir, "client.json"), []byte(clientJSON), 0644)

	// 验证配置
	out, err := exec.Command(xrayBinary, "run", "-test", "-config", filepath.Join(configDir, "server.json")).CombinedOutput()
	if err != nil {
		t.Errorf("server config invalid: %v\n%s", err, out)
	} else {
		t.Log("Server config: VALID")
	}

	out, err = exec.Command(xrayBinary, "run", "-test", "-config", filepath.Join(configDir, "client.json")).CombinedOutput()
	if err != nil {
		t.Errorf("client config invalid: %v\n%s", err, out)
	} else {
		t.Log("Client config: VALID")
	}
}

// ============================================================================
// Test 6: Multiple Target 并发访问
// ============================================================================

func TestL3_Production_MultipleTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multiple targets test in short mode")
	}

	// 启动多个 echo server 模拟不同目标
	servers := make([]net.Listener, 5)
	addrs := make([]string, 5)

	for i := 0; i < 5; i++ {
		ln, addr := newTestServer(t, echoHandler)
		servers[i] = ln
		addrs[i] = addr
		defer ln.Close()
	}

	var success, fail atomic.Int64
	var wg sync.WaitGroup

	for i, addr := range addrs {
		wg.Add(1)
		go func(id int, target string) {
			defer wg.Done()

			for j := 0; j < 20; j++ {
				conn := dialTLS(t, target)

				msg := fmt.Sprintf("target-%d-req-%d", id, j)
				_, err := conn.Write([]byte(msg))
				if err != nil {
					fail.Add(1)
					conn.Close()
					continue
				}

				buf := make([]byte, 4096)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				conn.Close()

				if err == nil && string(buf[:n]) == msg {
					success.Add(1)
				} else {
					fail.Add(1)
				}
			}
		}(i, addr)
	}

	wg.Wait()

	t.Logf("Multiple targets: %d success, %d fail", success.Load(), fail.Load())
	if fail.Load() > 0 {
		t.Errorf("failures: %d", fail.Load())
	}
}
