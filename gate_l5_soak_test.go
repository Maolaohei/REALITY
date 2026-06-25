//go:build l5 || l5soak

package reality

import (
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Level 5：Soak Test — 内存泄漏、状态机问题
// 2h / 12h / 24h 持续运行
// ============================================================================

// TestL5_ShortSoak 5分钟短时 soak（CI 可跑）
func TestL5_ShortSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soak test in short mode")
	}

	const (
		duration     = 5 * time.Minute
		sendInterval = time.Second
		dataSize     = 1024
	)

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	// 基线内存
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	var successCount atomic.Int64
	var failCount atomic.Int64
	var eofCount atomic.Int64
	var rstCount atomic.Int64

	conn := dialTLS(t, addr)
	defer conn.Close()

	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	start := time.Now()
	for time.Since(start) < duration {
		<-ticker.C

		data := genPayload(dataSize)
		if _, err := conn.Write(data); err != nil {
			failCount.Add(1)
			// 尝试重连
			conn.Close()
			conn = dialTLS(t, addr)
			continue
		}

		buf := make([]byte, dataSize)
		n, err := conn.Read(buf)
		if err != nil {
			eofCount.Add(1)
			conn.Close()
			conn = dialTLS(t, addr)
			continue
		}

		if string(buf[:n]) == string(data) {
			successCount.Add(1)
		} else {
			failCount.Add(1)
		}
	}

	// 后期内存
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	elapsed := time.Since(start)
	memGrowth := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / 1024 / 1024
	heapGrowth := float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / 1024 / 1024

	t.Logf("Soak 5min results:")
	t.Logf("  Duration: %v", elapsed)
	t.Logf("  Success: %d", successCount.Load())
	t.Logf("  Failed: %d", failCount.Load())
	t.Logf("  EOF: %d", eofCount.Load())
	t.Logf("  RST: %d", rstCount.Load())
	t.Logf("  Total alloc: %.2f MB", memGrowth)
	t.Logf("  Heap growth: %.2f MB", heapGrowth)

	// 标准
	if eofCount.Load() > 0 {
		t.Errorf("EOF detected: %d", eofCount.Load())
	}
	if memGrowth > 50 {
		t.Errorf("memory growth %.2f MB > 50 MB", memGrowth)
	}
}

// TestL5_2HourSoak 2小时 soak（标记为 Long，CI 可选跑）
func TestL5_2HourSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 2h soak in short mode")
	}

	const (
		duration     = 2 * time.Hour
		sendInterval = time.Second
		dataSize     = 1024
	)

	soakTest(t, duration, sendInterval, dataSize)
}

// TestL5_12HourSoak 12小时 soak
func TestL5_12HourSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 12h soak in short mode")
	}

	const (
		duration     = 12 * time.Hour
		sendInterval = time.Minute
		dataSize     = 4096
	)

	soakTest(t, duration, sendInterval, dataSize)
}

// TestL5_24HourSoak 24小时 soak
func TestL5_24HourSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 24h soak in short mode")
	}

	const (
		duration     = 24 * time.Hour
		sendInterval = time.Minute
		dataSize     = 4096
	)

	soakTest(t, duration, sendInterval, dataSize)
}

func soakTest(t *testing.T, duration, sendInterval time.Duration, dataSize int) {
	t.Helper()

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	var successCount atomic.Int64
	var failCount atomic.Int64
	var eofCount atomic.Int64
	var rstCount atomic.Int64
	var panicCount atomic.Int64

	conn := dialTLS(t, addr)

	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	start := time.Now()
	lastReport := start

	for time.Since(start) < duration {
		<-ticker.C

		data := genPayload(dataSize)
		if _, err := conn.Write(data); err != nil {
			failCount.Add(1)
			// 重连
			conn.Close()
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicCount.Add(1)
					}
				}()
				conn = dialTLS(t, addr)
			}()
			if conn == nil {
				time.Sleep(time.Second)
				continue
			}
			continue
		}

		buf := make([]byte, dataSize)
		n, err := conn.Read(buf)
		if err != nil {
			eofCount.Add(1)
			conn.Close()
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicCount.Add(1)
					}
				}()
				conn = dialTLS(t, addr)
			}()
			continue
		}

		if string(buf[:n]) == string(data) {
			successCount.Add(1)
		} else {
			failCount.Add(1)
		}

		// 每 10 分钟报告
		if time.Since(lastReport) >= 10*time.Minute {
			elapsed := time.Since(start)
			t.Logf("[%v] success=%d fail=%d eof=%d rst=%d panic=%d",
				elapsed.Round(time.Second), successCount.Load(), failCount.Load(),
				eofCount.Load(), rstCount.Load(), panicCount.Load())
			lastReport = time.Now()
		}
	}

	conn.Close()

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	elapsed := time.Since(start)
	memGrowth := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / 1024 / 1024

	t.Logf("Soak final:")
	t.Logf("  Duration: %v", elapsed)
	t.Logf("  Success: %d", successCount.Load())
	t.Logf("  Failed: %d", failCount.Load())
	t.Logf("  EOF: %d", eofCount.Load())
	t.Logf("  RST: %d", rstCount.Load())
	t.Logf("  Panics: %d", panicCount.Load())
	t.Logf("  Total alloc: %.2f MB", memGrowth)

	// 发版标准
	if panicCount.Load() > 0 {
		t.Errorf("PANIC detected: %d", panicCount.Load())
	}
	if eofCount.Load() > 10 {
		t.Errorf("excessive EOF: %d", eofCount.Load())
	}
}

// TestL5_MemoryLeakDetection 专门的内存泄漏检测
func TestL5_MemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory leak test in short mode")
	}

	const iterations = 1000

	ln, addr := newTestServer(t, echoHandler)
	defer ln.Close()

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	for i := 0; i < iterations; i++ {
		conn := dialTLS(t, addr)
		data := genPayload(256)
		conn.Write(data)

		buf := make([]byte, 256)
		conn.Read(buf)
		conn.Close()
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	heapGrowth := float64(memAfter.HeapAlloc-memBefore.HeapAlloc) / 1024 / 1024
	t.Logf("Memory leak test: %d connections, heap growth: %.2f MB", iterations, heapGrowth)

	if heapGrowth > 20 {
		t.Errorf("potential memory leak: heap grew %.2f MB after %d connections", heapGrowth, iterations)
	}
}
