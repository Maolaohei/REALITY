//go:build l6 || l6regression || pprof

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
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestL6_PProfBenchmark is the standard profiling benchmark.
// It runs 20s of concurrent handshakes and outputs:
//   - Memory allocation top 10 (alloc_space)
//   - CPU sampling top 10 (20s)
//   - Goroutine count over time
//
// Run with:
//
//	go test -v -tags pprof -run TestL6_PProfBenchmark -timeout 60s
//	go tool pprof -top pprof_cpu_<timestamp>.prof
//	go tool pprof -top pprof_mem_<timestamp>.prof
func TestL6_PProfBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping pprof benchmark in short mode")
	}

	const (
		profileDuration = 20 * time.Second
		concurrency     = 50
		totalHandshakes = 500
	)

	// ── Setup target TLS server ──────────────────────────────────────
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"PPROF Target"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"pprof.test.com", "a.pprof.test.com", "b.pprof.test.com"},
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

	// ── Setup REALITY server ─────────────────────────────────────────
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i + 0x50)
	}
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverLn.Close()

	config := &Config{
		Dest:        targetLn.Addr().String(),
		Type:        "tcp",
		ServerNames: map[string]bool{"pprof.test.com": true},
		PrivateKey:  pk,
		ShortIds:    map[[8]byte]bool{{0x01}: true},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("tcp", targetLn.Addr().String())
		},
	}

	go func() {
		for {
			conn, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, err := Server(context.Background(), c, config)
				if err != nil {
					c.Close()
				}
			}(conn)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	serverAddr := serverLn.Addr().String()

	// ── Baseline ─────────────────────────────────────────────────────
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	goroutinesBefore := runtime.NumGoroutine()

	// ── Start CPU profile (20s) ──────────────────────────────────────
	ts := time.Now().Format("20060102_150405")
	cpuFile, err := os.Create(fmt.Sprintf("pprof_cpu_%s.prof", ts))
	if err != nil {
		t.Fatal(err)
	}
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		t.Fatal(err)
	}

	// ── Goroutine monitor ────────────────────────────────────────────
	var goroutinePeak atomic.Int32
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				n := int32(runtime.NumGoroutine())
				for {
					old := goroutinePeak.Load()
					if n <= old || goroutinePeak.CompareAndSwap(old, n) {
						break
					}
				}
			case <-done:
				return
			}
		}
	}()

	// ── Handshake workload ───────────────────────────────────────────
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var success atomic.Int64
	var fail atomic.Int64

	handshakeStart := time.Now()
	for i := 0; i < totalHandshakes; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "pprof.test.com",
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			})
			if err != nil {
				fail.Add(1)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("p-%d", idx)
			if _, err := conn.Write([]byte(msg)); err != nil {
				fail.Add(1)
				return
			}
			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			if err != nil || string(buf[:n]) != msg {
				fail.Add(1)
				return
			}
			success.Add(1)
		}(i)
	}
	wg.Wait()
	handshakeElapsed := time.Since(handshakeStart)

	// ── Stop CPU profile ─────────────────────────────────────────────
	pprof.StopCPUProfile()
	cpuFile.Close()

	// ── Memory profile ───────────────────────────────────────────────
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	memFile, err := os.Create(fmt.Sprintf("pprof_mem_%s.prof", ts))
	if err != nil {
		t.Fatal(err)
	}
	pprof.WriteHeapProfile(memFile)
	memFile.Close()

	// ── Goroutine snapshot ───────────────────────────────────────────
	close(done)
	goroutinesAfter := runtime.NumGoroutine()

	// ── Report ───────────────────────────────────────────────────────
	allocMB := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / 1024 / 1024
	heapMB := float64(memAfter.HeapAlloc) / 1024 / 1024
	allocPerConn := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / float64(success.Load())

	t.Logf("")
	t.Logf("╔══════════════════════════════════════════════════════╗")
	t.Logf("║           REALITY PProf Benchmark Report            ║")
	t.Logf("╠══════════════════════════════════════════════════════╣")
	t.Logf("║ Duration:        %-33v ║", handshakeElapsed.Round(time.Millisecond))
	t.Logf("║ Handshakes:      %-33v ║", fmt.Sprintf("%d/%d succeeded", success.Load(), totalHandshakes))
	t.Logf("║ Throughput:      %-33v ║", fmt.Sprintf("%.0f conn/s", float64(success.Load())/handshakeElapsed.Seconds()))
	t.Logf("║ Alloc/conn:      %-33v ║", fmt.Sprintf("%.1f KB", allocPerConn/1024))
	t.Logf("║ Total alloc:     %-33v ║", fmt.Sprintf("%.2f MB", allocMB))
	t.Logf("║ Heap in-use:     %-33v ║", fmt.Sprintf("%.2f MB", heapMB))
	t.Logf("║ Goroutines:      %-33v ║", fmt.Sprintf("%d → %d (peak %d)", goroutinesBefore, goroutinesAfter, goroutinePeak.Load()))
	t.Logf("╠══════════════════════════════════════════════════════╣")
	t.Logf("║ Profiles written:                                      ║")
	t.Logf("║   CPU: pprof_cpu_%s.prof               ║", ts)
	t.Logf("║   Mem: pprof_mem_%s.prof               ║", ts)
	t.Logf("║                                                        ║")
	t.Logf("║ Analyze with:                                          ║")
	t.Logf("║   go tool pprof -top pprof_cpu_%s.prof    ║", ts)
	t.Logf("║   go tool pprof -top pprof_mem_%s.prof    ║", ts)
	t.Logf("╚══════════════════════════════════════════════════════╝")
	t.Logf("")

	// ── Assertions ───────────────────────────────────────────────────
	if success.Load() == 0 {
		t.Fatal("no handshakes succeeded")
	}
	if fail.Load() > int64(totalHandshakes)/10 {
		t.Errorf("too many failures: %d/%d", fail.Load(), totalHandshakes)
	}
	if goroutinePeak.Load() > int32(concurrency*3) {
		t.Errorf("goroutine peak %d exceeds 3x concurrency %d", goroutinePeak.Load(), concurrency)
	}
}
