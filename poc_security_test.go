package reality

// POC tests: reproduce suspected bugs BEFORE fixing. Each test asserts the
// POST-FIX expected behavior, so it FAILS on the buggy code (RED) and
// PASSES after the fix (GREEN).

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func realityTestConfig(targetAddr string) *Config {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(i)
	}
	copy(priv, []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	})
	return &Config{
		Dest:        targetAddr,
		Type:        "tcp",
		ServerNames: map[string]bool{"test.example.com": true},
		PrivateKey:  priv,
		ShortIds:    map[[8]byte]bool{{0x01}: true},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("tcp", targetAddr)
		},
	}
}

// TestHandshakeSemExhaustionBlocksLegit (POC, HIGH):
// opening maxConcurrentHandshakes+ slow sockets that never send a full
// ClientHello must NOT be able to starve a legitimate handshake. Before the
// fix each slow socket holds a handshakeSem slot for the 10s read deadline,
// so 1000+ such sockets permanently occupy the semaphore and a legit
// Server() call blocks until its context fires.
func TestHandshakeSemExhaustionBlocksLegit(t *testing.T) {
	if testing.Short() {
		t.Skip("long resource test")
	}
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	targetAddr := targetLn.Addr().String()
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				_, _ = io.Copy(io.Discard, conn)
				conn.Close()
			}(c)
		}
	}()

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverLn.Close()
	serverAddr := serverLn.Addr().String()
	cfg := realityTestConfig(targetAddr)

	var served atomic.Int64
	go func() {
		for {
			c, err := serverLn.Accept()
			if err != nil {
				return
			}
			served.Add(1)
			go func(conn net.Conn) {
				_, _ = Server(context.Background(), conn, cfg)
				conn.Close()
			}(c)
		}
	}()

	// Flood: maxConcurrentHandshakes + margin connections that send nothing.
	const margin = 32
	slots := maxConcurrentHandshakes
	var slow []net.Conn
	for i := 0; i < slots+margin; i++ {
		c, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatal(err)
		}
		slow = append(slow, c)
	}
	defer func() {
		for _, c := range slow {
			c.Close()
		}
	}()

	// Give the accept loop time to acquire handshakeSem for every flood socket.
	deadline := time.Now().Add(5 * time.Second)
	for served.Load() < int64(slots) {
		if time.Now().After(deadline) {
			t.Fatalf("only %d/%d flood conns reached Server", served.Load(), slots)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Let any stragglers settle into their handshake read (slow client guard
	// holds each slot the full 10s).
	time.Sleep(150 * time.Millisecond)

	// Legit handshake: must not be blocked by the flood.
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	legit, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer legit.Close()
	_, hsErr := Server(ctx, legit, cfg)
	if hsErr != nil && errors.Is(hsErr, context.DeadlineExceeded) {
		t.Fatalf("BUG/HIGH: slow-socket flood exhausted handshakeSem — legit handshake blocked (%v)", hsErr)
	}
}

// TestProfileCountDriftOnNegativeSweep (POC, MED):
// MarkNegative on a fresh key must account for the entry, so the later
// sweep cannot drive ProfileEntries negative and disable the capacity gate.
func TestProfileCountDriftOnNegativeSweep(t *testing.T) {
	m := NewCacheManager()
	before := m.stats.ProfileEntries.Load()

	m.MarkNegative("drift-key-1")
	// MarkNegative on a new key now accounts the entry (that was the fix);
	// the invariant we assert is that a full negative cycle returns the
	// count to baseline (no drift), keeping the capacity gate accurate.

	// Force the entry past its negative backoff so GetProfile sweeps it.
	val, ok := m.entries.Load("drift-key-1")
	if !ok {
		t.Fatal("negative entry missing")
	}
	entry := val.(*ProfileEntry)
	entry.mu.Lock()
	entry.NextRetry = time.Now().Add(-time.Second)
	entry.mu.Unlock()
	m.GetProfile("drift-key-1")

	after := m.stats.ProfileEntries.Load()
	if after != before {
		t.Fatalf("BUG/MED: negative cycle drifted count %d -> %d (net %d) — eviction gate drifts", before, after, after-before)
	}
}
