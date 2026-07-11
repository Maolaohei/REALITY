//go:build l2 || l3 || l3e2e

package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ---------------------------------------------------------------------------
// Local end-to-end harness for REALITY amortize paths.
//
// Topology (100% loopback, no public network):
//
//	authorized uTLS client
//	        |
//	   REALITY.Server  ----(optional RA dial)---> local TLS 1.3 target (echo)
//
// Counters:
//   - dialCount: how many times DialContext was called (RA probes)
//   - authOK:    how many Server() handshakes completed successfully
// ---------------------------------------------------------------------------

type e2eHarness struct {
	t            *testing.T
	serverName   string
	shortID      [8]byte
	priv         [32]byte
	pub          [32]byte
	targetLn     net.Listener
	serverLn     net.Listener
	serverAddr   string
	targetAddr   string
	cfg          *Config
	dialCount    atomic.Int64
	authOK       atomic.Int64
	authFail     atomic.Int64
	stopOnce     sync.Once
	echoBytes    atomic.Int64
	echoWriteErr atomic.Int64
	mode         AmortizeMode
}

type e2eHarnessOpts struct {
	ServerName   string
	AmortizeMode AmortizeMode
	Show         bool
	MaxTimeDiff  time.Duration
	// If true, target accepts TLS but immediately closes after handshake (edge).
	TargetCloseAfterHS bool
}

func newE2EHarness(t *testing.T, opts e2eHarnessOpts) *e2eHarness {
	t.Helper()
	if opts.ServerName == "" {
		opts.ServerName = "test.example.com"
	}
	if opts.MaxTimeDiff == 0 {
		opts.MaxTimeDiff = -1 // disable time skew for tests
	}

	h := &e2eHarness{
		t:          t,
		serverName: opts.ServerName,
		mode:       opts.AmortizeMode,
	}
	if _, err := io.ReadFull(rand.Reader, h.priv[:]); err != nil {
		t.Fatal(err)
	}
	// Clamp X25519 private key.
	h.priv[0] &= 248
	h.priv[31] &= 127
	h.priv[31] |= 64
	curve25519.ScalarBaseMult(&h.pub, &h.priv)
	h.shortID = [8]byte{0, 0, 0, 0, 0, 0, 0, 1}

	// Local TLS 1.3 target (camouflage dest).
	targetCert := mustTestCert()
	targetLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{targetCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.targetLn = targetLn
	h.targetAddr = targetLn.Addr().String()
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if opts.TargetCloseAfterHS {
					// Complete TLS via first Read/Write then close.
					_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
					buf := make([]byte, 1)
					_, _ = conn.Read(buf)
					return
				}
				buf := make([]byte, 65536)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					if _, err := conn.Write(buf[:n]); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.serverLn = serverLn
	h.serverAddr = serverLn.Addr().String()

	h.cfg = &Config{
		Dest:         h.targetAddr,
		Type:         "tcp",
		Show:         opts.Show,
		ServerNames:  map[string]bool{h.serverName: true},
		PrivateKey:   h.priv[:],
		ShortIds:     map[[8]byte]bool{h.shortID: true},
		MaxTimeDiff:  opts.MaxTimeDiff,
		AmortizeMode: opts.AmortizeMode,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			h.dialCount.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, "tcp", h.targetAddr)
		},
	}

	go func() {
		for {
			c, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				rc, err := Server(context.Background(), conn, h.cfg)
				if err != nil {
					h.authFail.Add(1)
					conn.Close()
					return
				}
				h.authOK.Add(1)
				// Echo application data on authorized path.
				buf := make([]byte, 65536)
				for {
					n, err := rc.Read(buf)
					if err != nil {
						return
					}
					h.echoBytes.Add(int64(n))
					if _, werr := rc.Write(buf[:n]); werr != nil {
						h.echoWriteErr.Add(1)
						return
					}
				}
			}(c)
		}
	}()

	// Isolate from other tests / async DetectPostHandshakeRecordsLens.
	GlobalPostHandshakeRecordsLens = sync.Map{}
	GlobalMaxCSSMsgCount = sync.Map{}

	// Give accept loops a moment.
	time.Sleep(30 * time.Millisecond)
	t.Cleanup(h.Close)
	return h
}

func (h *e2eHarness) Close() {
	h.stopOnce.Do(func() {
		if h.serverLn != nil {
			_ = h.serverLn.Close()
		}
		if h.targetLn != nil {
			_ = h.targetLn.Close()
		}
	})
}

func (h *e2eHarness) Dials() int64 { return h.dialCount.Load() }
func (h *e2eHarness) AuthOK() int64 { return h.authOK.Load() }
func (h *e2eHarness) AuthFail() int64 { return h.authFail.Load() }

func (h *e2eHarness) shortIDBytes() []byte {
	b := make([]byte, 8)
	copy(b, h.shortID[:])
	return b
}

// dialAuthorized performs a REALITY-authenticated client handshake.
func (h *e2eHarness) dialAuthorized(serverName string, shortID []byte, nextProtos []string) (*utls.UConn, error) {
	if serverName == "" {
		serverName = h.serverName
	}
	if shortID == nil {
		shortID = h.shortIDBytes()
	}
	if nextProtos == nil {
		nextProtos = []string{"h2", "http/1.1"}
	}

	raw, err := net.DialTimeout("tcp", h.serverAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	serverPub, err := ecdh.X25519().NewPublicKey(h.pub[:])
	if err != nil {
		raw.Close()
		return nil, err
	}

	uConn := utls.UClient(raw, &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		NextProtos:             nextProtos,
	}, utls.HelloChrome_Auto)

	if err := uConn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("BuildHandshakeState: %w", err)
	}
	hello := uConn.HandshakeState.Hello
	if len(hello.Raw) < 71 {
		raw.Close()
		return nil, fmt.Errorf("ClientHello Raw too short: %d", len(hello.Raw))
	}
	hello.SessionId = make([]byte, 32)
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID)
	if _, err := io.ReadFull(rand.Reader, hello.SessionId[16:]); err != nil {
		raw.Close()
		return nil, err
	}
	plain16 := make([]byte, 16)
	copy(plain16, hello.SessionId[:16])
	// Server Open() AAD uses ClientHello with session_id zeroed.
	copy(hello.Raw[39:71], make([]byte, 32))

	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		raw.Close()
		return nil, fmt.Errorf("fingerprint has no ECDHE key share")
	}
	authKey, err := ecdhe.ECDH(serverPub)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		raw.Close()
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		raw.Close()
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		raw.Close()
		return nil, err
	}
	sealed := aead.Seal(nil, hello.Random[20:], plain16, hello.Raw)
	if len(sealed) != 32 {
		raw.Close()
		return nil, fmt.Errorf("unexpected seal len %d", len(sealed))
	}
	copy(hello.SessionId, sealed)
	copy(hello.Raw[39:71], sealed)

	if err := uConn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return uConn, nil
}

func (h *e2eHarness) mustDialAuthorized(t *testing.T) *utls.UConn {
	t.Helper()
	c, err := h.dialAuthorized("", nil, nil)
	if err != nil {
		t.Fatalf("authorized dial: %v", err)
	}
	return c
}

func (h *e2eHarness) echoRoundTrip(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	// ReadFull once; if peer still delivering post-handshake noise, retry briefly.
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		_, err = io.ReadFull(c, buf)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf, payload)
	}
}

// handshakeOnly completes an authorized handshake without requiring app-data echo.
func (h *e2eHarness) handshakeOnly(t *testing.T) {
	t.Helper()
	before := h.AuthOK()
	c := h.mustDialAuthorized(t)
	// Wait until server finishes readClientFinished and returns from Server().
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.AuthOK() > before {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.Close()
	if h.AuthOK() <= before {
		t.Fatalf("server did not complete authorized handshake (authOK=%d authFail=%d)", h.AuthOK(), h.AuthFail())
	}
}

func (h *e2eHarness) maxEvidence() int {
	maxEv := 0
	globalCacheManager.entries.Range(func(_, v any) bool {
		e := v.(*ProfileEntry)
		if e.Profile != nil && e.Profile.Evidence > maxEv {
			maxEv = e.Profile.Evidence
		}
		return true
	})
	return maxEv
}

func (h *e2eHarness) report(t *testing.T, label string) {
	t.Helper()
	t.Logf("[%s] dials=%d authOK=%d authFail=%d maxEvidence=%d l1=%d l2=%d l2fail=%d quarantine=%d\n%s",
		label,
		h.Dials(), h.AuthOK(), h.AuthFail(), h.maxEvidence(),
		globalCacheManager.stats.L1Hits.Load(),
		globalCacheManager.stats.L2Hits.Load(),
		globalCacheManager.stats.L2Fails.Load(),
		globalCacheManager.stats.Quarantines.Load(),
		globalCacheManager.CacheReport(),
	)
}

// dialPlainTLS is an unauthenticated standard TLS client (auth should fail / mirror).
func (h *e2eHarness) dialPlainTLS(t *testing.T, serverName string) (*tls.Conn, error) {
	t.Helper()
	if serverName == "" {
		serverName = h.serverName
	}
	return tls.Dial("tcp", h.serverAddr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
	})
}
