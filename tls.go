// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-Go file.

// Server side implementation of REALITY protocol, a fork of package tls in latest Go.
// For client side, please follow https://github.com/XTLS/Xray-core/blob/main/transport/internet/reality/reality.go.

// Package tls partially implements TLS 1.2, as specified in RFC 5246,
// and TLS 1.3, as specified in RFC 8446.
//
// # FIPS 140-3 mode
//
// When the program is in [FIPS 140-3 mode], this package behaves as if only
// SP 800-140C and SP 800-140D approved protocol versions, cipher suites,
// signature algorithms, certificate public key types and sizes, and key
// exchange and derivation algorithms were implemented. Others are silently
// ignored and not negotiated, or rejected. This set may depend on the
// algorithms supported by the FIPS 140-3 Go Cryptographic Module selected with
// GOFIPS140, and may change across Go versions.
//
// [FIPS 140-3 mode]: https://go.dev/doc/security/fips140
package reality

// BUG(agl): The crypto/tls package only implements some countermeasures
// against Lucky13 attacks on CBC-mode encryption, and only on SHA1
// variants. See http://www.isg.rhul.ac.uk/tls/TLStiming.pdf and
// https://www.imperialviolet.org/2013/02/04/luckythirteen.html.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/juju/ratelimit"
)

type CloseWriteConn interface {
	net.Conn
	CloseWrite() error
}

var (
	errMirrorWrite = errors.New("mirror: write not supported")
	errMirrorClose = errors.New("mirror: close not supported")
)

type MirrorConn struct {
	*sync.Mutex
	net.Conn
	Target net.Conn
}

// mirrorIdleTimeout is the maximum time a MirrorConn.Read will wait for data
// from the client before giving up. Prevents permanent hangs if the client
// or target becomes unresponsive during the handshake phase.
const mirrorIdleTimeout = 2 * time.Minute

func (c *MirrorConn) Read(b []byte) (int, error) {
	// Caller holds the mutex. We release it here to allow the target read
	// goroutine to proceed, then re-acquire after our read completes.
	// defer c.Lock() guarantees the mutex is always re-locked before returning,
	// even if c.Conn.Read panics (unlikely for syscalls) or Write/Close panics.
	c.Unlock()
	defer c.Lock()
	// Set idle deadline on client read to prevent permanent hangs.
	_ = c.Conn.SetReadDeadline(time.Now().Add(mirrorIdleTimeout))
	n, err := c.Conn.Read(b)
	// Clear deadline after successful read so subsequent operations are not affected.
	if err == nil {
		_ = c.Conn.SetReadDeadline(time.Time{})
	}
	if n != 0 {
		c.Target.Write(b[:n])
	}
	if err != nil {
		c.Target.Close()
	}
	return n, err
}

func (c *MirrorConn) Write(b []byte) (int, error) {
	return 0, errMirrorWrite
}

func (c *MirrorConn) Close() error {
	return errMirrorClose
}

func (c *MirrorConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *MirrorConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *MirrorConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type RatelimitedConn struct {
	net.Conn
	After  int64
	Bucket *ratelimit.Bucket
}

func (c *RatelimitedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n != 0 {
		if c.After > 0 {
			c.After -= int64(n)
		} else {
			c.Bucket.Wait(int64(n))
		}
	}
	return n, err
}

func NewRatelimitedConn(conn net.Conn, limit *LimitFallback) net.Conn {
	if limit.BytesPerSec == 0 {
		return conn
	}

	burstBytesPerSec := limit.BurstBytesPerSec
	if burstBytesPerSec < limit.BytesPerSec {
		burstBytesPerSec = limit.BytesPerSec
	}

	return &RatelimitedConn{
		Conn:   conn,
		After:  int64(limit.AfterBytes),
		Bucket: ratelimit.NewBucketWithRate(float64(limit.BytesPerSec), int64(burstBytesPerSec)),
	}
}

// ProfileTTL is the time-to-live for cached RealityProfile entries.
const ProfileTTL = 30 * time.Minute

// DefaultCacheDir returns the platform-appropriate default directory for
// persistent profile storage. Returns empty string if the user cache dir
// cannot be determined.
func DefaultCacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "REALITY")
	}
	return ""
}

var (
	// maxRecordSize is the buffer size for reading TLS handshake records from
	// the target server. Raised from 8192 to 65536 (64 KiB) to support targets
	// with large certificate chains (long SANs, multi-level intermediates).
	maxRecordSize = 65536

	// maxTLSRecordPayload is the maximum payload size of a single TLS record
	// as defined by RFC 8446 ?5.1 (2^14 = 16384 bytes).
	maxTLSRecordPayload = 16384

	// maxConcurrentHandshakes limits the number of simultaneous handshake
	// attempts to prevent resource exhaustion from connection flooding.
	maxConcurrentHandshakes = 1000

	// handshakeSem is a counting semaphore for concurrent handshakes.
	handshakeSem = make(chan struct{}, maxConcurrentHandshakes)

	// globalReplayGuard deduplicates ClientHello.random prefixes to prevent
	// resource-wasting replays within the MaxTimeDiff window.
	globalReplayGuard *ReplayGuard

	// empty is a reusable zero-filled buffer for padding and ML-DSA-65 cert
	// extensions. 8192 bytes is sufficient (largest use: 3309 bytes).
	empty = make([]byte, 8192)
	types = [7]string{
		"Server Hello",
		"Change Cipher Spec",
		"Encrypted Extensions",
		"Certificate",
		"Certificate Verify",
		"Finished",
		"New Session Ticket",
	}

	// recordBufPool reuses 64 KiB buffers for Server() handshake reads,
	// avoiding per-connection allocation of two 64 KiB slices.
	recordBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, maxRecordSize)
			return &buf
		},
	}

	// drainBufPool reuses 4 KiB buffers for the background drain goroutine
	// in Server(), avoiding a per-connection heap allocation.
	drainBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, 4096)
			return &buf
		},
	}
)

// FNV-1a 64-bit constants for inline hashing (avoids hash/fnv allocs).
const (
	fnv64Offset = 14695981039346656037
	fnv64Prime  = 1099511628211
)

// RealityProfile is the unified cache entry for REALITY handshake profiles.
// Combines output record lengths, fingerprint, handshake policy metadata, and
// optional ServerHello template for zero-dial (L2) amortize.
//
// R0 is never replayed as ciphertext to the client. ServerHelloTemplate holds
// a captured handshake message shape so L2 can patch a fresh random/keyshare.
type RealityProfile struct {
	RecordLens    [7]int
	Fingerprint   uint64
	CipherSuite   uint16
	ALPN          string
	TLSVersion    uint16 // TLS 1.2 or 1.3 - different versions have different record layouts
	RecordCount   int
	CapturedAt    time.Time
	RecordMode    uint8 // RecordModeSplit / RecordModeCoalesced

	// Amortize / policy fields (optional for legacy entries).
	Dest                string
	ServerName          string
	CHClass             string
	KeyShareGroup       CurveID
	AcceptsHRR          bool
	ShapeHash           uint64
	ServerHelloTemplate []byte // handshake message only (no record header)
	Evidence            int    // consecutive matching observations (live quality for L2)
	LiveEvidence        int    // consecutive matching live-only observations
	Stability           int
	Source              string // "live" | "probe" | "persist"
	CHClassVer          uint8  // ClassifyClientHello algorithm version used for CHClass
}

// IsExpired checks if the profile has exceeded the TTL.
func (p *RealityProfile) IsExpired() bool {
	return time.Since(p.CapturedAt) > ProfileTTL
}

// targetFingerprintCache caches the target server's TLS capabilities.
// Updated in background; reduces synchronous ProbeTarget frequency.
type targetFingerprintCache struct {
	CipherSuite       uint16
	ALPN              string
	SupportedVersions []uint16
	KeyShareGroup     uint16
	SignatureSchemes  []SignatureScheme
	LastUpdated       time.Time
}

// bigEndianUint16 decodes a big-endian 16-bit unsigned integer from b.
// This is equivalent to the previous Value() helper for 2-byte slices,
// but uses the optimized encoding/binary path.
func bigEndianUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// computeFingerprint computes FNV64 hash of (CipherSuite, ALPN, ServerHelloLen, ExtensionsLen).
// Used for cache hit/miss decisions ?more robust than comparing individual fields.
func computeFingerprint(cipherSuite uint16, alpn string, serverHelloLen, extensionsLen int) uint64 {
	var h uint64 = fnv64Offset
	mixU16 := func(v uint16) {
		h ^= uint64(v >> 8)
		h *= fnv64Prime
		h ^= uint64(v & 0xff)
		h *= fnv64Prime
	}
	mixU16(cipherSuite)
	for i := 0; i < len(alpn); i++ {
		h ^= uint64(alpn[i])
		h *= fnv64Prime
	}
	mixU16(uint16(serverHelloLen))
	mixU16(uint16(extensionsLen))
	return h
}

// bigEndianUint24 decodes a big-endian 24-bit unsigned integer from b.
// Used for 3-byte version fields (e.g., ClientVer[3]).
func bigEndianUint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// Value(vals ...byte) converts a big-endian byte sequence to an int.
// Deprecated: use bigEndianUint16/24 for fixed-width cases.
func Value(vals ...byte) (value int) {
	for i, val := range vals {
		value |= int(val) << ((len(vals) - i - 1) * 8)
	}
	return
}

var maxTimeDiffWarnOnce sync.Once

// You MUST call `DetectPostHandshakeRecordsLens(config)` in advance manually
// if you don't use REALITY's listener, e.g., Xray-core's RAW transport.
// Server implementation lives in server_amortize.go (auth-first L0/L1/L2 paths).

func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
	c.handshakeFn = c.clientHandshake
	return c
}

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *Config
	conns  chan net.Conn
	err    error
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	/*
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		return Server(c, l.config), nil
	*/
	if c, ok := <-l.conns; ok {
		return c, nil
	}
	return nil, l.err
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with [Server].
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func NewListener(inner net.Listener, config *Config) net.Listener {
	go DetectPostHandshakeRecordsLens(config)
	l := new(listener)
	l.Listener = inner
	l.config = config
	{
		l.conns = make(chan net.Conn)
		go func() {
			for {
				c, err := l.Listener.Accept()
				if err != nil {
					l.err = err
					close(l.conns)
					return
				}
				go func() {
					defer func() { recover() }()
					c, err = Server(context.Background(), c, l.config)
					if err == nil {
						l.conns <- c
					}
				}()
			}
		}()
	}
	return l
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	// If this condition changes, consider updating http.Server.ServeTLS too.
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a TLS handshake, returning the resulting TLS connection. Any
// timeout or deadline given in the dialer apply to connection and TLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of [Config] for the defaults.
//
// DialWithDialer uses context.Background internally; to specify the context,
// use [Dialer.DialContext] with NetDialer set to the desired dialer.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	if netDialer.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, netDialer.Timeout)
		defer cancel()
	}

	if !netDialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, netDialer.Deadline)
		defer cancel()
	}

	rawConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	conn := Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a TLS handshake, returning the resulting
// TLS connection.
// Dial interprets a nil configuration as equivalent to
// the zero configuration; see the documentation of Config
// for the defaults.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// Dialer dials TLS connections given a configuration and a Dialer for the
// underlying connection.
type Dialer struct {
	// NetDialer is the optional dialer to use for the TLS connections'
	// underlying TCP connections.
	// A nil NetDialer is equivalent to the net.Dialer zero value.
	NetDialer *net.Dialer

	// Config is the TLS configuration to use for new connections.
	// A nil configuration is equivalent to the zero
	// configuration; see the documentation of Config for the
	// defaults.
	Config *Config
}

// Dial connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The returned [Conn], if any, will always be of type *[Conn].
//
// Dial uses context.Background internally; to specify the context,
// use [Dialer.DialContext].
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

// DialContext connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// The returned [Conn], if any, will always be of type *[Conn].
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
	if err != nil {
		// Don't return c (a typed nil) in an interface.
		return nil, err
	}
	return c, nil
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair of
// files. The files must contain PEM encoded data. The certificate file may
// contain intermediate certificates following the leaf certificate to form a
// certificate chain. On successful return, Certificate.Leaf will be populated.
//
// Before Go 1.23 Certificate.Leaf was left nil, and the parsed certificate was
// discarded. This behavior can be re-enabled by setting "x509keypairleaf=0"
// in the GODEBUG environment variable.
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be populated.
//
// Before Go 1.23 Certificate.Leaf was left nil, and the parsed certificate was
// discarded. This behavior can be re-enabled by setting "x509keypairleaf=0"
// in the GODEBUG environment variable.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	fail := func(err error) (Certificate, error) { return Certificate{}, err }

	var cert Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("tls: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tls: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("tls: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}

	cert.Leaf = x509Cert

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return fail(err)
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fail(errors.New("tls: private key does not match public key"))
		}
	default:
		return fail(errors.New("tls: unknown public key algorithm"))
	}

	return cert, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}


