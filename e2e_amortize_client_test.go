//go:build l2 || l3 || l3e2e

package reality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// realityAuthClient is a production-like REALITY client:
// AuthTag in SessionId + HMAC cert verification (same idea as Xray UClient).
type realityAuthClient struct {
	*utls.UConn
	authKey  []byte
	verified bool
}

func (h *e2eHarness) dialAuthorizedVerified(t *testing.T) *realityAuthClient {
	t.Helper()
	c, err := h.dialAuthorizedVerifiedErr("", nil, []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatalf("verified dial: %v", err)
	}
	return c
}

func (h *e2eHarness) dialAuthorizedVerifiedErr(serverName string, shortID []byte, nextProtos []string) (*realityAuthClient, error) {
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

	rc := &realityAuthClient{}
	uConn := utls.UClient(raw, &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		NextProtos:             nextProtos,
		VerifyPeerCertificate:  rc.verifyPeerCertificate,
	}, utls.HelloChrome_Auto)
	rc.UConn = uConn

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
	copy(hello.Raw[39:71], make([]byte, 32))

	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		raw.Close()
		return nil, fmt.Errorf("no ECDHE key share")
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
	rc.authKey = authKey

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
		return nil, fmt.Errorf("seal len %d", len(sealed))
	}
	copy(hello.SessionId, sealed)
	copy(hello.Raw[39:71], sealed)

	if err := uConn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if !rc.verified {
		raw.Close()
		return nil, fmt.Errorf("REALITY certificate not verified")
	}
	return rc, nil
}

func (rc *realityAuthClient) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certs")
	}
	// Prefer peerCertificates from conn (same as production) when available.
	var certs []*x509.Certificate
	if rc.UConn != nil && rc.UConn.Conn != nil {
		if p, ok := reflect.TypeOf(rc.UConn.Conn).Elem().FieldByName("peerCertificates"); ok {
			certs = *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(rc.UConn.Conn)) + p.Offset))
		}
	}
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		certs = []*x509.Certificate{cert}
	}
	pub, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("peer cert is not ed25519")
	}
	if len(rc.authKey) == 0 {
		return fmt.Errorf("missing authKey")
	}
	mac := hmac.New(sha512.New, rc.authKey)
	mac.Write(pub)
	if !hmac.Equal(mac.Sum(nil), certs[0].Signature) {
		return fmt.Errorf("REALITY HMAC cert verify failed")
	}
	rc.verified = true
	return nil
}

// fullDuplexEcho requires client Write+Read roundtrip after authorized handshake.
func (h *e2eHarness) fullDuplexEcho(t *testing.T, payload []byte) {
	t.Helper()
	beforeOK := h.AuthOK()
	c := h.dialAuthorizedVerified(t)
	// Wait server authOK
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && h.AuthOK() <= beforeOK {
		time.Sleep(5 * time.Millisecond)
	}
	if h.AuthOK() <= beforeOK {
		c.Close()
		t.Fatalf("server auth not complete")
	}

	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(payload); err != nil {
		c.Close()
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		c.Close()
		t.Fatalf("read: %v (serverEchoBytes=%d writeErr=%d)", err, h.echoBytes.Load(), h.echoWriteErr.Load())
	}
	if string(buf) != string(payload) {
		c.Close()
		t.Fatalf("echo mismatch")
	}
	// second round on same conn (regression for "handshake ok then disconnect")
	p2 := append([]byte("round2-"), payload...)
	if _, err := c.Write(p2); err != nil {
		c.Close()
		t.Fatalf("write2: %v", err)
	}
	buf2 := make([]byte, len(p2))
	if _, err := io.ReadFull(c, buf2); err != nil {
		c.Close()
		t.Fatalf("read2: %v", err)
	}
	if string(buf2) != string(p2) {
		c.Close()
		t.Fatalf("echo2 mismatch")
	}
	c.Close()
}
