//go:build l1 || l2 || l3 || l4 || l5 || l6 || l3e2e || l3xray || l3prod || l3production

package reality

import (
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
	"testing"
	"time"
)

// ============================================================================
// Release Gate — 共享测试工具
// ============================================================================

// ReleaseGateTargets 定义发版测试目标
var ReleaseGateTargets = []struct {
	Name       string
	ServerName string
}{
	{"Microsoft", "www.microsoft.com"},
	{"Apple", "www.apple.com"},
	{"Tesla", "www.tesla.com"},
	{"Lovelive", "www.lovelive-anime.com"},
}

// CertPool 用于缓存测试证书，避免每次生成
var (
	testCertOnce   sync.Once
	testCertCert   tls.Certificate
	testCertErr    error
)

func mustTestCert() tls.Certificate {
	testCertOnce.Do(func() {
		testCertCert, testCertErr = generateCertPair()
	})
	if testCertErr != nil {
		panic("failed to generate test cert: " + testCertErr.Error())
	}
	return testCertCert
}

func generateCertPair() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"REALITY Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// newTestServer 创建一个标准测试 TLS 服务器，返回 listener 和地址
func newTestServer(t *testing.T, handler func(net.Conn)) (net.Listener, string) {
	t.Helper()

	cert := mustTestCert()
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()

	return ln, ln.Addr().String()
}

// echoHandler 回显所有读取到的数据
func echoHandler(conn net.Conn) {
	defer conn.Close()
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
}

// drainHandler 读取所有数据但不回复
func drainHandler(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 65536)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

func dialTLS(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func genPayload(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func iterationTag(i int) string {
	return fmt.Sprintf("#%d", i)
}
