package reality

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

// ProbeResult holds the raw TLS record data captured from a target server probe.
type ProbeResult struct {
	CipherSuite uint16
	RecordLens  [7]int
	RecordCount int
	// CertMeta is display-only leaf/chain shape learned from the probe peer
	// certificates (A1/A2). Never used for REALITY authentication.
	CertMeta *DestCertMeta
}

// probeConn is a net.Conn wrapper that captures all bytes read from the server
// side. It implements io.ReaderFrom so that uTLS's internal io.Copy (used during
// Handshake) also goes through our buffer.
type probeConn struct {
	net.Conn
	mu     sync.Mutex
	buf    bytes.Buffer
	closed chan struct{}
}

func newProbeConn(conn net.Conn) *probeConn {
	return &probeConn{
		Conn:   conn,
		closed: make(chan struct{}),
	}
}

func (c *probeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		c.buf.Write(b[:n])
		c.mu.Unlock()
	}
	return n, err
}

// ReadFrom implements io.ReaderFrom, which uTLS uses during Handshake via
// io.Copy. This ensures all server bytes (including those transferred via
// sendfile or splice on Linux) are captured in our buffer.
func (c *probeConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(&writeCapture{parent: c}, r)
}

func (c *probeConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return c.Conn.Close()
}

func (c *probeConn) capturedBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Bytes()
}

// writeCapture redirects writes from io.Copy into the probeConn buffer.
type writeCapture struct {
	parent *probeConn
}

func (w *writeCapture) Write(b []byte) (int, error) {
	w.parent.mu.Lock()
	defer w.parent.mu.Unlock()
	return w.parent.buf.Write(b)
}

// selectFingerprintAndALPN picks the uTLS fingerprint and ALPN protocols
// based on the desired ALPN index (0=none, 1=http/1.1, 2=h2+http/1.1).
func selectFingerprintAndALPN(alpn int) (utls.ClientHelloID, []string) {
	switch alpn {
	case 0:
		return utls.HelloGolang, nil
	case 1:
		return utls.HelloGolang, []string{"http/1.1"}
	default: // 2
		return utls.HelloChrome_Auto, []string{"h2", "http/1.1"}
	}
}

// dialAndProbe establishes a TCP connection to dest, performs a uTLS handshake
// to send a real ClientHello, and captures the raw server response bytes.
// The caller must provide ctx for timeout/cancellation, dest for the target
// address, serverName for SNI, and alpn for ALPN selection (0/1/2).
func dialAndProbe(ctx context.Context, dest, serverName string, alpn int, xver byte) (data []byte, peerCerts []*x509.Certificate, err error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}

	if xver == 1 || xver == 2 {
		if _, err = proxyproto.HeaderProxyFromAddrs(xver, conn.LocalAddr(), conn.RemoteAddr()).WriteTo(conn); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("proxy proto: %w", err)
		}
	}

	pConn := newProbeConn(conn)

	fingerprint, nextProtos := selectFingerprintAndALPN(alpn)
	uConn := utls.UClient(pConn, &utls.Config{
		ServerName:         serverName,
		NextProtos:         nextProtos,
		InsecureSkipVerify: true, // probe is observational, not authenticated
	}, fingerprint)

	if err = uConn.Handshake(); err != nil {
		pConn.Close()
		return nil, nil, fmt.Errorf("utls handshake: %w", err)
	}
	// Learn peer cert chain for A1/A2 fidelity (display-only).
	if st := uConn.ConnectionState(); len(st.PeerCertificates) > 0 {
		peerCerts = st.PeerCertificates
	}

	// Drain any remaining server data (post-handshake records like
	// NewSessionTicket) with a short deadline.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, maxRecordSize)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}

	pConn.Close()
	return pConn.capturedBytes(), peerCerts, nil
}

// parseRecordLens parses TLS record lengths from raw captured bytes.
// Returns the record lens array, the ServerHello cipher suite, and whether
// parsing succeeded. Reads up to 7 records (ServerHello through
// NewSessionTicket).
func parseRecordLens(data []byte) (lens [7]int, cipherSuite uint16, ok bool) {
	saved := data
	recordIndex := 0
	handshakeLen := 0

	for recordIndex < 7 {
		for recordIndex < 7 && len(saved) > recordHeaderLen {
			if handshakeLen == 0 {
				if bigEndianUint16(saved[1:3]) != VersionTLS12 {
					return
				}
				rt := recordType(saved[0])
				switch recordIndex {
				case 0:
					if rt != recordTypeHandshake || saved[5] != typeServerHello {
						return
					}
				case 1:
					if rt != recordTypeChangeCipherSpec || saved[5] != 1 {
						return
					}
				default:
					if rt != recordTypeApplicationData {
						return
					}
				}
				handshakeLen = recordHeaderLen + int(bigEndianUint16(saved[3:5]))
			}
			if handshakeLen > maxTLSRecordPayload {
				return
			}
			if recordIndex == 1 && handshakeLen > 0 && handshakeLen != 6 {
				return
			}
			if len(saved) < handshakeLen {
				break
			}
			lens[recordIndex] = handshakeLen

			if recordIndex == 0 {
				hello := new(serverHelloMsg)
				if !hello.unmarshal(saved[recordHeaderLen:handshakeLen]) {
					return
				}
				cipherSuite = hello.cipherSuite
			}

			saved = saved[handshakeLen:]
			handshakeLen = 0
			recordIndex++
		}
		if recordIndex >= 7 {
			break
		}
		// No more data available 鈥?partial capture, accept what we have.
		break
	}

	ok = recordIndex > 0
	return
}

// ProbeTargetViaUTLS probes the target server using a real uTLS ClientHello
// and returns the captured record lengths and cipher suite. This is the single
// trusted probe implementation used by prebuild.
//
// Parameters:
//   - ctx: context for timeout/cancellation
//   - dest: target address (e.g. "microsoft.com:443")
//   - serverName: SNI for the probe connection
//   - alpn: ALPN selector (0=none, 1=http/1.1, 2=h2+http/1.1)
//   - xver: PROXY protocol version (0=disabled, 1=v1, 2=v2)
func ProbeTargetViaUTLS(ctx context.Context, dest, serverName string, alpn int, xver byte) (*ProbeResult, error) {
	data, peerCerts, err := dialAndProbe(ctx, dest, serverName, alpn, xver)
	if err != nil {
		return nil, err
	}

	lens, cs, ok := parseRecordLens(data)
	if !ok {
		return nil, fmt.Errorf("failed to parse TLS records from %s", dest)
	}

	recordCount := 0
	for _, l := range lens {
		if l > 0 {
			recordCount++
		}
	}

	var meta *DestCertMeta
	if len(peerCerts) > 0 {
		// Index by dest and by SNI/serverName for handshake lookup.
		meta = LearnDestCertMetaFromChain(dest, peerCerts)
		if serverName != "" && serverName != dest {
			LearnDestCertMetaFromChain(serverName, peerCerts)
		}
		// B2: warm CertPlans after probe-learned meta so first success path is hot.
		if dest != "" {
			go WarmCertPlansForDest(dest)
		}
	}

	return &ProbeResult{
		CipherSuite: cs,
		RecordLens:  lens,
		RecordCount: recordCount,
		CertMeta:    meta,
	}, nil
}
