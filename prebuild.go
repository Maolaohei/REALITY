package reality

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// ProbeTarget connects to the target server, captures its TLS record
// lengths, and returns a RealityProfile.
func ProbeTarget(ctx context.Context, config *Config) (*RealityProfile, error) {
	target, err := config.DialContext(ctx, config.Type, config.Dest)
	if err != nil {
		return nil, err
	}
	defer target.Close()

	// Apply a read deadline so slow targets don't block forever.
	// Context only covers the dial; reads need their own deadline.
	target.SetReadDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, maxRecordSize)
	s2cSaved := make([]byte, 0, maxRecordSize)
	handshakeLen := 0
	var recordLens [7]int
	var cipherSuite uint16

	recordIndex := 0
	for recordIndex < 7 {
		n, err := target.Read(buf)
		if err != nil {
			break
		}
		s2cSaved = append(s2cSaved, buf[:n]...)

		for recordIndex < 7 && len(s2cSaved) > recordHeaderLen {
			if handshakeLen == 0 {
				if bigEndianUint16(s2cSaved[1:3]) != VersionTLS12 {
					return nil, fmt.Errorf("invalid TLS version")
				}
				rt := recordType(s2cSaved[0])
				switch recordIndex {
				case 0:
					if rt != recordTypeHandshake || s2cSaved[5] != typeServerHello {
						return nil, fmt.Errorf("not ServerHello")
					}
				case 1:
					if rt != recordTypeChangeCipherSpec || s2cSaved[5] != 1 {
						return nil, fmt.Errorf("not ChangeCipherSpec")
					}
				default:
					if rt != recordTypeApplicationData {
						return nil, fmt.Errorf("not ApplicationData")
					}
				}
				handshakeLen = recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
			}
			if handshakeLen > maxTLSRecordPayload {
				return nil, fmt.Errorf("record too large")
			}
			if len(s2cSaved) < handshakeLen {
				break
			}
			recordLens[recordIndex] = handshakeLen

			if recordIndex == 0 {
				hello := new(serverHelloMsg)
				if !hello.unmarshal(s2cSaved[recordHeaderLen:handshakeLen]) {
					return nil, fmt.Errorf("failed to unmarshal ServerHello")
				}
				cipherSuite = hello.cipherSuite
			}

			s2cSaved = s2cSaved[handshakeLen:]
			handshakeLen = 0
			recordIndex++
		}
	}

	if recordIndex == 0 {
		return nil, fmt.Errorf("no records read")
	}

	recordCount := 0
	for _, l := range recordLens {
		if l > 0 {
			recordCount++
		}
	}

	return &RealityProfile{
		RecordLens:   recordLens,
		Fingerprint:  computeFingerprint(cipherSuite, "", recordLens[0], recordLens[2]),
		CipherSuite:  cipherSuite,
		ALPN:         "",
		TLSVersion:   VersionTLS13,
		RecordCount:  recordCount,
		CapturedAt:   time.Now(),
	}, nil
}

// ============================================================================
// Auto-start infrastructure
// ============================================================================

var (
	probeOnces sync.Map
	warmupOnce sync.Once
)

type probeConfig struct {
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
	show        bool
	dest        string
	typ         string
}

func newProbeConfig(config *Config) probeConfig {
	return probeConfig{
		dialContext: config.DialContext,
		show:        config.Show,
		dest:        config.Dest,
		typ:         config.Type,
	}
}

func ensureAutoProbe(config *Config) {
	dest := config.Dest
	if dest == "" {
		return
	}

	onceVal, _ := probeOnces.LoadOrStore(dest, &sync.Once{})
	once := onceVal.(*sync.Once)

	once.Do(func() {
		m := GetRefreshManager()
		if !m.started {
			m.Start()
		}
		m.AddTarget(dest, "")
	})
}

func StopAutoProbe(dest string) {
	if globalRefreshManager != nil {
		globalRefreshManager.RemoveTarget(dest, "")
	}
	probeOnces.Delete(dest)
}

func probeTargetRaw(dest string) (*RealityProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", dest)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	buf := make([]byte, maxRecordSize)
	s2cSaved := make([]byte, 0, maxRecordSize)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadAtLeast(conn, buf, recordHeaderLen+1)
	if err != nil {
		return nil, err
	}
	s2cSaved = append(s2cSaved, buf[:n]...)

	if bigEndianUint16(s2cSaved[1:3]) != VersionTLS12 {
		return nil, fmt.Errorf("invalid TLS version")
	}
	if recordType(s2cSaved[0]) != recordTypeHandshake || s2cSaved[5] != typeServerHello {
		return nil, fmt.Errorf("not ServerHello")
	}
	serverHelloLen := recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
	if serverHelloLen > maxTLSRecordPayload || serverHelloLen > len(s2cSaved) {
		return nil, fmt.Errorf("invalid ServerHello length")
	}

	hello := new(serverHelloMsg)
	if !hello.unmarshal(s2cSaved[recordHeaderLen:serverHelloLen]) {
		return nil, fmt.Errorf("failed to unmarshal ServerHello")
	}

	var recordLens [7]int
	recordLens[0] = serverHelloLen
	recordIndex := 1
	s2cSaved = s2cSaved[serverHelloLen:]

	for recordIndex < 7 {
		for recordIndex < 7 && len(s2cSaved) > recordHeaderLen {
			handshakeLen := recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
			if handshakeLen > maxTLSRecordPayload {
				break
			}
			if len(s2cSaved) < handshakeLen {
				break
			}
			recordLens[recordIndex] = handshakeLen
			s2cSaved = s2cSaved[handshakeLen:]
			recordIndex++
		}
		if recordIndex >= 7 {
			break
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := io.ReadAtLeast(conn, buf, recordHeaderLen+1)
		if err != nil {
			break
		}
		s2cSaved = append(s2cSaved, buf[:n]...)
	}

	recordCount := 0
	for _, l := range recordLens {
		if l > 0 {
			recordCount++
		}
	}

	return &RealityProfile{
		RecordLens:   recordLens,
		Fingerprint:  computeFingerprint(hello.cipherSuite, "", recordLens[0], recordLens[2]),
		CipherSuite:  hello.cipherSuite,
		ALPN:         "",
		TLSVersion:   VersionTLS13,
		RecordCount:  recordCount,
		CapturedAt:   time.Now(),
	}, nil
}

func WarmupProfiles(dir string) {
	warmupOnce.Do(func() {
		go func() {
			if profileStore == nil {
				return
			}
			var keys []string
			globalCacheManager.entries.Range(func(key, val any) bool {
				keys = append(keys, key.(string))
				return true
			})
			if len(keys) == 0 {
				return
			}

			sem := make(chan struct{}, 5)
			var wg sync.WaitGroup
			for _, key := range keys {
				wg.Add(1)
				sem <- struct{}{}
				go func(k string) {
					defer wg.Done()
					defer func() { <-sem }()

					dest := k
					if idx := strings.Index(k, "|"); idx > 0 {
						dest = k[:idx]
					}
					if dest == "" {
						return
					}

					globalCacheManager.DoProbe(dest, func() (*RealityProfile, error) {
						return probeTargetRaw(dest)
					})
				}(key)
			}
			wg.Wait()
		}()
	})
}
