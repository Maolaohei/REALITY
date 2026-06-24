package reality

import (
	"context"
	"sync"
	"time"
)

// TargetProfile holds cached TLS record lengths captured from a target
// server during a probe. These lengths are used to construct the fake
// handshake without connecting to the target in real-time.
type TargetProfile struct {
	// HandshakeLen mirrors hs.c.out.handshakeLen — the exact byte lengths
	// of each TLS 1.3 record the target sends:
	//   [0] ServerHello
	//   [1] ChangeCipherSpec (always 6)
	//   [2] EncryptedExtensions
	//   [3] Certificate
	//   [4] CertificateVerify
	//   [5] Finished
	//   [6] NewSessionTicket (0 if not sent)
	HandshakeLen [7]int

	// CipherSuite is the TLS 1.3 cipher suite from the target's ServerHello.
	// Needed to construct a compatible fake ServerHello.
	CipherSuite uint16

	// KeyGroup is the key exchange group from the target's ServerHello
	// (X25519 or X25519MLKEM768).
	KeyGroup CurveID

	CapturedAt time.Time
	TTL        time.Duration
}

// PrebuildCache stores per-serverName target profiles with automatic
// expiration. Safe for concurrent use.
type PrebuildCache struct {
	mu       sync.RWMutex
	profiles map[string]*TargetProfile
	ttl      time.Duration
}

// NewPrebuildCache creates a new cache with the given per-entry TTL.
func NewPrebuildCache(ttl time.Duration) *PrebuildCache {
	return &PrebuildCache{
		profiles: make(map[string]*TargetProfile),
		ttl:      ttl,
	}
}

// Get returns the cached profile for serverName, or nil if expired/missing.
func (pc *PrebuildCache) Get(serverName string) *TargetProfile {
	pc.mu.RLock()
	p, ok := pc.profiles[serverName]
	pc.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(p.CapturedAt) > p.TTL {
		pc.mu.Lock()
		delete(pc.profiles, serverName)
		pc.mu.Unlock()
		return nil
	}
	return p
}

// Store adds or replaces a profile for serverName.
func (pc *PrebuildCache) Store(serverName string, p *TargetProfile) {
	pc.mu.Lock()
	pc.profiles[serverName] = p
	pc.mu.Unlock()
}

// ProbeTarget connects to the target server, captures its TLS record
// lengths, and caches the result. This is the core "pre-build" operation.
// It should be called periodically (e.g., every 30 minutes) to refresh
// cached data before expiration.
func ProbeTarget(ctx context.Context, config *Config) error {
	target, err := config.DialContext(ctx, config.Type, config.Dest)
	if err != nil {
		return err
	}
	defer target.Close()

	// Read the target's TLS response to capture record lengths.
	// We use the same approach as the real Server() goroutine.
	buf := make([]byte, maxRecordSize)
	s2cSaved := make([]byte, 0, maxRecordSize)
	handshakeLen := 0
	profile := &TargetProfile{
		CapturedAt: time.Now(),
		TTL:        30 * time.Minute,
	}

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
					return nil
				}
				recordType := recordType(s2cSaved[0])
				switch recordIndex {
				case 0: // ServerHello
					if recordType != recordTypeHandshake || s2cSaved[5] != typeServerHello {
						return nil
					}
				case 1: // ChangeCipherSpec
					if recordType != recordTypeChangeCipherSpec || s2cSaved[5] != 1 {
						return nil
					}
				default: // ApplicationData records
					if recordType != recordTypeApplicationData {
						return nil
					}
				}
				handshakeLen = recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
			}
			if handshakeLen > maxTLSRecordPayload {
				return nil
			}
			if len(s2cSaved) < handshakeLen {
				break // need more data
			}
			profile.HandshakeLen[recordIndex] = handshakeLen
			s2cSaved = s2cSaved[handshakeLen:]
			handshakeLen = 0
			recordIndex++
		}
	}

	if recordIndex > 0 {
		defaultPrebuildCache.Store(config.Dest, profile)
	}
	return nil
}
