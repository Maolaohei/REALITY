package reality

import (
	"fmt"
	"strconv"
)

// AmortizeMode controls how aggressively REALITY reuses observed target
// handshake profiles to skip RA (dest) work.
//
//	AmortizeL0: always dial RA and read live records (baseline).
//	AmortizeL1: dial RA, read live R0, may reuse cached R1-R6.
//	AmortizeL2: after enough evidence, skip RA dial entirely (zero-dial) (default).
//	AmortizeAuto: L2 when profile is L2-eligible, else L1.
type AmortizeMode int

const (
	// AmortizeDefault is the zero value: resolve to DefaultAmortizeMode (L2).
	AmortizeDefault AmortizeMode = iota
	AmortizeL0
	AmortizeL1
	AmortizeL2
	AmortizeAuto
)

// AmortizePath is the selected runtime path for one connection.
type AmortizePath int

const (
	PathL0 AmortizePath = iota // live dial + full R0-R6
	PathL1                     // live dial + live R0 + cached R1-R6
	PathL2                     // zero-dial, policy + full lens from cache
)

func (p AmortizePath) String() string {
	switch p {
	case PathL0:
		return "L0"
	case PathL1:
		return "L1"
	case PathL2:
		return "L2"
	default:
		return fmt.Sprintf("L%d", int(p))
	}
}

// DefaultAmortizeMode is L2: zero-dial after evidence; falls back to L1/L0 when ineligible.
const DefaultAmortizeMode = AmortizeL2

// MinL2Evidence is the minimum consecutive matching live observations required
// before a profile may be used for zero-dial (Path L2).
const MinL2Evidence = 2

// MaxL2FailWindow is how many recent L2 handshake failures on a key trigger quarantine.
const MaxL2FailWindow = 2

// isGREASE reports TLS GREASE values (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && (v>>8) == (v&0xff)
}

// ClassifyClientHello derives a stable ClientHello equivalence-class id.
// Profiles are keyed by this so different cipher/group/ALPN/ECH shapes never mix.
// Ordering of suites/groups is normalized so fingerprint shuffle does not split cache.
func ClassifyClientHello(ch *clientHelloMsg) string {
	if ch == nil {
		return "empty"
	}
	var h uint64 = fnv64Offset
	mixU16 := func(v uint16) {
		h ^= uint64(v >> 8)
		h *= fnv64Prime
		h ^= uint64(v & 0xff)
		h *= fnv64Prime
	}
	mixByte := func(b byte) {
		h ^= uint64(b)
		h *= fnv64Prime
	}

	// Primary ALPN only (first). Empty is distinct from h2/http1.1.
	alpn := clientALPN(ch)
	for i := 0; i < len(alpn); i++ {
		h ^= uint64(alpn[i])
		h *= fnv64Prime
	}
	mixByte(0)

	// Key-share capability flags (order/GREASE independent).
	var hasX25519, hasMLKEM, hasP256 bool
	for _, ks := range ch.keyShares {
		switch ks.group {
		case X25519:
			hasX25519 = true
		case X25519MLKEM768:
			hasMLKEM = true
		case CurveP256:
			hasP256 = true
		}
	}
	// Also consider supported_groups in case keyshare deferred (HRR).
	for _, g := range ch.supportedCurves {
		switch g {
		case X25519:
			hasX25519 = true
		case X25519MLKEM768:
			hasMLKEM = true
		case CurveP256:
			hasP256 = true
		}
	}
	if hasX25519 {
		mixByte(1)
	} else {
		mixByte(0)
	}
	if hasMLKEM {
		mixByte(1)
	} else {
		mixByte(0)
	}
	if hasP256 {
		mixByte(1)
	} else {
		mixByte(0)
	}
	if len(ch.encryptedClientHello) > 0 {
		mixByte(1)
	} else {
		mixByte(0)
	}
	// Prefer TLS 1.3 bit
	has13 := false
	for _, v := range ch.supportedVersions {
		if v == VersionTLS13 {
			has13 = true
			break
		}
	}
	if has13 {
		mixU16(VersionTLS13)
	}
	return strconv.FormatUint(h, 16)
}
// clientALPN returns the first ALPN protocol or empty string.
func clientALPN(ch *clientHelloMsg) string {
	if ch == nil || len(ch.alpnProtocols) == 0 {
		return ""
	}
	return ch.alpnProtocols[0]
}

// clientHasKeyShare reports whether the ClientHello already offers group.
func clientHasKeyShare(ch *clientHelloMsg, group CurveID) bool {
	if ch == nil {
		return false
	}
	for _, ks := range ch.keyShares {
		if ks.group == group {
			return true
		}
	}
	return false
}

// clientOffersCipher reports whether suite is in the ClientHello list.
func clientOffersCipher(ch *clientHelloMsg, suite uint16) bool {
	if ch == nil {
		return false
	}
	for _, cs := range ch.cipherSuites {
		if cs == suite {
			return true
		}
	}
	return false
}

// ResolveAmortizeMode returns the effective mode (default L2).
func ResolveAmortizeMode(mode AmortizeMode) AmortizeMode {
	switch mode {
	case AmortizeDefault:
		return DefaultAmortizeMode
	case AmortizeL0, AmortizeL1, AmortizeL2, AmortizeAuto:
		return mode
	default:
		return DefaultAmortizeMode
	}
}

// profileL2Eligible reports whether p may be used for zero-dial.
func profileL2Eligible(p *RealityProfile) bool {
	if p == nil {
		return false
	}
	if p.Evidence < MinL2Evidence {
		return false
	}
	if p.AcceptsHRR {
		return false
	}
	if p.KeyShareGroup == 0 || p.CipherSuite == 0 {
		return false
	}
	if len(p.ServerHelloTemplate) == 0 {
		return false
	}
	if !ValidateRecordLens(p.RecordLens) || p.RecordLens[0] == 0 {
		return false
	}
	return true
}

// wrapHandshakeRecord builds a single TLS record around a handshake message.
// ClientHello records commonly use legacy version 0x0301.
func wrapHandshakeRecord(msg []byte, legacyVersion uint16) []byte {
	if legacyVersion == 0 {
		legacyVersion = VersionTLS10
	}
	n := len(msg)
	rec := make([]byte, recordHeaderLen+n)
	rec[0] = byte(recordTypeHandshake)
	rec[1] = byte(legacyVersion >> 8)
	rec[2] = byte(legacyVersion)
	rec[3] = byte(n >> 8)
	rec[4] = byte(n)
	copy(rec[5:], msg)
	return rec
}

// patchServerHelloTemplate clones a captured ServerHello handshake message and
// installs a fresh 32-byte random. Key share bytes are left for handshake() to
// overwrite in place (same as live R0 path).
func patchServerHelloTemplate(template, newRandom []byte) (*serverHelloMsg, error) {
	if len(template) < 4+2+32+1 {
		return nil, fmt.Errorf("server hello template too short")
	}
	if len(newRandom) != 32 {
		return nil, fmt.Errorf("random must be 32 bytes")
	}
	cloned := make([]byte, len(template))
	copy(cloned, template)
	// Handshake message: type(1)+len(3)+vers(2)+random(32)+...
	copy(cloned[6:38], newRandom)

	hello := new(serverHelloMsg)
	if !hello.unmarshal(cloned) {
		return nil, fmt.Errorf("server hello template unmarshal failed")
	}
	if hello.vers != VersionTLS12 || hello.supportedVersion != VersionTLS13 {
		return nil, fmt.Errorf("server hello template version mismatch")
	}
	if cipherSuiteTLS13ByID(hello.cipherSuite) == nil {
		return nil, fmt.Errorf("server hello template cipher unsupported")
	}
	return hello, nil
}

// computeShapeHash fingerprints ServerHello structural fields used for L2 safety.
func computeShapeHash(cipherSuite uint16, group CurveID, r0Len int, templateLen int) uint64 {
	var h uint64 = fnv64Offset
	mixU16 := func(v uint16) {
		h ^= uint64(v >> 8)
		h *= fnv64Prime
		h ^= uint64(v & 0xff)
		h *= fnv64Prime
	}
	mixU16(cipherSuite)
	mixU16(uint16(group))
	mixU16(uint16(r0Len))
	mixU16(uint16(templateLen))
	return h
}