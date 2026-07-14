package reality

import (
	"sync"
	"sync/atomic"
	"time"
)

// Record emission modes for the post-ServerHello handshake flight.
const (
	// RecordModeSplit: EE / Certificate / CertificateVerify / Finished
	// each occupy their own TLS record (classic 7-slot lens model).
	RecordModeSplit uint8 = 0
	// RecordModeCoalesced: EE+Cert+CV+Finished are buffered and emitted as
	// one application_data record padded to RecordLens[2] (target large-R2).
	RecordModeCoalesced uint8 = 1
)

// CHClassVersion identifies the ClassifyClientHello algorithm.
// Bump when classification inputs change so persisted keys cannot mix.
const CHClassVersion uint8 = 2

// Dest capability states for fallback / suitability tracking.
const (
	DestCapUnknown uint8 = iota
	DestCapTLS13Ready
	DestCapDegraded
	DestCapUnsuitable
	DestCapOffline
)

const (
	destCapUnsuitableAfter = 3               // consecutive not-TLS13 shape failures
	destCapDegradedAfter   = 2               // consecutive generic capture failures
	destCapOfflineAfter    = 3               // consecutive dial failures
	destCapCooldown          = 5 * time.Minute // auto re-probe window
)

// InferRecordMode derives emission mode from an observed record-length vector.
// Large first encrypted record (>512) triggers the legacy coalesced write path.
func InferRecordMode(lens [7]int) uint8 {
	if lens[2] > 512 {
		return RecordModeCoalesced
	}
	return RecordModeSplit
}

// ValidateRecordLens checks that a RecordLens array contains sane values.
// When mode is known (non-zero profile field passed via ValidateRecordLensMode),
// coalesced profiles may leave slots 3-5 empty.
func ValidateRecordLens(lens [7]int) bool {
	return ValidateRecordLensMode(lens, InferRecordMode(lens))
}

// ValidateRecordLensMode validates lens under an explicit record mode.
func ValidateRecordLensMode(lens [7]int, mode uint8) bool {
	for i, l := range lens {
		if l == 0 {
			// R6 optional always; in coalesced mode R3-R5 may be unused.
			if i == 6 {
				continue
			}
			if mode == RecordModeCoalesced && i >= 3 && i <= 5 {
				continue
			}
			// R0 must be present for any usable profile; allow all-zero only
			// for empty templates (caller checks RecordLens[0] separately).
			continue
		}
		if l < recordHeaderLen || l > maxTLSRecordPayload {
			return false
		}
	}
	if lens[0] != 0 && (lens[0] < recordHeaderLen || lens[0] > maxTLSRecordPayload) {
		return false
	}
	// CCS must be exactly 6 when present.
	if lens[1] != 0 && lens[1] != 6 {
		return false
	}
	if mode == RecordModeCoalesced {
		if lens[2] != 0 && lens[2] <= 512 {
			// Inconsistent: marked coalesced but R2 not large.
			return false
		}
	}
	return true
}

// destCapability tracks whether a camouflage dest is suitable for REALITY success path.
type destCapability struct {
	state     atomic.Uint32
	failTLS13 atomic.Int32
	failDial  atomic.Int32
	failSoft  atomic.Int32
	updated   atomic.Int64 // unix nano
}

var destCaps sync.Map // map[string]*destCapability keyed by dest

func getDestCap(dest string) *destCapability {
	if dest == "" {
		return nil
	}
	if v, ok := destCaps.Load(dest); ok {
		return v.(*destCapability)
	}
	d := &destCapability{}
	actual, _ := destCaps.LoadOrStore(dest, d)
	return actual.(*destCapability)
}

// DestCapabilityState returns the current suitability state for dest.
func DestCapabilityState(dest string) uint8 {
	d := getDestCap(dest)
	if d == nil {
		return DestCapUnknown
	}
	// Cooldown: Unsuitable/Offline/Degraded may return to Unknown after window.
	st := uint8(d.state.Load())
	if st == DestCapUnsuitable || st == DestCapOffline || st == DestCapDegraded {
		u := d.updated.Load()
		if u > 0 && time.Since(time.Unix(0, u)) > destCapCooldown {
			d.state.Store(uint32(DestCapUnknown))
			d.failTLS13.Store(0)
			d.failDial.Store(0)
			d.failSoft.Store(0)
			return DestCapUnknown
		}
	}
	return st
}

// NoteDestTLS13Ready marks dest as a valid TLS 1.3 camouflage source.
func NoteDestTLS13Ready(dest string) {
	d := getDestCap(dest)
	if d == nil {
		return
	}
	d.failTLS13.Store(0)
	d.failDial.Store(0)
	d.failSoft.Store(0)
	d.state.Store(uint32(DestCapTLS13Ready))
	d.updated.Store(time.Now().UnixNano())
}

// NoteDestCaptureFailure classifies a failed target capture.
// reason: "not_tls13" | "bad_shape" | "timeout" | "dial" | other.
func NoteDestCaptureFailure(dest, reason string) {
	d := getDestCap(dest)
	if d == nil {
		return
	}
	d.updated.Store(time.Now().UnixNano())
	switch reason {
	case "dial":
		n := d.failDial.Add(1)
		if n >= destCapOfflineAfter {
			d.state.Store(uint32(DestCapOffline))
		}
	case "not_tls13", "bad_shape":
		n := d.failTLS13.Add(1)
		if n >= destCapUnsuitableAfter {
			d.state.Store(uint32(DestCapUnsuitable))
		} else if n >= destCapDegradedAfter {
			d.state.Store(uint32(DestCapDegraded))
		}
	default:
		n := d.failSoft.Add(1)
		if n >= destCapDegradedAfter {
			cur := uint8(d.state.Load())
			if cur != DestCapUnsuitable && cur != DestCapOffline {
				d.state.Store(uint32(DestCapDegraded))
			}
		}
	}
}

// DestAllowsAmortize reports whether L1/L2 may be attempted for dest.
// Unsuitable/Offline force L0-or-mirror only (caller decides).
func DestAllowsAmortize(dest string) bool {
	switch DestCapabilityState(dest) {
	case DestCapUnsuitable, DestCapOffline:
		return false
	default:
		return true
	}
}

// DestShouldMirrorOnly reports whether even authenticated clients should mirror
// rather than synthesize a REALITY TLS 1.3 success path (anti-probe default).
func DestShouldMirrorOnly(dest string) bool {
	return DestCapabilityState(dest) == DestCapUnsuitable
}

// ResetDestCapabilitiesForTesting clears capability state (tests only).
func ResetDestCapabilitiesForTesting() {
	destCaps.Range(func(key, _ any) bool {
		destCaps.Delete(key)
		return true
	})
}

// classifyCaptureError maps capture errors to dest-cap reasons.
func classifyCaptureError(err error) string {
	if err == nil {
		return "bad_shape"
	}
	s := err.Error()
	switch {
	case containsFold(s, "invalid ServerHello"),
		containsFold(s, "unexpected record type"),
		containsFold(s, "version"):
		return "not_tls13"
	case containsFold(s, "timeout"), containsFold(s, "deadline"):
		return "timeout"
	case containsFold(s, "dial"), containsFold(s, "connection refused"):
		return "dial"
	default:
		return "bad_shape"
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		indexFold(s, sub) >= 0)
}

func indexFold(s, sub string) int {
	// ASCII-lower fold search (errors are English).
	ls := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		ls[i] = c
	}
	lsub := make([]byte, len(sub))
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lsub[i] = c
	}
	return indexBytes(ls, lsub)
}

func indexBytes(s, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
