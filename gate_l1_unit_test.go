//go:build l1 || l1unit

package reality

import (
	"testing"
)

// ============================================================================
// Level 1：单元测试 — Fingerprint
// 要求：PASS 率 100%
// ============================================================================

// --- Fingerprint ---

func TestL1_FingerprintDeterministic(t *testing.T) {
	f1 := computeFingerprint(0x1301, "h2", 1215, 41)
	f2 := computeFingerprint(0x1301, "h2", 1215, 41)
	if f1 != f2 {
		t.Errorf("deterministic check failed: %d != %d", f1, f2)
	}
}

func TestL1_FingerprintCipherSuiteChange(t *testing.T) {
	f1 := computeFingerprint(0x1301, "h2", 127, 51)
	f2 := computeFingerprint(0x1302, "h2", 127, 51)
	if f1 == f2 {
		t.Error("different CipherSuite should produce different fingerprint")
	}
}

func TestL1_FingerprintALPNChange(t *testing.T) {
	f1 := computeFingerprint(0x1301, "h2", 127, 51)
	f2 := computeFingerprint(0x1301, "http/1.1", 127, 51)
	if f1 == f2 {
		t.Error("different ALPN should produce different fingerprint")
	}
}

func TestL1_FingerprintRecordLenChange(t *testing.T) {
	f1 := computeFingerprint(0x1301, "h2", 127, 51)
	f2 := computeFingerprint(0x1301, "h2", 200, 51)
	if f1 == f2 {
		t.Error("different ServerHelloLen should produce different fingerprint")
	}
}

// --- ProbeResult ---

func TestL1_ProbeResultCreation(t *testing.T) {
	result := &ProbeResult{
		CipherSuite: 0x1301,
		RecordLens:  [7]int{1215, 6, 41, 8273, 286, 74, 0},
		RecordCount: 6,
	}

	if result.CipherSuite != 0x1301 {
		t.Error("CipherSuite mismatch")
	}
	if result.RecordCount != 6 {
		t.Error("RecordCount mismatch")
	}
}
