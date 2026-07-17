package reality

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// REALITY certificate authenticity extension OID.
// Placed first so legacy clients reading Extensions[0] still work.
// Value holds ML-DSA-65 signature when enabled, else optional length padding.
var realityAuthOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 20226, 1, 1}

// ML-DSA-65 signature size used for extension capacity (matches circl mldsa65).
const mldsa65SigSize = 3309

// hmacSHA512Pool reuses HMAC-SHA512 states across MaterializeCert calls.
// crypto/hmac binds the key at New; Reset restores that key. Entries are
// keyed so concurrent handshakes with different AuthKeys do not cross-MAC.
var hmacSHA512Pool = sync.Pool{}

type pooledHMAC struct {
	h   hash.Hash
	key []byte
}

func acquireHMACSHA512(key []byte) *pooledHMAC {
	if v := hmacSHA512Pool.Get(); v != nil {
		ph := v.(*pooledHMAC)
		if bytes.Equal(ph.key, key) {
			ph.h.Reset()
			return ph
		}
		// Key mismatch: discard entry (AuthKey is typically process-stable).
	}
	kc := append([]byte(nil), key...)
	return &pooledHMAC{
		h:   hmac.New(sha512.New, kc),
		key: kc,
	}
}

func releaseHMACSHA512(ph *pooledHMAC) {
	if ph == nil || ph.h == nil {
		return
	}
	ph.h.Reset()
	hmacSHA512Pool.Put(ph)
}

// CertPlan describes a camouflage certificate chain for one handshake.
// Auth invariant: leaf is Ed25519; HMAC-SHA512(AuthKey, pub) overwrites the
// 64-byte signature payload at HMACOffset; optional ML-DSA at MLDSAOffset.
type CertPlan struct {
	LeafDER     []byte
	ChainDERs   [][]byte
	HMACOffset  int
	HMACLen     int
	MLDSAOffset int // -1 if none
	MLDSALen    int
	InnerMsgLen int // certificateMsgTLS13 marshalled size (approx via Estimate)
	Mode        uint8
	Budget      int
}

// certPlanCacheKey identifies a reusable plan.
type certPlanCacheKey struct {
	budget  int
	mldsa   bool
	mode    uint8
	chainN  int
	padHint int
	metaFP  uint32 // dest leaf/chain meta fingerprint (0 = none)
}

var (
	certPlanMu    sync.RWMutex
	certPlanCache = make(map[certPlanCacheKey]*CertPlan)
)

// GetCertPlan returns a plan sized for the given record budget.
//
// Split mode (RecordModeSplit):
//   budget = observed Certificate outer record length (handshakeLen[3]).
// Coalesced mode (RecordModeCoalesced):
//   budget = residual Certificate-message capacity inside the coalesced R2
//   flight after reserving EE+CV+Finished (see CoalescedCertBudget).
// When budget is 0, the plan stays minimal (historical leaf size).
// mldsa enables ML-DSA extension capacity on the leaf.
//
// Hard invariant: grown plans must never make encrypt padding negative.
// Split uses outer-record math; coalesced uses residual inner capacity.
// GetCertPlan returns a plan sized for budget (no dest meta / shape hint).
func GetCertPlan(budget int, mldsa bool, mode uint8) *CertPlan {
	return GetCertPlanFor(budget, mldsa, mode, "", nil)
}

// GetCertPlanFor sizes a plan under budget, optionally using dest-learned leaf
// metadata (A1) and chain-shape hints (A2). Auth remains Ed25519+HMAC.
// Prefer GetCertPlanWithMeta when profile-attached CertMeta is available (D1).
func GetCertPlanFor(budget int, mldsa bool, mode uint8, dest string, shape *CertShapeHint) *CertPlan {
	return GetCertPlanWithMeta(budget, mldsa, mode, dest, nil, shape)
}

// GetCertPlanWithMeta is GetCertPlanFor with an explicit DestCertMeta override.
// When meta is nil, falls back to GetDestCertMeta(dest). Shape nil => from meta.
func GetCertPlanWithMeta(budget int, mldsa bool, mode uint8, dest string, meta *DestCertMeta, shape *CertShapeHint) *CertPlan {
	if budget < 0 {
		budget = 0
	}
	if meta == nil {
		meta = GetDestCertMeta(dest)
	}
	if shape == nil {
		shape = ShapeHintFromMeta(meta)
	}
	mfp := metaFingerprint(meta)
	key := certPlanCacheKey{budget: budget, mldsa: mldsa, mode: mode, metaFP: mfp}
	certPlanMu.RLock()
	if p, ok := certPlanCache[key]; ok {
		certPlanMu.RUnlock()
		return p
	}
	certPlanMu.RUnlock()

	p, err := buildCertPlan(budget, mldsa, mode, meta, shape)
	if err != nil {
		return fallbackCertPlan(mldsa)
	}
	if budget > 0 {
		over := false
		if mode == RecordModeSplit {
			over = !certPlanFitsBudget(p, budget)
		} else if mode == RecordModeCoalesced {
			over = !certPlanFitsInnerBudget(p, budget)
		}
		if over {
			min := fallbackCertPlan(mldsa)
			if min != nil && min.InnerMsgLen < p.InnerMsgLen {
				p = min
			}
			return p
		}
	}
	certPlanMu.Lock()
	certPlanCache[key] = p
	certPlanMu.Unlock()
	return p
}

// certPlanFitsBudget reports whether the Certificate handshake message fits
// into an outer TLS record of length budget with AEAD overhead and ctype.
// Used for split-mode Certificate records (handshakeLen[3]).
func certPlanFitsBudget(p *CertPlan, budget int) bool {
	if p == nil || budget <= 0 {
		return true
	}
	inner := p.InnerMsgLen
	if inner <= 0 {
		inner = estimateCertMsgLen(p.LeafDER, p.ChainDERs)
	}
	// Minimum outer length without padding: header + plaintext + ctype + tag.
	const aeadTag = 16
	const contentType = 1
	minOuter := recordHeaderLen + inner + contentType + aeadTag
	return minOuter <= budget
}

// certPlanFitsInnerBudget reports whether plan.InnerMsgLen <= maxInner.
// Used for coalesced residual capacity (already handshake-message bytes).
func certPlanFitsInnerBudget(p *CertPlan, maxInner int) bool {
	if p == nil || maxInner <= 0 {
		return true
	}
	inner := p.InnerMsgLen
	if inner <= 0 {
		inner = estimateCertMsgLen(p.LeafDER, p.ChainDERs)
	}
	return inner <= maxInner
}

// MaxCertInnerForBudget returns the largest Certificate message length that
// still leaves non-negative padding for a target outer record length (split).
func MaxCertInnerForBudget(budget int) int {
	if budget <= 0 {
		return 0
	}
	const aeadTag = 16
	const contentType = 1
	max := budget - recordHeaderLen - contentType - aeadTag
	if max < 0 {
		return 0
	}
	return max
}

// C1 calibrated coalesced flight overhead (handshake message bytes only).
// Measured against REALITY success-path marshalled sizes:
//   EE (ALPN "h2"):            ~16-48 (use 40 typical + 40 headroom)
//   CertificateVerify Ed25519: 4 + 2 + 2 + 64 = 72
//   Finished SHA-256:          4 + 32 = 36
// Baseline 40+72+36=148; +40 ALPN variance => 188. SafetyInner 48.
// Only raise these constants if live EE grows; never lower without re-proof.
const (
	coalescedEETypical            = 40
	coalescedCVEd25519            = 72
	coalescedFinishedSHA256       = 36
	coalescedEEHeadroom           = 40
	coalescedEECVFinishedOverhead = coalescedEETypical + coalescedCVEd25519 + coalescedFinishedSHA256 + coalescedEEHeadroom // 188
	coalescedSafetyInner          = 48
)

// CoalescedCertBudget derives max Certificate handshake message length that
// still leaves non-negative AEAD padding when EE+Cert+CV+Finished are sealed
// as one application_data record of outer length r2Outer.
//
// encrypt pads: padding = r2Outer - (recordHeaderLen + plaintext + 1 + tag)
// plaintext = EE||Cert||CV||Finished (handshake messages only).
// => maxCertInner = r2Outer - recordHeaderLen - 1 - tag - overheadOthers - safety
func CoalescedCertBudget(r2Outer int) int {
	if r2Outer <= 512 {
		return 0
	}
	const aeadTag = 16
	const contentType = 1
	maxPlain := r2Outer - recordHeaderLen - contentType - aeadTag
	if maxPlain <= 0 {
		return 0
	}
	maxCert := maxPlain - coalescedEECVFinishedOverhead - coalescedSafetyInner
	if maxCert < 0 {
		return 0
	}
	return maxCert
}

// CoalescedCertBudgetForDest is CoalescedCertBudget with optional per-dest EE
// calibration (D2). When split-mode samples show a larger EE plaintext p90,
// residual Certificate capacity is reduced accordingly so coalesced padding
// never goes negative. SafetyInner (48) is never lowered. Overhead never
// drops below coalescedEECVFinishedOverhead. When samples are insufficient
// or p90 <= typical EE, this equals CoalescedCertBudget.
func CoalescedCertBudgetForDest(r2Outer int, dest string) int {
	base := CoalescedCertBudget(r2Outer)
	if base <= 0 {
		return 0
	}
	p90, _, ok := GetDestEEPlainP90(dest)
	if !ok || p90 <= coalescedEETypical {
		return base
	}
	// Raise EE reserve only; keep headroom + safety; floor total overhead.
	const aeadTag = 16
	const contentType = 1
	maxPlain := r2Outer - recordHeaderLen - contentType - aeadTag
	if maxPlain <= 0 {
		return 0
	}
	overhead := p90 + coalescedCVEd25519 + coalescedFinishedSHA256 + coalescedEEHeadroom
	if overhead < coalescedEECVFinishedOverhead {
		overhead = coalescedEECVFinishedOverhead
	}
	maxCert := maxPlain - overhead - coalescedSafetyInner
	if maxCert < 0 {
		return 0
	}
	// Larger EE => smaller cert budget (never above base).
	if maxCert > base {
		return base
	}
	return maxCert
}

// MeasureCoalescedFlightOverhead returns the conservative overhead constants
// used by CoalescedCertBudget (for tests / calibration reports).
func MeasureCoalescedFlightOverhead() (ee, cv, finished, headroom, total, safety int) {
	return coalescedEETypical, coalescedCVEd25519, coalescedFinishedSHA256,
		coalescedEEHeadroom, coalescedEECVFinishedOverhead, coalescedSafetyInner
}

// ResetCertPlanCacheForTesting clears the plan cache.
func ResetCertPlanCacheForTesting() {
	certPlanMu.Lock()
	certPlanCache = make(map[certPlanCacheKey]*CertPlan)
	certPlanMu.Unlock()
}

func fallbackCertPlan(mldsa bool) *CertPlan {
	// Ensure init ran.
	if initErr != nil || len(signedCert) == 0 {
		return nil
	}
	if mldsa && len(signedCertMldsa65) > 0 {
		off := locateHMACOffset(signedCertMldsa65)
		mOff := locateMLDSAOffset(signedCertMldsa65)
		leaf := append([]byte(nil), signedCertMldsa65...)
		return &CertPlan{
			LeafDER:     leaf,
			HMACOffset:  off,
			HMACLen:     64,
			MLDSAOffset: mOff,
			MLDSALen:    mldsa65SigSize,
			InnerMsgLen: estimateCertMsgLen(leaf, nil),
		}
	}
	off := locateHMACOffset(signedCert)
	leaf := append([]byte(nil), signedCert...)
	return &CertPlan{
		LeafDER:     leaf,
		HMACOffset:  off,
		HMACLen:     64,
		MLDSAOffset: -1,
		InnerMsgLen: estimateCertMsgLen(leaf, nil),
	}
}

func buildCertPlan(budget int, mldsa bool, mode uint8, meta *DestCertMeta, shape *CertShapeHint) (*CertPlan, error) {
	if ed25519Priv == nil || len(ed25519Priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 key not initialized")
	}
	pub := ed25519.PublicKey(ed25519Priv[32:])

	// Build leaf with optional REALITY auth extension.
	extVal := []byte{}
	if mldsa {
		extVal = make([]byte, mldsa65SigSize)
	}
	leaf, err := createLeaf(pub, ed25519Priv, extVal, 0, meta)
	if err != nil {
		return nil, err
	}

	var chain [][]byte
	// Grow when residual budget is clearly larger than a minimal leaf.
	// Split: budget is outer Certificate record length.
	// Coalesced: budget is residual Certificate-message capacity inside R2.
	targetInner := 0
	maxInner := 0
	const safety = 32
	switch mode {
	case RecordModeSplit:
		maxInner = MaxCertInnerForBudget(budget)
		if maxInner > 256+safety {
			targetInner = maxInner - safety
		}
	case RecordModeCoalesced:
		maxInner = budget
		if maxInner > 256+safety {
			targetInner = maxInner - safety
		}
	}

	if targetInner > 0 {
		leaf, chain = growCertsToward(pub, ed25519Priv, leaf, mldsa, targetInner, meta, shape)
	}

	// If growth still overshot, discard fillers and keep minimal leaf.
	if targetInner > 0 {
		inner := estimateCertMsgLen(leaf, chain)
		if maxInner > 0 && inner > maxInner {
			leaf, err = createLeaf(pub, ed25519Priv, extVal, 0, meta)
			if err != nil {
				return nil, err
			}
			chain = nil
		}
	}

	hmacOff := locateHMACOffset(leaf)
	if hmacOff < 0 {
		return nil, fmt.Errorf("cannot locate HMAC slot in leaf")
	}
	mOff := -1
	mLen := 0
	if mldsa {
		mOff = locateMLDSAOffset(leaf)
		if mOff < 0 {
			// Extension missing; still usable without ML-DSA slot.
			mOff = -1
		} else {
			mLen = mldsa65SigSize
		}
	}

	inner := estimateCertMsgLen(leaf, chain)
	return &CertPlan{
		LeafDER:     leaf,
		ChainDERs:   chain,
		HMACOffset:  hmacOff,
		HMACLen:     64,
		MLDSAOffset: mOff,
		MLDSALen:    mLen,
		InnerMsgLen: inner,
		Mode:        mode,
		Budget:      budget,
	}, nil
}

func createLeaf(pub ed25519.PublicKey, priv ed25519.PrivateKey, extVal []byte, subjectPad int, meta *DestCertMeta) ([]byte, error) {
	// Realistic-ish leaf metadata (NotBefore/NotAfter/Serial/KU/EKU/SAN).
	// Auth still overwrites the Ed25519 signature slot with HMAC; these fields
	// only improve passive certificate-shape fidelity (A1: prefer dest meta).
	now := truncatedPlanTime() // B3: minute-truncated for plan cache stability
	serial := big.NewInt(now.UnixNano())
	if serial.Sign() <= 0 {
		serial = big.NewInt(1)
	}
	notBefore := now.Add(-30 * 24 * time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)
	org := "Cloud"
	cn := "www.example.com"
	dns := []string{cn}

	if meta != nil {
		if meta.CN != "" {
			cn = meta.CN
		}
		if meta.Organization != "" {
			org = meta.Organization
		}
		if !meta.NotBefore.IsZero() && !meta.NotAfter.IsZero() && meta.NotAfter.After(meta.NotBefore) {
			notBefore = meta.NotBefore
			notAfter = meta.NotAfter
			if notAfter.Before(now) {
				notBefore = now.Add(-30 * 24 * time.Hour)
				notAfter = now.Add(365 * 24 * time.Hour)
			}
		}
		if len(meta.DNSNames) > 0 {
			dns = append([]string(nil), meta.DNSNames...)
			if cn == "www.example.com" || cn == "" {
				cn = meta.DNSNames[0]
			}
		} else if meta.CN != "" {
			dns = []string{meta.CN}
		}
	}

	if subjectPad > 0 && meta == nil {
		pad := make([]byte, subjectPad)
		for i := range pad {
			pad[i] = 'a'
		}
		cn = string(pad)
		dns = []string{cn}
	}

	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dns,
	}
	if len(extVal) > 0 {
		// REALITY auth OID first so legacy Extensions[0] readers still work.
		tpl.ExtraExtensions = []pkix.Extension{{
			Id:    realityAuthOID,
			Value: extVal,
		}}
	}
	return x509.CreateCertificate(rand.Reader, &tpl, &tpl, pub, priv)
}

func growCertsToward(pub ed25519.PublicKey, priv ed25519.PrivateKey, leaf []byte, mldsa bool, targetInner int, meta *DestCertMeta, shape *CertShapeHint) ([]byte, [][]byte) {
	chain := [][]byte{}
	cur := estimateCertMsgLen(leaf, chain)
	if cur >= targetInner {
		return leaf, chain
	}

	// Max intermediate count (not including leaf). Default 3; dest shape may prefer fewer (A2).
	maxIntermediates := 3
	if shape != nil && shape.PreferredChainDepth > 0 {
		wantInter := shape.PreferredChainDepth - 1
		if wantInter < 0 {
			wantInter = 0
		}
		if wantInter < maxIntermediates {
			maxIntermediates = wantInter
		}
	}

	// 1) Subject padding on leaf only when no dest meta (meta CN is identity).
	if meta == nil {
		for step := 32; step <= 256 && cur < targetInner; step += 32 {
			extVal := []byte{}
			if mldsa {
				extVal = make([]byte, mldsa65SigSize)
			}
			nl, err := createLeaf(pub, priv, extVal, step, meta)
			if err != nil {
				break
			}
			nCur := estimateCertMsgLen(nl, chain)
			if nCur > targetInner {
				break
			}
			leaf = nl
			cur = nCur
		}
	}

	// 2) Intermediate fillers for CDN-like chain shape (A2 dest sizes when known).
	for len(chain) < maxIntermediates && cur < targetInner {
		need := targetInner - cur
		if need < 96 {
			break
		}
		want := need - 8
		if shape != nil && len(shape.TargetChainLens) > len(chain)+1 {
			hint := shape.TargetChainLens[len(chain)+1]
			if hint > 64 && hint < want {
				want = hint
			}
		}
		if want < 64 {
			break
		}
		fc, actual, ok := createFillerCertFit(want, need-5, meta, len(chain))
		if !ok || actual <= 0 {
			break
		}
		trial := append(append([][]byte{}, chain...), fc)
		nCur := estimateCertMsgLen(leaf, trial)
		if nCur > targetInner {
			break
		}
		if nCur-cur < 48 {
			break
		}
		chain = trial
		cur = nCur
	}

	// 3) Length-only extension padding. C2: ML-DSA keeps first mldsa65SigSize
	// bytes as the auth slot; extra bytes after that are length noise only.
	if cur < targetInner {
		need := targetInner - cur
		if need > 16 {
			lo, hi := 8, need-8
			if hi > 4000 {
				hi = 4000
			}
			if mldsa {
				lo = mldsa65SigSize + 8
				hi = mldsa65SigSize + (need - 8)
				if hi > mldsa65SigSize+4000 {
					hi = mldsa65SigSize + 4000
				}
				if hi < lo {
					hi = lo
				}
			}
			bestLeaf := leaf
			bestCur := cur
			for lo <= hi {
				mid := (lo + hi) / 2
				extVal := make([]byte, mid)
				nl, err := createLeaf(pub, priv, extVal, 0, meta)
				if err != nil {
					hi = mid - 1
					continue
				}
				if mldsa && locateMLDSAOffset(nl) < 0 {
					hi = mid - 1
					continue
				}
				nCur := estimateCertMsgLen(nl, chain)
				if nCur <= targetInner {
					bestLeaf = nl
					bestCur = nCur
					lo = mid + 1
				} else {
					hi = mid - 1
				}
			}
			leaf = bestLeaf
			cur = bestCur
		}
	}

	_ = cur
	return leaf, chain
}

// createFillerCertFit builds a filler cert whose DER length is as close as
// possible to want, but never makes the TLS cert entry exceed maxEntry.
// meta/chainIdx drive cosmetic issuer-style DN (D3); auth is unaffected.
// Returns der, actualLen, ok.
func createFillerCertFit(want, maxEntry int, meta *DestCertMeta, chainIdx int) ([]byte, int, bool) {
	if maxEntry < 64 {
		return nil, 0, false
	}
	if want > maxEntry {
		want = maxEntry
	}
	if want < 64 {
		want = 64
	}
	// Map desired DER length to CN pad via binary search (ASN.1 overhead varies).
	lo, hi := 0, want
	if hi > 1800 {
		hi = 1800
	}
	var best []byte
	bestLen := 0
	for lo <= hi {
		mid := (lo + hi) / 2
		fc, err := createFillerCertStyled(mid+200, meta, chainIdx) // approxLen-200 as CN pad
		if err != nil {
			hi = mid - 1
			continue
		}
		n := len(fc)
		if n <= maxEntry {
			if n >= bestLen {
				best = fc
				bestLen = n
			}
			if n < want {
				lo = mid + 1
			} else {
				best = fc
				bestLen = n
				hi = mid - 1
			}
		} else {
			hi = mid - 1
		}
	}
	if best == nil || bestLen == 0 {
		return nil, 0, false
	}
	return best, bestLen, true
}

func createFillerCert(approxLen int) ([]byte, error) {
	return createFillerCertStyled(approxLen, nil, 0)
}

// createFillerCertStyled builds a cosmetic intermediate-like filler.
// Display only: CA BasicConstraints + issuer-style DN from meta when present.
// Keys are throwaway; never used for REALITY auth.
func createFillerCertStyled(approxLen int, meta *DestCertMeta, chainIdx int) ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := ed25519.PublicKey(priv[32:])
	pad := approxLen - 200
	if pad < 0 {
		pad = 0
	}
	if pad > 1800 {
		pad = 1800
	}

	// Prefer learned intermediate / issuer names; pad only when length-driven.
	subjCN := ""
	if meta != nil {
		if chainIdx >= 0 && chainIdx < len(meta.IntermediateNames) {
			subjCN = meta.IntermediateNames[chainIdx]
		}
		if subjCN == "" {
			subjCN = meta.IssuerCN
		}
	}
	if subjCN == "" {
		cn := make([]byte, pad)
		for i := range cn {
			cn[i] = 'x'
		}
		subjCN = string(cn)
	} else if pad > len(subjCN)+8 {
		// Length-match without erasing the readable CN prefix.
		extra := pad - len(subjCN)
		if extra > 0 {
			buf := make([]byte, len(subjCN)+extra)
			copy(buf, subjCN)
			for i := len(subjCN); i < len(buf); i++ {
				buf[i] = 'x'
			}
			subjCN = string(buf)
		}
	}

	org := ""
	country := ""
	if meta != nil {
		if meta.IssuerOrg != "" {
			org = meta.IssuerOrg
		}
		if meta.IssuerCountry != "" {
			country = meta.IssuerCountry
		}
	}
	if org == "" {
		org = "Certificate Authority"
	}

	subj := pkix.Name{CommonName: subjCN, Organization: []string{org}}
	if country != "" {
		subj.Country = []string{country}
	}

	now := truncatedPlanTime()
	tpl := x509.Certificate{
		SerialNumber:          big.NewInt(int64(2 + chainIdx)),
		Subject:               subj,
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	// Self-signed filler for size/shape only (CreateCertificate parent == subject).
	return x509.CreateCertificate(rand.Reader, &tpl, &tpl, pub, priv)
}

// estimateCertMsgLen estimates TLS 1.3 Certificate handshake message length.
// type(1)+len(3)+context(1)+cert_list_len(3)+entries(3+cert+2 each, empty exts).
func estimateCertMsgLen(leaf []byte, chain [][]byte) int {
	n := 1 + 3 + 1 + 3
	add := func(cert []byte) {
		n += 3 + len(cert) + 2 // cert len + empty extensions
	}
	add(leaf)
	for _, c := range chain {
		add(c)
	}
	return n
}

// locateHMACOffset finds the 64-byte Ed25519 signature payload offset in DER.
// Strategy: parse cert; Signature must be 64 bytes; find last occurrence in DER
// that matches (CreateCertificate places it at the end).
func locateHMACOffset(der []byte) int {
	if len(der) < 64 {
		return -1
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || len(cert.Signature) != 64 {
		// Fallback: last 64 bytes (historical REALITY layout).
		return len(der) - 64
	}
	sig := cert.Signature
	// Search from end for exact match.
	for i := len(der) - 64; i >= 0; i-- {
		match := true
		for j := 0; j < 64; j++ {
			if der[i+j] != sig[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return len(der) - 64
}

// locateMLDSAOffset finds the REALITY auth extension value (or legacy first
// extension) inside leaf DER for in-place ML-DSA signature write.
func locateMLDSAOffset(der []byte) int {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return -1
	}
	// Prefer REALITY OID.
	for _, e := range cert.Extensions {
		if e.Id.Equal(realityAuthOID) && len(e.Value) >= mldsa65SigSize {
			return indexBytes(der, e.Value[:min(32, len(e.Value))])
		}
	}
	// Legacy: first extension value (0.0 / empty[:3309] path).
	if len(cert.Extensions) > 0 && len(cert.Extensions[0].Value) >= mldsa65SigSize {
		v := cert.Extensions[0].Value
		return indexBytes(der, v[:min(32, len(v))])
	}
	return -1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaterializeCert applies AuthKey HMAC (and optional ML-DSA) onto a plan copy.
// Returns certificate chain bytes suitable for hs.cert.Certificate.
// Auth invariant:
//   - signature slot = HMAC-SHA512(AuthKey, ed25519.pub)
//   - optional ML-DSA = Sign(HMAC-SHA512(AuthKey, pub||CH||SH)) into REALITY auth extension
// Performance: only the leaf is copied; intermediate filler DERs are shared.
func MaterializeCert(plan *CertPlan, authKey []byte, mldsaKey []byte, clientHelloOrig, serverHelloOrig []byte) ([][]byte, error) {
	if plan == nil || len(plan.LeafDER) == 0 {
		return nil, fmt.Errorf("nil cert plan")
	}
	// B1: one leaf copy (HMAC mutates signature slot); intermediate DERs are shared.
	// Leaf escapes into Certificate.Certificate and cannot return to a pool.
	leaf := make([]byte, len(plan.LeafDER))
	copy(leaf, plan.LeafDER)

	off := plan.HMACOffset
	if off < 0 || off+64 > len(leaf) {
		off = len(leaf) - 64
	}
	ph := acquireHMACSHA512(authKey)
	defer releaseHMACSHA512(ph)
	h := ph.h
	if len(ed25519Priv) >= 64 {
		h.Write(ed25519Priv[32:])
	}
	// Sum directly into the signature slot (avoids Sum(nil) heap slice).
	_ = h.Sum(leaf[off:off])

	if len(mldsaKey) > 0 && plan.MLDSAOffset >= 0 && plan.MLDSALen > 0 {
		h.Write(clientHelloOrig)
		h.Write(serverHelloOrig)
		key, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(mldsaKey)
		if err != nil {
			return nil, fmt.Errorf("REALITY: invalid Mldsa65Key: %w", err)
		}
		priv, ok := key.(*mldsa65.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("REALITY: unexpected ML-DSA private key type")
		}
		mOff := plan.MLDSAOffset
		if mOff < 0 || mOff+mldsa65SigSize > len(leaf) {
			return nil, fmt.Errorf("REALITY: ML-DSA offset out of range")
		}
		var hmacSum [64]byte
		mldsa65.SignTo(priv, h.Sum(hmacSum[:0]), nil, false, leaf[mOff:mOff+mldsa65SigSize])
	}

	// Pre-size chain slice; share intermediate DER (immutable after plan build).
	out := make([][]byte, 1+len(plan.ChainDERs))
	out[0] = leaf
	copy(out[1:], plan.ChainDERs)
	return out, nil
}

func newHMACSHA512(key []byte) hash.Hash {
	return hmac.New(sha512.New, key)
}

// writeMLDSA writes ML-DSA-65 over HMAC(AuthKey, pub||CH||SH) into leaf at offset.
// Matches historical handshake_server_tls13: HMAC first on pub only, then continue
// the same hash with CH/SH originals for the PQ signature.
func writeMLDSA(leaf []byte, off, mlen int, authKey, clientHelloOrig, serverHelloOrig, mldsaKey []byte) error {
	if off < 0 || mlen <= 0 || off+mlen > len(leaf) {
		return fmt.Errorf("ML-DSA slot out of range: off=%d len=%d leaf=%d", off, mlen, len(leaf))
	}
	if mlen < mldsa65SigSize {
		return fmt.Errorf("ML-DSA slot too small: %d < %d", mlen, mldsa65SigSize)
	}
	h := hmac.New(sha512.New, authKey)
	if len(ed25519Priv) >= 64 {
		h.Write(ed25519Priv[32:])
	}
	h.Write(clientHelloOrig)
	h.Write(serverHelloOrig)
	key, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(mldsaKey)
	if err != nil {
		return fmt.Errorf("invalid Mldsa65Key: %w", err)
	}
	priv, ok := key.(*mldsa65.PrivateKey)
	if !ok {
		return fmt.Errorf("unexpected ML-DSA private key type")
	}
	// Sign into the extension value region (may be larger than sig size; SignTo fills 3309).
	dst := leaf[off : off+mldsa65SigSize]
	mldsa65.SignTo(priv, h.Sum(nil), nil, false, dst)
	return nil
}
