package reality

import (
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

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// REALITY certificate authenticity extension OID.
// Placed first so legacy clients reading Extensions[0] still work.
// Value holds ML-DSA-65 signature when enabled, else optional length padding.
var realityAuthOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 20226, 1, 1}

// ML-DSA-65 signature size used for extension capacity (matches circl mldsa65).
const mldsa65SigSize = 3309

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
}

var (
	certPlanMu    sync.RWMutex
	certPlanCache = make(map[certPlanCacheKey]*CertPlan)
)

// GetCertPlan returns a plan sized for the given record budget.
// budget is the target Certificate record outer length (split mode). When 0,
// or in coalesced mode, the plan stays minimal (historical leaf size).
// mldsa enables ML-DSA extension capacity on the leaf.
//
// Hard invariant for split mode: plan.InnerMsgLen must fit inside budget with
// AEAD framing so conn.encrypt padding never goes negative:
//   budget >= recordHeaderLen + InnerMsgLen + 1(ctype) + aeadTag
func GetCertPlan(budget int, mldsa bool, mode uint8) *CertPlan {
	if budget < 0 {
		budget = 0
	}
	key := certPlanCacheKey{budget: budget, mldsa: mldsa, mode: mode}
	certPlanMu.RLock()
	if p, ok := certPlanCache[key]; ok {
		certPlanMu.RUnlock()
		return p
	}
	certPlanMu.RUnlock()

	p, err := buildCertPlan(budget, mldsa, mode)
	if err != nil {
		// Fall back to process-global minimal certs (init path).
		return fallbackCertPlan(mldsa)
	}
	// Never cache a grown plan that cannot fit the observed Certificate record.
	// Minimal leaf may still exceed a pathological tiny budget (target cert smaller
	// than Ed25519 leaf+HMAC); encrypt will fail in that case — caller must keep
	// dest TLS1.3 capture lens honest. Prefer minimal over oversized growth.
	if mode == RecordModeSplit && budget > 0 && !certPlanFitsBudget(p, budget) {
		min := fallbackCertPlan(mldsa)
		if min != nil {
			// Only replace if minimal is smaller / better chance to fit.
			if min.InnerMsgLen < p.InnerMsgLen {
				p = min
			}
		}
		// Do not cache oversize-for-budget plans.
		return p
	}
	certPlanMu.Lock()
	certPlanCache[key] = p
	certPlanMu.Unlock()
	return p
}

// certPlanFitsBudget reports whether the Certificate handshake message fits
// into an outer TLS record of length budget with AEAD overhead and ctype.
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

// MaxCertInnerForBudget returns the largest Certificate message length that
// still leaves non-negative padding for a target outer record length.
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

func buildCertPlan(budget int, mldsa bool, mode uint8) (*CertPlan, error) {
	if ed25519Priv == nil || len(ed25519Priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519 key not initialized")
	}
	pub := ed25519.PublicKey(ed25519Priv[32:])

	// Build leaf with optional REALITY auth extension.
	extVal := []byte{}
	if mldsa {
		extVal = make([]byte, mldsa65SigSize)
	}
	leaf, err := createLeaf(pub, ed25519Priv, extVal, 0)
	if err != nil {
		return nil, err
	}

	var chain [][]byte
	// Grow only in split mode when residual budget is clearly larger than a
	// minimal leaf. Target stays strictly under MaxCertInnerForBudget so
	// conn.encrypt padding never goes negative (even with DER size noise).
	targetInner := 0
	if mode == RecordModeSplit {
		maxInner := MaxCertInnerForBudget(budget)
		// Leave headroom for DER estimate error and optional OCSP/SCT hooks.
		const safety = 32
		if maxInner > 256+safety {
			targetInner = maxInner - safety
		}
	}

	if targetInner > 0 {
		leaf, chain = growCertsToward(pub, ed25519Priv, leaf, mldsa, targetInner)
	}

	// If growth still overshot, discard fillers and keep minimal leaf.
	if targetInner > 0 {
		inner := estimateCertMsgLen(leaf, chain)
		maxInner := MaxCertInnerForBudget(budget)
		if maxInner > 0 && inner > maxInner {
			leaf, err = createLeaf(pub, ed25519Priv, extVal, 0)
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

func createLeaf(pub ed25519.PublicKey, priv ed25519.PrivateKey, extVal []byte, subjectPad int) ([]byte, error) {
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	if subjectPad > 0 {
		// CN padding to grow DER without changing public key.
		pad := make([]byte, subjectPad)
		for i := range pad {
			pad[i] = 'a'
		}
		tpl.Subject = pkix.Name{CommonName: string(pad)}
	}
	if len(extVal) > 0 {
		tpl.ExtraExtensions = []pkix.Extension{{
			Id:    realityAuthOID,
			Value: extVal,
		}}
	}
	return x509.CreateCertificate(rand.Reader, &tpl, &tpl, pub, priv)
}

func growCertsToward(pub ed25519.PublicKey, priv ed25519.PrivateKey, leaf []byte, mldsa bool, targetInner int) ([]byte, [][]byte) {
	chain := [][]byte{}
	cur := estimateCertMsgLen(leaf, chain)
	if cur >= targetInner {
		return leaf, chain
	}

	// 1) Subject padding on leaf (up to 256 bytes of CN). Accept only if still <= target.
	for step := 32; step <= 256 && cur < targetInner; step += 32 {
		extVal := []byte{}
		if mldsa {
			extVal = make([]byte, mldsa65SigSize)
		}
		nl, err := createLeaf(pub, priv, extVal, step)
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

	// 2) Intermediate fillers (1-2 certs) for CDN-like chain shape.
	// Never append a filler that pushes over targetInner.
	for len(chain) < 2 && cur < targetInner {
		need := targetInner - cur
		// Each chain entry adds 3+len+2 overhead in TLS1.3 cert msg.
		fill := need - 32 // leave room for DER/TLS entry overhead
		if fill < 64 {
			break
		}
		if fill > 1200 {
			fill = 1200
		}
		fc, err := createFillerCert(fill)
		if err != nil {
			break
		}
		trial := append(append([][]byte{}, chain...), fc)
		nCur := estimateCertMsgLen(leaf, trial)
		if nCur > targetInner {
			// Try a smaller filler once.
			smaller := fill / 2
			if smaller < 64 {
				break
			}
			fc2, err2 := createFillerCert(smaller)
			if err2 != nil {
				break
			}
			trial2 := append(append([][]byte{}, chain...), fc2)
			n2 := estimateCertMsgLen(leaf, trial2)
			if n2 > targetInner {
				break
			}
			chain = trial2
			cur = n2
			continue
		}
		chain = trial
		cur = nCur
	}

	// 3) Length-only extension padding if still short and not using ML-DSA capacity fully.
	if cur < targetInner && !mldsa {
		need := targetInner - cur
		if need > 16 {
			pad := need - 16
			if pad > 2000 {
				pad = 2000
			}
			// Shrink pad until estimate fits.
			for tries := 0; tries < 6; tries++ {
				extVal := make([]byte, pad)
				nl, err := createLeaf(pub, priv, extVal, 0)
				if err != nil {
					break
				}
				nCur := estimateCertMsgLen(nl, chain)
				if nCur <= targetInner {
					leaf = nl
					cur = nCur
					break
				}
				pad = pad * 3 / 4
				if pad < 8 {
					break
				}
			}
		}
	}
	return leaf, chain
}

func createFillerCert(approxLen int) ([]byte, error) {
	// Independent throwaway key ? not used for auth.
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
	cn := make([]byte, pad)
	for i := range cn {
		cn[i] = 'x'
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: string(cn)},
	}
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
func MaterializeCert(plan *CertPlan, authKey []byte, mldsaKey []byte, clientHelloOrig, serverHelloOrig []byte) ([][]byte, error) {
	if plan == nil || len(plan.LeafDER) == 0 {
		return nil, fmt.Errorf("nil cert plan")
	}
	leaf := make([]byte, len(plan.LeafDER))
	copy(leaf, plan.LeafDER)

	off := plan.HMACOffset
	if off < 0 || off+64 > len(leaf) {
		off = len(leaf) - 64
	}
	h := newHMACSHA512(authKey)
	if len(ed25519Priv) >= 64 {
		h.Write(ed25519Priv[32:])
	}
	sum := h.Sum(nil)
	copy(leaf[off:off+64], sum)

	if len(mldsaKey) > 0 && plan.MLDSAOffset >= 0 && plan.MLDSALen > 0 {
		// Continue same HMAC state with CH||SH (matches handshake_server_tls13).
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
		mldsa65.SignTo(priv, h.Sum(nil), nil, false, leaf[mOff:mOff+mldsa65SigSize])
	}

	out := make([][]byte, 0, 1+len(plan.ChainDERs))
	out = append(out, leaf)
	for _, c := range plan.ChainDERs {
		out = append(out, append([]byte(nil), c...))
	}
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



