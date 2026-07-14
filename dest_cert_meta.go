package reality

import (
	"crypto/x509"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DestCertMeta is display-only certificate shape learned from dest probes.
// It never participates in REALITY authentication (still Ed25519 + HMAC).
type DestCertMeta struct {
	CN           string
	DNSNames     []string
	Organization string
	NotBefore    time.Time
	NotAfter     time.Time
	// ChainDepth includes the leaf. 0 means unknown.
	ChainDepth int
	// ChainLens are DER lengths leaf-first when known.
	ChainLens []int
	LeafLen   int
	Updated   time.Time
}

// CertShapeHint steers filler chain growth toward a dest-like shape.
type CertShapeHint struct {
	// PreferredChainDepth includes leaf. 0 = no preference (default growth).
	PreferredChainDepth int
	// TargetChainLens optional per-entry DER sizes (leaf-first). Lengths are
	// hints only; budget hard-guards still apply.
	TargetChainLens []int
}

var destCertMetaMap sync.Map // map[string]*DestCertMeta keyed by dest or SNI

// NoteDestCertMeta stores/refreshes learned meta for dest.
// Empty dest is ignored. Safe for concurrent use.
func NoteDestCertMeta(dest string, meta *DestCertMeta) {
	dest = strings.TrimSpace(dest)
	if dest == "" || meta == nil {
		return
	}
	cp := *meta
	if cp.Updated.IsZero() {
		cp.Updated = time.Now().UTC()
	}
	if len(meta.DNSNames) > 0 {
		cp.DNSNames = append([]string(nil), meta.DNSNames...)
	}
	if len(meta.ChainLens) > 0 {
		cp.ChainLens = append([]int(nil), meta.ChainLens...)
	}
	destCertMetaMap.Store(dest, &cp)
}

// GetDestCertMeta returns a copy of learned meta for dest, or nil.
func GetDestCertMeta(dest string) *DestCertMeta {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return nil
	}
	v, ok := destCertMetaMap.Load(dest)
	if !ok {
		return nil
	}
	src := v.(*DestCertMeta)
	cp := *src
	if len(src.DNSNames) > 0 {
		cp.DNSNames = append([]string(nil), src.DNSNames...)
	}
	if len(src.ChainLens) > 0 {
		cp.ChainLens = append([]int(nil), src.ChainLens...)
	}
	return &cp
}

// ResetDestCertMetaForTesting clears the meta map.
func ResetDestCertMetaForTesting() {
	destCertMetaMap.Range(func(k, _ any) bool {
		destCertMetaMap.Delete(k)
		return true
	})
}

// LearnDestCertMetaFromChain extracts display fields + chain shape from a
// peer certificate chain (leaf first). Suitable for probe ConnectionState.
func LearnDestCertMetaFromChain(dest string, chain []*x509.Certificate) *DestCertMeta {
	if len(chain) == 0 || chain[0] == nil {
		return nil
	}
	leaf := chain[0]
	meta := &DestCertMeta{
		CN:         leaf.Subject.CommonName,
		DNSNames:   append([]string(nil), leaf.DNSNames...),
		NotBefore:  leaf.NotBefore.UTC(),
		NotAfter:   leaf.NotAfter.UTC(),
		ChainDepth: len(chain),
		Updated:    time.Now().UTC(),
	}
	if len(leaf.Subject.Organization) > 0 {
		meta.Organization = leaf.Subject.Organization[0]
	}
	meta.ChainLens = make([]int, 0, len(chain))
	for _, c := range chain {
		if c == nil {
			continue
		}
		n := len(c.Raw)
		if n == 0 {
			n = estimateParsedCertSize(c)
		}
		meta.ChainLens = append(meta.ChainLens, n)
	}
	if len(meta.ChainLens) > 0 {
		meta.LeafLen = meta.ChainLens[0]
	}
	if dest != "" {
		NoteDestCertMeta(dest, meta)
		if meta.CN != "" {
			NoteDestCertMeta(meta.CN, meta)
		}
	}
	return meta
}

func estimateParsedCertSize(c *x509.Certificate) int {
	n := 300
	n += len(c.Subject.CommonName)
	for _, d := range c.DNSNames {
		n += len(d)
	}
	if c.PublicKey != nil {
		n += 64
	}
	return n
}

// ShapeHintFromMeta converts learned meta into a growth hint.
func ShapeHintFromMeta(meta *DestCertMeta) *CertShapeHint {
	if meta == nil {
		return nil
	}
	h := &CertShapeHint{
		PreferredChainDepth: meta.ChainDepth,
	}
	if len(meta.ChainLens) > 0 {
		h.TargetChainLens = append([]int(nil), meta.ChainLens...)
	}
	return h
}

// metaFingerprint is a coarse cache-key component for CertPlan.
func metaFingerprint(meta *DestCertMeta) uint32 {
	if meta == nil {
		return 0
	}
	var h uint32 = 2166136261
	mix := func(b byte) {
		h ^= uint32(b)
		h *= 16777619
	}
	for i := 0; i < len(meta.CN) && i < 64; i++ {
		mix(meta.CN[i])
	}
	for i := 0; i < len(meta.Organization) && i < 32; i++ {
		mix(meta.Organization[i])
	}
	mix(byte(meta.ChainDepth))
	if len(meta.ChainLens) > 0 {
		mix(byte(meta.ChainLens[0] / 64))
	}
	if len(meta.DNSNames) > 0 {
		dn := meta.DNSNames[0]
		for i := 0; i < len(dn) && i < 48; i++ {
			mix(dn[i])
		}
	}
	return h
}

// truncatedPlanTime returns UTC now truncated to 1 minute for stable plan serials.
var certPlanTimeNow = func() time.Time { return time.Now().UTC() }

func truncatedPlanTime() time.Time {
	return certPlanTimeNow().Truncate(time.Minute)
}

// SoftClassifyClientHello is the dual-key soft class (A5).
// Same core CH features as ClassifyClientHello, but extension presence collapses
// SCT|OCSP and ignores ECH; "s:" prefix keeps soft keys out of exact L2 slots.
func SoftClassifyClientHello(ch *clientHelloMsg) string {
	if ch == nil {
		return ""
	}
	tmp := *ch
	if ch.scts || ch.ocspStapling {
		tmp.scts = true
		tmp.ocspStapling = false
	} else {
		tmp.scts = false
		tmp.ocspStapling = false
	}
	tmp.encryptedClientHello = nil
	return "s:" + ClassifyClientHello(&tmp)
}

// WarmCertPlansForDest pre-builds common CertPlan entries (B2).
func WarmCertPlansForDest(dest string) {
	meta := GetDestCertMeta(dest)
	shape := ShapeHintFromMeta(meta)
	budgets := []struct {
		budget int
		mode   uint8
	}{
		{0, RecordModeSplit},
		{800, RecordModeSplit},
		{1500, RecordModeSplit},
		{2500, RecordModeSplit},
		{4000, RecordModeSplit},
		{CoalescedCertBudget(1200), RecordModeCoalesced},
		{CoalescedCertBudget(2500), RecordModeCoalesced},
		{CoalescedCertBudget(4000), RecordModeCoalesced},
	}
	for _, b := range budgets {
		if b.budget < 0 {
			continue
		}
		_ = GetCertPlanFor(b.budget, false, b.mode, dest, shape)
		_ = GetCertPlanFor(b.budget, true, b.mode, dest, shape)
		certPlanWarmCount.Add(1)
	}
}

var certPlanWarmCount atomic.Uint64
