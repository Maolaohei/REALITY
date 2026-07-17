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

	// Issuer / intermediate display style (D3). Cosmetic only; not a real trust chain.
	IssuerCN      string
	IssuerOrg     string
	IssuerCountry string
	// IntermediateNames are subject CNs for chain[1..] when learned.
	IntermediateNames []string
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
	if len(meta.IntermediateNames) > 0 {
		cp.IntermediateNames = append([]string(nil), meta.IntermediateNames...)
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
	if len(src.IntermediateNames) > 0 {
		cp.IntermediateNames = append([]string(nil), src.IntermediateNames...)
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
	// Issuer style from leaf.Issuer and first intermediate subject (D3).
	meta.IssuerCN = leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		meta.IssuerOrg = leaf.Issuer.Organization[0]
	}
	if len(leaf.Issuer.Country) > 0 {
		meta.IssuerCountry = leaf.Issuer.Country[0]
	}
	if len(chain) > 1 {
		meta.IntermediateNames = make([]string, 0, len(chain)-1)
		for i := 1; i < len(chain); i++ {
			if chain[i] == nil {
				continue
			}
			cn := chain[i].Subject.CommonName
			if cn == "" && len(chain[i].Subject.Organization) > 0 {
				cn = chain[i].Subject.Organization[0]
			}
			if cn != "" {
				meta.IntermediateNames = append(meta.IntermediateNames, cn)
			}
			// Prefer first intermediate subject as issuer-style makeup.
			if i == 1 {
				if chain[i].Subject.CommonName != "" {
					meta.IssuerCN = chain[i].Subject.CommonName
				}
				if len(chain[i].Subject.Organization) > 0 {
					meta.IssuerOrg = chain[i].Subject.Organization[0]
				}
				if len(chain[i].Subject.Country) > 0 {
					meta.IssuerCountry = chain[i].Subject.Country[0]
				}
			}
		}
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
// Includes issuer-style bits so D3 DN changes invalidate plan cache.
func metaFingerprint(meta *DestCertMeta) uint32 {
	if meta == nil {
		return 0
	}
	var h uint32 = 2166136261
	mix := func(b byte) {
		h ^= uint32(b)
		h *= 16777619
	}
	mixStr := func(str string, max int) {
		for i := 0; i < len(str) && i < max; i++ {
			mix(str[i])
		}
	}
	mixStr(meta.CN, 64)
	mixStr(meta.Organization, 32)
	mixStr(meta.IssuerCN, 48)
	mixStr(meta.IssuerOrg, 32)
	mixStr(meta.IssuerCountry, 8)
	mix(byte(meta.ChainDepth))
	if len(meta.ChainLens) > 0 {
		mix(byte(meta.ChainLens[0] / 64))
	}
	if len(meta.DNSNames) > 0 {
		mixStr(meta.DNSNames[0], 48)
	}
	if len(meta.IntermediateNames) > 0 {
		mixStr(meta.IntermediateNames[0], 32)
		mix(byte(len(meta.IntermediateNames)))
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
	// Common path: no SCT/OCSP/ECH presence bits differ from exact class → soft is exact with "s:" prefix.
	if !ch.scts && !ch.ocspStapling && len(ch.encryptedClientHello) == 0 {
		return "s:" + ClassifyClientHello(ch)
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

// SoftClassifyFromExact is SoftClassifyClientHello when the exact class is already known.
// Avoids a second full FNV pass on the common no-SCT/OCSP/ECH path.
func SoftClassifyFromExact(ch *clientHelloMsg, exactClass string) string {
	if ch == nil {
		return ""
	}
	if exactClass != "" && !ch.scts && !ch.ocspStapling && len(ch.encryptedClientHello) == 0 {
		return "s:" + exactClass
	}
	return SoftClassifyClientHello(ch)
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

// CloneDestCertMeta returns a deep copy suitable for profile storage (D1).
func CloneDestCertMeta(meta *DestCertMeta) *DestCertMeta {
	if meta == nil {
		return nil
	}
	cp := *meta
	if len(meta.DNSNames) > 0 {
		cp.DNSNames = append([]string(nil), meta.DNSNames...)
	}
	if len(meta.ChainLens) > 0 {
		cp.ChainLens = append([]int(nil), meta.ChainLens...)
	}
	if len(meta.IntermediateNames) > 0 {
		cp.IntermediateNames = append([]string(nil), meta.IntermediateNames...)
	}
	return &cp
}

// ResolveDestCertMeta prefers profile-attached meta, then dest/SNI global map (D1).
func ResolveDestCertMeta(profile *RealityProfile, dest, serverName string) *DestCertMeta {
	if profile != nil && profile.CertMeta != nil {
		return CloneDestCertMeta(profile.CertMeta)
	}
	if m := GetDestCertMeta(dest); m != nil {
		return m
	}
	if serverName != "" && serverName != dest {
		return GetDestCertMeta(serverName)
	}
	return nil
}

// ---- D2: per-dest coalesced EE plaintext calibration ----
// Samples are EE handshake-message plaintext sizes observed on split-mode
// handshakes. Coalesced residual may use p90 EE when samples are sufficient.
// SafetyInner (48) is never reduced. Overhead never drops below a hard floor.

type destEEStats struct {
	samples [8]int
	n       int
	idx     int
}

var destEEMap sync.Map // map[string]*destEEStats

var destEEMu sync.Mutex

// NoteDestEEPlain records one observed EE plaintext length for dest (bytes of
// handshake message only, not outer record). Ignores nonsense sizes.
func NoteDestEEPlain(dest string, eePlain int) {
	dest = strings.TrimSpace(dest)
	if dest == "" || eePlain < 12 || eePlain > 512 {
		return
	}
	v, _ := destEEMap.LoadOrStore(dest, &destEEStats{})
	st := v.(*destEEStats)
	destEEMu.Lock()
	st.samples[st.idx%len(st.samples)] = eePlain
	st.idx++
	if st.n < len(st.samples) {
		st.n++
	}
	destEEMu.Unlock()
}

// GetDestEEPlainP90 returns a conservative high percentile of sampled EE sizes.
// ok=false when fewer than 3 samples.
func GetDestEEPlainP90(dest string) (ee int, samples int, ok bool) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return 0, 0, false
	}
	v, found := destEEMap.Load(dest)
	if !found {
		return 0, 0, false
	}
	st := v.(*destEEStats)
	destEEMu.Lock()
	n := st.n
	if n <= 0 {
		destEEMu.Unlock()
		return 0, 0, false
	}
	tmp := make([]int, n)
	for i := 0; i < n; i++ {
		tmp[i] = st.samples[i]
	}
	destEEMu.Unlock()
	// insertion sort small
	for i := 1; i < len(tmp); i++ {
		j := i
		for j > 0 && tmp[j-1] > tmp[j] {
			tmp[j-1], tmp[j] = tmp[j], tmp[j-1]
			j--
		}
	}
	// p90 index
	idx := (len(tmp) * 9) / 10
	if idx >= len(tmp) {
		idx = len(tmp) - 1
	}
	return tmp[idx], n, n >= 3
}

// ResetDestEEStatsForTesting clears EE calibration.
func ResetDestEEStatsForTesting() {
	destEEMu.Lock()
	defer destEEMu.Unlock()
	destEEMap.Range(func(k, _ any) bool {
		destEEMap.Delete(k)
		return true
	})
}

// NoteDestEEFromRecordLens extracts EE plaintext from split-mode lens[2].
func NoteDestEEFromRecordLens(dest string, lens [7]int, mode uint8) {
	if mode != RecordModeSplit {
		return
	}
	outer := lens[2]
	if outer <= recordHeaderLen+1+16 {
		return
	}
	// Outer = header + plaintext + ctype + tag
	eePlain := outer - recordHeaderLen - 1 - 16
	NoteDestEEPlain(dest, eePlain)
}
