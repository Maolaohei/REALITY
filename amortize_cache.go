package reality

import (
	"io"
	"time"
)

// Extended profile states for amortize (beyond Valid/Stale/Negative).
const (
	ProfileSuspect ProfileState = ProfileNegative + 1 + iota
	ProfileQuarantined
)

// LookupResult is returned by amortize-aware cache lookup.
type LookupResult struct {
	Profile *RealityProfile
	Path    AmortizePath
	Key     string
	Stale   bool
}

// LookupAmortize selects L0/L1/L2 based on mode and cached evidence.
// chClass may be empty for legacy callers (falls back to legacy key).
func (m *CacheManager) LookupAmortize(mode AmortizeMode, dest, serverName, alpn string, tlsVersion uint16, chClass string, liveCipher uint16, liveGroup CurveID) LookupResult {
	mode = ResolveAmortizeMode(mode)
	if mode == AmortizeL0 {
		return LookupResult{Path: PathL0}
	}

	// Prefer V2 key when chClass is known.
	var keys []string
	if chClass != "" {
		keys = append(keys, CacheKeyV2(dest, serverName, alpn, tlsVersion, chClass))
	}
	// Legacy key for backward compatibility (L1 only; never L2).
	keys = append(keys, CacheKey(serverName, alpn, tlsVersion))

	for _, key := range keys {
		val, ok := m.entries.Load(key)
		if !ok {
			continue
		}
		entry := val.(*ProfileEntry)
		// Lock-free fast-path: skip rejected states without taking the mutex.
		s := ProfileState(entry.atomicState.Load())
		if s == ProfileNegative || s == ProfileQuarantined {
			continue
		}
		entry.mu.Lock()
		if entry.State == ProfileNegative || entry.State == ProfileQuarantined {
			entry.mu.Unlock()
			continue
		}
		suspect := entry.State == ProfileSuspect
		p := entry.Profile
		if p == nil || !ValidateRecordLens(p.RecordLens) {
			entry.mu.Unlock()
			continue
		}
		// TTL: allow stale for L1, never for L2.
		expired := time.Since(p.CapturedAt) >= entry.TTL
		if expired && entry.State == ProfileValid {
			entry.State = ProfileStale
			entry.atomicState.Store(int32(ProfileStale))
		}
		stale := entry.State == ProfileStale || expired

		// L2 only on non-stale non-suspect V2 keys with full evidence (Wave-2 S1-lite).
		if !suspect && !stale && !IsLegacyCacheKey(key) && profileL2Eligible(p) {
			if mode == AmortizeL2 || mode == AmortizeAuto {
				if clientPolicyCompatible(p, liveCipher, liveGroup) {
					cp := *p
					entry.mu.Unlock()
					m.stats.L2Hits.Add(1)
					return LookupResult{Profile: &cp, Path: PathL2, Key: key, Stale: false}
				}
			}
		}

		// L1: need matching cipher if liveCipher known; group if known.
		if mode == AmortizeL1 || mode == AmortizeAuto || mode == AmortizeL2 {
			if liveCipher != 0 && p.CipherSuite != 0 && p.CipherSuite != liveCipher {
				entry.mu.Unlock()
				continue
			}
			if liveGroup != 0 && p.KeyShareGroup != 0 && p.KeyShareGroup != liveGroup {
				entry.mu.Unlock()
				continue
			}
			if p.TLSVersion != 0 && tlsVersion != 0 && p.TLSVersion != tlsVersion {
				entry.mu.Unlock()
				continue
			}
			cp := *p
			entry.mu.Unlock()
			if stale {
				m.stats.StaleServed.Add(1)
			}
			m.stats.L1Hits.Add(1)
			return LookupResult{Profile: &cp, Path: PathL1, Key: key, Stale: stale}
		}
		entry.mu.Unlock()
	}
	return LookupResult{Path: PathL0}
}

func clientPolicyCompatible(p *RealityProfile, liveCipher uint16, liveGroup CurveID) bool {
	if p == nil {
		return false
	}
	// When liveCipher/group are 0, compatibility is checked against CH elsewhere.
	if liveCipher != 0 && p.CipherSuite != liveCipher {
		return false
	}
	if liveGroup != 0 && p.KeyShareGroup != liveGroup {
		return false
	}
	return true
}

// FindCachedProfileByDest searches for a cached profile matching the given
// serverName, cipher suite, ALPN, and TLS version.
// Extended to also try dest-aware keys when dest is non-empty (second form via overload behavior).
func (m *CacheManager) FindCachedProfileByDest(dest, serverName string, cipherSuite uint16, alpn string, tlsVersion uint16) (lens [7]int, foundTLSVersion uint16, ok bool) {
	// Try legacy key first (existing tests).
	key := CacheKey(serverName, alpn, tlsVersion)
	if lens, foundTLSVersion, ok = m.findLensAtKey(key, dest, cipherSuite, tlsVersion); ok {
		return
	}
	// Also scan V2 entries for matching serverName/alpn/cipher when dest provided.
	if dest == "" {
		return
	}
	// Direct V2 without chClass is not possible; scan.
	m.entries.Range(func(k, val any) bool {
		ks := k.(string)
		d, sn, a, ver, _, isV2 := ParseCacheKeyV2(ks)
		if !isV2 || d != dest || sn != serverName || a != alpn {
			return true
		}
		if ver != 0 && tlsVersion != 0 && ver != tlsVersion {
			return true
		}
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.State == ProfileNegative || entry.State == ProfileQuarantined || entry.Profile == nil {
			return true
		}
		if time.Since(entry.Profile.CapturedAt) >= entry.TTL {
			return true
		}
		if entry.Profile.CipherSuite != cipherSuite {
			return true
		}
		if !ValidateRecordLens(entry.Profile.RecordLens) {
			return true
		}
		lens = entry.Profile.RecordLens
		foundTLSVersion = entry.Profile.TLSVersion
		ok = true
		return false
	})
	return
}

func (m *CacheManager) findLensAtKey(key, dest string, cipherSuite, tlsVersion uint16) (lens [7]int, foundTLSVersion uint16, ok bool) {
	if val, found := m.entries.Load(key); found {
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		defer entry.mu.Unlock()
		if entry.State != ProfileNegative && entry.State != ProfileQuarantined &&
			entry.Profile != nil &&
			time.Since(entry.Profile.CapturedAt) < entry.TTL &&
			entry.Profile.CipherSuite == cipherSuite &&
			(tlsVersion == 0 || entry.Profile.TLSVersion == 0 || entry.Profile.TLSVersion == tlsVersion) &&
			ValidateRecordLens(entry.Profile.RecordLens) {
			// Dest isolation: if profile has Dest set, it must match.
			if dest != "" && entry.Profile.Dest != "" && entry.Profile.Dest != dest {
				return
			}
			lens = entry.Profile.RecordLens
			foundTLSVersion = entry.Profile.TLSVersion
			ok = true
		}
	}
	return
}

// StoreObservation merges a live observation into the cache with evidence counting.
// Matching policy increments Evidence; mismatch debounces then HotSwaps.
func (m *CacheManager) StoreObservation(key string, obs *RealityProfile) {
	if obs == nil || !ValidateRecordLens(obs.RecordLens) {
		return
	}
	if val, ok := m.entries.Load(key); ok {
		entry := val.(*ProfileEntry)
		entry.mu.Lock()
		if entry.State == ProfileQuarantined {
			// After cooldown, allow a live observation to start calibration
			// (Evidence=1 => L1 only until MinL2Evidence rebuilds).
			if time.Now().Before(entry.NextRetry) {
				entry.mu.Unlock()
				return
			}
			cp := *obs
			cp.Evidence = 1
			if cp.Stability < 1 {
				cp.Stability = 1
			}
			cp.Source = "live"
			entry.Profile = &cp
			entry.State = ProfileValid
			entry.atomicState.Store(int32(ProfileValid))
			entry.FailCount = 0
			entry.NextRetry = time.Time{}
			entry.TTL = m.baseTTL
			entry.mu.Unlock()
			m.stats.Calibrations.Add(1)
			m.dirty.Store(true)
			return
		}
		cur := entry.Profile
		if cur != nil && profilesMatch(cur, obs) {
			// Promote evidence and refresh template/lens timestamps.
			merged := *cur
			merged.RecordLens = obs.RecordLens
			merged.Fingerprint = obs.Fingerprint
			merged.CipherSuite = obs.CipherSuite
			merged.ALPN = obs.ALPN
			merged.TLSVersion = obs.TLSVersion
			merged.RecordCount = obs.RecordCount
			merged.CapturedAt = obs.CapturedAt
			merged.Dest = obs.Dest
			merged.ServerName = obs.ServerName
			merged.CHClass = obs.CHClass
			merged.KeyShareGroup = obs.KeyShareGroup
			merged.AcceptsHRR = obs.AcceptsHRR
			merged.ShapeHash = obs.ShapeHash
			if len(obs.ServerHelloTemplate) > 0 {
				merged.ServerHelloTemplate = append([]byte(nil), obs.ServerHelloTemplate...)
			}
			merged.Evidence = cur.Evidence + 1
			if merged.Stability < 10 {
				merged.Stability = cur.Stability + 1
			}
			merged.Source = "live"
			entry.Profile = &merged
			entry.State = ProfileValid
			entry.atomicState.Store(int32(ProfileValid))
			entry.TTL = m.baseTTL
			entry.FailCount = 0
			entry.mu.Unlock()
			m.dirty.Store(true)
			return
		}
		// Mismatch: require two consecutive identical new observations (stored in Profile candidate via HotSwap debounce fields on entry).
		// Use FailCount as pending-mismatch counter with Profile as last candidate when State==Suspect.
		if entry.State == ProfileSuspect && entry.Profile != nil && profilesMatch(entry.Profile, obs) {
			entry.FailCount++
			if entry.FailCount >= 2 {
				cp := *obs
				if cp.Evidence < 1 {
					cp.Evidence = 1
				}
				entry.Profile = &cp
				entry.State = ProfileValid
				entry.atomicState.Store(int32(ProfileValid))
				entry.FailCount = 0
				entry.TTL = m.baseTTL
				m.stats.HotSwaps.Add(1)
			}
			entry.mu.Unlock()
			m.dirty.Store(true)
			return
		}
		// First mismatch observation: mark suspect with new candidate.
		cp := *obs
		cp.Evidence = 1
		entry.Profile = &cp
		entry.State = ProfileSuspect
		entry.atomicState.Store(int32(ProfileSuspect))
		entry.FailCount = 1
		entry.mu.Unlock()
		m.dirty.Store(true)
		return
	}

	// New entry.
	cp := *obs
	if cp.Evidence < 1 {
		cp.Evidence = 1
	}
	entry := &ProfileEntry{
		Profile: &cp,
		State:   ProfileValid,
		TTL:     m.baseTTL,
	}
	entry.atomicState.Store(int32(ProfileValid))
	if _, loaded := m.entries.LoadOrStore(key, entry); !loaded {
		m.stats.ProfileEntries.Add(1)
		m.dirty.Store(true)
		m.evictIfFull()
	}
}

func profilesMatch(a, b *RealityProfile) bool {
	if a == nil || b == nil {
		return false
	}
	if a.CipherSuite != b.CipherSuite {
		return false
	}
	if a.KeyShareGroup != 0 && b.KeyShareGroup != 0 && a.KeyShareGroup != b.KeyShareGroup {
		return false
	}
	if a.AcceptsHRR != b.AcceptsHRR {
		return false
	}
	// Compare R0-R5; R6 (NewSessionTicket) is optional and may jitter.
	for i := 0; i < 6; i++ {
		if a.RecordLens[i] != b.RecordLens[i] {
			return false
		}
	}
	if a.ShapeHash != 0 && b.ShapeHash != 0 && a.ShapeHash != b.ShapeHash {
		return false
	}
	return true
}

// Quarantine marks a key as unusable for L1/L2 until cooldown elapses.
// After QuarantineCooldown, the next live StoreObservation starts calibration
// with Evidence=1 (L0/L1 only until MinL2Evidence is rebuilt).
func (m *CacheManager) Quarantine(key, reason string) {
	val, ok := m.entries.Load(key)
	if !ok {
		entry := &ProfileEntry{
			State:     ProfileQuarantined,
			FailCount: MaxL2FailWindow,
			NextRetry: time.Now().Add(QuarantineCooldown),
			TTL:       m.baseTTL,
		}
		entry.atomicState.Store(int32(ProfileQuarantined))
		m.entries.Store(key, entry)
		m.stats.Quarantines.Add(1)
		m.dirty.Store(true)
		return
	}
	entry := val.(*ProfileEntry)
	entry.mu.Lock()
	entry.State = ProfileQuarantined
	entry.atomicState.Store(int32(ProfileQuarantined))
	entry.FailCount = MaxL2FailWindow
	entry.NextRetry = time.Now().Add(QuarantineCooldown)
	// Drop evidence so post-cooldown recovery cannot immediately L2.
	if entry.Profile != nil {
		cp := *entry.Profile
		cp.Evidence = 0
		entry.Profile = &cp
	}
	entry.mu.Unlock()
	m.stats.Quarantines.Add(1)
	m.dirty.Store(true)
	_ = reason
}

// NoteHandshakeFailure records an amortize-path failure; quarantines after threshold.
func (m *CacheManager) NoteHandshakeFailure(key string, path AmortizePath) {
	if key == "" {
		return
	}
	if path != PathL1 && path != PathL2 {
		return
	}
	val, ok := m.entries.Load(key)
	if !ok {
		return
	}
	entry := val.(*ProfileEntry)
	entry.mu.Lock()
	entry.FailCount++
	fc := entry.FailCount
	if path == PathL2 {
		m.stats.L2Fails.Add(1)
		m.stats.L2SoftDemotions.Add(1)
	} else if path == PathL1 {
		m.stats.L1Fails.Add(1)
	}
	if fc >= MaxL2FailWindow {
		entry.State = ProfileQuarantined
		entry.atomicState.Store(int32(ProfileQuarantined))
		entry.NextRetry = time.Now().Add(QuarantineCooldown)
		if entry.Profile != nil {
			cp := *entry.Profile
			cp.Evidence = 0
			entry.Profile = &cp
		}
		entry.mu.Unlock()
		m.stats.Quarantines.Add(1)
		m.dirty.Store(true)
		return
	}
	if entry.State == ProfileValid {
		entry.State = ProfileSuspect
		entry.atomicState.Store(int32(ProfileSuspect))
	}
	entry.mu.Unlock()
	m.dirty.Store(true)
}

// InvalidateKey deletes a single key (precise invalidation).
func (m *CacheManager) InvalidateKey(key string) {
	m.InvalidateProfile(key)
}

// InvalidateAndReprobe clears profiles for a dest/serverName/alpn and reprobes.
// Prefer precise invalidation over InvalidateAll.
func (m *CacheManager) InvalidateAndReprobe(dest, serverName, alpn string) {
	// Precise: remove matching legacy + any V2 keys for dest/sn/alpn.
	legacy := CacheKey(serverName, alpn, VersionTLS13)
	m.InvalidateProfile(legacy)

	var toDelete []string
	m.entries.Range(func(k, val any) bool {
		ks := k.(string)
		d, sn, a, _, _, isV2 := ParseCacheKeyV2(ks)
		if isV2 {
			if (dest == "" || d == dest) && sn == serverName && a == alpn {
				toDelete = append(toDelete, ks)
			}
			return true
		}
		// legacy: serverName|alpn|ver
		sn2, a2, _ := ParseCacheKey(ks)
		if sn2 == serverName && a2 == alpn {
			toDelete = append(toDelete, ks)
		}
		return true
	})
	for _, k := range toDelete {
		m.InvalidateProfile(k)
	}

	key := CacheKey(serverName, alpn, VersionTLS13)
	go m.DoProbe(key, func() (*RealityProfile, error) {
		return probeTargetRaw(dest, serverName, alpnToInt(alpn))
	})
}

// EnsureServerHelloTemplateFromRecord extracts handshake message from a full R0 record.
func EnsureServerHelloTemplateFromRecord(r0 []byte) []byte {
	if len(r0) <= recordHeaderLen {
		return nil
	}
	// r0 may be full TLS record or raw handshake message.
	if len(r0) >= recordHeaderLen && r0[0] == byte(recordTypeHandshake) {
		return append([]byte(nil), r0[recordHeaderLen:]...)
	}
	return append([]byte(nil), r0...)
}

// WriteAll is a tiny helper used by mirror CH replay.
func WriteAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
