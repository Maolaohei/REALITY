package reality

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// PersistentProfileStore manages saving and loading of cached profiles.
type PersistentProfileStore struct {
	mu       sync.Mutex
	filePath string
	enabled  atomic.Bool
	quit     chan struct{}
}

// ProfileFile is the JSON structure for persistent storage.
type ProfileFile struct {
	Version  int                             `json:"version"`
	SavedAt  time.Time                       `json:"saved_at"`
	Profiles map[string]*PersistProfileEntry `json:"profiles"`
}

// profileFileCurrentVersion is the current on-disk schema version.
// Bump this when the PersistProfileEntry struct changes and add a
// migration case in migrateProfileFile.
const profileFileCurrentVersion = 3

// migrateProfileFile applies in-place migrations from older schema versions
// to the current version. Each case should transform the file and fall through
// to the next version.
func migrateProfileFile(file *ProfileFile) {
	if file == nil {
		return
	}
	// v1 -> v2: default RecordMode from lens; LiveEvidence/CHClassVer remain 0.
	for file.Version < 2 {
		for _, e := range file.Profiles {
			if e == nil {
				continue
			}
			if e.RecordMode == 0 {
				e.RecordMode = InferRecordMode(e.RecordLens)
			}
		}
		file.Version = 2
	}
	// v2 -> v3: CertMeta optional; older files load with nil CertMeta.
	for file.Version < 3 {
		// No structural transform required; new fields default to zero/nil.
		file.Version = 3
	}
}

// PersistCertMeta is the JSON form of DestCertMeta (display-only, D1/D3).
type PersistCertMeta struct {
	CN                string   `json:"cn,omitempty"`
	DNSNames          []string `json:"dns_names,omitempty"`
	Organization      string   `json:"organization,omitempty"`
	NotBefore         int64    `json:"not_before,omitempty"`
	NotAfter          int64    `json:"not_after,omitempty"`
	ChainDepth        int      `json:"chain_depth,omitempty"`
	ChainLens         []int    `json:"chain_lens,omitempty"`
	LeafLen           int      `json:"leaf_len,omitempty"`
	IssuerCN          string   `json:"issuer_cn,omitempty"`
	IssuerOrg         string   `json:"issuer_org,omitempty"`
	IssuerCountry     string   `json:"issuer_country,omitempty"`
	IntermediateNames []string `json:"intermediate_names,omitempty"`
}

func persistCertMetaFrom(m *DestCertMeta) *PersistCertMeta {
	if m == nil {
		return nil
	}
	out := &PersistCertMeta{
		CN:            m.CN,
		Organization:  m.Organization,
		ChainDepth:    m.ChainDepth,
		LeafLen:       m.LeafLen,
		IssuerCN:      m.IssuerCN,
		IssuerOrg:     m.IssuerOrg,
		IssuerCountry: m.IssuerCountry,
	}
	if len(m.DNSNames) > 0 {
		out.DNSNames = append([]string(nil), m.DNSNames...)
	}
	if len(m.ChainLens) > 0 {
		out.ChainLens = append([]int(nil), m.ChainLens...)
	}
	if len(m.IntermediateNames) > 0 {
		out.IntermediateNames = append([]string(nil), m.IntermediateNames...)
	}
	if !m.NotBefore.IsZero() {
		out.NotBefore = m.NotBefore.Unix()
	}
	if !m.NotAfter.IsZero() {
		out.NotAfter = m.NotAfter.Unix()
	}
	return out
}

func destCertMetaFromPersist(p *PersistCertMeta) *DestCertMeta {
	if p == nil {
		return nil
	}
	out := &DestCertMeta{
		CN:            p.CN,
		Organization:  p.Organization,
		ChainDepth:    p.ChainDepth,
		LeafLen:       p.LeafLen,
		IssuerCN:      p.IssuerCN,
		IssuerOrg:     p.IssuerOrg,
		IssuerCountry: p.IssuerCountry,
	}
	if len(p.DNSNames) > 0 {
		out.DNSNames = append([]string(nil), p.DNSNames...)
	}
	if len(p.ChainLens) > 0 {
		out.ChainLens = append([]int(nil), p.ChainLens...)
	}
	if len(p.IntermediateNames) > 0 {
		out.IntermediateNames = append([]string(nil), p.IntermediateNames...)
	}
	if p.NotBefore != 0 {
		out.NotBefore = time.Unix(p.NotBefore, 0).UTC()
	}
	if p.NotAfter != 0 {
		out.NotAfter = time.Unix(p.NotAfter, 0).UTC()
	}
	return out
}

// PersistProfileEntry is the serialized form of RealityProfile for disk storage.
type PersistProfileEntry struct {
	RecordLens   [7]int `json:"record_lens"`
	Fingerprint  uint64 `json:"fingerprint"`
	CipherSuite  uint16 `json:"cipher_suite"`
	ALPN         string `json:"alpn"`
	TLSVersion   uint16 `json:"tls_version"`
	RecordCount  int    `json:"record_count"`
	CapturedAt   int64  `json:"captured_at"`
	RecordMode   uint8  `json:"record_mode,omitempty"`
	LiveEvidence int    `json:"live_evidence,omitempty"`
	Evidence     int    `json:"evidence,omitempty"`
	CHClassVer   uint8  `json:"ch_class_ver,omitempty"`
	Source       string `json:"source,omitempty"`
	Dest         string `json:"dest,omitempty"`
	ServerName   string `json:"server_name,omitempty"`
	// CertMeta is display-only dest leaf/chain shape (D1). Never used for auth.
	CertMeta *PersistCertMeta `json:"cert_meta,omitempty"`
}

var (
	profileStore *PersistentProfileStore
	loadOnce     sync.Once
)

// InitPersistentStore initializes the persistent profile store.
// Call this once at startup. filePath is where profiles.json will be stored.
func InitPersistentStore(dir string) *PersistentProfileStore {
	loadOnce.Do(func() {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return
		}
		profileStore = &PersistentProfileStore{
			filePath: filepath.Join(dir, "profiles.json"),
		}
		profileStore.enabled.Store(true)
		profileStore.load()
	})
	return profileStore
}

// Save persists current cache state to disk. Skips write if cache is clean.
func (s *PersistentProfileStore) Save() {
	if !s.enabled.Load() {
		return
	}
	// Skip write if nothing has changed.
	if !globalCacheManager.IsDirty() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	file := ProfileFile{
		Version:  profileFileCurrentVersion,
		SavedAt:  time.Now(),
		Profiles: make(map[string]*PersistProfileEntry),
	}

	// Take a snapshot for consistent serialization.
	snapshot := globalCacheManager.SnapshotProfiles()
	for key, p := range snapshot {
		file.Profiles[key] = &PersistProfileEntry{
			RecordLens:   p.RecordLens,
			Fingerprint:  p.Fingerprint,
			CipherSuite:  p.CipherSuite,
			ALPN:         p.ALPN,
			TLSVersion:   p.TLSVersion,
			RecordCount:  p.RecordCount,
			CapturedAt:   p.CapturedAt.UnixNano(),
			RecordMode:   p.RecordMode,
			LiveEvidence: p.LiveEvidence,
			Evidence:     p.Evidence,
			CHClassVer:   p.CHClassVer,
			Source:       p.Source,
			Dest:         p.Dest,
			ServerName:   p.ServerName,
			CertMeta:     persistCertMetaFrom(p.CertMeta),
		}
	}

	data, err := json.Marshal(file)
	if err != nil {
		return
	}

	// Atomic write: write to temp file ?fsync ?rename.
	tmpPath := s.filePath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return
	}
	f.Close()
	os.Rename(tmpPath, s.filePath)

	// Clear dirty flag after successful write.
	globalCacheManager.ClearDirty()
}

// load reads profiles from disk and populates caches.
func (s *PersistentProfileStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return
	}

	var file ProfileFile
	if err := json.Unmarshal(data, &file); err != nil {
		return
	}

	// Reject files from an unknown future version.
	if file.Version > profileFileCurrentVersion {
		return
	}

	// Apply migrations from older versions to current.
	if file.Version < profileFileCurrentVersion {
		migrateProfileFile(&file)
	}

	// Don't load expired entries
	now := time.Now()
	for key, entry := range file.Profiles {
		capturedAt := time.Unix(0, entry.CapturedAt)
		if now.Sub(capturedAt) > ProfileTTL {
			continue
		}
		mode := entry.RecordMode
		if mode == 0 {
			mode = InferRecordMode(entry.RecordLens)
		}
		profile := &RealityProfile{
			RecordLens:   entry.RecordLens,
			Fingerprint:  entry.Fingerprint,
			CipherSuite:  entry.CipherSuite,
			ALPN:         entry.ALPN,
			TLSVersion:   entry.TLSVersion,
			RecordCount:  entry.RecordCount,
			CapturedAt:   capturedAt,
			RecordMode:   mode,
			LiveEvidence: entry.LiveEvidence,
			Evidence:     entry.Evidence,
			CHClassVer:   entry.CHClassVer,
			Source:       entry.Source,
			Dest:         entry.Dest,
			ServerName:   entry.ServerName,
			CertMeta:     destCertMetaFromPersist(entry.CertMeta),
		}
		if profile.Source == "" {
			profile.Source = "persist"
		}
		// Recover Dest/ServerName from V2 cache key when older files omit them.
		if profile.Dest == "" || profile.ServerName == "" {
			if d, sn, _, _, _, isV2 := ParseCacheKeyV2(key); isV2 {
				if profile.Dest == "" {
					profile.Dest = d
				}
				if profile.ServerName == "" {
					profile.ServerName = sn
				}
			} else {
				if sn, _, _ := ParseCacheKey(key); profile.ServerName == "" {
					profile.ServerName = sn
				}
			}
		}
		// Persisted profiles never skip straight to L2 without live reconfirmation.
		if profile.LiveEvidence > 0 {
			profile.LiveEvidence = 0
		}
		// D1: rehydrate global dest meta map from persisted CertMeta so L0/L1
		// after cold start can materialize the same leaf makeup without probe.
		if profile.CertMeta != nil {
			if d := profile.Dest; d != "" {
				NoteDestCertMeta(d, profile.CertMeta)
			}
			if sn := profile.ServerName; sn != "" {
				NoteDestCertMeta(sn, profile.CertMeta)
			}
			if profile.CertMeta.CN != "" {
				NoteDestCertMeta(profile.CertMeta.CN, profile.CertMeta)
			}
		}
		globalCacheManager.StoreProfile(key, profile)
	}
}

// StartPeriodicSave starts a goroutine that saves cache every interval.
func (s *PersistentProfileStore) StartPeriodicSave(interval time.Duration) {
	s.quit = make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Save()
			case <-s.quit:
				return
			}
		}
	}()
}

// StopPeriodicSave stops the periodic save goroutine.
func (s *PersistentProfileStore) StopPeriodicSave() {
	if s.quit != nil {
		select {
		case <-s.quit:
		default:
			close(s.quit)
		}
	}
}

// SaveOnShutdown should be called via defer or signal handler.
func (s *PersistentProfileStore) SaveOnShutdown() {
	s.Save()
}

// Enabled returns whether persistence is active.
func (s *PersistentProfileStore) Enabled() bool {
	return s.enabled.Load()
}

// GetFilePath returns the path to the profiles file.
func (s *PersistentProfileStore) GetFilePath() string {
	return s.filePath
}
