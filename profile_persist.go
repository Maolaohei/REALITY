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
}

// ProfileFile is the JSON structure for persistent storage.
type ProfileFile struct {
	Version   int                        `json:"version"`
	SavedAt   time.Time                  `json:"saved_at"`
	Profiles  map[string]*ProfileEntry   `json:"profiles"`
	Layouts   map[string]*LayoutEntry    `json:"layouts"`
}

// ProfileEntry is the serialized form of RealityProfile.
type ProfileEntry struct {
	RecordLens  [7]int   `json:"record_lens"`
	Fingerprint uint64   `json:"fingerprint"`
	CipherSuite uint16   `json:"cipher_suite"`
	ALPN        string   `json:"alpn"`
	RecordCount int      `json:"record_count"`
	CapturedAt  int64    `json:"captured_at"`
}

// LayoutEntry is the serialized form of HandshakeLayout.
type LayoutEntry struct {
	Fingerprint          uint64   `json:"fingerprint"`
	ServerHelloLen       int      `json:"server_hello_len"`
	EncryptedExtensionsLen int    `json:"encrypted_extensions_len"`
	CertificateLen       int      `json:"certificate_len"`
	CertificateVerifyLen int      `json:"certificate_verify_len"`
	FinishedLen          int      `json:"finished_len"`
	RecordLens           [7]int   `json:"record_lens"`
	RecordCount          int      `json:"record_count"`
	CapturedAt           int64    `json:"captured_at"`
}

var (
	profileStore *PersistentProfileStore
	loadOnce     sync.Once
)

// InitPersistentStore initializes the persistent profile store.
// Call this once at startup. filePath is where profiles.json will be stored.
func InitPersistentStore(dir string) *PersistentProfileStore {
	loadOnce.Do(func() {
		profileStore = &PersistentProfileStore{
			filePath: filepath.Join(dir, "profiles.json"),
		}
		profileStore.enabled.Store(true)
		profileStore.load()
	})
	return profileStore
}

// Save persists current cache state to disk.
func (s *PersistentProfileStore) Save() {
	if !s.enabled.Load() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	file := ProfileFile{
		Version:  1,
		SavedAt:  time.Now(),
		Profiles: make(map[string]*ProfileEntry),
		Layouts:  make(map[string]*LayoutEntry),
	}

	// Collect profiles
	realityProfileCache.Range(func(key, val any) bool {
		p := val.(*RealityProfile)
		file.Profiles[key.(string)] = &ProfileEntry{
			RecordLens:  p.RecordLens,
			Fingerprint: p.Fingerprint,
			CipherSuite: p.CipherSuite,
			ALPN:        p.ALPN,
			RecordCount: p.RecordCount,
			CapturedAt:  p.CapturedAt.UnixNano(),
		}
		return true
	})

	// Collect layouts
	realityLayoutCache.Range(func(key, val any) bool {
		l := val.(*HandshakeLayout)
		file.Layouts[key.(string)] = &LayoutEntry{
			Fingerprint:            l.Fingerprint,
			ServerHelloLen:         l.ServerHelloLen,
			EncryptedExtensionsLen: l.EncryptedExtensionsLen,
			CertificateLen:         l.CertificateLen,
			CertificateVerifyLen:   l.CertificateVerifyLen,
			FinishedLen:            l.FinishedLen,
			RecordLens:             l.RecordLens,
			RecordCount:            l.RecordCount,
			CapturedAt:             l.CapturedAt.UnixNano(),
		}
		return true
	})

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return
	}

	// Atomic write: write to temp file, then rename.
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return
	}
	os.Rename(tmpPath, s.filePath)
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

	// Don't load expired entries
	now := time.Now()
	for key, entry := range file.Profiles {
		capturedAt := time.Unix(0, entry.CapturedAt)
		if now.Sub(capturedAt) > ProfileTTL {
			continue
		}
		profile := &RealityProfile{
			RecordLens:  entry.RecordLens,
			Fingerprint: entry.Fingerprint,
			CipherSuite: entry.CipherSuite,
			ALPN:        entry.ALPN,
			RecordCount: entry.RecordCount,
			CapturedAt:  capturedAt,
		}
		realityProfileCache.Store(key, profile)
		cacheStats.ProfileEntries.Add(1)
	}

	for key, entry := range file.Layouts {
		capturedAt := time.Unix(0, entry.CapturedAt)
		if now.Sub(capturedAt) > ProfileTTL {
			continue
		}
		layout := &HandshakeLayout{
			Fingerprint:            entry.Fingerprint,
			ServerHelloLen:         entry.ServerHelloLen,
			EncryptedExtensionsLen: entry.EncryptedExtensionsLen,
			CertificateLen:         entry.CertificateLen,
			CertificateVerifyLen:   entry.CertificateVerifyLen,
			FinishedLen:            entry.FinishedLen,
			RecordLens:             entry.RecordLens,
			RecordCount:            entry.RecordCount,
			CapturedAt:             capturedAt,
		}
		realityLayoutCache.Store(key, layout)
		cacheStats.LayoutEntries.Add(1)
	}
}

// StartPeriodicSave starts a goroutine that saves cache every interval.
func (s *PersistentProfileStore) StartPeriodicSave(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.Save()
		}
	}()
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
