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
	Version  int                                  `json:"version"`
	SavedAt  time.Time                            `json:"saved_at"`
	Profiles map[string]*PersistProfileEntry      `json:"profiles"`
}

// PersistProfileEntry is the serialized form of RealityProfile for disk storage.
type PersistProfileEntry struct {
	RecordLens  [7]int   `json:"record_lens"`
	Fingerprint uint64   `json:"fingerprint"`
	CipherSuite uint16   `json:"cipher_suite"`
	ALPN        string   `json:"alpn"`
	RecordCount int      `json:"record_count"`
	CapturedAt  int64    `json:"captured_at"`
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
		Version:  1,
		SavedAt:  time.Now(),
		Profiles: make(map[string]*PersistProfileEntry),
	}

	// Take a snapshot for consistent serialization.
	snapshot := globalCacheManager.SnapshotProfiles()
	for key, p := range snapshot {
		file.Profiles[key] = &PersistProfileEntry{
			RecordLens:  p.RecordLens,
			Fingerprint: p.Fingerprint,
			CipherSuite: p.CipherSuite,
			ALPN:        p.ALPN,
			RecordCount: p.RecordCount,
			CapturedAt:  p.CapturedAt.UnixNano(),
		}
	}

	data, err := json.Marshal(file)
	if err != nil {
		return
	}

	// Atomic write: write to temp file → fsync → rename.
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
		globalCacheManager.StoreProfile(key, profile)
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
