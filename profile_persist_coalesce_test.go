package reality

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestPersistentProfileStoreRequestSaveCoalescesBurst(t *testing.T) {
	dir := t.TempDir()
	profileStoreMu.Lock()
	loadOnce = sync.Once{}
	profileStore = nil
	profileStoreMu.Unlock()
	t.Cleanup(func() {
		profileStoreMu.Lock()
		profileStore = nil
		loadOnce = sync.Once{}
		profileStoreMu.Unlock()
	})

	store := InitPersistentStore(dir)
	key := "coalesce.persist|example.com|h2"
	globalCacheManager.StoreProfile(key, &RealityProfile{CipherSuite: 0x1301, ALPN: "h2", CapturedAt: time.Now()})
	defer globalCacheManager.InvalidateProfile(key)

	for range 64 {
		store.RequestSave()
	}
	if !store.saveScheduled.Load() {
		t.Fatal("burst did not schedule a save")
	}

	deadline := time.Now().Add(profileSaveDebounce + 2*time.Second)
	for store.saveScheduled.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if store.saveScheduled.Load() {
		t.Fatal("coalesced save did not complete")
	}
	if _, err := os.Stat(store.filePath); err != nil {
		t.Fatalf("coalesced save did not create profile file: %v", err)
	}
}
