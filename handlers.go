package reality

import "fmt"

// RegisterCacheHandlers subscribes CacheManager to handshake events.
func RegisterCacheHandlers(bus *EventBus) {
	bus.On(EventHandshakeComplete, func(e Event) {
		profileKey := CacheKey(e.Dest, e.ServerName, e.ALPN, e.TLSVersion)

		// Store profile in cache.
		if globalCacheManager.StoreProfile(profileKey, e.Profile) {
			// New entry — also store fingerprint.
			if e.Fingerprint != nil {
				fpKey := e.Dest + "|" + e.ServerName
				globalCacheManager.StoreFingerprint(fpKey, e.Fingerprint)
			}
		}
	})
}

// RegisterPersistHandlers subscribes PersistManager to handshake events.
func RegisterPersistHandlers(bus *EventBus) {
	bus.On(EventHandshakeComplete, func(e Event) {
		// Persist new profiles to disk.
		if profileStore != nil {
			go profileStore.Save()
		}
	})
}

// RegisterRefreshHandlers subscribes RefreshManager to handshake events.
func RegisterRefreshHandlers(bus *EventBus) {
	bus.On(EventHandshakeComplete, func(e Event) {
		// Start background refresh for this target.
		StartBackgroundRefreshForProfile(e.Dest, e.ServerName, e.ALPN)
	})
}

// RegisterDiagnosticsHandlers subscribes diagnostics logging.
func RegisterDiagnosticsHandlers(bus *EventBus, show bool) {
	if !show {
		return
	}
	bus.On(EventHandshakeComplete, func(e Event) {
		fmt.Printf("REALITY: cached profile for %v\n", e.Dest)
		fmt.Println(globalCacheManager.CacheReport())
	})
}

// RegisterAllHandlers registers all default handlers on the global event bus.
func RegisterAllHandlers(show bool) {
	RegisterCacheHandlers(globalEventBus)
	RegisterPersistHandlers(globalEventBus)
	RegisterRefreshHandlers(globalEventBus)
	RegisterDiagnosticsHandlers(globalEventBus, show)
}
