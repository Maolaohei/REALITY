package reality

import "fmt"

// RegisterCacheHandlers subscribes CacheManager to handshake events.
func RegisterCacheHandlers(bus *EventBus) {
	bus.On(EventHandshakeComplete, func(e Event) {
		// Use StoreObservation for evidence-counting and mismatch debounce.
		// Server() already stores via StoreObservation, but the handler also
		// fires for legacy code paths that don't store directly.
		if e.Profile != nil {
			profileKey := CacheKey(e.ServerName, e.ALPN, e.TLSVersion)
			globalCacheManager.StoreObservation(profileKey, e.Profile)
		}
		// Store fingerprint regardless of cache state.
		if e.Fingerprint != nil {
			fpKey := e.Dest + "|" + e.ServerName + "|" + e.ALPN
			globalCacheManager.StoreFingerprint(fpKey, e.Fingerprint)
		}
	})
}

// RegisterPersistHandlers subscribes PersistManager to handshake events.
func RegisterPersistHandlers(bus *EventBus) {
	bus.On(EventHandshakeComplete, func(e Event) {
		// EventBus already runs this handler off the handshake path with a
		// bounded worker set. Do not spawn another goroutine per handshake:
		// Save itself skips clean state and serializes writers with its mutex.
		if profileStore != nil {
			profileStore.Save()
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
