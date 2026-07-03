package reality

import (
	"context"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Auto-start infrastructure
// ============================================================================

var (
	probeOnces sync.Map
	warmupOnce sync.Once
)

func ensureAutoProbe(config *Config) {
	dest := config.Dest
	if dest == "" {
		return
	}

	onceVal, _ := probeOnces.LoadOrStore(dest, &sync.Once{})
	once := onceVal.(*sync.Once)

	once.Do(func() {
		m := GetRefreshManager()
		if !m.started {
			m.Start()
		}
		// Don't register target here — serverName/ALPN are unknown at this
		// point. Registration happens in RegisterRefreshHandlers via the
		// EventHandshakeComplete event with correct parameters.
	})
}

// StopAutoProbe stops auto-probing for a given dest.
// Note: RefreshManager targets are keyed by serverName, so this only
// cleans up the probeOnces guard. Full target removal requires
// StopBackgroundRefreshForProfile(dest, serverName, alpn).
func StopAutoProbe(dest string) {
	probeOnces.Delete(dest)
}

// probeTargetRaw probes the target using a real uTLS ClientHello and returns
// a RealityProfile. serverName is the SNI, alpnIndex is the ALPN selector (0/1/2).
func probeTargetRaw(dest, serverName string, alpnIndex int) (*RealityProfile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := ProbeTargetViaUTLS(ctx, dest, serverName, alpnIndex, 0)
	if err != nil {
		return nil, err
	}

	alpn := intToALPN(alpnIndex)
	return &RealityProfile{
		RecordLens:   result.RecordLens,
		Fingerprint:  computeFingerprint(result.CipherSuite, alpn, result.RecordLens[0], result.RecordLens[2]),
		CipherSuite:  result.CipherSuite,
		ALPN:         alpn,
		TLSVersion:   VersionTLS13,
		RecordCount:  result.RecordCount,
		CapturedAt:   time.Now(),
	}, nil
}

func WarmupProfiles(dir string) {
	warmupOnce.Do(func() {
		go func() {
			if profileStore == nil {
				return
			}
			var keys []string
			globalCacheManager.entries.Range(func(key, val any) bool {
				keys = append(keys, key.(string))
				return true
			})
			if len(keys) == 0 {
				return
			}

			sem := make(chan struct{}, 5)
			var wg sync.WaitGroup
			for _, key := range keys {
				wg.Add(1)
				sem <- struct{}{}
				go func(k string) {
					defer wg.Done()
					defer func() { <-sem }()

					// Parse serverName, alpn, dest from cache key.
					// New format: "serverName|alpn|0x0303"
					// Legacy format: "dest|serverName|alpn|0x0303"
					parts := strings.SplitN(k, "|", 4)
					var dest, serverName, alpn string
					if len(parts) >= 4 {
						// Legacy 4-part key: extract dest from first segment
						dest = parts[0]
						serverName = parts[1]
						alpn = parts[2]
					} else if len(parts) >= 3 {
						// New 3-part key: dest not in key, use serverName as dest
						serverName = parts[0]
						alpn = parts[2]
						dest = serverName
					} else {
						return
					}
					if serverName == "" || dest == "" {
						return
					}

					alpnIndex := alpnToInt(alpn)

					profileKey := CacheKey(serverName, alpn, VersionTLS13)
					globalCacheManager.DoProbe(profileKey, func() (*RealityProfile, error) {
						return probeTargetRaw(dest, serverName, alpnIndex)
					})
				}(key)
			}
			wg.Wait()
		}()
	})
}
