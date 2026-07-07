package reality

import (
	"context"
	"strings"
	"sync"
	"time"
)

// ProbeTarget connects to the target server using a real uTLS ClientHello,
// captures its TLS record lengths, and returns a RealityProfile.
func ProbeTarget(ctx context.Context, config *Config) (*RealityProfile, error) {
	result, err := ProbeTargetViaUTLS(ctx, config.Dest, config.Dest, 2, config.Xver)
	if err != nil {
		return nil, err
	}

	alpn := intToALPN(2)
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

func StopAutoProbe(dest string) {
	if globalRefreshManager != nil {
		globalRefreshManager.RemoveTarget(dest, "", "")
	}
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

					// Parse dest, serverName, alpn from cache key.
					// Format: "dest|serverName|alpn|0x0303"
					parts := strings.SplitN(k, "|", 4)
					if len(parts) < 3 {
						return
					}
					dest := parts[0]
					serverName := parts[1]
					if dest == "" {
						return
					}

					alpnIndex := alpnToInt(parts[2])

					profileKey := CacheKey(serverName, parts[2], VersionTLS13)
					globalCacheManager.DoProbe(profileKey, func() (*RealityProfile, error) {
						return probeTargetRaw(dest, serverName, alpnIndex)
					})
				}(key)
			}
			wg.Wait()
		}()
	})
}
