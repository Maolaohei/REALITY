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
		CertMeta:     CloneDestCertMeta(result.CertMeta),
		Source:       "probe",
		Evidence:     0,
		LiveEvidence: 0,
		CHClassVer:   CHClassVersion,
	}, nil
}

// ============================================================================
// Auto-start infrastructure
// ============================================================================

var (
	probeOnces sync.Map
	warmupDirs sync.Map // per-dir dedup so WarmupProfiles can run for different dirs
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
		// Don't register target here ?serverName/ALPN are unknown at this
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
		RecordMode:   InferRecordMode(result.RecordLens),
		Dest:         dest,
		ServerName:   serverName,
		Source:       "probe",
		Evidence:     0,
		LiveEvidence: 0,
		CHClassVer:   CHClassVersion,
		CertMeta:     CloneDestCertMeta(result.CertMeta),
	}, nil
}

func WarmupProfiles(dir string) {
	// Per-directory dedup: each dir gets one warmup pass, resettable for tests.
	if _, loaded := warmupDirs.LoadOrStore(dir, struct{}{}); loaded {
		return
	}
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

				// Parse cache key. Supports both legacy (3 parts: serverName|alpn|ver)
				// and V2 (5 parts: dest|serverName|alpn|ver|chClass) formats.
				parts := strings.SplitN(k, "|", 5)
				var dest, serverName, alpnStr string
				if len(parts) >= 5 {
					dest = parts[0]
					serverName = parts[1]
					alpnStr = parts[2]
				} else if len(parts) >= 3 {
					// Legacy key: serverName|alpn|ver -- dest unknown, skip.
					return
				} else {
					return
				}
				if dest == "" {
					return
				}

				alpnIndex := alpnToInt(alpnStr)

				profileKey := k // reuse the original V2 key for DoProbe lookup
				globalCacheManager.DoProbe(profileKey, func() (*RealityProfile, error) {
					return probeTargetRaw(dest, serverName, alpnIndex)
				})
			}(key)
		}
		wg.Wait()
	}()
}

// ResetWarmupForTesting clears the warmup dedup map so WarmupProfiles can
// be called again in subsequent test runs. Only for use in tests.
func ResetWarmupForTesting() {
	warmupDirs.Range(func(key, _ any) bool {
		warmupDirs.Delete(key)
		return true
	})
}
