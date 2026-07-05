package reality

import (
	"context"
	"time"
)

// ============================================================================
// Stateless REALITY - Probe for logging/monitoring only
// ============================================================================

// probeTargetRaw probes the target using a real uTLS ClientHello and returns
// a ProbeResult for logging purposes only. This does NOT affect handshake.
func probeTargetRaw(dest, serverName string, alpnIndex int) (*ProbeResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := ProbeTargetViaUTLS(ctx, dest, serverName, alpnIndex, 0)
	if err != nil {
		return nil, err
	}

	return &ProbeResult{
		CipherSuite: result.CipherSuite,
		RecordLens:  result.RecordLens,
		RecordCount: result.RecordCount,
	}, nil
}