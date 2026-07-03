package reality

import "strconv"

// CacheKey constructs a cache key from connection parameters.
// Format: "serverName|alpn|tlsVersion"
// TLS version ensures different profiles for TLS 1.2 vs 1.3.
func CacheKey(serverName, alpn string, tlsVersion uint16) string {
	return serverName + "|" + alpn + "|" + uint16ToHex(tlsVersion)
}

// CacheKeyFromProfile constructs a cache key from a RealityProfile.
func CacheKeyFromProfile(serverName string, p *RealityProfile) string {
	return serverName + "|" + p.ALPN + "|" + uint16ToHex(p.TLSVersion)
}

// ParseCacheKey extracts components from a cache key.
// Supports both new format "serverName|alpn|0x0303" and legacy "dest|serverName|alpn|0x0303".
func ParseCacheKey(key string) (serverName, alpn string, tlsVersion uint16) {
	parts := splitKey(key)
	if len(parts) >= 4 {
		// Legacy format: "dest|serverName|alpn|tlsVersion"
		serverName = parts[1]
		alpn = parts[2]
		tlsVersion = hexToUint16(parts[3])
	} else if len(parts) == 3 {
		// New format: "serverName|alpn|tlsVersion"
		serverName = parts[0]
		alpn = parts[1]
		tlsVersion = hexToUint16(parts[2])
	} else if len(parts) == 2 {
		serverName = parts[0]
		alpn = parts[1]
		tlsVersion = VersionTLS13
	}
	return
}

func uint16ToHex(v uint16) string {
	return "0x" + strconv.FormatUint(uint64(v), 16)
}

func hexToUint16(s string) uint16 {
	s = trimPrefix(s, "0x")
	v, _ := strconv.ParseUint(s, 16, 16)
	return uint16(v)
}

func splitKey(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
