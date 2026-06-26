package reality

import "strconv"

// CacheKey constructs a cache key from connection parameters.
// Format: "dest|serverName|alpn|tlsVersion"
// TLS version ensures different profiles for TLS 1.2 vs 1.3.
func CacheKey(dest, serverName, alpn string, tlsVersion uint16) string {
	return dest + "|" + serverName + "|" + alpn + "|" + uint16ToHex(tlsVersion)
}

// CacheKeyFromProfile constructs a cache key from a RealityProfile.
func CacheKeyFromProfile(dest, serverName string, p *RealityProfile) string {
	return dest + "|" + serverName + "|" + p.ALPN + "|" + uint16ToHex(p.TLSVersion)
}

// ParseCacheKey extracts components from a cache key.
func ParseCacheKey(key string) (dest, serverName, alpn string, tlsVersion uint16) {
	// Format: "dest|serverName|alpn|0x0303"
	parts := splitKey(key)
	if len(parts) >= 4 {
		dest = parts[0]
		serverName = parts[1]
		alpn = parts[2]
		tlsVersion = hexToUint16(parts[3])
	} else if len(parts) == 3 {
		// Legacy format without TLS version.
		dest = parts[0]
		serverName = parts[1]
		alpn = parts[2]
		tlsVersion = VersionTLS13 // default
	} else if len(parts) == 2 {
		dest = parts[0]
		serverName = parts[1]
		tlsVersion = VersionTLS13
	}
	return
}

// DestFromKey extracts just the dest from a cache key.
func DestFromKey(key string) string {
	if idx := indexOf(key, '|'); idx > 0 {
		return key[:idx]
	}
	return key
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

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
