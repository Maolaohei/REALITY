package reality

import (
	"strconv"
	"strings"
)

// CacheKey constructs a legacy cache key from connection parameters.
// Format: "serverName|alpn|tlsVersion"
// Kept for backward compatibility with existing tests and disk profiles.
func CacheKey(serverName, alpn string, tlsVersion uint16) string {
	return serverName + "|" + alpn + "|" + uint16ToHex(tlsVersion)
}

// CacheKeyV2 constructs a full amortize cache key.
// Format: "dest|serverName|alpn|tlsVersion|chClass"
func CacheKeyV2(dest, serverName, alpn string, tlsVersion uint16, chClass string) string {
	if chClass == "" {
		chClass = "-"
	}
	return dest + "|" + serverName + "|" + alpn + "|" + uint16ToHex(tlsVersion) + "|" + chClass
}

// CacheKeyFromProfile constructs a cache key from a RealityProfile.
// Prefer V2 when Dest/CHClass are present.
func CacheKeyFromProfile(serverName string, p *RealityProfile) string {
	if p == nil {
		return CacheKey(serverName, "", VersionTLS13)
	}
	if p.Dest != "" || p.CHClass != "" {
		sn := serverName
		if p.ServerName != "" {
			sn = p.ServerName
		}
		return CacheKeyV2(p.Dest, sn, p.ALPN, p.TLSVersion, p.CHClass)
	}
	return CacheKey(serverName, p.ALPN, p.TLSVersion)
}

// ParseCacheKey extracts components from a cache key (legacy or V2).
func ParseCacheKey(key string) (serverName, alpn string, tlsVersion uint16) {
	parts := splitKey(key)
	// V2: dest|serverName|alpn|tlsVersion|chClass
	if len(parts) >= 5 {
		serverName = parts[1]
		alpn = parts[2]
		tlsVersion = hexToUint16(parts[3])
		return
	}
	// Format: "serverName|alpn|0x0303"
	if len(parts) >= 3 {
		serverName = parts[0]
		alpn = parts[1]
		tlsVersion = hexToUint16(parts[2])
	} else if len(parts) == 2 {
		serverName = parts[0]
		alpn = parts[1]
		tlsVersion = VersionTLS13 // default
	} else if len(parts) == 1 {
		serverName = parts[0]
		tlsVersion = VersionTLS13
	}
	return
}

// ParseCacheKeyV2 extracts V2 components when present.
func ParseCacheKeyV2(key string) (dest, serverName, alpn string, tlsVersion uint16, chClass string, ok bool) {
	parts := splitKey(key)
	if len(parts) >= 5 {
		return parts[0], parts[1], parts[2], hexToUint16(parts[3]), parts[4], true
	}
	return "", "", "", 0, "", false
}

// IsLegacyCacheKey reports whether key is pre-V2 (no dest/chClass).
func IsLegacyCacheKey(key string) bool {
	return strings.Count(key, "|") < 4
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
