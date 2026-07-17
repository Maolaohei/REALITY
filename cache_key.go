package reality

import (
	"strconv"
	"strings"
)

// CacheKey constructs a legacy cache key from connection parameters.
// Format: "serverName|alpn|tlsVersion"
// Kept for backward compatibility with existing tests and disk profiles.
func CacheKey(serverName, alpn string, tlsVersion uint16) string {
	var b strings.Builder
	// Typical SNI + alpn + version hex fits well under 96B.
	b.Grow(len(serverName) + len(alpn) + 10)
	b.WriteString(serverName)
	b.WriteByte('|')
	b.WriteString(alpn)
	b.WriteByte('|')
	writeUint16Hex(&b, tlsVersion)
	return b.String()
}

// CacheKeyV2 constructs a full amortize cache key.
// Format: "dest|serverName|alpn|tlsVersion|chClass"
func CacheKeyV2(dest, serverName, alpn string, tlsVersion uint16, chClass string) string {
	if chClass == "" {
		chClass = "-"
	}
	var b strings.Builder
	b.Grow(len(dest) + len(serverName) + len(alpn) + len(chClass) + 16)
	b.WriteString(dest)
	b.WriteByte('|')
	b.WriteString(serverName)
	b.WriteByte('|')
	b.WriteString(alpn)
	b.WriteByte('|')
	writeUint16Hex(&b, tlsVersion)
	b.WriteByte('|')
	b.WriteString(chClass)
	return b.String()
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
	var b strings.Builder
	b.Grow(6)
	writeUint16Hex(&b, v)
	return b.String()
}

// writeUint16Hex appends "0x" + lowercase hex without leading zeros (matches strconv.FormatUint).
func writeUint16Hex(b *strings.Builder, v uint16) {
	b.WriteByte('0')
	b.WriteByte('x')
	if v == 0 {
		b.WriteByte('0')
		return
	}
	const hexdigits = "0123456789abcdef"
	// TLS versions are small (0x0303/0x0304); emit without left padding.
	started := false
	for shift := 12; shift >= 0; shift -= 4 {
		nibble := byte((v >> shift) & 0xf)
		if !started {
			if nibble == 0 {
				continue
			}
			started = true
		}
		b.WriteByte(hexdigits[nibble])
	}
}

func hexToUint16(s string) uint16 {
	s = trimPrefix(s, "0x")
	v, _ := strconv.ParseUint(s, 16, 16)
	return uint16(v)
}

func splitKey(s string) []string {
	// V2 keys have 5 fields; legacy has <=3. Fixed buffer avoids growable appends.
	var buf [5]string
	n := 0
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			if n < len(buf) {
				buf[n] = s[start:i]
				n++
			} else {
				// Rare malformed key with >4 separators: fall back to full split.
				parts := make([]string, 0, n+2)
				parts = append(parts, buf[:n]...)
				parts = append(parts, s[start:i])
				start = i + 1
				for j := i + 1; j < len(s); j++ {
					if s[j] == '|' {
						parts = append(parts, s[start:j])
						start = j + 1
					}
				}
				parts = append(parts, s[start:])
				return parts
			}
			start = i + 1
		}
	}
	if n < len(buf) {
		buf[n] = s[start:]
		n++
		return buf[:n]
	}
	parts := make([]string, 0, n+1)
	parts = append(parts, buf[:n]...)
	parts = append(parts, s[start:])
	return parts
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// isSoftCacheKey reports whether a V2 key's chClass is a soft dual-key class (A5).
func isSoftCacheKey(key string) bool {
	// V2 keys have exactly 4 separators; soft class is the last field and starts with "s:".
	if strings.Count(key, "|") < 4 {
		return false
	}
	idx := strings.LastIndexByte(key, '|')
	if idx < 0 || idx+1 >= len(key) {
		return false
	}
	ch := key[idx+1:]
	return len(ch) >= 2 && ch[0] == 's' && ch[1] == ':'
}
