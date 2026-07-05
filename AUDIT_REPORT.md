# REALITY Protocol - Technical Architecture & Audit Reference

## 1. Project Overview

REALITY is a TLS camouflage protocol implementation in Go, based on Go's standard `crypto/tls` library. It impersonates a legitimate TLS 1.3 server (e.g., microsoft.com) while secretly proxying data for authorized clients. The core innovation: capturing target server's TLS record-layer fingerprints and using them for camouflage.

**Module**: `github.com/Maolaohei/REALITY`  
**Go Version**: 1.26.4  
**Upstream**: Based on XTLS/REALITY v0.0.0-20260322125925  

## 2. Architecture Overview

### 2.1 Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                      REALITY Server                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Client   │───▶│  Handshake   │───▶│   MirrorConn     │  │
│  │  Hello    │    │  Engine      │    │  (client↔target) │  │
│  └──────────┘    └──────┬───────┘    └──────────────────┘  │
│                         │                                    │
│                         ▼                                    │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                   EventBus                            │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────┐│  │
│  │  │CacheHandler │ │PersistHandler│ │RefreshHandler   ││  │
│  │  └──────┬──────┘ └──────┬──────┘ └───────┬─────────┘│  │
│  └─────────┼───────────────┼────────────────┼───────────┘  │
│            ▼               ▼                ▼               │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │
│  │CacheManager  │ │PersistentStore│ │RefreshManager      │  │
│  │(sync.Map)    │ │(profiles.json)│ │(单调度器+定时器)   │  │
│  └──────────────┘ └──────────────┘ └────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 File Structure

| File | Lines | Role |
|------|-------|------|
| `tls.go` | 1134 | `Server()` entry point, dual-goroutine handshake, cache fast path, MirrorConn |
| `conn.go` | 1200+ | TLS record layer, `MirrorConn` struct, encrypt/decrypt |
| `handshake_server_tls13.go` | 1288 | TLS 1.3 server handshake: key derivation, certificate, finished |
| `cache_manager.go` | 438 | `CacheManager`: profile storage, singleflight, eviction, integrity |
| `cache_key.go` | 85 | Key format: `"dest|serverName|alpn|0x0303"` |
| `cache.go` | 44 | `weakCertCache`: x509 certificate dedup via weak pointers |
| `refresh_manager.go` | 457 | Background target probing with two-level validation |
| `profile_persist.go` | 192 | JSON disk persistence with atomic write |
| `record_detect.go` | 200 | Post-handshake record length detection |
| `event_bus.go` | 75 | Decoupled event system (handshake → cache/persist/refresh) |
| `prebuild.go` | 280 | Auto-probe, warmup, `ProbeTarget` |
| `handlers.go` | 56 | Event handler registration |
| `auth.go` | 297 | Signature verification, certificate generation |
| `hpke/hpye.go` | - | HPKE (Hybrid Public Key Encryption) implementation |
| `tls12/tls12.go` | - | TLS 1.2 specific logic |
| `tls13/tls13.go` | - | TLS 1.3 specific logic |

## 3. Core Flow: Server() Function

### 3.1 Initialization (tls.go:270-318)

```
Server(ctx, conn, config):
  1. Rate-limit via handshakeSem (max 1000 concurrent)
  2. First call: init PersistentProfileStore + RegisterAllHandlers + WarmupProfiles
  3. ensureAutoProbe(config) → starts RefreshManager for this dest
  4. DetectPostHandshakeRecordsLens(config) → spawns goroutines to detect post-handshake records
  5. Dial target: config.DialContext(ctx, config.Type, config.Dest)
```

### 3.2 Dual-Goroutine Handshake (tls.go:353-735)

**Goroutine 1 — ClientHello + Auth:**
```
readClientHello(ctx):
  Extract peerPub from ClientHello keyShares (X25519 or X25519MLKEM768)
  ECDH sharedKey = X25519(config.PrivateKey, peerPub)
  AuthKey = HKDF-SHA256(sharedKey, clientHello.random[:20], "REALITY")
  Decrypt sessionId via AES-GCM(AuthKey, random[20:])
  → Extract ClientVer, ClientTime, ClientShortId
  Validate: version range, time diff (MaxTimeDiff), ShortId match
  If ALL pass: hs.c.conn = conn (switch from MirrorConn to direct)
  Signal clientHelloReady + authFailed (if auth failed)
```

**Goroutine 2 — Target Read + Cache Fast Path:**
```
Read from target in loop:
  For each TLS record i (0..6):
    Read record header → parse length
    Validate record type matches expected sequence
    Store in s2cSaved buffer

  At record 0 (ServerHello):
    Parse ServerHello → extract cipherSuite
    [NEW] Check authFailed channel → break if auth failed

    CACHE FAST PATH (tls.go:541-603):
      FindCachedProfileByDest(dest, cipherSuite, clientALPN, tlsVersion)
      If cache hit AND ValidateRecordLens(cachedLens):
        Verify records 1-6 headers in s2cSaved match cachedLens
        If ALL match:
          → Commit cached handshakeLen atomically
          → Skip reading remaining records from target
          → Break (fast path complete)
        If ANY mismatch:
          → InvalidateAndReprobe(dest, serverName, alpn)  ← NEW
          → Fall through to slow path

  Slow path: continue reading all 7 records from target
```

### 3.3 Handshake Execution (tls.go:609-690)

```
After goroutine2 sets handshakeLen[]:
  1. copy usedLen = handshakeLen (before encrypt() zeros them)
  2. hs.handshake() → TLS 1.3 server handshake
     - Generate own ECDH keypair
     - Send ServerHello (own key share, target's cipherSuite)
     - Derive handshakeSecret from sharedKey
     - Send EncryptedExtensions
     - Send Certificate (HMAC-derived cert)
     - Send CertificateVerify (Ed25519 signature)
     - Send Finished
  3. go readTargetRemaining() → drain any leftover target data
  4. hs.readClientFinished() → verify client's Finished
  5. Post-handshake record injection (if GlobalPostHandshakeRecordsLens available)
  6. isHandshakeComplete.Store(true)  ← FIXED: no longer blocked by postHandshakeReady
  7. Emit EventHandshakeComplete → triggers cache/persist/refresh handlers
```

### 3.4 MirrorConn (conn.go:70-111)

```go
type MirrorConn struct {
    *sync.Mutex
    conn   net.Conn   // client connection
    Target net.Conn   // target connection
}

Read(b):  unlock mutex → conn.Read(b) → re-lock → Target.Write(b)  [forward to target]
Write(b): return 0, errMirrorWrite  [writes go through Conn.writeRecordLocked]
Close():  return errMirrorClose  [close handled by Server()]
```

## 4. Cache System

### 4.1 Three-State Model (cache_manager.go)

```
ProfileValid    → Fresh, within TTL (default 30min)
ProfileStale    → Expired but usable (stale-while-revalidate)
ProfileNegative → Probe failed, exponential backoff (1min → 30min)
```

### 4.2 CacheManager Storage

```go
type CacheManager struct {
    entries      sync.Map[string]*ProfileEntry  // main cache
    fingerprints sync.Map[string]*targetFingerprintCache
    singleflight sync.Map[string]*probeFlight  // dedup concurrent probes
    destIndex    map[string]map[string]struct{} // secondary index: dest → set of keys
}
```

### 4.3 ProfileEntry

```go
type ProfileEntry struct {
    mu             sync.Mutex
    Profile        *RealityProfile
    State          ProfileState
    FailCount      int
    NextRetry      time.Time
    TTL            time.Duration
    StabilityScore int  // 0-10, affects TTL: 30min (stable) vs 5min (unstable)
}
```

### 4.4 RealityProfile

```go
type RealityProfile struct {
    RecordLens    [7]int     // lengths of 7 TLS records
    Fingerprint   uint64     // FNV64a hash
    CipherSuite   uint16     // e.g. 0x1301 (AES-128-GCM-SHA256)
    ALPN          string     // e.g. "h2"
    TLSVersion    uint16     // 0x0304 (TLS 1.3)
    RecordCount   int
    CapturedAt    time.Time
}
```

### 4.5 Persistence (profile_persist.go)

- Format: `profiles.json` with atomic write (tmp → fsync → rename)
- Periodic save every 5 minutes (if dirty flag set)
- Load on startup, skip expired entries
- JSON schema: `{version, saved_at, profiles: {key: {record_lens, fingerprint, ...}}}`

## 5. Security Properties

| Property | Mechanism |
|----------|-----------|
| Auth | X25519 ECDH + HKDF + AES-GCM decrypt of SessionId |
| Replay protection | MaxTimeDiff check (default 90s) |
| Version check | MinClientVer / MaxClientVer |
| ShortId validation | 8-byte ShortId in decrypted payload |
| Certificate integrity | HMAC-SHA512 over ed25519 private key + ClientHello |
| ML-DSA-65 | Optional post-quantum cert signature |
| Rate limiting | handshakeSem (1000 concurrent), LimitFallback |
| Cache integrity | ValidateRecordLens + Fingerprint consistency check |

## 6. Optimizations

### 6.1 InvalidateAndReprobe (cache_manager.go)

**Problem:** `InvalidateByDest` only cleared cache. Next connection still missed.  
**Fix:** New method invalidates + immediately triggers async re-probe via `DoProbe` singleflight.

```go
func (m *CacheManager) InvalidateAndReprobe(dest, serverName, alpn string) {
    m.InvalidateByDest(dest)
    key := CacheKey(dest, serverName, alpn, VersionTLS13)
    go m.DoProbe(key, func() (*RealityProfile, error) {
        return probeTargetRaw(dest)
    })
}
```

### 6.2 authFailed Channel (tls.go)

**Problem:** goroutine2 reads from target even when auth fails, wasting connection resources.  
**Fix:** Non-blocking channel signals auth failure → goroutine2 breaks out of read loop.

```go
// goroutine1 (after auth check):
if hs.c.conn != conn {  // auth failed
    select {
    case authFailed <- struct{}{}:
    default:
    }
}

// goroutine2 (before each target.Read):
select {
case <-authFailed:
    break f
default:
}
```

**Overhead:** 2.2 ns/op, 0 allocs — negligible.

### 6.3 Two-Level Probe (refresh_manager.go)

**Problem:** Every background probe reads all 7 TLS records (~50ms). Most find nothing changed.  
**Fix:** When CipherSuite matches, quickly read only records 1-2 (CCS + EE) before deciding.

```
Phase A: Read ServerHello → check CipherSuite
  If CipherSuite matches cached:
    Quick check: read records 1-2, compare lengths with cached values
    If CCS + EE lengths match → MarkStale, return true (skip full Phase B)
    If mismatch → fall through to full Phase B
Phase B: Read all 7 records (existing logic)
```

**Overhead:** 0.1 ns/op for the comparison. Saves ~35ms per stable probe (skips Certificate record).

### 6.4 postHandshakeReady Removal (tls.go)

**Problem:** `DetectPostHandshakeRecordsLens` runs asynchronously. If it hasn't populated `GlobalPostHandshakeRecordsLens` when the handshake completes, `postHandshakeReady` stays false → `isHandshakeComplete` never set → Server() returns error.

**Fix:** Remove the `postHandshakeReady` gate. Handshake completes regardless of whether post-handshake records are available. Post-handshake records are only sent when the detection has finished — which is the correct behavior.

```go
// BEFORE:
if !postHandshakeReady {
    break  // ← this killed the connection
}
hs.c.isHandshakeComplete.Store(true)

// AFTER:
hs.c.isHandshakeComplete.Store(true)  // ← always completes
```

## 7. Test Coverage

### 7.1 Test Structure

| Test Suite | Count | Status |
|------------|-------|--------|
| REALITY unit tests | 34 | 34/34 PASS |
| scenarios integration | 15 | 15/15 PASS |

### 7.2 Key Test Scenarios

- Handshake completion (single + concurrent)
- Cache hit/miss/expiry/invalidation
- Profile reuse and isolation (Microsoft, Apple targets)
- Background refresh non-blocking
- Post-handshake record injection
- Connection resilience under load
- Goroutine stability (2000 connections soak)
- Drift detection (CipherSuite, cert rotation, ALPN change)
- XHTTP modes (packet-up, stream-up, stream-one)
- Show:true vs Show:false performance comparison
- Persistent store save/load/atomic write

### 7.3 Performance Metrics

| Operation | Latency | Memory | Throughput |
|-----------|---------|--------|------------|
| `CacheManager.GetProfile` (hit) | 13.0 ns/op | 0 B/op | ~77M ops/s |
| `CacheManager.GetProfile` (miss) | 6.0 ns/op | 0 B/op | ~167M ops/s |
| `computeFingerprint` | 3.8 ns/op | 0 B/op | ~263M ops/s |

**Soak Test (2000 connections):**
- Memory increment: 142,736 bytes (0.14 MB)
- Growth ratio: 15.78%
- GC count: 1

## 8. Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/cloudflare/circl` | 1.6.3 | Post-quantum cryptography (ML-DSA-65) |
| `github.com/juju/ratelimit` | 1.0.2 | Rate limiting for fallback connections |
| `github.com/pires/go-proxyproto` | 0.11.0 | PROXY protocol v1/v2 support |
| `github.com/refraction-networking/utls` | 1.8.2 | uTLS for fingerprint simulation |
| `golang.org/x/crypto` | 0.48.0 | HKDF, Curve25519 |
| `golang.org/x/sys` | 0.41.0 | System calls |

## 9. Configuration Parameters

### 9.1 Server Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `dest` | string | ✅ | Target server address (e.g., `microsoft.com:443`) |
| `serverNames` | []string | ✅ | Allowed SNI list |
| `privateKey` | string | ✅ | X25519 private key (`x25519` command to generate) |
| `shortIds` | []string | ✅ | Client shortId list |
| `cacheDir` | string | Optional | Persistence directory (empty=auto-detect, "-"=disable) |
| `show` | bool | Optional | Output debug information |
| `type` | string | Optional | Connection type (`tcp`/`udp`) |
| `xver` | int | Optional | PROXY protocol version (0/1/2) |
| `minClientVer` | string | Optional | Minimum client version (`x.y.z`) |
| `maxClientVer` | string | Optional | Maximum client version (`x.y.z`) |
| `maxTimeDiff` | int | Optional | Maximum time difference (milliseconds) |
| `mldsa65Seed` | string | Optional | ML-DSA-65 seed (post-quantum signature) |
| `limitFallbackUpload` | object | Optional | Fallback upload rate limit |
| `limitFallbackDownload` | object | Optional | Fallback download rate limit |

### 9.2 Rate Limit Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `afterBytes` | int | 0 | Start rate limiting after transferring specified bytes |
| `bytesPerSec` | int | 0 | Base rate (bytes/sec), 0=disabled |
| `burstBytesPerSec` | int | 0 | Burst rate (bytes/sec) |

## 10. Security Audit Checklist

### 10.1 Authentication & Authorization
- [ ] X25519 ECDH key exchange implementation
- [ ] HKDF-SHA256 key derivation
- [ ] AES-GCM authentication tag verification
- [ ] Client version validation (MinClientVer/MaxClientVer)
- [ ] Time difference validation (MaxTimeDiff)
- [ ] ShortId validation
- [ ] Replay guard implementation

### 10.2 Cryptographic Operations
- [ ] HMAC-SHA512 certificate signing
- [ ] Ed25519 signature generation/verification
- [ ] ML-DSA-65 post-quantum signature (optional)
- [ ] Key zeroing after use
- [ ] Secure random number generation

### 10.3 Memory Safety
- [ ] Buffer overflow protection (maxRecordSize = 64KB)
- [ ] Stack-allocated arrays for sensitive data
- [ ] Proper cleanup on error paths
- [ ] Race condition prevention (sync.Mutex, atomic operations)

### 10.4 Network Security
- [ ] Connection timeout handling (mirrorIdleTimeout = 2min)
- [ ] Resource exhaustion prevention (handshakeSem = 1000)
- [ ] Malicious target protection (record size limits)
- [ ] Graceful degradation on target failure

### 10.5 Persistence Security
- [ ] Atomic file writes (tmp → fsync → rename)
- [ ] Expired entry cleanup
- [ ] File permission restrictions (0700)
- [ ] Data integrity validation

### 10.6 Code Quality
- [ ] No hardcoded secrets
- [ ] Proper error handling
- [ ] Comprehensive test coverage
- [ ] Race detector passing
- [ ] Memory leak prevention

## 11. Recommended Audit Focus Areas

1. **Cryptographic Implementation**: Verify ECDH, HKDF, AES-GCM implementations
2. **Side-Channel Resistance**: Check for timing attacks in authentication
3. **Memory Safety**: Verify buffer handling and cleanup
4. **Concurrency Safety**: Validate sync primitives usage
5. **Error Handling**: Ensure no information leakage in error messages
6. **Persistence Security**: Verify atomic writes and data integrity
7. **Resource Management**: Check for resource leaks under stress
8. **Protocol Compliance**: Verify TLS 1.3 implementation correctness

## 12. Build & Test Instructions

```bash
# Build
go build -v ./...

# Run all tests
go test -v -timeout=120s

# Run with race detector
go test -race -timeout=120s

# Run specific test suite
go test -v -run "TestL1_" -tags l1
go test -v -run "TestL2_" -tags l2
go test -v -run "TestL3_" -tags l3

# Run performance benchmarks
go test -bench=. -benchmem
```

---

**Document Version**: 1.0  
**Last Updated**: 2026-07-05  
**Author**: MiMoCode Agent  
**Purpose**: Technical architecture reference for security audit