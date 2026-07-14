package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)


// detectOnceConfigs tracks which dests have already had detection launched.
// Each dest gets exactly one DetectPostHandshakeRecordsLens goroutine.
var detectOnceConfigs sync.Map // map[string]struct{} keyed by dest

// triggerDetectPostHandshake ensures detection runs at most once per dest.
func triggerDetectPostHandshake(config *Config) {
	if config.Dest == "" {
		return
	}
	if _, loaded := detectOnceConfigs.LoadOrStore(config.Dest, struct{}{}); !loaded {
		// First time seeing this dest ?launch detection in background.
		go DetectPostHandshakeRecordsLens(config)
	}
}

// Server establishes a REALITY camouflage TLS connection as the server side.
//
// Amortize paths:
//   - L0: dial RA, read full R0-R6
//   - L1: dial RA, live R0, cached R1-R6 (default)
//   - L2: zero-dial when evidence-rich policy matches ClientHello class
//
// Auth always runs first. Unauthenticated traffic is never served from cache;
// it dials RA and mirrors after replaying the original ClientHello record.
func Server(ctx context.Context, conn net.Conn, config *Config) (*Conn, error) {
	select {
	case handshakeSem <- struct{}{}:
		defer func() { <-handshakeSem }()
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}

	if config.MaxTimeDiff == 0 {
		maxTimeDiffWarnOnce.Do(func() {
			fmt.Println("REALITY WARNING: MaxTimeDiff not configured, defaulting to 90s. Set MaxTimeDiff=-1 to disable or MaxTimeDiff=<duration> to set explicitly.")
		})
	}

	remoteAddr := conn.RemoteAddr().String()
	show := config.Show
	if show {
		fmt.Printf("REALITY remoteAddr: %v\n", remoteAddr)
	}

	initServerSideOnce(config, show)
	ensureAutoProbe(config)
	triggerDetectPostHandshake(config)

	raw := conn
	if pc, ok := conn.(*proxyproto.Conn); ok {
		raw = pc.Raw()
	}
	underlying, _ := raw.(CloseWriteConn)

	hs := serverHandshakeStateTLS13{
		c: &Conn{
			conn:   conn,
			config: config,
		},
		ctx: ctx,
	}

	// --- Phase 1: read ClientHello (no RA dial yet) ---
	var err error
	hs.clientHello, _, err = hs.c.readClientHello(context.Background())
	if err != nil || hs.c.vers != VersionTLS13 || hs.clientHello == nil || !config.ServerNames[hs.clientHello.serverName] {
		// Still try to look like the real site if possible.
		return mirrorAfterFailedAuth(ctx, conn, underlying, config, hs.clientHello, remoteAddr, show,
			"failed to read client hello or unsupported version/sni")
	}

	// --- Phase 2: REALITY auth ---
	authed := authenticateClientHello(hs.c, hs.clientHello, config, show, remoteAddr)
	if show {
		fmt.Printf("REALITY remoteAddr: %v\tauthenticated: %v\n", remoteAddr, authed)
	}
	if !authed {
		return mirrorAfterFailedAuth(ctx, conn, underlying, config, hs.clientHello, remoteAddr, show,
			"authentication failed or validation criteria not met")
	}

	// --- Phase 3: path selection ---
	alpn := clientALPN(hs.clientHello)
	chClass := ClassifyClientHello(hs.clientHello)
	mode := ResolveAmortizeMode(config.AmortizeMode)

	// Unsuitable dest: mirror even after auth (anti-probe; no synthetic TLS1.3 success).
	if DestShouldMirrorOnly(config.Dest) {
		if show {
			fmt.Printf("REALITY remoteAddr: %v\tdest unsuitable ? mirror only\n", remoteAddr)
		}
		return mirrorAfterFailedAuth(ctx, conn, underlying, config, hs.clientHello, remoteAddr, show,
			"dest unsuitable for REALITY success path")
	}
	// Offline / unsuitable force no amortize (L0 only if we continue ? here offline also mirrors).
	if !DestAllowsAmortize(config.Dest) {
		mode = AmortizeL0
		if show {
			fmt.Printf("REALITY remoteAddr: %v\tdest capability blocks amortize (force L0)\n", remoteAddr)
		}
	}

	// Pre-lookup without live cipher (for L2 eligibility).
	pre := globalCacheManager.LookupAmortize(mode, config.Dest, hs.clientHello.serverName, alpn, VersionTLS13, chClass, 0, 0)
	path := pre.Path
	profileKey := pre.Key
	if profileKey == "" {
		profileKey = CacheKeyV2(config.Dest, hs.clientHello.serverName, alpn, VersionTLS13, chClass)
	}

	// Validate L2 against this ClientHello before committing.
	if path == PathL2 && pre.Profile != nil {
		if !clientOffersCipher(hs.clientHello, pre.Profile.CipherSuite) ||
			!clientHasKeyShare(hs.clientHello, pre.Profile.KeyShareGroup) ||
			pre.Profile.AcceptsHRR {
			path = PathL1
			if show {
				fmt.Printf("REALITY remoteAddr: %v\tL2 downgraded: CH incompatible with policy\n", remoteAddr)
			}
		}
	} else if path == PathL2 {
		path = PathL0
	}

	if show {
		fmt.Printf("REALITY remoteAddr: %v\tpath=%s mode=%v chClass=%s evidence=%d\n",
			remoteAddr, path.String(), mode, chClass, profileEvidence(pre.Profile))
	}

	// --- Path L2: zero-dial ---
	// Important: L2 writes to the client. On failure after any write we must NOT
	// fall through into a live path on the same conn (would mix transcripts).
	if path == PathL2 {
		rc, err := runL2Handshake(&hs, pre.Profile, show, remoteAddr)
		if err != nil {
			globalCacheManager.NoteHandshakeFailure(profileKey, PathL2)
			if show {
				fmt.Printf("REALITY remoteAddr: %v\tL2 failed: %v\n", remoteAddr, err)
			}
			conn.Close()
			return nil, fmt.Errorf("REALITY: L2 amortize failed from %s: %v", remoteAddr, err)
		}
		emitHandshakeComplete(config, &hs, pre.Profile.RecordLens, chClass, alpn, PathL2, pre.Profile)
		return rc, nil
	}

	// --- Path L0/L1: dial RA and observe ---
	target, err := dialTarget(ctx, conn, config)
	if err != nil {
		NoteDestCaptureFailure(config.Dest, "dial")
		conn.Close()
		return nil, err
	}
	defer target.Close()

	// Replay original ClientHello to RA so it emits ServerHello...
	if hs.clientHello.original == nil {
		conn.Close()
		return nil, errors.New("REALITY: missing ClientHello original bytes")
	}
	chRecord := wrapHandshakeRecord(hs.clientHello.original, VersionTLS10)
	if err := WriteAll(target, chRecord); err != nil {
		conn.Close()
		return nil, errors.New("REALITY: failed to replay ClientHello to dest: " + err.Error())
	}

	usedLen, helloMsg, r0Template, capturedPath, err := captureTargetRecords(target, &hs, config, mode, chClass, alpn, show, remoteAddr)
	if err != nil || helloMsg == nil || usedLen[0] == 0 {
		// Mirror remaining like legacy failure path.
		NoteDestCaptureFailure(config.Dest, classifyCaptureError(err))
		if show {
			fmt.Printf("REALITY remoteAddr: %v\ttarget capture failed: %v\n", remoteAddr, err)
		}
		if underlying != nil {
			go func() { _, _ = io.Copy(target, NewRatelimitedConn(underlying, &config.LimitFallbackUpload)) }()
			_, _ = io.Copy(underlying, NewRatelimitedConn(target, &config.LimitFallbackDownload))
			underlying.CloseWrite()
		}
		conn.Close()
		return nil, fmt.Errorf("REALITY: processed invalid connection from %s: target sent incorrect server hello or handshake incomplete", remoteAddr)
	}
	if capturedPath != PathL0 && capturedPath != PathL1 {
		capturedPath = PathL0
	}
	path = capturedPath
	hs.hello = helloMsg

	// Copy lens into out halfConn for encrypt padding.
	copy(hs.c.out.handshakeLen[:], usedLen[:])
	// encrypt() zeros lens; keep a copy for observation/cache.
	var savedLen [7]int
	copy(savedLen[:], usedLen[:])
	if err := hs.handshake(); err != nil {
		globalCacheManager.NoteHandshakeFailure(profileKey, path)
		conn.Close()
		return nil, fmt.Errorf("REALITY: processed invalid connection from %s: %v", remoteAddr, err)
	}
	// Ensure camouflage length slots cannot affect post-handshake app-data records.
	for i := range hs.c.out.handshakeLen {
		hs.c.out.handshakeLen[i] = 0
	}
	hs.c.out.handshakeBuf = nil

	// Drain leftover target data in background (same as legacy).
	go func() {
		bufPtr := drainBufPool.Get().(*[]byte)
		defer drainBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			target.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := target.Read(buf); err != nil {
				return
			}
		}
	}()

	if err := hs.readClientFinished(); err != nil {
		globalCacheManager.NoteHandshakeFailure(profileKey, path)
		conn.Close()
		return nil, fmt.Errorf("REALITY: processed invalid connection from %s: %v", remoteAddr, err)
	}

	// post-handshake camouflage optional; disabled when empty/invalid (see injectPostHandshakeRecords)
	injectPostHandshakeRecords(&hs, config, show, remoteAddr)
	hs.c.isHandshakeComplete.Store(true)

	// Build observation profile for amortize.
	obs := buildObservationProfile(config, &hs, savedLen, chClass, alpn, r0Template, "live")
	NoteDestTLS13Ready(config.Dest)
	// Also store under legacy key for backward-compatible L1 hits.
	v2Key := CacheKeyV2(config.Dest, hs.clientHello.serverName, alpn, VersionTLS13, chClass)
	globalCacheManager.StoreObservation(v2Key, obs)
	// Legacy key for FindCachedProfileByDest / older L1 path.
	legacyKey := CacheKey(hs.clientHello.serverName, alpn, VersionTLS13)
	legacyObs := *obs
	legacyObs.ServerHelloTemplate = nil
	legacyObs.Evidence = 0 // never L2 via legacy key
	legacyObs.CHClass = ""
	if existing, _ := globalCacheManager.GetProfile(legacyKey); existing != nil {
		// refresh lens/cipher only
		legacyObs.Evidence = 0
		globalCacheManager.HotSwapProfile(legacyKey, &legacyObs)
	} else {
		globalCacheManager.StoreProfile(legacyKey, &legacyObs)
	}

	emitHandshakeComplete(config, &hs, savedLen, chClass, alpn, path, obs)
	if show {
		fmt.Printf("REALITY remoteAddr: %v\thandshake complete path=%s evidence=%d\n", remoteAddr, path.String(), obs.Evidence)
	}
	return hs.c, nil
}

func profileEvidence(p *RealityProfile) int {
	if p == nil {
		return 0
	}
	return p.Evidence
}

func initServerSideOnce(config *Config, show bool) {
	if profileStore == nil {
		cacheDir := config.CacheDir
		if cacheDir == "-" {
			cacheDir = ""
		}
		if cacheDir == "" {
			cacheDir = DefaultCacheDir()
		}
		if cacheDir != "" {
			store := InitPersistentStore(cacheDir)
			store.StartPeriodicSave(5 * time.Minute)
			RegisterAllHandlers(show)
			WarmupProfiles(cacheDir)
		}
	}
	// Replay guard init: use sync.Once to prevent concurrent creation races.
	window := config.MaxTimeDiff
	if window == 0 {
		window = 90 * time.Second
	}
	if window > 0 {
		InitGlobalReplayGuard(window)
	}
}

func dialTarget(ctx context.Context, client net.Conn, config *Config) (net.Conn, error) {
	target, err := config.DialContext(ctx, config.Type, config.Dest)
	if err != nil {
		return nil, errors.New("REALITY: failed to dial dest: " + err.Error())
	}
	if config.Xver == 1 || config.Xver == 2 {
		if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, client.RemoteAddr(), client.LocalAddr()).WriteTo(target); err != nil {
			target.Close()
			return nil, errors.New("REALITY: failed to send PROXY protocol: " + err.Error())
		}
	}
	return target, nil
}

func authenticateClientHello(c *Conn, ch *clientHelloMsg, config *Config, show bool, remoteAddr string) bool {
	var peerPub []byte
	for _, keyShare := range ch.keyShares {
		if keyShare.group == X25519 && len(keyShare.data) == 32 {
			peerPub = keyShare.data
			break
		}
	}
	if peerPub == nil {
		for _, keyShare := range ch.keyShares {
			if keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32 {
				peerPub = keyShare.data[mlkem.EncapsulationKeySize768:]
				break
			}
		}
	}
	if peerPub == nil {
		return false
	}

	var err error
	if c.AuthKey, err = curve25519.X25519(config.PrivateKey, peerPub); err != nil {
		return false
	}
	if _, err = hkdf.New(sha256.New, c.AuthKey, ch.random[:20], []byte("REALITY")).Read(c.AuthKey); err != nil {
		return false
	}
	block, _ := aes.NewCipher(c.AuthKey)
	aead, _ := cipher.NewGCM(block)
	if show {
		fmt.Printf("REALITY remoteAddr: %v\tAuthKey[:16]: %v\tAEAD: %T\n", remoteAddr, c.AuthKey[:16], aead)
	}

	var ctBuf, ptBuf [32]byte
	ciphertext := ctBuf[:]
	plainText := ptBuf[:]
	copy(ciphertext, ch.sessionId)
	copy(ch.sessionId, plainText) // sessionId aliases raw
	if _, err = aead.Open(plainText[:0], ch.random[20:], ciphertext, ch.original); err != nil {
		copy(ch.sessionId, ciphertext)
		return false
	}
	copy(ch.sessionId, ciphertext)
	copy(c.ClientVer[:], plainText)
	c.ClientTime = time.Unix(int64(binary.BigEndian.Uint32(plainText[4:])), 0)
	copy(c.ClientShortId[:], plainText[8:])
	if show {
		fmt.Printf("REALITY remoteAddr: %v\tClientVer: %v\n", remoteAddr, c.ClientVer)
		fmt.Printf("REALITY remoteAddr: %v\tClientTime: %v\n", remoteAddr, c.ClientTime)
		fmt.Printf("REALITY remoteAddr: %v\tClientShortId: %v\n", remoteAddr, c.ClientShortId)
	}

	maxTimeDiff := config.MaxTimeDiff
	if maxTimeDiff == 0 {
		maxTimeDiff = 90 * time.Second
	}
	if (config.MinClientVer != nil && bigEndianUint24(c.ClientVer[:]) < bigEndianUint24(config.MinClientVer)) ||
		(config.MaxClientVer != nil && bigEndianUint24(c.ClientVer[:]) > bigEndianUint24(config.MaxClientVer)) ||
		(maxTimeDiff >= 0 && time.Since(c.ClientTime).Abs() > maxTimeDiff) ||
		(!config.ShortIds[c.ClientShortId]) {
		return false
	}
	if globalReplayGuard != nil && !globalReplayGuard.CheckAndMark([20]byte(ch.random[:20])) {
		if show {
			fmt.Printf("REALITY remoteAddr: %v\treplay detected, rejecting\n", remoteAddr)
		}
		return false
	}
	return true
}

func mirrorAfterFailedAuth(ctx context.Context, conn net.Conn, underlying CloseWriteConn, config *Config, ch *clientHelloMsg, remoteAddr string, show bool, reason string) (*Conn, error) {
	target, err := dialTarget(ctx, conn, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Bound mirror lifetime so failed-auth paths cannot pin handshakeSem forever.
	deadline := time.Now().Add(8 * time.Second)
	_ = conn.SetDeadline(deadline)
	_ = target.SetDeadline(deadline)

	// Replay ClientHello if we have it.
	if ch != nil && ch.original != nil {
		_ = WriteAll(target, wrapHandshakeRecord(ch.original, VersionTLS10))
		if show {
			fmt.Printf("REALITY remoteAddr: %v\tforwarded SNI: %v\n", remoteAddr, ch.serverName)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		src := net.Conn(conn)
		if underlying != nil {
			if config.LimitFallbackUpload.BytesPerSec > 0 {
				src = NewRatelimitedConn(underlying, &config.LimitFallbackUpload)
			} else {
				src = underlying
			}
		} else if config.LimitFallbackUpload.BytesPerSec > 0 {
			src = NewRatelimitedConn(conn, &config.LimitFallbackUpload)
		}
		_, copyErr := io.Copy(target, src)
		if copyErr == nil {
			if tw, ok := target.(CloseWriteConn); ok {
				tw.CloseWrite()
			}
		} else {
			target.Close()
		}
	}()

	dst := net.Conn(conn)
	if underlying != nil {
		dst = underlying
	}
	if config.LimitFallbackDownload.BytesPerSec > 0 {
		_, _ = io.Copy(dst, NewRatelimitedConn(target, &config.LimitFallbackDownload))
	} else {
		_, _ = io.Copy(dst, target)
	}
	if underlying != nil {
		underlying.CloseWrite()
	}
	wg.Wait()
	target.Close()
	conn.Close()
	return nil, fmt.Errorf("REALITY: processed invalid connection from %s: %s", remoteAddr, reason)
}

func runL2Handshake(hs *serverHandshakeStateTLS13, profile *RealityProfile, show bool, remoteAddr string) (*Conn, error) {
	if profile == nil || !profileL2Eligible(profile) {
		return nil, errors.New("profile not L2 eligible")
	}
	if !clientOffersCipher(hs.clientHello, profile.CipherSuite) {
		return nil, errors.New("client does not offer cached cipher suite")
	}
	if !clientHasKeyShare(hs.clientHello, profile.KeyShareGroup) {
		return nil, errors.New("client missing cached key share group")
	}
	random := make([]byte, 32)
	if _, err := io.ReadFull(hs.c.config.rand(), random); err != nil {
		return nil, err
	}
	// Patch template: fresh random + echo client session id (TLS 1.3 middlebox compat).
	tpl := append([]byte(nil), profile.ServerHelloTemplate...)
	if len(tpl) < 39 {
		return nil, errors.New("server hello template too short")
	}
	copy(tpl[6:38], random)
	// session_id length at offset 38
	sidLen := int(tpl[38])
	if 39+sidLen > len(tpl) {
		return nil, errors.New("server hello template session id truncated")
	}
	if len(hs.clientHello.sessionId) == sidLen {
		copy(tpl[39:39+sidLen], hs.clientHello.sessionId)
	}
	hello := new(serverHelloMsg)
	if !hello.unmarshal(tpl) {
		return nil, errors.New("server hello template unmarshal failed")
	}
	if hello.vers != VersionTLS12 || hello.supportedVersion != VersionTLS13 {
		return nil, errors.New("server hello template version mismatch")
	}
	if cipherSuiteTLS13ByID(hello.cipherSuite) == nil {
		return nil, errors.New("server hello template cipher unsupported")
	}
	if hello.serverShare.group != profile.KeyShareGroup && profile.KeyShareGroup != 0 {
		return nil, errors.New("server hello template group mismatch")
	}

	hs.hello = hello
	// Prefer live-compatible R0 length from template record framing.
	lens := profile.RecordLens
	if lens[0] == 0 {
		lens[0] = recordHeaderLen + len(hello.original)
	}
	copy(hs.c.out.handshakeLen[:], lens[:])
	if err := hs.handshake(); err != nil {
		return nil, err
	}
	for i := range hs.c.out.handshakeLen {
		hs.c.out.handshakeLen[i] = 0
	}
	hs.c.out.handshakeBuf = nil
	if err := hs.readClientFinished(); err != nil {
		return nil, err
	}
	injectPostHandshakeRecords(hs, hs.c.config, show, remoteAddr)
	hs.c.isHandshakeComplete.Store(true)
	if show {
		fmt.Printf("REALITY remoteAddr: %v\tL2 handshake complete suite=0x%04x group=%v\n",
			remoteAddr, hello.cipherSuite, hello.serverShare.group)
	}
	return hs.c, nil
}

// captureTargetRecords reads R0 (always) and R1-R6 (unless L1 cache hit).
func captureTargetRecords(target net.Conn, hs *serverHandshakeStateTLS13, config *Config, mode AmortizeMode, chClass, alpn string, show bool, remoteAddr string) (usedLen [7]int, hello *serverHelloMsg, r0Template []byte, path AmortizePath, err error) {
	path = PathL0
	bufPtr := recordBufPool.Get().(*[]byte)
	buf := *bufPtr
	savedPtr := recordBufPool.Get().(*[]byte)
	s2cSaved := (*savedPtr)[:0]
	defer recordBufPool.Put(bufPtr)
	defer recordBufPool.Put(savedPtr)

	target.SetReadDeadline(time.Now().Add(mirrorIdleTimeout))
	handshakeLen := 0
	const maxTargetReads = 64
	reads := 0

	for {
		reads++
		if reads > maxTargetReads {
			if usedLen[0] != 0 {
				return usedLen, hello, r0Template, path, nil
			}
			err = errors.New("too many target reads without complete handshake records")
			return
		}
		n, readErr := target.Read(buf)
		if n == 0 {
			if readErr != nil {
				err = readErr
				return
			}
			continue
		}
		if len(s2cSaved)+n > maxRecordSize {
			err = errors.New("target handshake too large")
			return
		}
		s2cSaved = append(s2cSaved, buf[:n]...)

		for i, t := range types {
			if usedLen[i] != 0 {
				continue
			}
			if i == 6 && len(s2cSaved) == 0 {
				// optional NewSessionTicket
				return usedLen, hello, r0Template, path, nil
			}
			if handshakeLen == 0 && len(s2cSaved) > recordHeaderLen {
				if bigEndianUint16(s2cSaved[1:3]) != VersionTLS12 ||
					(i == 0 && (recordType(s2cSaved[0]) != recordTypeHandshake || s2cSaved[5] != typeServerHello)) ||
					(i == 1 && (recordType(s2cSaved[0]) != recordTypeChangeCipherSpec || s2cSaved[5] != 1)) ||
					(i > 1 && recordType(s2cSaved[0]) != recordTypeApplicationData) {
					err = fmt.Errorf("unexpected record type at index %d", i)
					return
				}
				handshakeLen = recordHeaderLen + int(bigEndianUint16(s2cSaved[3:5]))
			}
			if show {
				fmt.Printf("REALITY remoteAddr: %v\tlen(s2cSaved): %v\t%v: %v\n", remoteAddr, len(s2cSaved), t, handshakeLen)
			}
			if handshakeLen > maxTLSRecordPayload {
				err = errors.New("record exceeds TLS max")
				return
			}
			if i == 1 && handshakeLen > 0 && handshakeLen != 6 {
				err = errors.New("invalid CCS length")
				return
			}
			if i == 2 && handshakeLen > 512 {
				// Large EE: same special-case as legacy (buffer, break early for this record).
				// Do NOT use the pool buffer here ?it will be returned to the pool
				// via defer while handshakeBuf is still live in the Conn. Instead
				// allocate a dedicated slice that the caller owns.
				usedLen[i] = handshakeLen
				hs.c.out.handshakeBuf = make([]byte, 0, handshakeLen)
				// continue reading until full record consumed below
			}
			if i == 6 && handshakeLen > 0 {
				usedLen[i] = handshakeLen
				// optional
			}
			if handshakeLen == 0 || len(s2cSaved) < handshakeLen {
				break
			}

			if i == 0 {
				hello = new(serverHelloMsg)
				if !hello.unmarshal(s2cSaved[recordHeaderLen:handshakeLen]) ||
					hello.vers != VersionTLS12 || hello.supportedVersion != VersionTLS13 ||
					cipherSuiteTLS13ByID(hello.cipherSuite) == nil {
					err = errors.New("invalid ServerHello")
					hello = nil
					return
				}
				r0Template = append([]byte(nil), s2cSaved[recordHeaderLen:handshakeLen]...)
				usedLen[0] = handshakeLen

				// L1 fast path after live R0.
				if ResolveAmortizeMode(mode) != AmortizeL0 {
					res := globalCacheManager.LookupAmortize(mode, config.Dest, hs.clientHello.serverName, alpn, VersionTLS13, chClass, hello.cipherSuite, hello.serverShare.group)
					if res.Path == PathL1 && res.Profile != nil && ValidateRecordLens(res.Profile.RecordLens) {
						for ci := 1; ci < 7; ci++ {
							usedLen[ci] = res.Profile.RecordLens[ci]
						}
						// Prefer live R0 length over cached R0.
						usedLen[0] = handshakeLen
						path = PathL1
						if show {
							fmt.Printf("REALITY remoteAddr: %v\tcache hit - using cached RecordLens (skipping R1-R6)\n", remoteAddr)
						}
						return usedLen, hello, r0Template, path, nil
					}
					if res.Path == PathL0 || res.Profile == nil {
						// async reprobe on miss
						go globalCacheManager.DoProbe(CacheKey(hs.clientHello.serverName, alpn, VersionTLS13), func() (*RealityProfile, error) {
							p, err := probeTargetRaw(config.Dest, hs.clientHello.serverName, alpnToInt(alpn))
							if err == nil && p != nil {
								p.Source = "probe"
								if p.RecordMode == 0 {
									p.RecordMode = InferRecordMode(p.RecordLens)
								}
								// Store under legacy key without L2 promotion.
								globalCacheManager.StoreObservation(CacheKey(hs.clientHello.serverName, alpn, VersionTLS13), p)
							}
							return p, err
						})
					}
				}
			} else {
				usedLen[i] = handshakeLen
			}
			s2cSaved = s2cSaved[handshakeLen:]
			handshakeLen = 0

			// Finished reading required records 0-5; 6 optional.
			if i >= 5 {
				// If more data available for R6, loop will continue; else return.
				if i == 5 {
					// try to get optional R6 with short idle if already buffered
					if len(s2cSaved) == 0 {
						return usedLen, hello, r0Template, path, nil
					}
				}
				if i == 6 {
					return usedLen, hello, r0Template, path, nil
				}
			}
		}
		if readErr != nil && len(s2cSaved) == 0 {
			// completed with partial optional tail
			if usedLen[0] != 0 && usedLen[5] != 0 {
				return usedLen, hello, r0Template, path, nil
			}
			err = readErr
			return
		}
	}
}

func injectPostHandshakeRecords(hs *serverHandshakeStateTLS13, config *Config, show bool, remoteAddr string) {
	// Post-handshake camouflage is optional. The async detector may store
	// placeholders (bool) or lengths that do not match a safe sealed record.
	// Never inject unvalidated records: a bad inject desynchronizes AEAD seq
	// and breaks subsequent application data for legitimate clients.
	if hs == nil || hs.clientHello == nil {
		return
	}
	key := config.Dest + " " + hs.clientHello.serverName
	if len(hs.clientHello.alpnProtocols) == 0 {
		key += " 0"
	} else if hs.clientHello.alpnProtocols[0] == "h2" {
		key += " 2"
	} else {
		key += " 1"
	}
	if maxUseless, ok := GlobalMaxCSSMsgCount.Load(key); ok {
		if v, ok := maxUseless.(int); ok {
			hs.c.MaxUselessRecords = v
		}
	}
	// Intentionally do not write camouflage app-data here unless lens is
	// explicitly validated by a future, stricter path.
	_ = show
	_ = remoteAddr
}

func buildObservationProfile(config *Config, hs *serverHandshakeStateTLS13, usedLen [7]int, chClass, alpn string, r0Template []byte, source string) *RealityProfile {
	recordCount := 0
	for _, l := range usedLen {
		if l > 0 {
			recordCount++
		}
	}
	group := CurveID(0)
	if hs.hello != nil {
		group = hs.hello.serverShare.group
	}
	suite := uint16(0)
	if hs.hello != nil {
		suite = hs.hello.cipherSuite
	}
	now := time.Now()
	mode := InferRecordMode(usedLen)
	liveEv := 0
	ev := 1
	if source == "live" {
		liveEv = 1
	} else if source == "probe" {
		ev = 0
		liveEv = 0
	}
	return &RealityProfile{
		RecordLens:          usedLen,
		Fingerprint:         computeFingerprint(suite, alpn, usedLen[0], usedLen[2]),
		CipherSuite:         suite,
		ALPN:                alpn,
		TLSVersion:          hs.c.vers,
		RecordCount:         recordCount,
		CapturedAt:          now,
		RecordMode:          mode,
		Dest:                config.Dest,
		ServerName:          hs.clientHello.serverName,
		CHClass:             chClass,
		KeyShareGroup:       group,
		AcceptsHRR:          false,
		ShapeHash:           computeShapeHash(suite, group, usedLen[0], len(r0Template)),
		ServerHelloTemplate: append([]byte(nil), r0Template...),
		Evidence:            ev,
		LiveEvidence:        liveEv,
		Source:              source,
		CHClassVer:          CHClassVersion,
	}
}

func emitHandshakeComplete(config *Config, hs *serverHandshakeStateTLS13, usedLen [7]int, chClass, alpn string, path AmortizePath, obs *RealityProfile) {
	if obs == nil {
		obs = buildObservationProfile(config, hs, usedLen, chClass, alpn, nil, "live")
	}
	fp := &targetFingerprintCache{
		CipherSuite:       obs.CipherSuite,
		ALPN:              alpn,
		SupportedVersions: hs.clientHello.supportedVersions,
		KeyShareGroup:     uint16(obs.KeyShareGroup),
		SignatureSchemes:  hs.clientHello.supportedSignatureAlgorithms,
		LastUpdated:       time.Now(),
	}
	// Ensure handlers also see V2 fields.
	globalEventBus.Emit(Event{
		Type:        EventHandshakeComplete,
		Dest:        config.Dest,
		ServerName:  hs.clientHello.serverName,
		ALPN:        alpn,
		TLSVersion:  hs.c.vers,
		Profile:     obs,
		Fingerprint: fp,
	})
	_ = path
}


