# REALITY Local Amortize E2E

## Topology

```
uTLS REALITY client (AuthTag + HMAC cert verify)
        |
 REALITY.Server  --DialContext--> local TLS1.3 target
```

100% loopback. No public network. No xray.exe required.

## Run

```bat
cd REALITY
go test -tags l2 -count=1 -timeout 180s -run "TestE2E_|TestL2_Authorized"
```

or:

```bat
test_e2e_amortize.bat
```

## Critical gates

### Handshake amortize
- `TestE2E_Amortize_L0L1L2_Progression` — dials `+1,+1,0,0,0`
- `TestE2E_NoRAWhenL2_Hit` — hard zero-dial after evidence
- mode L0 / L1 guards

### Application data (must not drop after handshake)
- `TestE2E_AppData_FullDuplex_AfterHandshake` — cold/warm/L2 + 16KB, **two rounds per conn**
- `TestE2E_AppData_FullDuplex_ModeL0`
- `TestE2E_AppData_FullDuplex_ModeL1`
- `TestE2E_AppData_FullDuplex_Concurrent`

These use a production-like client:
1. SessionId AuthTag
2. HMAC-SHA512 cert verification (same idea as Xray `UClient`)
3. hard `Write` + `ReadFull` echo (not best-effort)

### Auth / isolation / load
- wrong ShortId / plain TLS / wrong SNI
- ALPN variants, cache isolation, 50 sequential, concurrent HS

## Fix related to post-handshake disconnect

REALITY now **never emits real NewSessionTicket** (`shouldSendSessionTickets=false`).
Camouflage may still *measure* target R6 lengths, but sending our own NST under
application traffic keys caused strict clients to fail the first application Read
and drop the connection right after a successful handshake.
