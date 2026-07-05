# REALITY 优化路线图 — 可行性分析

## 当前架构分析

### 双协程握手流程（tls.go）

```
Goroutine 1: ClientHello + Auth
  ├── readClientHello()
  ├── ECDH + HKDF + AES-GCM
  ├── Validate: Version, TimeDiff, ShortId
  └── Signal authFailed or success

Goroutine 2: Target Read + Record Parsing
  ├── target.Read() → s2cSaved buffer
  ├── Parse ServerHello (i=0)
  ├── Parse CCS (i=1)
  ├── Parse EE (i=2)
  ├── Parse Certificate (i=3)
  ├── Parse CertificateVerify (i=4)
  ├── Parse Finished (i=5)
  └── Parse NewSessionTicket (i=6)

Sequential: Handshake Execution
  ├── hs.handshake()
  │   ├── Send ServerHello (own key)
  │   ├── Send EncryptedExtensions
  │   ├── Send Certificate (pre-generated)
  │   ├── Send CertificateVerify (Sign) ← CPU热点
  │   └── Send Finished
  └── readClientFinished()
```

### 瓶颈分析

| 阶段 | 操作 | 耗时 | 类型 |
|------|------|------|------|
| Goroutine 2 | target.Read() 7条记录 | ~50ms | 网络I/O |
| CertificateVerify | ed25519.Sign() | ~1ms | CPU |
| CertificateVerify | rsa.SignPSS() | ~10ms | CPU |
| hkdf.DeriveSecret() | 密钥派生 | ~0.1ms | CPU |
| writeHandshakeRecord() | 发送到客户端 | ~1ms | 网络I/O |

**关键发现**：
- 网络I/O（~50ms）远大于CPU（~1ms）
- 当前Goroutine 2和`hs.handshake()`是**串行**的
- 如果能重叠CPU和I/O，可以节省~1ms（ed25519）或~10ms（RSA）

---

## 优化项可行性分析

### P1: Handshake Pipeline ⭐⭐⭐⭐⭐

**当前问题**：Goroutine 2读取完所有7条记录后，才开始`hs.handshake()`（包含CPU密集的签名操作）。

**优化方案**：
```
当前：
Goroutine 2: [Read R0] → [Read R1-R6] → [handshake() 签名] → [发送]

优化后：
Goroutine 2: [Read R0] → [Read R1-R2]
Goroutine 3: [签名CertificateVerify] ← 与Goroutine 2并行
Goroutine 2: [Read R3-R6] → [发送签名结果]
```

**实现难度**：中等
**收益**：高（重叠CPU和I/O，节省1-10ms）
**风险**：低（不改变协议语义）

**具体实现**：
1. 在`hs.handshake()`中，将`sendServerCertificate()`拆分为两阶段：
   - 阶段1：准备Certificate消息（可立即发送）
   - 阶段2：签名CertificateVerify（需要transcript）
2. 启动Goroutine 3提前开始签名
3. Goroutine 2继续读取R3-R6
4. 发送时等待签名完成

**代码位置**：`handshake_server_tls13.go:955-1021`

---

### P2: 减少TLS解析 ⭐⭐⭐⭐⭐

**当前问题**：解析ServerHello时，完整解析所有Extension字段。

**优化方案**：
```go
// 当前：完整解析
hs.hello = new(serverHelloMsg)
hs.hello.unmarshal(s2cSaved[recordHeaderLen:handshakeLen])

// 优化：只解析需要的字段
cipherSuite := bigEndianUint16(s2cSaved[recordHeaderLen+34:recordHeaderLen+36])
```

**实现难度**：低
**收益**：中（减少解析开销）
**风险**：低

**具体实现**：
1. 在`tls.go`的Goroutine 2中，对ServerHello（i=0）：
   - 直接从原始字节读取CipherSuite（偏移量固定）
   - 跳过Extension解析
   - 只在需要时调用完整解析

**代码位置**：`tls.go:525-540`

---

### P3: Zero Copy ⭐⭐⭐⭐⭐

**当前问题**：`writeHandshakeRecord()`中存在多次拷贝。

**优化方案**：
```go
// 当前：
plainText := make([]byte, ...)
copy(plainText, handshakeData)
encrypted := aesGCM.Seal(nil, nonce, plainText, additionalData)

// 优化：in-place加密
buf := recordBufPool.Get().(*[]byte)
copy(buf[5:], handshakeData)  // 偏移5字节TLS头
encrypted := aesGCM.Seal(buf[:5], nonce, buf[5:5+len], additionalData)
// 直接发送buf，无额外拷贝
```

**实现难度**：中等
**收益**：高（减少内存分配和拷贝）
**风险**：中（需要仔细管理buffer生命周期）

**代码位置**：`conn.go`的`write()`和`writeRecordLocked()`

---

### P4: Buffer Pool ⭐⭐⭐⭐⭐

**当前状态**：已有`recordBufPool`用于Goroutine 2的读取buffer。

**进一步优化**：
1. 扩展Pool使用范围到`writeHandshakeRecord()`
2. 为Certificate消息预分配buffer
3. 为post-handshake记录预分配buffer

**实现难度**：低
**收益**：中（减少GC压力）
**风险**：极低

**代码位置**：`tls.go:206-213`（已有recordBufPool）

---

### P5: MirrorConn流水线 ⭐⭐⭐⭐

**当前问题**：`MirrorConn.Read()`每次都要`Unlock()→Read()→Lock()`。

**优化方案**：
```go
// 当前：
func (c *MirrorConn) Read(b []byte) (int, error) {
    c.Unlock()
    defer c.Lock()
    n, err := c.Conn.Read(b)
    ...
}

// 优化：使用RingBuffer + 条件变量
type MirrorConn struct {
    ringBuf   *RingBuffer
    targetCh  chan []byte
    ...
}
```

**实现难度**：高
**收益**：中（减少锁竞争）
**风险**：中（需要重写MirrorConn）

**代码位置**：`conn.go:70-111`

---

### P6: TLS Record Reader ⭐⭐⭐⭐

**当前问题**：每条记录单独`target.Read()`，共7次系统调用。

**优化方案**：
```go
// 当前：
for i := 0; i < 7; i++ {
    n, err := target.Read(buf)  // 7次Read
    // 解析记录
}

// 优化：一次读取，按偏移解析
n, err := io.ReadFull(target, buf[:65536])  // 1次Read
offset := 0
for i := 0; i < 7; i++ {
    recordLen := parseRecordHeader(buf[offset:])
    // 处理记录
    offset += recordLen
}
```

**实现难度**：中等
**收益**：中（减少系统调用）
**风险**：低

**代码位置**：`tls.go:444-544`

---

### P7: Certificate编码优化 ⭐⭐⭐⭐

**当前状态**：证书在`init()`中预生成（`signedCert`全局变量），这是正确的。

**进一步优化**：
```go
// 当前：每次签名都计算transcript
signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
sig, err := hs.cert.PrivateKey.(crypto.Signer).Sign(rand, signed, signOpts)

// 优化：缓存签名结果（如果transcript相同）
// 注意：实际上transcript每次连接都不同，所以缓存签名不可行
// 但是：可以缓存ASN1编码的Certificate消息
```

**实现难度**：中等
**收益**：小（Certificate已经预生成）
**风险**：低

**代码位置**：`handshake_server_tls13.go:81-107`

---

### P8: Crypto微优化 ⭐⭐

**分析**：Go的crypto标准库已经高度优化，进一步优化收益有限。

**建议**：不建议在此投入精力。

---

## 推荐实施顺序

### 第一阶段：高收益低风险（立即实施）

1. **P2: 减少TLS解析** — 简单修改，立即见效
2. **P4: Buffer Pool扩展** — 简单修改，减少GC

### 第二阶段：高收益中等风险

3. **P1: Handshake Pipeline** — 重叠CPU和I/O
4. **P6: TLS Record Reader** — 减少系统调用

### 第三阶段：中等收益

5. **P3: Zero Copy** — 减少内存拷贝
6. **P5: MirrorConn流水线** — 减少锁竞争

### 第四阶段：低收益

7. **P7: Certificate编码优化** — 收益有限
8. **P8: Crypto微优化** — 不建议

---

## 性能基准（预期）

| 优化项 | 预期收益 | 测量方法 |
|--------|----------|----------|
| P2: 减少TLS解析 | ~0.5ms/连接 | BenchmarkServerHelloParse |
| P4: Buffer Pool | ~10% GC减少 | GC暂停时间 |
| P1: Handshake Pipeline | ~1-10ms/连接 | 端到端握手时间 |
| P6: TLS Record Reader | ~0.5ms/连接 | 系统调用次数 |
| P3: Zero Copy | ~5% 吞吐提升 | 内存分配次数 |
| P5: MirrorConn | ~2% 吞吐提升 | 锁竞争时间 |

---

## 结论

**最有价值的优化**：
1. **P1: Handshake Pipeline** — 重叠CPU和I/O，收益最高
2. **P2: 减少TLS解析** — 简单修改，立即见效
3. **P3: Zero Copy** — 减少内存拷贝，提升吞吐

**建议**：先实施P2和P4（简单修改），再实施P1（需要更多设计）。