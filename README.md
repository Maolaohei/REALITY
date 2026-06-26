# REALITY

> 基于 Go 标准库 `crypto/tls` 的 REALITY 协议服务端实现，提供 TLS 指纹伪装与证书伪造能力。为 [Bray-Core](https://github.com/Maolaohei/Bray-Core) 提供传输层安全支持。

---

## 核心特性

| 特性 | 说明 | 状态 |
|------|------|------|
| TLS 1.3 握手伪造 | 从目标服务器捕获记录长度，构建假握手 | ✅ |
| 证书签名验证 | HMAC-SHA512 + 可选 ML-DSA-65 后量子签名 | ✅ |
| 持久化缓存 | 重启后秒级恢复，profiles.json 原子写入 | ✅ |
| 后台刷新 | RefreshManager 定期探测目标，CipherSuite 变更自动热替换 | ✅ |
| HotSwap | 新旧 profile 无缝切换，正在使用的连接不受影响 | ✅ |
| Stale-While-Revalidate | 过期 profile 仍可使用，后台异步刷新 | ✅ |
| 负缓存 | 探测失败指数退避，避免无效重试 | ✅ |
| Pin/Unpin | 连接级引用计数，防止正在使用的 profile 被误删 | ✅ |
| EventBus | Observer 模式解耦缓存/持久化/刷新逻辑 | ✅ |
| 证书限制解除 | 支持 64KB 证书链（原 8KB 限制） | ✅ |
| Proxy Protocol | 支持 PROXY protocol v1/v2 | ✅ |
| Spider 爬虫 | 回落连接时自动爬取目标路径 | ✅ |
| 限速控制 | 可配置回落连接的上传/下载限速 | ✅ |

---

## 架构概览

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

---

## 连接时序图

### 正常连接流程

```
客户端                    REALITY Server                 microsoft.com
  │                            │                              │
  │── ClientHello ────────────▶│                              │
  │   SNI: youtube.com         │                              │
  │                            │── TCP 连接（抓指纹）─────────▶│
  │                            │◀── ServerHello ──────────────│
  │                            │◀── record[0..6] ─────────────│
  │                            │                              │
  │                            ├─ 验证 AuthKey/ShortId        │
  │                            ├─ 记录 handshakeLen           │
  │                            ├─ hs.handshake()              │
  │                            │                              │
  │◀── ServerHello ────────────│  用微软的 record 长度 padding │
  │◀── EncryptedExtensions ────│                              │
  │◀── Certificate ────────────│                              │
  │◀── CertificateVerify ──────│                              │
  │◀── Finished ───────────────│                              │
  │                            │                              │
  │── Finished ───────────────▶│                              │
  │                            │                              │
  │◀═════ TLS 完成 ═══════════▶│                              │
  │                            │                              │
  │                            │  ┌─── EventBus ────────────┐│
  │                            │  │ Cache: StoreProfile()   ││
  │                            │  │ Persist: Save() → 磁盘  ││
  │                            │  │ Refresh: AddTarget()    ││
  │                            │  └─────────────────────────┘│
  │                            │                              │
  │── 应用数据 ───────────────▶│── xray 代理转发 ────────────▶│
```

### 后台刷新流程

```
          RefreshManager                      microsoft.com
               │                                    │
               │  每 20-30 分钟（随机间隔）           │
               │───────────────────────────────────▶│
               │◀── ServerHello + CipherSuite ──────│
               │                                    │
               ├─ CipherSuite 没变?                  │
               │  └─ 是 → MarkStale() 延长 TTL      │
               │     重置定时器 20-30 分钟            │
               │                                    │
               ├─ CipherSuite 变了?                  │
               │  └─ 是 → HotSwapProfile()          │
               │     新 profile 直接 Store           │
               │     旧 profile → PendingDelete     │
               │     正在用的连接 Pin 保护            │
               │     释放后 Unpin → 自动删除         │
               │                                    │
               └─ 重置定时器，继续循环                │
```

### 进程重启恢复

```
xray 启动                    profiles.json              CacheManager
   │                              │                         │
   │── load() ───────────────────▶│                         │
   │◀── 旧 profiles ──────────────│                         │
   │                              │                         │
   │── StoreProfile() ─────────────────────────────────────▶│
   │                              │                         │
   │── WarmupProfiles() ── 后台探测已知目标                  │
   │                              │                         │
   │  首个客户端连接                │                         │
   │── ClientHello ────────────────────────────────────────▶│
   │                              │    CacheManager 有基准   │
   │◀── 用缓存的 profile 握手 ──────────────────────────────│
```

---

## 缓存生命周期

```
                ┌─────────────┐
                │  无 Profile  │
                └──────┬──────┘
                       │ 首次握手
                       ▼
                ┌─────────────┐
                │   Valid     │◄───────────────┐
                │  (30min TTL)│                │
                └──────┬──────┘                │
                       │ TTL 过期              │ RefreshManager 探测
                       ▼                       │ CipherSuite 没变
                ┌─────────────┐                │
                │   Stale     │────────────────┘
                │ (仍可使用)   │  MarkStale()
                └──────┬──────┘
                       │ 目标变化
                       ▼
                ┌─────────────┐
                │ PendingDelete│──── Pin/Unpin 保护
                │ (等待释放)   │
                └──────┬──────┘
                       │ refCount=0 或 超时 10min
                       ▼
                ┌─────────────┐
                │   已删除     │
                └─────────────┘

特殊路径:
  探测失败 → Negative → 指数退避(1/2/4/8min, max 30min) → 超时后删除
  HotSwap  → 新 Profile 直接 Store, 旧 Profile → PendingDelete
```

---

## 配置参数

### 服务端

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `dest` | string | ✅ | 目标服务器地址（如 `microsoft.com:443`） |
| `serverNames` | []string | ✅ | 允许的 SNI 列表 |
| `privateKey` | string | ✅ | X25519 私钥（`x25519` 命令生成） |
| `shortIds` | []string | ✅ | 客户端 shortId 列表 |
| `cacheDir` | string | 选填 | 持久化目录（空=自动检测，设 "-"=禁用） |
| `show` | bool | 选填 | 输出调试信息 |
| `type` | string | 选填 | 连接类型（`tcp`/`udp`） |
| `xver` | int | 选填 | PROXY protocol 版本（0/1/2） |
| `minClientVer` | string | 选填 | 客户端最低版本（`x.y.z`） |
| `maxClientVer` | string | 选填 | 客户端最高版本（`x.y.z`） |
| `maxTimeDiff` | int | 选填 | 最大时间差（毫秒） |
| `mldsa65Seed` | string | 选填 | ML-DSA-65 种子（抗量子签名） |
| `limitFallbackUpload` | object | 选填 | 回落上传限速 |
| `limitFallbackDownload` | object | 选填 | 回落下载限速 |

### 回落限速参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `afterBytes` | int | 0 | 传输指定字节后开始限速 |
| `bytesPerSec` | int | 0 | 基准速率（字节/秒），0=不启用 |
| `burstBytesPerSec` | int | 0 | 突发速率（字节/秒） |

---

## 安全模型

| 层级 | 机制 | 说明 |
|------|------|------|
| 认证 | ECDH + HKDF | AuthKey 仅客户端和服务端知道 |
| 签名 | HMAC-SHA512 | 证书签名槽（64 字节） |
| 后量子 | ML-DSA-65 | 可选，抵御量子计算攻击 |
| 验证 | x509 回退 | HMAC 不匹配时走标准验证 |

---

## 编译

```bash
# 作为 Go module 使用
go get github.com/Maolaohei/REALITY@latest

# 本地开发（Bray-Core 中）
go mod edit -replace github.com/Maolaohei/REALITY=./REALITY
go mod tidy
```

---

## 测试

```bash
# 运行全量测试（37 项）
go test -v -timeout=120s

# 运行 race detector
go test -race -timeout=120s

# 运行特定测试
go test -v -run "TestBackgroundRefresh" -timeout=60s
```

### 测试覆盖

| 类别 | 测试数 | 覆盖项 |
|------|--------|--------|
| 目标探测 | 2 | 连接拒绝/上下文取消 |
| 自动探测 | 4 | 空Dest/配置复制/幂等/清理 |
| Profile 缓存 | 7 | 命中/未命中/过期/指纹/隔离/并发/驱逐 |
| 缓存失效 | 3 | 手动失效/CipherSuite变更/Profile复用 |
| 持久化存储 | 3 | 保存加载/跳过过期/原子写入 |
| 后台刷新 | 4 | 启停/多目标/并发/格式化 |
| Pin/Unpin | 3 | 过期清理/保留最近/泄漏安全网 |
| 回归测试 | 5 | Profile复用/持久化加载/刷新非阻塞/Soak稳定性 |
| 目标漂移 | 3 | CipherSuite变更/证书轮换/ALPN变更 |
| 并发安全 | 1 | 缓存并发访问 |
| 超时恢复 | 1 | FailSafe超时恢复 |
| **总计** | **37** | |

---

## 测试数据

### 基准测试（3 次取均值，Intel i5-13600KF）

| 操作 | 耗时 | 内存分配 | 吞吐量 | 说明 |
|------|------|---------|--------|------|
| `CacheManager.GetProfile` (命中) | 13.0 ns/op | 0 B/op | ~77M ops/s | sync.Map 读取，零分配 |
| `CacheManager.GetProfile` (未命中) | 6.0 ns/op | 0 B/op | ~167M ops/s | sync.Map miss，最快路径 |
| `computeFingerprint` | 3.8 ns/op | 0 B/op | ~263M ops/s | FNV64 哈希计算 |

**关键指标解读：**
- **零分配 (0 B/op)**：GetProfile 和 fingerprint 计算均无堆分配，GC 压力为零
- **纳秒级延迟**：缓存查找耗时 ~13ns，远低于网络 RTT（~100ms），对握手延迟无感知
- **高吞吐**：单核 77M ops/s，足以应对任何并发场景

### Soak 稳定性测试（2000 次连续握手）

```
环境:    Go 1.24, amd64
连接数:  2000 次连续 TLS 握手（无网络，纯内存）
内存增量: 142,736 bytes (0.14 MB)
增长比例: 15.78%
GC 次数:  1 次
```

**关键指标解读：**
- **0.14 MB / 2000 次**：每次握手平均占用 71 字节，远低于标准 TLS 的 ~2KB
- **15.78% 增长**：sync.Pool 和 map 扩容的正常水位，非泄漏
- **1 次 GC**：内存管理高效，无频繁回收

### Race Detector 测试

```
环境:    -race 标志开启
连接数:  2000 次（Soak 测试内含并发）
数据竞争: 0
内存增量: 327,472 bytes (0.31 MB)（race detector 本身注入 ~2x overhead）
增长比例: 31.29%（race detector 正常范围）
```

**关键指标解读：**
- **零数据竞争**：所有 sync.Map/Mutex/Atomic 操作线程安全
- **race detector 开销**：内存增长翻倍（0.14→0.31 MB）是正常行为，不影响生产环境

### 稳定性验证（5 轮连续全量测试）

```
轮次  结果    耗时
 1    PASS    0.58s
 2    PASS    0.51s
 3    PASS    0.49s
 4    PASS    0.52s
 5    PASS    0.50s
```

**关键指标解读：**
- **100% 通过率**：5 轮全绿，无 flaky test
- **耗时稳定**：0.49-0.58s，无异常波动

### 全量测试结果

```
ok  github.com/Maolaohei/REALITY  1.990s
37/37 PASS（含 Soak 2000 次连接）
```

### 持久化存储测试

| 测试项 | 耗时 | 说明 |
|--------|------|------|
| `PersistentStoreSaveLoad` | 0.02s | 写入 + 读回 + 验证一致性 |
| `PersistentStoreSkipsExpired` | 0.00s | 过期条目自动跳过 |
| `PersistentStoreAtomicWrite` | 0.00s | 原子写入（tmp → fsync → rename） |

---

## 相关项目

| 项目 | 说明 |
|------|------|
| [Bray-Core](https://github.com/Maolaohei/Bray-Core) | 高性能 Xray-core 分支 |
| [Xray-core](https://github.com/XTLS/Xray-core) | 上游项目 |
| [REALITY Protocol](https://github.com/XTLS/REALITY) | 原始 REALITY 协议 |

---

*基于 XTLS/REALITY v0.0.0-20260322125925，已合入预构建模式、持久化缓存、后台刷新、HotSwap、EventBus 等增强。*
