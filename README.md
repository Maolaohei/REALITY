# REALITY

> 基于 Go 标准库 `crypto/tls` 的 REALITY 协议服务端实现，提供 TLS 指纹伪装与证书伪造能力。为 [Bray-Core](https://github.com/Maolaohei/Bray-Core) 提供传输层安全支持。

---

## 功能特性

| 特性 | 说明 | 状态 |
|------|------|------|
| TLS 1.3 握手伪造 | 从目标服务器捕获记录长度，构建假握手 | ✅ |
| 证书签名验证 | HMAC-SHA512 + 可选 ML-DSA-65 后量子签名 | ✅ |
| 预构建模式 | 缓存目标特征，消除 Target RTT 延迟 | ✅ |
| 自动探测 | 首次连接自动探测 + 随机间隔后台刷新 | ✅ |
| LRU 缓存淘汰 | 可配置容量上限，LRU 策略防内存泄漏 | ✅ |
| 证书限制解除 | 支持 64KB 证书链（原 8KB 限制） | ✅ |
| Proxy Protocol | 支持 PROXY protocol v1/v2 | ✅ |
| Spider 爬虫 | 回落连接时自动爬取目标路径 | ✅ |
| 限速控制 | 可配置回落连接的上传/下载限速 | ✅ |

---

## 配置参数

### 服务端

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `dest` | string | ✅ | 目标服务器地址（如 `example.com:443`） |
| `serverNames` | []string | ✅ | 允许的 SNI 列表 |
| `privateKey` | string | ✅ | X25519 私钥（`x25519` 命令生成） |
| `shortIds` | []string | ✅ | 客户端 shortId 列表 |
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

## 架构设计

### 握手流程

```
Client → REALITY Server: ClientHello
    ↓
REALITY → Target: 连接 + 读取 TLS 响应
    ↓
REALITY 捕获: ServerHello/CCS/EE/Cert/CertVerify/Finished 长度
    ↓
REALITY → Client: 伪造握手（使用捕获的长度 + 自己的签名）
    ↓
Client 验证: HMAC(authKey, pubKey) == cert.Signature?
    → 匹配: REALITY 连接建立
    → 不匹配: 转发到 Target
```

### 预构建模式

```
首次连接:
  Client → REALITY → Target → 捕获特征 → 缓存
  延迟: Target RTT (~100-500ms)

后续连接:
  Client → REALITY → 查缓存 → 直接使用 → 0-RTT
  延迟: 缓存查找 (~15ns)

后台刷新:
  每 20-30 分钟随机间隔自动探测
  缓存过期后自动回退到实时探测
```

### 安全模型

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
go mod edit -replace github.com/xtls/reality=D:\path\to\REALITY
go mod tidy
```

---

## 测试

```bash
# 运行预构建模式测试（21 项）
go test -v -run "TestPrebuild" -timeout=30s

# 运行 race detector
go test -race -run "TestPrebuild" -timeout=30s

# 运行基准测试
go test -bench="BenchmarkPrebuild" -benchmem -timeout=30s
```

### 测试覆盖

| 类别 | 测试数 | 覆盖项 |
|------|--------|--------|
| 缓存基本操作 | 6 | Store/Get/Miss/Expired/Replace/Nil |
| 边界情况 | 5 | 空Key/零TTL/负TTL/零长度/最大长度 |
| 并发安全 | 3 | 读写并发/删除并发/Get+Store并发 |
| LRU 淘汰 | 4 | 淘汰/访问更新/替换不淘汰/无限容量 |
| 自动探测 | 6 | 空Dest/配置复制/幂等/清理/无内存泄漏 |
| **总计** | **21** | |

---

## 基准数据

| 操作 | 耗时 | 内存分配 |
|------|------|---------|
| Cache Get（命中） | ~15 ns/op | 0 B/op |
| Cache Get（未命中） | ~10 ns/op | 0 B/op |
| Cache Store | ~40 ns/op | 96 B/op |
| Cache Get（并发） | ~43 ns/op | 0 B/op |

---

## 相关项目

| 项目 | 说明 |
|------|------|
| [Bray-Core](https://github.com/Maolaohei/Bray-Core) | 高性能 Xray-core 分支 |
| [Xray-core](https://github.com/XTLS/Xray-core) | 上游项目 |
| [REALITY Protocol](https://github.com/XTLS/REALITY) | 原始 REALITY 协议 |

---

*基于 XTLS/REALITY v0.0.0-20260322125925，已合入预构建模式、LRU 缓存、自动探测、证书限制解除等增强。*
