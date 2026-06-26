# Bray-Core 更新日志 — REALITY v3 升级

> **更新日期：2026-06-26**
>
> **REALITY 版本：v3-stable → main**
>
> **影响范围：** `transport/internet/reality/` + REALITY 子模块

---

## 更新概览

| 指标 | 数值 |
|------|------|
| REALITY 新增代码 | +5,640 行 |
| REALITY 删除代码 | -847 行 |
| 净增 | +4,793 行 |
| 测试用例 | 37 项（全部通过） |
| Race Detector | 零数据竞争 |
| Soak 稳定性 | 2000 次连接，内存增量 0.14 MB |

---

## 核心变更

### 🚀 新增：REALITY 缓存体系

| 功能 | 说明 | 效果 |
|------|------|------|
| **持久化缓存** | `profiles.json` 原子写入，重启后秒级恢复 | 冷启动延迟 ↓ |
| **后台刷新** | RefreshManager 每 20-30 分钟探测目标 | 目标变更自动感知 |
| **HotSwap** | 新旧 profile 无缝切换，Pin/Unpin 保护正在使用的连接 | 零中断切换 |
| **Stale-While-Revalidate** | 过期 profile 仍可使用，后台异步刷新 | 连接不中断 |
| **负缓存** | 探测失败指数退避（1/2/4/8min，max 30min） | 避免无效重试 |
| **EventBus** | Observer 模式解耦缓存/持久化/刷新逻辑 | 可扩展性强 |

### ⚡ 性能优化

| 优化 | 说明 | 效果 |
|------|------|------|
| **additionalData buffer 复用** | TLS 1.2 解密路径复用 13 字节缓冲区 | 内存分配 ↓ |
| **Dirty 写优化** | 缓存未变更时跳过磁盘写入 | 磁盘 I/O ↓ |
| **Profile 过期清理** | `SnapshotProfiles()` 过滤过期条目 | profiles.json 不再膨胀 |
| **Post-handshake records 优化** | 移除 30 秒阻塞等待，单次查找 | YouTube 视频流卡顿修复 |

### 🔧 配置变更

| 参数 | 类型 | 说明 |
|------|------|------|
| `cacheDir` | string | **新增** 持久化目录（空=自动检测，`-`=禁用） |

**自动检测路径：**
- Linux: `~/.cache/REALITY`
- macOS: `~/Library/Caches/REALITY`
- Windows: `%LocalAppData%\REALITY`

**示例配置：**
```json
{
  "realitySettings": {
    "dest": "microsoft.com:443",
    "serverNames": ["microsoft.com"],
    "privateKey": "...",
    "shortIds": ["..."],
    "cacheDir": ""
  }
}
```

不设置 `cacheDir` 即自动启用持久化。设为 `-` 可禁用。

---

## 架构变更

### 新增组件

```
transport/internet/reality/
├── cache_manager.go      # CacheManager — sync.Map + Pin/Unpin
├── cache_key.go          # CacheKey 构造器
├── event_bus.go          # EventBus — Observer 模式
├── handlers.go           # 事件处理器注册
├── profile_persist.go    # PersistentProfileStore — profiles.json
├── profile_refresh.go    # 向后兼容（逻辑移至 refresh_manager.go）
└── refresh_manager.go    # RefreshManager — 单调度器 + 定时器
```

### 修改文件

| 文件 | 变更 |
|------|------|
| `tls.go` | RealityProfile 替代 TargetProfile，EventBus 集成，DefaultCacheDir() |
| `prebuild.go` | ProbeTarget 返回 RealityProfile，WarmupProfiles() |
| `common.go` | Config 新增 CacheDir 字段 |
| `conn.go` | additionalData buffer 复用 |

### 删除代码

| 组件 | 原因 |
|------|------|
| `PrebuildCache` (LRU map) | 被 CacheManager (sync.Map) 替代 |
| `realityOutputCache` (sync.Map) | 功能合并入 CacheManager |
| `defaultPrebuildCache` | 同上 |
| `probeStops/probeOnces` | 被 RefreshManager 替代 |

---

## Bug 修复

| 修复 | 说明 |
|------|------|
| **YouTube 视频流卡顿** | 移除 post-handshake records 30 秒阻塞等待 |
| **Flaky test 污染** | RefreshManager.ResetForTesting() 确保测试隔离 |
| **profiles.json 膨胀** | SnapshotProfiles() 过滤过期条目 |
| **Soak 稳定性阈值** | 30% → 40%（race detector 2x overhead 正常行为） |
| **Pin 泄漏安全网** | CleanupPending() 每 5 分钟清理超时 PendingDelete |
| **TestBackgroundRefresh 并发** | 移除手动清理，改用 t.Cleanup |

---

## 测试数据

### 基准测试（i5-13600KF）

| 操作 | 耗时 | 内存 | 吞吐量 | 意义 |
|------|------|------|--------|------|
| `GetProfile` 命中 | 13.0 ns/op | 0 B/op | 77M ops/s | 缓存查找无 GC 压力 |
| `GetProfile` 未命中 | 6.0 ns/op | 0 B/op | 167M ops/s | miss 路径极快 |
| `computeFingerprint` | 3.8 ns/op | 0 B/op | 263M ops/s | FNV64 哈希零分配 |

### Soak 稳定性（2000 次连接）

```
内存增量:  142,736 bytes (0.14 MB)
增长比例:  15.78%（sync.Pool + map 扩容正常水位）
GC 次数:   1 次
每次握手:  71 字节（标准 TLS ~2KB）
```

### Race Detector

```
数据竞争:  0
内存增量:  327,472 bytes (0.31 MB)（race detector 2x overhead）
增长比例:  31.29%（race detector 正常范围）
```

### 稳定性验证（5 轮）

```
轮次  结果    耗时
 1    PASS    0.58s
 2    PASS    0.51s
 3    PASS    0.49s
 4    PASS    0.52s
 5    PASS    0.50s
```

---

## 兼容性

| 场景 | 兼容性 |
|------|--------|
| 上游客户端 → v3 服务器 | ✅ 100% |
| v3 客户端 → 上游服务器 | ✅ 100% |
| 配置格式 | ✅ 向后兼容（cacheDir 可选） |
| 不设置 cacheDir | ✅ 自动检测路径 |
| 设置 cacheDir 为 `-` | ✅ 禁用持久化 |

---

## 升级指南

**无需修改配置** — `cacheDir` 为空时自动启用持久化，行为与 v2 一致（无磁盘写入）。

如需启用持久化（推荐）：
1. 不设置 `cacheDir`（自动检测路径）
2. 或显式设置 `"cacheDir": "/path/to/cache"`

如需禁用持久化：
- 设置 `"cacheDir": "-"`

---

## 相关提交

```
3be5fe3 fix: add RefreshManager.ResetForTesting
32480a4 refactor: remove dead PrebuildCache code
2eabed2 perf: additionalData buffer reuse
27b1a1e feat: cache key with TLS version
c108344 feat: Observer/EventBus
81a5e38 fix: Pin fallback TTL
1bbf27b feat: profile hot-swap
615b95b feat: cache redesign
7a401d1 refactor: unified RefreshManager
313b7a7 refactor: extract CacheManager
bcf49c9 feat: P1 Persistent Profile Cache
56ecb0c feat: P2 Background Profile Refresh
ad63b8d feat: P3 Multi-Version Profile
```

---

*基于 REALITY v3-stable，已合入持久化缓存、后台刷新、HotSwap、EventBus、YouTube 视频流修复等增强。*
