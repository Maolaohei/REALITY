# REALITY 第一阶段重构计划：Stateless REALITY

## 重构目标

移除握手缓存，实现"实时镜像"架构：
- 握手永远相信真实Target
- Probe仅用于日志/监控，不影响握手
- 消除缓存一致性问题

## 需要删除的文件

| 文件 | 行数 | 说明 |
|------|------|------|
| `cache_manager.go` | 401 | CacheManager核心实现 |
| `cache_key.go` | 85 | 缓存键生成 |
| `cache.go` | 44 | weakCertCache |
| `profile_persist.go` | 199 | 持久化存储 |
| `profile_refresh.go` | ? | Profile刷新 |
| `event_bus.go` | 75 | 事件总线 |
| `handlers.go` | 56 | 事件处理器 |
| `refresh_manager.go` | 375 | 后台刷新管理器 |

## 需要修改的文件

### 1. tls.go (核心修改)

**删除的代码：**
- `globalCacheManager` 引用
- 缓存快速路径逻辑 (lines 610-660)
- `InvalidateAndReprobe` 调用
- `DoProbe` 调用
- Profile存储逻辑

**保留的代码：**
- `Server()` 函数结构
- 双协程握手机制
- MirrorConn
- Auth认证逻辑
- TLS 1.3握手流程

**新增的代码：**
- 实时读取目标记录（无缓存）
- Probe日志输出（可选）

### 2. prebuild.go

**删除的代码：**
- `WarmupProfiles()` 函数
- `globalCacheManager.entries.Range` 逻辑
- `DoProbe` 调用

**保留的代码：**
- `ensureAutoProbe()` 函数（简化版）
- `probeTargetRaw()` 函数（仅用于日志）

### 3. record_detect.go

**保留的代码：**
- `DetectPostHandshakeRecordsLens()` 函数
- `GlobalPostHandshakeRecordsLens` 变量

### 4. 测试文件

**需要更新的测试：**
- `gate_l1_unit_test.go` - 删除缓存相关测试
- `gate_l2_handshake_test.go` - 删除缓存断言
- `gate_l3_*.go` - 更新集成测试
- `gate_l5_soak_test.go` - 更新稳定性测试
- `regression_test.go` - 删除缓存回归测试
- `refresh_manager_test.go` - 删除或重写
- `prebuild_test.go` - 更新预构建测试

## 重构步骤

### 步骤1：创建简化版ProbeResult结构

```go
// probe_result.go (新文件)
package reality

import "time"

// ProbeResult 存储后台探测结果（仅用于日志/监控）
type ProbeResult struct {
    Dest           string
    ServerName     string
    ALPN           string
    CipherSuite    uint16
    RecordLens     [7]int
    CertHash       [32]byte
    ExtensionHash  uint64
    Timestamp      time.Time
    Changed        bool
    ChangeDetail   string
}
```

### 步骤2：简化tls.go中的Server()函数

**关键修改点：**
1. 移除`globalCacheManager`初始化
2. 移除缓存快速路径（lines 610-660）
3. 保留实时读取目标记录的逻辑
4. 添加可选的Probe日志输出

### 步骤3：删除缓存相关文件

按依赖顺序删除：
1. `handlers.go` - 事件处理器
2. `event_bus.go` - 事件总线
3. `profile_persist.go` - 持久化存储
4. `profile_refresh.go` - Profile刷新
5. `refresh_manager.go` - 后台刷新管理器
6. `cache_manager.go` - CacheManager核心
7. `cache_key.go` - 缓存键生成
8. `cache.go` - weakCertCache

### 步骤4：更新prebuild.go

简化为仅保留探测功能，移除缓存交互。

### 步骤5：更新测试文件

删除或重写所有依赖缓存的测试用例。

### 步骤6：验证编译

确保所有删除和修改后代码能正确编译。

## 预期结果

**代码量变化：**
- 删除：~1500-2000行缓存相关代码
- 新增：~50-100行ProbeResult结构
- 净减少：~1400-1900行

**功能变化：**
- 握手：始终实时读取目标服务器
- 缓存：完全移除
- Probe：仅用于日志/监控
- 持久化：完全移除

**兼容性：**
- 客户端：无需修改
- 协议：完全兼容
- 配置：移除缓存相关配置项

## 风险评估

**低风险：**
- 核心握手逻辑不变
- MirrorConn机制不变
- Auth认证不变
- TLS 1.3流程不变

**中风险：**
- 测试覆盖可能下降
- 性能可能略有变化（每次握手需完整读取7条记录）

**缓解措施：**
- 保留所有核心测试
- 第二阶段实施TCP连接池优化
- 性能基准测试验证

## 实施时间估计

- 步骤1-2：2-3小时（核心修改）
- 步骤3-4：1-2小时（文件删除和简化）
- 步骤5-6：2-3小时（测试更新和验证）
- **总计：5-8小时**

## 验证标准

1. 编译通过（go build）
2. 核心测试通过（go test -v -run "TestL2_"）
3. 无缓存相关代码残留
4. 握手流程正确完成
5. Probe日志正常输出（show=true时）