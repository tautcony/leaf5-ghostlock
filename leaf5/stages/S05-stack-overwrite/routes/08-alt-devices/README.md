> **路由**: 非 KGSL 设备 / shell 可达浅 CFU | **状态**: ⚠️ 2026-07-25 重开重扫（CORRECTED −0x168）

# 08 — alt devices + shell-reachable shallow CFU

## 目标

在 **CORRECTED** waiter 目标 `task @ stack_top − 0x168`（`do_futex` `rt_mutex_init_waiter(x29−0xc8)`）下，寻找 shell 可达且深度对齐的 CFU。

## 代码

| 文件 | 作用 | 效果 | 证据 |
|------|------|------|------|
| `probes/test_drm.c` | DRM open | ❌ | SELinux EACCES |
| `probes/test_fcntl.c` | fcntl | ❌ | 深度不足 |
| `probes/test_evdev_cfu.c` | EVIOCGKEYCODE_V2 | ⚠️ CFU✅ 对齐差 | O_RDONLY；bad→**EFAULT**；wrapper +0x10 → abs −0x178（过深 0x10） |
| `probes/ghostlock_evdev_cfu.c` | GhostLock+evdev | ❌ 存活 | CFU EINVAL/路径可达，无 OOPS |
| `probes/test_binder_cfu.c` | binder ioctl 矩阵 | ✅ CFU | GET_NODE_DEBUG_INFO / NODE_INFO / WRITE_READ48 **EFAULT** |
| `probes/ghostlock_binder_cfu.c` | GhostLock+binder | ❌ 存活 | ioctl ret=0，sched 后无 crash |
| `probes/ghostlock_binder_wake_cfu.c` | requeue+unlock+CFU | ❌ 存活 | WAIT ret=0 后立即 CFU，仍无 crash |

## 静态重扫（相对 stack_top，ioctl nest 含/不含 thin wrapper）

| 路径 | shell | CFU | abs 范围 | vs −0x168 |
|------|-------|-----|----------|-----------|
| `evdev_ioctl`+handler | ✅ event* O_RDONLY（组 input） | 40B @ SP+8 | **−0x178**（+0x10 wrap） | 过深 0x10 |
| `binder_ioctl` GET_NODE_DEBUG_INFO | ✅ `/dev/binder` | 24B @ SP+0x10 | **[−0x160,−0x178)** | **静态 HIT**（task@buf+8=cookie） |
| `uinput_ioctl_handler` | ✅ | 12B @ SP+0x60 | −0x1a0 | 过深 ~0x38 |
| kgsl list CFU | ✅ | 32B @ SP+8 | −0x308 | 过深 ~0x1A0 |
| `/dev/tun` | ❌ vpn 组 | HIT 静态 | — | 权限 |
| DRM | ❌ SELinux | — | — | — |

### binder 设备矩阵（`test_binder_cfu`）

| ioctl | good | bad ptr |
|-------|------|---------|
| WRITE_READ sz=48 | ret=0 | **EFAULT** |
| GET_NODE_DEBUG_INFO sz=24 | ret=0 | **EFAULT** |
| GET_NODE_INFO_FOR_REF sz=24 | EPERM | **EFAULT** |

`struct binder_node_debug_info`：`cookie` 在 +0x08 → 对齐 task。

### GhostLock e2e（binder）

```
CMP_REQUEUE_PI ret=1
WAIT_REQUEUE_PI ret=0（wake 变体）或 ETIMEDOUT
GET_NODE_DEBUG_INFO ret=0，cookie=0x4141…
sched_setattr / PI kick → 内核存活
```

## 结论

1. **shell 可达真 CFU** 已证明：evdev、binder（EFAULT 矩阵）。
2. **静态最强对齐**：binder `GET_NODE_DEBUG_INFO` 覆盖 `task @ −0x168`。
3. **GhostLock + 该 CFU 仍无 cover 副作用**（无 OOPS / 无 fops）。可能原因：
   - 成功返回路径清理了 dangling waiter，残差模型不成立；
   - 仍有未计入的公共入口帧使绝对偏移整体平移；
   - 本机构建上 GhostLock 需更窄竞态窗口。
4. 旧「uinput 差 352B / 全关」在 CORRECTED 目标下 **过时**；本节点改为 ⚠️ 继续（binder 主候选）。

## 下游

- 验证 GhostLock 在 ret=0 返回后 `pi_state`/waiter 是否仍指向栈（需更多 futex 路径或 kprobe/崩溃侧证）。
- 扩大 binder WRITE_READ 48B CFU 帧分析；尝试在 waiter **仍阻塞** 窗口用同线程信号 handler 触发 CFU。
- 无 cover 前 **不** 集成 exploit root 链。
