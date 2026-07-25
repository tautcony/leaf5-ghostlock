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
| `probes/ghostlock_binder_signal_cfu.c` | 信号 handler CFU | ❌ 存活 | SIGUSR1 中 CFU ret=0 |
| `probes/test_adjtimex_cfu.c` | adjtimex 208B | ✅ CFU | bad→EFAULT；sizeof=208 |
| `probes/ghostlock_adjtimex_cfu.c` | GhostLock+adjtimex | ❌ 存活 | 0x41 填满 [0x118,0x1e8) 含 task 槽仍无 OOPS |

## 静态重扫（相对 stack_top，ioctl nest 含/不含 thin wrapper）

| 路径 | shell | CFU | abs 范围 | vs −0x168 |
|------|-------|-----|----------|-----------|
| `evdev_ioctl`+handler | ✅ event* O_RDONLY（组 input） | 40B @ SP+8 | **−0x178**（+0x10 wrap） | 过深 0x10 |
| `binder_ioctl` GET_NODE_DEBUG_INFO | ✅ `/dev/binder` | 24B @ SP+0x10 | **[−0x160,−0x178)** | **静态 HIT**（task@buf+8=cookie） |
| `uinput_ioctl_handler` | ✅ | 12B @ SP+0x60 | −0x1a0 | 过深 ~0x38 |
| kgsl list CFU | ✅ | 32B @ SP+8 | −0x308 | 过深 ~0x1A0 |
| **`adjtimex` syscall** | ✅ | **208B @ SP+8** | **[−0x118,−0x1e8)** | **静态 HIT（宽窗）** |
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

## 结论（本轮终局）

1. **shell 可达真 CFU**：evdev、binder、**adjtimex**（EFAULT 矩阵）。
2. **静态对齐 task@−0x168**：binder cookie；**adjtimex 208B 宽窗完整覆盖 waiter 区间 [0x138,0x178)**。
3. **GhostLock 返回后 + 上述 CFU（含 0x41 全窗）内核仍存活**。
4. **推断**：在 Leaf5 #245 上，`WAIT_REQUEUE_PI` **返回之后** 不存在仍被 PI 路径解引用的栈上 stale waiter 残差；post-return 栈 CFU 覆盖模型 **关闭**（非单纯“位差 88B”）。
5. 仍阻塞时同线程无法跑 CFU；跨线程 CFU 写的是对方栈。live-stack 覆盖需其它原语。

## 下游

- 不集成 post-return 栈 CFU 到 exploit。
- 若继续 root：需 **非 post-return 栈残差** 路径（heap 假 waiter 需 physrw 环依赖；或 bootloader/Magisk，需用户确认）。
