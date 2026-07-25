> **路由**: GhostLock 真·栈 UAF（pi_blocked_on）| **状态**: ⛔ 终局（shell 链写原语关闭）  
> **权威**: 本节点 + `PROCESS_LOG` §51–§53

# 10 — CVE-2026-43499 全链路与 Leaf5 终局

## 1. 漏洞机制

1. Waiter：`FUTEX_WAIT_REQUEUE_PI`，`rt_mutex_waiter` 在内核栈。
2. 三 futex 死锁 + `FUTEX_CMP_REQUEUE_PI` → 内部 **EDEADLK** 回滚。
3. `remove_waiter` 误清 **`current->pi_blocked_on`**（[BIN] `str xzr,[sp_el0,#0x8d0]`）。
4. Victim 返回后 `pi_blocked_on` 悬空 → 栈 UAF。
5. 理论后续：同线程 CFU reclaim → `sched_setattr` PI walk → 受限写 → root。

## 2. Leaf5 CORRECTED 事实

| 项 | 值 |
|----|-----|
| Waiter 路径 | do_futex / WAIT_REQUEUE_PI |
| `waiter->task` | stack_top − 0x168 |
| Waiter 布局 [BIN] | **0x50**：task+0x30, lock+0x38, **prio+0x40**, **deadline+0x48**（非 stock 0x40） |
| `PSELECT_WAITER_WORD_SHIFT` | **+15**（旧 −46 作废） |
| EDEADLK 用户态 | `CMP ret=-1 errno=35` |
| WAIT 返回 | 常 `ETIMEDOUT`（4.19 不立即 wake） |
| popsicle | pselect reclaim + SHIFT 依 6.12 几何；direct `init_cred` |

## 3. 已关闭（勿重打，无新理论）

| 路径 | 结果 | 引用 |
|------|------|------|
| live 同线程 CFU | ❌ | S05-08 |
| post-return 0x41 无 EDEADLK | ❌ | S05-08 / §49 |
| pselect SHIFT=−46 | ❌ 旧深度 | S05-01 → CORRECTED |
| KGSL list / 32-bit / personality | ❌ | S05-07 |
| binder 数据可控 / qcedev shell | ❌ | S05-02/06 |
| PR_SET_MM_MAP | ❌ 无符号 | [BIN] |

## 4. 设备矩阵：受限写（终局 B）

前置均满足：EDEADLK(35)、WAIT 返回、pselect reclaim、`sched_setattr success=1`、**无** root。  
写命中判定：`try_cfi_stage` → ashmem `pwrite`（期望 configfs 路径）；成功 ⇒ fops 已劫持。

| 假设 | 参数 | 写命中 | 证据 |
|------|------|--------|------|
| prio 粉刷 + shape0 parent=target−8 | SHIFT=15, LOCK_SHAPE=0 | ❌ errno=22 | `{SCRATCH}/run_shape0.log` / `run_shift15.log` |
| null-parent root → spray waiters | LOCK_SHAPE=1 | ❌ errno=22 | `run_shape1.log` |
| legacy parent=value left=target | LOCK_SHAPE=2 | ❌ errno=22 | `run_shape2.log` |
| SHIFT 带 | 13,14,15,16,17 × shape0 | ❌ 全 22 | `run_shift{13..17}.log` |
| shape1 复测存活 | LOCK_SHAPE=1 | ❌ 无 OOPS/无写 | `run_shape1_surv.log` |
| 0x41 宽窗+consumer（对照） | adjtimex | panic only | §51 `ghostlock_uaf_reclaim_consumer` |

**静态原因（关闭写链，非“待分析”）**:

1. **`rt_mutex_adjust_pi` [BIN]** 读 `waiter+0x40/0x48`；未粉刷时可能 early-exit（已粉刷 prio=0x82 仍无写）。
2. **`lock=target-8` 叠在 `ashmem_misc.name` 上当 wait_lock** → trylock 失败，无法在 fops 槽上做 root 写。
3. **`lock=fake_lock`（wait_lock=0）** 时 erase 写落在 **spray 页 waiters**，不是 `ashmem_misc.fops`；CFI 仍失败。
4. **`sched_setattr success=1` ≠ store**；全矩阵无 fops 读回/CFI 成功，也无 shape 导致的可控 OOPS 写证。

## 5. 终局判定

```
S00–S04     ✅ 泄漏 / spray / GhostLock 触发（EDEADLK）
S05 写原语  ⛔ shell 可达 constrained write 未达成（矩阵关闭）
S06–S07     ⛔ 依赖写原语
root        ❌ 无 uid=0 证据
```

**Outcome B**：在 #245 上，本仓库 shell 可达的 GhostLock→pselect/adjtimex reclaim→`sched_setattr` 路径 **不能** 证明对 `ashmem_misc.fops`（或等价 CFI 槽）的受控写。  
**不再保留** SHIFT 二分 / shape 对照 / “下一步再分析” 作为开放待办。

## 6. 下游

- **无** 本链开放实验。
- 超出 shell 链：用户授权的 Magisk/刷写；或 **新的** 二进制理论（新 VA / 新 syscall / 新写邻接）才可重开节点。

## 7. 文件

| 路径 | 说明 |
|------|------|
| `analysis/edeadlk_path.md` | EDEADLK 静态 |
| `analysis/pselect_shift_corrected.md` | SHIFT=+15 |
| `probes/ghostlock_edeadlk_*.c` | EDEADLK / panic 对照 |
| `exploit/src/{main,fops,util}.c` | 集成 EDEADLK+pselect+prio |
| `exploit/targets/onyx-leaf5/target.h` | waiter 0x50、SHIFT=15、fops+0x10 |
