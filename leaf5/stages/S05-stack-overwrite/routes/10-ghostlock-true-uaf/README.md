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
| **`residual.lock = target−8`**（fops−8 当 wait_lock） | prio 粉刷；`ex2=…3970f70` | ❌ errno=22 | `run_prio_paint.log`：`ex2=ffffff8003970f70`（= data fops−8 / name 槽），EDEADLK✅，sched_setattr success=1，cfi pwrite 22 |
| **`residual.lock = fake_lock`**（spray wait_lock=0） | LOCK_SHAPE=0 parent=target−8\|1 | ❌ errno=22 | `run_shape0.log`：`ex2=fake_lock`，`out5=…0f71`，cfi 22 |
| null-parent root → spray waiters | LOCK_SHAPE=1（fake_lock） | ❌ errno=22 | `run_shape1.log` |
| legacy parent=value left=target | LOCK_SHAPE=2（fake_lock） | ❌ errno=22 | `run_shape2.log` |
| SHIFT 带 | 13–17 × shape0 | ❌ 全 22 | `run_shift{13..17}.log` |
| shape1 复测存活 | LOCK_SHAPE=1 | ❌ 无 OOPS/无写 | `run_shape1_surv.log` |
| 0x41 宽窗+consumer（对照） | adjtimex | panic only | §51 `ghostlock_uaf_reclaim_consumer` |

**关闭原因（设备行 + 静态，非待办）**:

1. **target−8 行**：设备 `ex2=…0f70` 已装 `lock=target−8`；`ashmem_misc.name` 作 wait_lock → trylock 失败路径，CFI 仍 22。  
2. **fake_lock 行**：wait_lock=0 可进 walk（success=1），erase 写不落在 `ashmem_misc.fops`，CFI 仍 22。  
3. **prio@+0x40 [BIN]** 已粉刷 0x82 仍无写命中。  
4. **`sched_setattr success=1` ≠ store**；无 fops 读回成功、无 uid=0。

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

- **本链（ashmem fops 写矩阵）无** 开放实验；勿重打 SHIFT/shape 同行。
- **其它提权方向**（换写 gadget/consumer、oracle、BPF、授权刷写等）：见  
  [`analysis/POST_B_ALTERNATIVES.md`](analysis/POST_B_ALTERNATIVES.md)。  
  仅当出现 **新 [BIN] 理论** 时再开探针节点。
- 确定性 root：用户授权的 Magisk/刷写/EDL 写。

## 7. 文件

| 路径 | 说明 |
|------|------|
| `analysis/edeadlk_path.md` | EDEADLK 静态 |
| `analysis/pselect_shift_corrected.md` | SHIFT=+15 |
| `analysis/POST_B_ALTERNATIVES.md` | 终局 B 后可选方向（研究） |
| `analysis/CHAIN_MATRIX.md` | popsicle vs Leaf5 对照 |
| `probes/ghostlock_edeadlk_*.c` | EDEADLK / panic 对照 |
| `exploit/src/{main,fops,util}.c` | 集成 EDEADLK+pselect+prio |
| `exploit/targets/onyx-leaf5/target.h` | waiter 0x50、SHIFT=15、fops+0x10 |
