# CORRECTED pselect geometry vs GhostLock waiter

**日期**: 2026-07-26  
**节点**: S05-10 analysis  
**权威**: PROCESS_LOG §47 + 本文件 + `recompute_pselect_shift_corrected.py`  
**范围**: 静态栈几何 only — **geometry reopen ≠ UAF success**

---

## 1. 旧 SHIFT=-46 为何关闭（错误深度）

`S01/scripts/compute_pselect_shift.py` 用 **futex_wait 内嵌** `futex_q.waiter` 模型：

| 量 | 值 |
|----|-----|
| Futex 深度 | `sys_futex+do_futex+futex_wait` = **0x3d0** |
| Waiter SP | futex_wait SP+**0x50** |
| Waiter abs | **-0x380** |
| Fd_set abs | **-0x210**（pselect 0x260, stack_fds@+0x50） |
| Δ / SHIFT | **-368 B / −46** |
| NFDS=640 可达 | **0/8**（global words [−46..−39] 全负） |

→ 对 **GhostLock / `FUTEX_WAIT_REQUEUE_PI`** 作废：该路径 waiter 在 **do_futex**，不进 `futex_wait`（§47 CORRECTED）。

---

## 2. CORRECTED 理论 SHIFT

同源 `stack_top`（异常入口帧两侧抵消）；futex 侧只计到 do_futex：

```
task_abs        = -(sys_futex 0x70 + 0xF8) = stack_top - 0x168   [BIN]
waiter_base_abs = task_abs - 0x30          = stack_top - 0x198
fdset_abs       = -0x260 + 0x50            = stack_top - 0x210   (同旧脚本 pselect 侧)
delta_bytes     = -0x198 - (-0x210)        = +0x78 (120)
SHIFT           = 120 / 8                  = +15
```

**>>> `PSELECT_WAITER_WORD_SHIFT = 15` <<<**

脚本：`analysis/recompute_pselect_shift_corrected.py`  
（`stack_top` 与 `__arm64_sys_futex` 0x70 一致性见脚本头注释 / assert。）

---

## 3. Reachability 表（NFDS=640，words_per_set=10，global [0..29]）

| 字段 off | word | global | set[idx] | 可达 |
|----------|------|--------|----------|------|
| +0x00 tree_entry.parent | 0 | 15 | out[5] | OK |
| +0x08 tree_entry.rb_right | 1 | 16 | out[6] | OK |
| +0x10 tree_entry.rb_left | 2 | 17 | out[7] | OK |
| +0x18 pi_tree_entry.parent | 3 | 18 | out[8] | OK |
| +0x20 pi_tree_entry.rb_right | 4 | 19 | out[9] | OK |
| +0x28 pi_tree_entry.rb_left | 5 | 20 | ex[0] | OK |
| +0x30 **task** | 6 | 21 | ex[1] | OK |
| +0x38 lock | 7 | 22 | ex[2] | OK |

**reachable: 8/8** — 全部 waiter 字段落在 `in/out/ex` 三块 fd_set 词内（旧 SHIFT=−46 为 0/8）。

---

## 4. 结论

| 项 | 结论 |
|----|------|
| 旧 SHIFT=−46 | **CLOSED 旧几何** — 深度模型错（futex_wait），非终局 |
| CORRECTED SHIFT | **+15**（理论，[BIN] 深度 + 旧 pselect 帧） |
| 字段可达 NFDS=640 | **8/8 全 OK** → **几何 REOPEN** |
| UAF / 利用 | **未证明** — 仍需 EDEADLK 真触发 + 返回后 reclaim + consumer |

勿将本结果写入 target.h 关键路径，直到设备探针确认 post-return pselect 与 stale waiter 叠放语义。
