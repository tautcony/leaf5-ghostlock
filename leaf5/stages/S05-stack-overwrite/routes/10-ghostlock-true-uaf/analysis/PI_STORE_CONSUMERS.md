# PI walk store / `pi_blocked_on` consumer 清单（Leaf5 #245）

> **日期**: 2026-07-26  
> **用途**: 支撑非 CFI oracle + 换 consumer/写目标（POST_B 方向 A/B）  
> **工具**: leaf5-vmlinux disasm + nm

---

## 1. `pi_blocked_on` load 站点（task+0x8d0）

| 符号 | VA | 行为摘要 |
|------|-----|----------|
| `rt_mutex_adjust_prio_chain` | `0xffffff8008149eb0` | `ldr x25,[x19,#0x8d0]`；主 chain；`waiter->lock` trylock；可 `bl rb_*` |
| `rt_mutex_adjust_pi` | `0xffffff8008149e00` | 短入口：读 `pi_blocked_on`，prio/deadline 比较后 `bl adjust_prio_chain` |
| `task_blocks_on_rt_mutex` | `0xffffff800814ab50` | **写入** `task->pi_blocked_on`（enqueue） |
| `remove_waiter` | `0xffffff800814af10` | BUG：`str xzr,[current,#0x8d0]`（清错主体） |
| `mark_wakeup_next_waiter` | `0xffffff800814a7a8` | 不直接 load 0x8d0；操作 current `pi_waiters` + `rb_erase_cached` + `rt_mutex_setprio` |

用户态可触发 `adjust_pi` / chain 的常见入口：

| Consumer | 用户接口 | 备注 |
|----------|----------|------|
| `sched_setattr` | syscall 274 | 现有默认；success≠store |
| `setpriority` / `nice` | 改 prio → `rt_mutex_adjust_pi` | 本轮矩阵 |
| `sched_setscheduler` | 策略/优先级 | 本轮矩阵 |
| `FUTEX_LOCK_PI` | 新 PI 锁 | 可能 enqueue 新 waiter，副作用大 |
| exit 路径 | 进程退出 | 未探针（危险） |

---

## 2. chain 内关键依赖（写 gadget 前置）

来自 `rt_mutex_adjust_prio_chain` 前段 [BIN]：

1. `pi_blocked_on` 非 NULL（residual waiter）  
2. `waiter->lock`（+0x38）可 `_raw_spin_trylock`  
3. `waiter->prio`（+0x40）与 `task->prio`（+0xac）关系决定是否 early-out  
4. 随后才进入 dequeue / rb / setprio 等 **store**

→ **empty_zero_page 作 lock**（全 0 = unlocked）是 stage oracle 的试验性选择；生产仍用 spray `fake_lock`。

---

## 3. 非 CFI 写目标

| 目标 | 地址构造 | 观测 |
|------|----------|------|
| `init_uts_ns.name.sysname` | `data_addr(INIT_UTS_NS)+0x4` **[BIN]** | `uname().sysname` ≠ `Linux` 或含 `GLORACLE` |
| `ashmem_misc.fops` | 旧路径 | CFI pwrite（终局 B 全 22） |
| `empty_zero_page` | 哨兵 | 难用户态读回 |

Marker：`UTS_ORACLE_MARKER_LE = 0x454c4341524f4c47`（`"GLORACLE"` LE）。

---

## 4. 与代码的对应

| 产物 | 路径 |
|------|------|
| stage UTS oracle + multi-consumer | `probes/ghostlock_uts_oracle.c` |
| BPF/perf 可达性 | `probes/bpf_perf_reach.c` |
| exploit `WRITE_ORACLE=uts` | `util.c` `pselect_write_target` |
| exploit `PI_CONSUMER=...` | `main.c` `consumer_thread` |
