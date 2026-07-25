# EDEADLK → `remove_waiter` path on Leaf5 4.19.157 #245

> **节点**: S05 / routes / 10-ghostlock-true-uaf  
> **类型**: 静态路径图（stream A）  
> **日期**: 2026-07-26  
> **权威**: Leaf5 `vmlinux` 符号/已知 [BIN] + mainline **4.19** 控制流（与本机构建同族）；kheaders 仅线索  
> **脚本**: `map_edeadlk_paths.py`（可复跑完整 capstone dump）

---

## 0. 结论（先读）

| 问题 | 结论 | 置信度 |
|------|------|--------|
| Leaf5 是否仍含 CVE-2026-43499 代码面？ | **是** — `remove_waiter` 清 **`current->pi_blocked_on`**（`mrs sp_el0` + `str xzr,[…,#0x8d0]`），非 `waiter->task` | **[BIN]** |
| `rt_mutex_start_proxy_lock` 在 `-EDEADLK` 时是否调用 `remove_waiter`？ | **是**（4.19 标准路径；Leaf5 符号邻接与已知 prologue 一致） | **[BIN+SRC]** |
| 三 futex + `FULL_CHAINWALK` 下 EDEADLK 是否**可达**？ | **静态可达**：`CONFIG_FUTEX_PI=y`、`CONFIG_DEBUG_RT_MUTEXES` **未开** 时仍由 `RT_MUTEX_FULL_CHAINWALK` 强制 detect；`start_proxy` 使用 FULL | **[CFG+SRC]** |
| `CMP_REQUEUE_PI` 用户态如何看到？ | 成功 requeue → **`ret ≥ 1`**（常见 `1`）；EDEADLK 回滚 → **`ret=-1`, `errno=EDEADLK(35)`**；**勿把 ret=1 当 GhostLock** | **[SRC]** |
| Waiter 是否立刻被 wake？ | **4.19 `futex_requeue` 在 start_proxy 失败时不 wake、不 requeue**；WAIT 可继续阻塞至 timeout/signal；**真 UAF 在 WAIT 返回后** | **[SRC]** |

**一句话**: Leaf5 4.19 **具备** GhostLock 所需的 EDEADLK→`remove_waiter` 代码路径；先前 shell 探针大量 `CMP ret=1` 是**成功 requeue**，不能证明悬空 `pi_blocked_on`。

---

## 1. Leaf5 符号 VA（`target.h` / 已知 [BIN]）

| 符号 | VA | 备注 |
|------|-----|------|
| `rt_mutex_adjust_prio_chain` | `0xffffff8008149eb0` | chain walk；可返回 `-EDEADLK` |
| `task_blocks_on_rt_mutex` | `0xffffff800814ab50` | 设置 **victim** `task->pi_blocked_on` |
| `rt_mutex_start_proxy_lock` | `0xffffff800814ae80` | proxy 入口；[KNOWN] |
| `remove_waiter` | `0xffffff800814af10` | **BUG 点** |
| `futex_requeue` | `0xffffff800818e5a8` | `FUTEX_CMP_REQUEUE_PI` |
| `do_futex` | `0xffffff800818c498` | WAIT_REQUEUE_PI 内联于此（CORRECTED） |

**布局**: `task_blocks` → `start_proxy`（约 `0x330` 字节后）→ `remove_waiter`（紧随其后 `+0x90`）。符合 4.19 将 proxy 包装与 `remove_waiter` 相邻放置的典型链接序。

**Config（设备真源）**:
- `CONFIG_FUTEX_PI=y`
- `CONFIG_RT_MUTEXES=y`
- `# CONFIG_DEBUG_RT_MUTEXES is not set` → 死锁检测 **仅** 在 `chwalk == RT_MUTEX_FULL_CHAINWALK` 时开启（非 debug 全开）

---

## 2. `remove_waiter` — BUG 本体 [BIN]

**VA**: `0xffffff800814af10`

Leaf5 反汇编（节点 README / 既有 [BIN]）:

```text
mrs  x20, sp_el0                 ; current
...
str  xzr, [x20, #0x8d0]          ; current->pi_blocked_on = NULL
```

对应 4.19 源码语义（`kernel/locking/rtmutex.c`）:

```c
raw_spin_lock(&current->pi_lock);
rt_mutex_dequeue(lock, waiter);
current->pi_blocked_on = NULL;   /* BUG on proxy path: should be waiter->task */
raw_spin_unlock(&current->pi_lock);
```

| 路径 | `current` | `waiter->task` | 清谁的 `pi_blocked_on` | GhostLock? |
|------|-----------|----------------|------------------------|------------|
| `rt_mutex_slowlock` 自阻塞失败 | waiter | waiter | 自己（碰巧正确） | 否 |
| `rt_mutex_cleanup_proxy_lock` | 通常即 waiter | waiter | 自己 | 否 |
| **`rt_mutex_start_proxy_lock` EDEADLK 回滚** | **requeuer (CMP 线程)** | **WAIT 线程** | **错误地清 requeuer** | **是** |

`TASK_PI_BLOCKED_ON_OFF = 0x8d0` 已由 `task_blocks_on_rt_mutex` 交叉验证：`str x21,[x20,#0x8d0]`。

---

## 3. `rt_mutex_start_proxy_lock` 控制流 [BIN+SRC]

**VA**: `0xffffff800814ae80`  
**大小量级**: 至 `remove_waiter` 约 `0x90` 字节（薄包装 + 内联/`__rt_mutex_start_proxy_lock` 体）。

### 3.1 4.19 源码等价逻辑（Leaf5 同构）

```c
/* 对外 API */
int rt_mutex_start_proxy_lock(lock, waiter, task) {
    raw_spin_lock_irq(&lock->wait_lock);
    ret = __rt_mutex_start_proxy_lock(lock, waiter, task);
    raw_spin_unlock_irq(&lock->wait_lock);
    return ret;
}

int __rt_mutex_start_proxy_lock(lock, waiter, task) {
    if (try_to_take_rt_mutex(lock, task, NULL))
        return 1;   /* 已替 task 拿到锁 → requeue 侧应 wake */

    /* 强制 FULL chainwalk：即使 DEBUG_RT_MUTEXES=n 也 detect */
    ret = task_blocks_on_rt_mutex(lock, waiter, task,
                                  RT_MUTEX_FULL_CHAINWALK);

    /* 竞态：chain walk 期间 owner 释放 → 抹掉 EDEADLK */
    if (ret && !rt_mutex_owner(lock))
        ret = 0;

    if (unlikely(ret))
        remove_waiter(lock, waiter);   /* ← GhostLock 触发点 */

    return ret;  /* 0 = enqueued; 1 = acquired; <0 = -EDEADLK 等 */
}
```

### 3.2 返回值语义（proxy）

| ret | 含义 | `futex_requeue` 行为 |
|-----|------|---------------------|
| `1` | 已替 waiter 取得 rt_mutex | `requeue_pi_wake_futex`；计入成功 wake |
| `0` | waiter 已挂到 rt_mutex 树 | `requeue_futex` 迁 hb；**合法阻塞** |
| `<0`（典型 `-EDEADLK`） | 回滚已 `remove_waiter` | 清 `this->pi_state`；**break**；最终 `return ret` |

### 3.3 调用 `remove_waiter` 的条件

1. `try_to_take` 失败（锁上有 owner / 不可偷）  
2. `task_blocks_on_rt_mutex` 返回非 0  
3. 且回查时 `rt_mutex_owner(lock)` 仍非 NULL（否则 ret 被置 0，**不** remove）

---

## 4. `task_blocks_on_rt_mutex` 返回 `-EDEADLK` 的路径 [SRC+BIN offsets]

**VA**: `0xffffff800814ab50`

### 4.1 写入 victim 状态（成功 enqueue 时）

```c
waiter->task = task;          /* +0x30 on 4.19 Leaf5 [BIN] */
waiter->lock = lock;          /* +0x38 */
rt_mutex_enqueue(lock, waiter);
task->pi_blocked_on = waiter; /* +0x8d0 [BIN] */
```

此处 `task` 是 **WAIT_REQUEUE_PI 线程**，不是 requeuer。

### 4.2 返回非 0 的分支

| 分支 | 条件 | 是否已写 `pi_blocked_on` | 随后 `remove_waiter` 效果 |
|------|------|--------------------------|---------------------------|
| **Early dead lock** | `owner == task` | **否**（return 在 enqueue 前） | 清 requeuer 的 `pi_blocked_on`（多为 NULL）；**不**产生 victim 悬空 |
| **Chain walk** | `chain_walk && next_lock` 后 `rt_mutex_adjust_prio_chain` 返回 `-EDEADLK` | **是** | 从锁树 dequeue waiter，但 **不清 victim->pi_blocked_on** → **GhostLock  priming** |
| 其它错误 | 少见 | 视路径 | 同 chain 若已 enqueue |

### 4.3 `rt_mutex_adjust_prio_chain` 检出环 [SRC]

**VA**: `0xffffff8008149eb0`

```c
/* detect_deadlock = true when FULL_CHAINWALK (proxy) */
if (lock == orig_lock || rt_mutex_owner(lock) == top_task) {
    ret = -EDEADLK;   /* -35 */
    goto out_unlock_pi;
}
/* depth > max_lock_depth 亦可 -EDEADLK（保护，非 exploit 主路径） */
```

`top_task` = proxy 的 `task` 参数 = WAIT 线程。三 futex 环使 walk 回到 `orig_lock` 或发现 owner 即 top_task。

### 4.4 detect 门控（Leaf5 关键）

```c
/* CONFIG_DEBUG_RT_MUTEXES=n 时 */
detect = (chwalk == RT_MUTEX_FULL_CHAINWALK);
```

- `rt_mutex_start_proxy_lock` → **FULL** → detect **开**  
- 普通 `rt_mutex_slowlock` 默认 **MIN** → 无 debug 时 **不** 为 detect 走满 chain（early `owner==task` 仍可 EDEADLK）

→ GhostLock 依赖 **proxy + FULL**，不是任意 PI lock。

---

## 5. `futex_requeue` / `CMP_REQUEUE_PI` 用户态表面 [SRC]

**VA**: `0xffffff800818e5a8`  
`do_futex` 将 `FUTEX_CMP_REQUEUE_PI` 落到 `futex_requeue(..., requeue_pi=1)`。

### 5.1 调用点（requeue_pi 循环）

```c
get_pi_state(pi_state);
this->pi_state = pi_state;
ret = rt_mutex_start_proxy_lock(&pi_state->pi_mutex,
                                this->rt_waiter,
                                this->task);
if (ret == 1) {
    requeue_pi_wake_futex(this, &key2, hb2);
    drop_count++;
    continue;
} else if (ret) {
    /* -EDEADLK 等：已在 start_proxy 内 remove_waiter */
    this->pi_state = NULL;
    put_pi_state(pi_state);
    break;   /* 停止继续 requeue */
}
requeue_futex(this, hb1, hb2, &key2);  /* 仅 ret==0 */
...
return ret ? ret : task_count;
```

### 5.2 用户态可观测返回值

| 内核 `ret` | `syscall` 返回 | `errno` | 含义 |
|------------|----------------|---------|------|
| `task_count` 且无错误 | `≥0`（常见 **`1`**） | 0 | **成功 requeue/wake 了 N 个 waiter** — **不是** GhostLock |
| `-EDEADLK` | `-1` | **`35` EDEADLK** | proxy 回滚；**候选 GhostLock priming** |
| `-EAGAIN` | `-1` | EAGAIN | cmpval / 退出竞态；重试 |
| `-EINVAL` | `-1` | EINVAL | 参数/配对错误 |
| `-EFAULT` | `-1` | EFAULT | 用户指针 |

**CORRECTED 旧误读**:

| 旧探针观测 | 旧解释 | 正确解释 |
|------------|--------|----------|
| `CMP_REQUEUE_PI ret=1` 且 W 仍 `S` | “GhostLock 已触发” | **成功 requeue**：waiter 合法挂在 target PI 上 |
| 无 owner `LOCK_PI(f_pi_chain)` | “环已形成” | **环不完整** → 难进 EDEADLK |
| post-return 0x41 无 OOPS | “残差不 live” | 未 priming 悬空时，填栈不会被 PI walk |

### 5.3 EDEADLK 后 waiter 线程状态（4.19 要点）

```
start_proxy 失败:
  - remove_waiter: 从 pi_mutex 树摘掉 waiter
  - victim->pi_blocked_on 仍指向栈上 waiter   ← 错误残留
  - futex_requeue: 不 requeue_futex、不 mark_wake
  - waiter 仍睡在源 futex (WAIT_REQUEUE_PI / f_wait)
```

因此：

1. **Priming 成功**（错误状态已写入）在 CMP 返回 `-EDEADLK` 时即成立；  
2. **真栈 UAF** 要等 **WAIT 返回**（timeout / signal / 其它 wake）后栈帧弹出；  
3. 探针若期望 “CMP 后 WAIT 立即返回”，在 4.19 上**不保证**——应用 **timeout** 或主动 abort，再做 reclaim + `sched_setattr`。

---

## 6. 端到端触发编排（静态要求）

```text
W (waiter):
  LOCK_PI(f_pi_chain)                 // W 持 chain
  WAIT_REQUEUE_PI(f_wait → f_pi_target)  // 栈上 rt_mutex_waiter；阻塞

O (owner):
  LOCK_PI(f_pi_target)                // O 持 target
  LOCK_PI(f_pi_chain)                 // 堵在 W 上 → 形成环边

M (main / requeuer = current):
  CMP_REQUEUE_PI(f_wait, f_pi_target, nr_wake=1, nr_requeue≥1)
    → futex_requeue(requeue_pi=1)
    → rt_mutex_start_proxy_lock(pi_mutex, W.rt_waiter, W.task)
    → task_blocks_on_rt_mutex(..., FULL)
    → adjust_prio_chain 见环 → -EDEADLK
    → remove_waiter: 清 M->pi_blocked_on，留下 W->pi_blocked_on
    → return -EDEADLK 给用户态
```

环: `W --blocked-on--> f_pi_target --owned-by--> O --blocked-on--> f_pi_chain --owned-by--> W`

缺 **任一边**（尤其 O 不锁 chain）→ 常变成 **ret=1 成功 requeue**。

---

## 7. 与 CORRECTED 栈几何的关系

| 项 | 值 | 用途 |
|----|-----|------|
| WAIT 路径 | `do_futex` 内联，非 `futex_wait` | 深度模型 |
| `waiter->task` | **stack_top − 0x168** | T3 reclaim 对齐 |
| waiter base | ≈ stack_top − 0x198 | fake 布局 |
| 旧 KSP0−0x2B0 | futex_wait 模型 | **GhostLock 作废** |

EDEADLK 路径**不改变** waiter 在 WAIT 栈上的位置；它只决定 `pi_blocked_on` 是否在返回后悬空。

---

## 8. Checklist — “如何知道触发真的生效”

### 8.1 必过（静态/逻辑门）

- [ ] Runtime `uname` = `4.19.157` `#245` `g3d47a6619220`
- [ ] 三 futex 均参与；**O 已阻塞在 `LOCK_PI(f_pi_chain)`** 后再发 CMP
- [ ] W 在 CMP 前处于 `WAIT_REQUEUE_PI`（可 `/proc` 或探针 barrier）

### 8.2 用户态主信号（EDEADLK 回滚）

| # | 观测 | 判定 |
|---|------|------|
| 1 | `FUTEX_CMP_REQUEUE_PI` → **`ret=-1`, `errno=35 (EDEADLK)`** | **强阳性**（进入 remove_waiter 回滚） |
| 2 | **不是** `ret=1`（或其它 `>0` 成功计数） | 排除成功 requeue 假阳性 |
| 3 | CMP 后 W 仍挂在 **源** futex / 未完成 PI 接管 | 与 “break 且未 requeue_futex” 一致 |
| 4 | W 的 `WAIT_REQUEUE_PI` 在 timeout 后返回（或 signal） | 栈帧弹出 → 真 UAF 窗口打开 |

### 8.3 悬空指针 / UAF 消费（后置）

| # | 观测 | 判定 |
|---|------|------|
| 5 | W 返回后 **同线程** CFU reclaim（adjtimex 208B / 其它已证窗口）塑形 fake waiter @ −0x168 | T3 |
| 6 | 他线程 `sched_setattr(waiter_tid)` 后 **OOPS / 可控异常 / 可观测链 walk** | T4 消费悬空 `pi_blocked_on` |
| 7 | 无 EDEADLK 时同样 reclaim+sched_setattr **无** 异常 | 对照：排除无关崩溃 |

### 8.4 明确阴性 / 勿误判

| 观测 | 不要解释为 |
|------|------------|
| `CMP ret=1` + W 仍 `S` | GhostLock 已触发 |
| 仅 post-return 填 `0x41` 无 OOPS | “链死”（可能从未 priming） |
| 无 `f_pi_chain` 环的双 futex | 完整 CVE 触发 |

### 8.5 推荐探针顺序

1. `probes/ghostlock_edeadlk_detect.c` — 盯 **errno=EDEADLK**，不要只盯 WAIT 立刻返回  
2. 给 WAIT **足够 timeout**；记录 CMP 与 WAIT 的 ret/errno 矩阵  
3. 阳性后再接 `ghostlock_uaf_reclaim_consumer.c`（adjtimex + sched_setattr）

---

## 9. 路径可达性判定（本节点）

```text
代码面 remove_waiter BUG          ✅ [BIN] Leaf5
start_proxy → remove_waiter       ✅ [BIN+SRC] 4.19 同构 + VA 邻接
FULL_CHAINWALK detect             ✅ [CFG] DEBUG_RT_MUTEXES=n 仍 FULL
futex_requeue 传递 -EDEADLK       ✅ [SRC]
三 futex 用户编排可达 EDEADLK     🔄 需探针确认（静态不否决）
返回后栈 UAF + reclaim            🔄 依赖上一步阳性
```

**静态结论**: **EDEADLK → `remove_waiter` 在 Leaf5 4.19 上可达且可产生 victim 悬空 `pi_blocked_on`。**  
关闭真 UAF 链的唯一静态理由不存在；未验证的是**实机编排是否稳定打出 errno=35**（非代码缺失）。

---

## 10. 复跑反汇编

```bash
# 仓库根
uv run python leaf5/stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/analysis/map_edeadlk_paths.py
# 或 MCP leaf5-vmlinux: symbol_lookup / disasm_range
#   remove_waiter @ 0xffffff800814af10
#   rt_mutex_start_proxy_lock @ 0xffffff800814ae80
#   task_blocks_on_rt_mutex @ 0xffffff800814ab50
#   futex_requeue @ 0xffffff800818e5a8
```

---

## 11. 参考

- 本节点 `README.md` §1–§4.1（CORRECTED ret=1 误读）  
- `exploit/targets/onyx-leaf5/target.h` futex/rtmutex 段  
- mainline `v4.19` `kernel/locking/rtmutex.c` / `kernel/futex.c`  
- CVE-2026-43499 / Nebula GhostLock：proxy 回滚 + 错误 `current`  
- `leaf5/raw/config_ghostlock_relevant.txt`：`CONFIG_DEBUG_RT_MUTEXES` 未设置  
