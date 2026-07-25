> **路由**: GhostLock 真·栈 UAF（pi_blocked_on 悬空）| **状态**: 🔄 2026-07-26 重开分析  
> **权威**: 本节点 + `PROCESS_LOG` §51；冲突以本节点最新证据为准

# 10 — CVE-2026-43499 全链路重述 + Leaf5 可能性矩阵

## 1. 漏洞机制（CVE 级，与设备无关）

来源：Nebula IonStack / AlmaLinux 摘要 + Leaf5 `remove_waiter` 反汇编。

1. Waiter 线程在 `FUTEX_WAIT_REQUEUE_PI` 中，`rt_mutex_waiter` 位于**本线程内核栈**。
2. 三 futex 死锁环：`f_pi_chain`（waiter 先持）→ `f_pi_target`（owner 先持后堵在 chain）→ requeue 到 target。
3. `FUTEX_CMP_REQUEUE_PI` 经 `rt_mutex_start_proxy_lock` 代理加锁；chain walk 检出环 → **`-EDEADLK` 回滚**。
4. 回滚调用 `remove_waiter()`，**错误地**清 `current->pi_blocked_on`（requeuer），而非 `waiter->task->pi_blocked_on`。
5. Waiter 被唤醒返回用户态时，`task->pi_blocked_on` 仍指向**已弹出的栈帧** → **栈 UAF / dangling pointer**。
6. 任意后续对该 task 的 PI chain walk（典型：`sched_setattr`）解引用悬空 waiter。

Leaf5 [BIN] `remove_waiter @ 0xffffff800814af10`：

```
mrs  x20, sp_el0                 ; current
...
str  xzr, [x20, #0x8d0]          ; current->pi_blocked_on = NULL  (TASK_PI_BLOCKED_ON=0x8d0)
```

→ **4.19.157 #245 仍含错误 `current` 清除逻辑**（漏洞代码面存在）。

## 2. 完整利用链（标准）

| 步 | 动作 | 产出 |
|----|------|------|
| T0 | 信息泄漏（KASLR / mm / physmap） | slide、可喷射页 |
| T1 | 三 futex 编排 + `CMP_REQUEUE_PI` 走 **EDEADLK 回滚** | `pi_blocked_on` 悬空 |
| T2 | Waiter 从 futex **返回**（栈帧“释放”） | 悬空指向 freed stack |
| T3 | **同线程** syscall 大块 CFU 回收该栈深度，写入 fake `rt_mutex_waiter` | 可控 UAF 内容 |
| T4 | 他线程 `sched_setattr(waiter_tid)` 触发 PI walk | 受限写（rb_erase 等） |
| T5 | 升格：fops / inet6_protos / direct `init_cred`+SELinux | root |

要点：原语是 **dangling `pi_blocked_on` + 返回后栈回收**，**不是**「wait 仍阻塞时跨线程写内核栈」。

## 3. popsicle（6.12 Android16）对照

参考：<https://github.com/x-spy/CVE-2026-43499-popsicle>

| 步 | popsicle | 说明 |
|----|----------|------|
| T0 | KernelSnitch 类 + target 生成 | 有 |
| T1–T2 | 同三 futex 模型（`main.c` waiter/owner/consumer） | 有 |
| T3 | **`do_pselect_fake_lock_route()`** 在 WAIT **返回后** 立刻跑 | fd_set 叠 stale waiter |
| T4 | `sched_setattr_tid` consumer | 有 |
| T5 | **`run_direct_root_stage`**：读 `__entry_task` → 写 `real_cred`/`cred`=`init_cred`，`selinux_enforcing=0` | 直接 root，非 DirtyMode |

pselect 侧字段布局（popsicle `fops.c`）：waiter words 含 `task`/`lock`/`fake_*`，`PSELECT_WAITER_WORD_SHIFT` 由 6.12 栈几何决定（Leaf5 不可照搬）。

## 4. Leaf5 CORRECTED 事实（ verbatim）

| 项 | 值 | 证据 |
|----|-----|------|
| Waiter 路径 | `WAIT_REQUEUE_PI` 在 **do_futex 内联**，非 `futex_wait` | PROCESS_LOG §47 |
| `rt_mutex_init_waiter` | `x29 - 0xc8` @ do_futex | [BIN] |
| **`waiter->task`** | **`stack_top − 0x168`** | [BIN] §47 |
| 旧 `KSP0−0x2B0` | 仅 futex_wait 模型；**对 GhostLock 作废** | CORRECTED |
| `PSELECT_WAITER_WORD_SHIFT` 旧值 | **−46** | 基于 **错误** futex_wait 深度 |
| pselect SHIFT 重算（理论） | waiter_base≈`−0x198`，fdset≈`−0x210` → **SHIFT≈+15**（可达） | `analysis/recompute_pselect_shift_corrected.py` |
| pselect 旧结论 ❌ | 几何基于过时 waiter 深度；**几何需重开**；UAF 触发条件另论 | 本节点 |
| shell CFU 对齐 −0x168 | binder cookie；**adjtimex 208B 宽窗** | S05-08 |
| post-return 0x41 + unlock 无 OOPS | S05-08/§49–50 | **未证明 EDEADLK 已触发**（见下） |
| live-window 同线程 CFU | ❌ 信号先 abort WAIT | S05-08 |
| S00–S04 | ✅ | stages 总览 |
| S05 旧栈盖 task 叙事 | ❌（模型偏） | 本节点 CORRECTED |
| S07 | ⛔ 仍依赖 T3–T5 | |

### 4.1 对先前「残差不 live」的 CORRECTED 解读

| 观测 | 旧解释 | 新解释（待探针） |
|------|--------|------------------|
| `CMP_REQUEUE_PI ret=1` 且 W 仍 `S` | GhostLock 已触发 | **成功 requeue**，**不是** EDEADLK 回滚；waiter 仍合法阻塞 |
| adjtimex 0x41 后无 crash | 残差不被解引用 | 若未挂悬空 `pi_blocked_on`，填栈本就不会被 PI walk |
| 信号 abort 后 CFU | live 窗口不可用 | 真链本来就是 **返回后** reclaim，不依赖 live 阻塞写 |

## 5. 可能性矩阵（排序）

| 优先级 | 候选 | 状态 | 关闭/开放理由 | 引用 |
|--------|------|------|---------------|------|
| **P0** | **EDEADLK 真触发 + 返回后 reclaim + sched_setattr** | **OPEN** | 漏洞代码存在；先前探针多为 ret=1 成功 requeue，未验证悬空 | 本节点 probes |
| **P0** | **pselect 几何 @ CORRECTED −0x168** | **REOPEN 静态** | 旧 SHIFT=−46 用错深度；理论 SHIFT≈+15 字段可达 | analysis/ |
| P1 | adjtimex 208B 作 T3 reclaim（宽窗盖 −0x168） | **OPEN** | shell CFU 已证；需接 EDEADLK + shaped fake + consumer | S05-08 + 本节点 |
| P1 | binder GET_NODE_DEBUG_INFO cookie 作 T3 | OPEN 次优 | 静态 HIT；窗口窄于 adjtimex | S05-08 |
| P2 | popsicle 式 direct `init_cred`（T5） | 依赖 T3–T4 | 代码在 exploit；无原语前 ⛔ | exploit main/fops |
| — | pselect SHIFT=−46 不可达 | **CLOSED 旧几何** | 被 CORRECTED 深度取代，不作为终局 | S05-01（几何作废） |
| — | live 同线程 CFU 盖阻塞 waiter | **CLOSED** | 架构不可能；信号 abort | S05-08 |
| — | post-return 0x41 无 OOPS ⇒ 链死 | **CLOSED 作为充分条件** | 未绑定 EDEADLK；不单独重跑 | S05-08 §49 |
| — | KGSL list CFU 盖 task | **CLOSED** | 过深 ~0x1A0 | S05-07e |
| — | kgsl 32-bit RB_ISSUEIBCMDS | **CLOSED** | compat 拒绝 | S05-07d |
| — | personality→TIF_32BIT | **CLOSED** | 不设位 | S05-07g |
| — | binder_thread_write 数据可控 | **CLOSED** | 内核指针非用户可控 | S05-02 |
| — | do_select / sendmsg 深度 | **CLOSED** | 无重叠 / 不足 | S05-03/04 |
| — | qcedev shell | **CLOSED** | drmrpc/SELinux | S05-06 |
| — | PR_SET_MM_MAP reclaim（桌面 Nebula） | **CLOSED/不适用** | vmlinux 无 `prctl_set_mm_map`；Android 4.19 非此路径 | [BIN] sym |
| — | heap physrw 绕过 T3 | **环依赖** | 需先有写原语 | S07 |
| ⛔ | Magisk/刷写 | 非 exploit | 需用户授权 | AGENTS |

## 6. 本节点文件

| 文件 | 作用 |
|------|------|
| `analysis/edeadlk_path.md` | **EDEADLK→remove_waiter 静态路径图 + 用户态 checklist** |
| `analysis/map_edeadlk_paths.py` | capstone 复跑 remove_waiter / start_proxy / futex_requeue |
| `analysis/recompute_pselect_shift_corrected.py` | CORRECTED waiter 下 SHIFT |
| `analysis/CHAIN_MATRIX.md` | 与 popsicle 对照摘要（本 README 为主） |
| `probes/ghostlock_edeadlk_detect.c` | 检测 EDEADLK/立即返回 vs 成功 requeue |
| `probes/ghostlock_uaf_reclaim_consumer.c` | EDEADLK 后 adjtimex 0x41 + sched_setattr |
| `probes/ghostlock_edeadlk_adjtimex_only.c` | 无 consumer 对照（存活） |

## 7. 结果（2026-07-26 设备 #245）

| 探针 | 效果 | 原因 / 证据 |
|------|------|-------------|
| 静态 `edeadlk_path.md` | ✅ 代码面可达 | `remove_waiter` 清 current@+0x8d0；proxy EDEADLK→remove_waiter |
| pselect SHIFT 重算 | ✅ **+15** | 8/8 字段 OK；旧 −46 作废 |
| `ghostlock_edeadlk_detect` | ✅ EDEADLK | `CMP ret=-1 errno=35`；WAIT ETIMEDOUT；存活 |
| `ghostlock_edeadlk_adjtimex_only` | ✅ 存活 | EDEADLK+adjtimex、**无** consumer → 不 panic |
| `ghostlock_uaf_reclaim_consumer` | ✅ **kernel_panic** | EDEADLK→timeout→adjtimex→consumer 后掉线；`bootreason=kernel_panic,null` |

**Outcome 4A**: 真 GhostLock 悬空 `pi_blocked_on` 可 priming；返回后 CFU 回收 + `sched_setattr` 解引用可控内容 → **panic**。  
**未完成**: shaped fake → 稳定受限写 / root（0x41 仅证明 live）。

## 8. 下游

1. KernelSnitch slide + spray 页构造合法 fake waiter（`task=init_task` 等）。
2. T3 用 pselect **SHIFT=15** 或 adjtimex 宽窗。
3. 接 popsicle `direct_root` / `exploit/` fops。
4. **禁止**将 `CMP ret=1` 当作 GhostLock 成功。
