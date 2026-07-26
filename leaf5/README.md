> **文档类型**: 索引文档（分析入口） | **状态**: ✅ 有效 | **最后更新**: 2026-07-26

# Leaf5 分析工作区

针对 **Onyx Leaf5** 的 GhostLock（CVE-2026-43499）适配调研。

## 从哪里读起

| 优先级 | 文档 | 说明 |
|--------|------|------|
| 1 | **[`stages/README.md`](stages/README.md)** | **流水线主索引**：按利用顺序的代码 + 效果记录 |
| 2 | 本文件 **「整条利用链」** | 每一步达成什么 / 卡在哪（叙事总览） |
| 3 | [`PROCESS_LOG.md`](PROCESS_LOG.md) | 时间线与原始证据（§51–§53 终局） |
| 4 | [`stages/.../10-ghostlock-true-uaf/`](stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/) | 真 UAF 与写矩阵权威节点 |
| 5 | [`docs/README.md`](docs/README.md) | 画像 / 偏移 / 路线等参考与归档 |

> 早期「qcedev 世界可写」「32-bit KGSL 完美重叠」「ret=1 即 GhostLock」「SHIFT=−46」等表述已废弃；以 **stages** 各节点 README 与 PROCESS_LOG 为准。

---

## 整条利用链（当前状况）

目标链（与 popsicle / 标准 GhostLock 写→root 同构）在 Leaf5 **#245** 上拆成前半与后半：

```text
S00 画像 → S01 偏移 → S02 泄漏 → S03 spray
       → S04/S05 触发真 UAF（EDEADLK）
       → reclaim 内核栈 waiter → sched_setattr PI walk
       → 受限写 fops → pipe physrw → cred/SELinux → root
```

**总评**：前半（到 **UAF 存在性**）已打通；后半（**受控写 → root**）在 shell 可达路径上 **终局 B 关闭**。无 uid=0。

### 链路总表

| 步 | 阶段 | 要达成什么 | 设备/二进制效果 | 状态 |
|----|------|------------|-----------------|------|
| 0 | **S00** 设备画像 | 确认 runtime 与镜像一致，CONFIG/安全面 | uname `#245` `g3d47a6619220`；`FUTEX_PI=y`；无 CFI；无 KPTI；SELinux Enforcing | ✅ |
| 1 | **S01** 偏移与栈 | 结构体偏移、waiter 栈位、CFU/pselect 几何 | waiter **0x50**（含 prio/deadline）；`task` @ stack_top−**0x168**；`PSELECT_WAITER_WORD_SHIFT`=**+15**（旧 −46 / 旧 KSP0−0x2B0 作废） | ✅ |
| 2 | **S02** Kernelsnitch | 泄漏 `mm_struct` → 推算 direct-map / KASLR | 时序碰撞可靠 FOUND mm；`KSNITCH_COLLISIONS=2` | ✅ |
| 3 | **S03** Heap spray | sk_buff 占位，供日后 fops/physrw reclaim | send 路径历史 4/4 成功；ION 对 shell 不可 open | ✅ |
| 4 | **S04** GhostLock 触发 | 三 futex + `CMP_REQUEUE_PI` 走 **EDEADLK 回滚** | `CMP ret=-1 errno=**35**`；**非**「ret=1 成功 requeue」 | ✅ |
| 5a | **S05** 真 UAF | `remove_waiter` 误清 `current->pi_blocked_on` → 栈悬空 | 静态 `[BIN]` + 用户态 EDEADLK 一致 | ✅ |
| 5b | **S05** UAF 活性 | reclaim 栈槽 + consumer 解引用 | 0x41 宽窗 + consumer → **kernel_panic**（证明 UAF live） | ✅ |
| 5c | **S05** 受控写 | shaped pselect 填 waiter 几何 + `sched_setattr` 走 PI chain，擦写 `ashmem_misc.fops` | 前置均满足（EDEADLK / reclaim / sched success=1）；**CFI oracle 全 errno=22**；无 fops 劫持 | ⛔ **终局 B** |
| 6 | **S06** E2E 集成 | exploit 串起泄漏→spray→EDEADLK→pselect→sched | 可跑到 reclaim/sched；**无** fops 写证据 | ⚠️ |
| 7 | **S07** 后半 | fops → pipe physrw → cred/SELinux → root | 源码在 `exploit/src/{fops,pipe,root}.c`；**从未在设备上生效** | ⛔ |

### 每一步在做什么（效果说明）

#### 前半链 — 已达成

1. **S00 画像**  
   固定分析对象：内核 banner、CONFIG、设备节点权限、是否与 `boot_a.bin` / `vmlinux` 同源。  
   **效果**：后续所有偏移与探针只对 `#245` 有效；镜像不一致则整链作废。

2. **S01 偏移与栈布局**  
   从 vmlinux 定 `rt_mutex_waiter`、`task_struct`（`pi_blocked_on`/`cred`）、pipe、ashmem misc 等；并算 WAIT_REQUEUE_PI 路径上 waiter 相对 stack_top 的位置。  
   **效果**：得到可编码常量（`target.h`），以及「哪条 CFU/syscall 能碰到 waiter」的几何判据。  
   **CORRECTED**：WAIT_REQUEUE_PI 的 waiter 在 **do_futex**，`task` @ **stack_top−0x168**；Leaf5 waiter 大小 **0x50**（多 prio/deadline）。

3. **S02 Kernelsnitch**  
   用户态大 mmap + futex 哈希碰撞侧信道，扫出本进程 `mm_struct` 内核地址。  
   **效果**：拿到内核堆/对象定向地址基（含 KASLR 相关推算），后续 spray / 伪造结构可寻址。

4. **S03 Heap spray**  
   用 socket 等路径喷射 `sk_buff`（及后续可能的 reclaim 形状）。  
   **效果**：为 **S07** 的 fops 覆写后的物理读写铺堆；**本身不提权**。当前因无 fops 写，spray 消费未进入生产路径。

5. **S04 / S05 真·GhostLock（EDEADLK）**  
   - Owner 持 PI 锁，构造三 futex 死锁图；  
   - `FUTEX_CMP_REQUEUE_PI` 内部检测死锁 → **EDEADLK 回滚**；  
   - 回滚路径 `remove_waiter` **错误清除** victim 的 `pi_blocked_on`（本应保留阻塞关系）。  
   **效果**：victim 返回用户态后，`pi_blocked_on` 仍指向 **已释放的内核栈 waiter** → **栈 UAF 原语成立**。  
   用户态信号：`CMP errno=35`；WAIT 侧常见超时返回。  
   **勿与旧模型混淆**：旧文档里的 `CMP ret=1` 只是成功 requeue，**不是**本 CVE 的 clear-`pi_blocked_on` 边。

6. **S05 UAF 活性证明（对照）**  
   EDEADLK 后用 adjtimex 等把栈槽刷成 `0x41`，再触发会 walk `pi_blocked_on` 的路径。  
   **效果**：**kernel_panic** → 证明悬空指针会在内核中被解引用（4A 级原语），不是「假阳性 errno」。

#### 后半链 — 理论目标与实际阻断

7. **S05 受控 reclaim（shaped pselect）— 已集成，写未命中**  
   用 **pselect** 用户缓冲按 `PSELECT_WAITER_WORD_SHIFT=+15` 对齐，把伪造 `rt_mutex_waiter`（含 lock/prio/deadline）刷进原 waiter 栈槽。  
   **效果（已达成）**：reclaim 形状可走通；`sched_setattr` 常 **success=1**（进入/完成某条 PI 相关路径）。  
   **效果（未达成）**：并未把可控数据写到 `ashmem_misc.fops`（CFI oracle：`pwrite` 仍 errno=**22**）。  
   有界矩阵（SHIFT 13–17 × LOCK_SHAPE 0–2；`lock=target−8` vs `fake_lock`；prio 粉刷）**全部未命中写** → **Outcome B**。

8. **S06 端到端**  
   `exploit/` 串 S02–S05 集成路径。  
   **效果**：一键可跑到 EDEADLK + shaped reclaim + sched；**停在写原语缺失**，不能宣称链完成。

9. **S07 fops / physrw / root — 代码就绪、链未点燃**  
   设计上：伪造 task 语境 → 改 ashmem/configfs `fops` → pipe 页物理读写 → 改 cred / 关 SELinux → root。  
   **效果**：**零**设备侧成功证据；阻塞点在 5c，不在 S07 实现 completeness。

### 与「旧 CFU 栈覆盖模型」的关系

| 模型 | 做法 | Leaf5 结论 |
|------|------|------------|
| 旧：live CFU 盖 `waiter->task` | GhostLock（常看 ret=1）后立刻 KGSL/binder/pselect 等 copy_from_user | **布局关闭**（过深/过浅/数据不可控/权限）；无 EDEADLK 时 post-return 0x41 也不崩 |
| 新：真 UAF + reclaim + PI walk | EDEADLK 清 `pi_blocked_on` → 同线程 shaped reclaim → `sched_setattr` | UAF ✅；**受控写 fops ❌（终局 B）** |

S05 路由 01–09 多针对旧模型或权限/深度死路；**当前权威写路径是路由 10**（见 stages 矩阵）。

### 终局一句话

```text
S00–S04 + EDEADLK + UAF panic     ✅  前半链与原语
shaped pselect → 受限写 fops      ⛔  shell 写矩阵关闭（Outcome B）
pipe / cred / root                ⛔  依赖写原语
uid=0                             ❌
```

**重开条件**（非「再扫一遍 SHIFT」）：新二进制理论（新 VA / 新 syscall 邻接 / 新写邻接），或用户明确授权的 Magisk/刷写等越权路径。细节见 [route 10 README](stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/README.md) 与 PROCESS_LOG §53。

**终局 B 之后还能怎么提权**（研究枚举，非开放待办清单）：  
[stages/.../10/.../POST_B_ALTERNATIVES.md](stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/analysis/POST_B_ALTERNATIVES.md)  
—— 优先：换 PI store 目标/gadget + 非 CFI oracle；并行：BPF/perf 可达性；确定性：授权刷写。

---

## 设备快照

| 项 | 值 |
|----|-----|
| 型号 | Onyx Leaf5（`ONYX/TabBoox/...`） |
| Android | 13 / API 33 |
| Kernel | `4.19.157-perf-g3d47a6619220-dirty` #245 |
| 平台 | Qualcomm SM6350 (LAGOON) |
| AVB | unlocked |
| SELinux | Enforcing |
| GhostLock CONFIG | `FUTEX_PI=y`，**无 CFI**，**无 KPTI** |

---

## 目录结构

```
leaf5/
├── README.md              # 本文件（链总览 + 入口）
├── PROCESS_LOG.md         # 操作流水（终局权威过程）
├── stages/                # ★ 流水线（代码 + 节点效果文档）
│   ├── README.md
│   ├── Makefile
│   └── S00 … S07 …
├── docs/                  # 参考与历史文档（见 docs/README.md）
├── edl/                   # EDL 只读提取 boot/分区（见 edl/README.md）
├── raw/                   # 设备原始采集（config / kheaders / vmlinux*）
├── scripts/               # uv 入口 shim → stages/*/scripts
└── boot_a.bin             # gitignore；runtime 对齐的 boot 镜像
```

仓库根目录 `../exploit/`：Leaf5 专用 exploit（`targets/onyx-leaf5`），对应 S02–S07 集成实现。

---

## 工具

```bash
# 仓库根：顶层 uv / .venv
uv sync
uv run leaf5-collect
uv run leaf5-extract-offsets

# 探针 → out/stages/.../{arm32|arm64}/
make -C leaf5/stages \
  SRC=S05-stack-overwrite/routes/10-ghostlock-true-uaf/probes/ghostlock_edeadlk_detect.c \
  BITS=64
```

产物布局：[`../BUILD_OUTPUT.md`](../BUILD_OUTPUT.md)。  
boot / vmlinux 来源：[`edl/README.md`](edl/README.md)（只读 dump）→ `boot_a.bin` → `raw/vmlinux.elf`。

---

## 文档地图

| 位置 | 说明 |
|------|------|
| [stages/](stages/README.md) | **主索引**（矩阵 + 链摘要） |
| [PROCESS_LOG.md](PROCESS_LOG.md) | 时间线 §51–§53 |
| [docs/](docs/README.md) | ANALYSIS、栈布局、验证报告、归档 |
| [edl/](edl/README.md) | EDL 提取流程（无改镜像 / Magisk） |
| [raw/](raw/README.md) | 原始采集 |
| [../exploit/targets/onyx-leaf5/target.h](../exploit/targets/onyx-leaf5/target.h) | 偏移代码真源 |

---

*最后更新: 2026-07-26 — 整条利用链分步效果与终局 B 写入本 README；旧「~70% / KSP0−0x2B0」总览作废*
