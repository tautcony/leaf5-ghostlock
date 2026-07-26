# 第二条件 / 多洞联用清单 + 设备独立 LPE CVE 候选

> **日期**: 2026-07-26  
> **设备**: Onyx Leaf5 · kernel **4.19.157-perf** `#245` `g3d47a6619220` · Android 13 · `security_patch=2026-04-01` · SoC lito · shell `u:r:shell:s0`  
> **前提**: 路由 10 **终局 B**（ashmem fops 受限写矩阵）已关闭；EDEADLK UAF / reclaim / panic 已证。  
> **目的**:  
> 1. 记录「GhostLock + 第二条件/第二洞」全部候选，**每项写清思路**；  
> 2. 另列「**不依赖 GhostLock 也能提权**」的 CVE / 攻击面候选，并做静态闸门。  
> **权威冲突时**: 本节点 README + `PROCESS_LOG` §51–§53 + `POST_B_ALTERNATIVES.md`。  
> **状态**: 清单与闸门（**未**宣称任何第二 CVE 已可利用；未修/已修必须以 vmlinux patch-gap 为准）。

---

## 0. 阅读约定

### 0.1 为何「新内核有人 root」≠「旧内核没洞」

公开 full-chain 成功，通常赢在 **后半布局 + 策略面**，不是赢在「触发 UAF 更容易」：

| 层 | 公开成功样本（常 5.x/6.x 或 kernelCTF） | Leaf5 `#245` |
|----|------------------------------------------|--------------|
| GhostLock 触发（EDEADLK） | 有 | **已有 ✅** |
| 可控 reclaim | 几何友好（如 `PR_SET_MM_MAP`/CEA） | pselect/adjtimex 可 paint，**有用 store 未证** |
| 写目标邻接 | `inet6_protos` 等整齐 | ashmem fops 邻接不满足 → 终局 B |
| SELinux / CAP | 依目标 | Enforcing；shell CapEff=0；BPF EACCES |
| CFI / KPTI | 常更强 | **无内核 CFI、无 KPTI**（后半反而松） |

### 0.2 GhostLock 已有筹码 vs 缺口

**已有（V1 资产）**

| 资产 | 来源 |
|------|------|
| runtime / vmlinux 对齐 | S00–S01 |
| `mm_struct` 泄漏 | S02 |
| sk_buff spray | S03 |
| EDEADLK + 悬空 `pi_blocked_on` | S04 / S05-10 |
| 栈 reclaim 塑形 residual | pselect / adjtimex |
| PI consumer 可 walk | `sched_setattr` 等 |
| 无 CFI / 无 KPTI | CONFIG |

**缺口（G1–G6，第二条件要填的）**

| ID | 缺口 |
|----|------|
| **G1** | 可证明的、落在「有用槽」上的 store |
| **G2** | 满足 rb_erase 邻接约束的写目标（或绕过 trylock） |
| **G3** | 更好的 reclaim 深度/稳定性 |
| **G4** | 更高 SELinux 上下文 / capability（开 BPF、ION、qce…） |
| **G5** | 任意读（放大 kimage / cred / policy） |
| **G6** | 独立任意写 / page-cache 写（可不吃 GhostLock gadget） |

### 0.3 联用模式

| 模式 | 含义 |
|------|------|
| **L** Leak+ | 第二洞给读/泄漏，GhostLock 负责写 |
| **W** Write+ | 第二洞给写，GhostLock 只 priming 或只 leak |
| **R** Reclaim+ | 改善 residual 占位 |
| **C** Context+ | shell → system/vendor，再开设备面 |
| **I** Independent | 第二洞自己 LPE；GhostLock 可选加速 |
| **S** Soften | 改 SELinux/cap 位后再接现有 gadget |

### 0.4 静态闸门（每条候选必过）

1. **代码面**：符号是否在 `vmlinux` / `CONFIG=y`？  
2. **补丁面**：4.19.157 vendor 是否 cherry-pick？（`security_patch` **只是弱提示**）  
3. **触达面**：shell 节点 mode + SELinux allow + capability？  
4. **缺口面**：填 G1–G6 哪一格？  
5. **正交面**：能否复用 S02 leak / S03 spray / 无 CFI？

**判定符号**

| 符号 | 含义 |
|------|------|
| ✅ 闸门通过（面存在） | 可开研究，非已利用 |
| ⚠️ 部分通过 / 未知补丁 | 需 patch-gap 或权限探针 |
| ❌ 闸门失败 | 本设备当前上下文不做 |
| ⛔ 与 stages 已关闭结论冲突且无新理论 | 勿重打 |

---

## 1. 联用清单：第二条件 / 第二洞（每项思路）

### 1.1 仍吃 GhostLock（优先，工作量相对可控）

#### S1 — 换写目标：其它 shell 可达 `*fops` / misc 邻接

| 项 | 内容 |
|----|------|
| **模式** | W 目标（同一 rb_erase gadget） |
| **填缺口** | G1、G2 |
| **闸门** | ✅ ashmem 已证邻接失败；其它 0666 节点待枚举 |
| **思路** | 终局 B 否的是「`ashmem_misc.fops−8` 当 wait_lock」这一 **特定几何**，不是「PI walk 永不 store」。同一 gadget 需要：`*(u32*)(target−8)==0`（unlocked）、`target` 为可写指针槽、后续字段不崩。扫描 `/dev` 中 shell 可 open 节点 → 映射到 vmlinux `miscdevice`/cdev → 检查 fops 指针前后 0x20 是否像 fake `rt_mutex_base`。 |
| **验收** | 非 CFI oracle（`uname` / spray 哨兵）读回差异，再 CFI 类 pwrite |
| **不做** | 重跑 ashmem × SHIFT 13–17 同构矩阵 |

#### S2 — 写到堆对象：pipe_buffer / sk_buff / file 内指针

| 项 | 内容 |
|----|------|
| **模式** | W → 二次利用 |
| **填缺口** | G1、G6（间接） |
| **闸门** | ✅ spray 能力有；地址需 S02/S03 可控 |
| **思路** | 若一次受限写只能写「指针」且邻接苛刻，把 `target` 对准 **已知内容的堆对象字段**（pipe buf ops、skb->data 旁指针等），再用用户态读写 pipe/socket 放大成 physrw。S07 源码已有 fops→pipe 骨架，缺的是 **第一次可证明 store**。 |
| **验收** | spray 页或 pipe 内容出现预期 qword |

#### S3 — 写策略软点：`selinux_enforcing` / 相关 `.data`

| 项 | 内容 |
|----|------|
| **模式** | S |
| **填缺口** | G1、G4（间接） |
| **闸门** | ⚠️ 符号可能在 data；Android 上位置与副作用需 [BIN] |
| **思路** | 无 CFI 时，把 enforcing 打成 0 或改 AVC 相关，可能打开原 shell 不可达的 ioctl/BPF。前提仍是 **受限写能命中该槽且邻接合法**。 |
| **风险** | 写错即不稳定；需先 oracle |

#### S4 — 桌面 DirtyMode 槽：`modprobe_path` / `core_pattern` / `poweroff_cmd`

| 项 | 内容 |
|----|------|
| **模式** | W 字符串 |
| **填缺口** | G1 |
| **闸门** | ✅ 符号在 vmlinux（POST_B 已列 VA）；触发面 **低** |
| **思路** | 桌面靠 usermodehelper / core_pipe 提权。Android 13 shell 通常 **不会** 走到 `call_usermodehelper(modprobe)`；`core_pattern` 写后仍受 SELinux 与 dumpable 约束。 |
| **结论** | 仅当已有任意写 **且** 构造出触发面时再评；**非第一优先** |

#### S5 — 换 consumer / 换 store 几何（非新 CVE）

| 项 | 内容 |
|----|------|
| **模式** | 同 UAF |
| **填缺口** | G1、G2 |
| **闸门** | ✅ `pi_blocked_on` load 站点已表（见 `PI_STORE_CONSUMERS.md`） |
| **思路** | `sched_setattr` success=1 ≠ store。其它入口（`setpriority` / `nice` / `sched_setscheduler` / `FUTEX_LOCK_PI` / 部分 wake 路径）对 `waiter->lock` trylock、prio 早退、后续 `rb_*` store 集合可能不同。先反汇编「唯一可控 `str` 的地址表达式」，再探针。 |
| **不做** | 无新 VA 的盲扫 |

#### S6 — residual.task = spray fake `task_struct`

| 项 | 内容 |
|----|------|
| **模式** | 变体 C（popsicle T5 类） |
| **填缺口** | G1（间接改 cred / pi 树） |
| **闸门** | ⚠️ 4.19 `task_struct` 巨大；`pi_lock` 必须合法 |
| **思路** | 当前 craft 多用 `INIT_TASK`。若 residual.task 指向可控喷页，walk 中对 task 字段的写可能别名到有用槽。最小证伪：fake task 稳定存活 + 某已知字段变化（依赖 UTS/spray oracle）。 |
| **风险** | 一点不对即 panic（0x41 对照已证解引用） |

#### S7 — Store oracle 方法论（强制前置）

| 项 | 内容 |
|----|------|
| **模式** | 验证手段 |
| **填缺口** | 证明 G1 |
| **闸门** | ✅ `WRITE_ORACLE=uts` / `ghostlock_uts_oracle` 管线已有；zero-lock 会 panic |
| **思路** | CFI pwrite errno=22 **只**否证 ashmem fops 劫持，**不**否证「内核零写」。任何 S1–S6 新 gadget **第一目标**应为可观测槽（`init_uts_ns.name`、spray 哨兵），再瞄准 fops/cred。 |
| **设备事实** | empty_zero_page 作 lock → walk panic；应用 spray `fake_lock` |

---

### 1.2 驱动 / 子系统第二洞（可与 GhostLock 正交）

#### Q1 — KGSL / Adreno 独立内存损坏（**最高研究优先级之一**）

| 项 | 内容 |
|----|------|
| **模式** | I 或 W；L 可用 S02 |
| **填缺口** | G5/G6 或整条 I |
| **闸门** | ✅ `CONFIG_QCOM_KGSL=y`；`/dev/kgsl-3d0` shell 0666 历史可达；符号 `kgsl_ioctl_*` / sparse / gpuobj 大量存在 |
| **思路** | stages 关闭的是 **「GhostLock 后 CFU 盖 waiter->task」布局**，**不是**「KGSL 无独立漏洞」。公开族包括 VBO/UAF（如 CVE-2024-23380 及相关）、历史 kgsl UAF、GPU 命令路径。联用：S02 给地址 → KGSL 给写；或 KGSL 独立 root。 |
| **下一步** | 对公开补丁做 **binary patch-gap**（引入提交是否在 #245）；禁止把已关 CFU 节点当新洞重打 |

#### Q2 — Adreno GPU 固件 / micronode 类（如 CVE-2025-21479/21480 族）

| 项 | 内容 |
|----|------|
| **模式** | I |
| **填缺口** | G6 / 整链 |
| **闸门** | ⚠️ 固件侧；是否进 Onyx 固件未知；安全补丁 2026-04 可能已含部分 2025 项 |
| **思路** | 野外部署链常见「WebView/shader → GPU mem → root」。从 adb shell 需能提交等价 GPU 命令序列。与 GhostLock 正交；验证成本在 **固件版本 + 补丁**。 |
| **结论** | 先查设备 GPU 固件版本 / 厂商公告，再定是否 dig |

#### Q3 — ION / dmabuf 页复用

| 项 | 内容 |
|----|------|
| **模式** | I 或 W |
| **填缺口** | G6 |
| **闸门** | ✅ `CONFIG_ION=y`；❌ `/dev/ion` **0664 system** — shell 通常不可 open |
| **思路** | 经典「释放页再映射改 cred」。需 **Context+（C）** 先拿到 system 或可 open 的 dmabuf 导出路径。 |
| **联用** | U\* 提权上下文 → 再打 ION |

#### Q4 — qcedev / qce

| 项 | 内容 |
|----|------|
| **模式** | 旧路径曾作 CFU；现作独立洞面 |
| **闸门** | ✅ 符号 `compat_qcedev_ioctl` 等在 vmlinux；❌ shell drmrpc/SELinux |
| **思路** | 栈深度 theoretically 有过讨论，但 **权限死**。仅 Context+ 后重开。 |
| **结论** | ⛔ 勿 shell 硬闯（与 stages 一致） |

#### Q5 — Binder 事务 UAF / OOB 族

| 项 | 内容 |
|----|------|
| **模式** | I 或 L |
| **填缺口** | G5/G6 或整链 |
| **闸门** | ✅ `CONFIG_ANDROID_BINDER_IPC=y` + binderfs；符号 `binder_transaction*` 在；触达受 SELinux 约束 |
| **代表 CVE（需逐条 patch-gap）** | CVE-2023-20938、CVE-2024-46740、以及 4.19 Android common 上历史 binder EoP |
| **思路** | 公开利用常见：有限泄漏 → unlink → 任意读 → 改 cred。本机 **4.19.157 远低于** 公告中部分 4.19.312 修复线，**vendor 可能 cherry-pick 也可能漏**。S05-02 关闭的是「作 GhostLock 栈 CFU 数据源」，**不是**「binder 无独立洞」。 |
| **下一步** | 对每条 CVE 的 fix commit 在 vmlinux 反汇编比对 |

#### Q6 — FastRPC / ADSPrpc

| 项 | 内容 |
|----|------|
| **模式** | I |
| **闸门** | ✅ `fastrpc_*` / `fastrpc_device_ioctl` 在 vmlinux；触达多为 system/vendor |
| **思路** | 历史多起 ioctl 校验/映射洞。shell 常不可 open 节点 → 先枚举 `/dev` + SELinux，再定。 |
| **联用** | 可选 S02 加速 |

#### Q7 — DIAG / IPA / RMNET / QRTR

| 项 | 内容 |
|----|------|
| **模式** | I |
| **闸门** | ✅ `diagchar_*`、`CONFIG_RMNET`、`CONFIG_QRTR`；节点权限常 system |
| **思路** | 厂商补丁滞后时偶发。优先级低于 Q1/Q5。 |

#### Q8 — DRM / display（非 MSM_DRM）

| 项 | 内容 |
|----|------|
| **闸门** | ✅ `CONFIG_DRM=y`；`# CONFIG_DRM_MSM is not set` |
| **思路** | 旧「栈加深 CFU」已关。仅当发现 **堆/对象** 类新洞才相关。 |
| **结论** | 低优先 |

---

### 1.3 Context+（用户态 / 服务，填 G4）

#### U1 — 高权 binder 服务（如 vendor.perfservice 历史族）

| 项 | 内容 |
|----|------|
| **模式** | C |
| **思路** | shell 可 `service list` / `service call` 的部分接口历史上存在 OOB。拿到 system 后再打 ION/qce/fastrpc。 |
| **下一步** | 设备上 `service list` 落盘 + 标 high-priv |

#### U2 — system_server / media / surfaceflinger 逻辑洞

| 项 | 内容 |
|----|------|
| **模式** | C |
| **思路** | 标准 Android 两跳。与内核 GhostLock 并行项目。 |

#### U3 — init / 属性 / 可写配置

| 项 | 内容 |
|----|------|
| **模式** | C |
| **思路** | 可写 sys 属性或错误权限文件 → 代码执行。需现场枚举。 |

---

### 1.4 放大器（非 CVE，但改变联用价值）

| ID | 条件 | 作用 | Leaf5 |
|----|------|------|-------|
| H1 | 无内核 CFI / 无 KPTI / 无 SCS | 函数指针写成本低 | ✅ |
| H2 | `perf_event_paranoid=-1` | 侧信道/采样 | ✅ perf open 成功 |
| H3 | BL unlocked / orange | Magisk/刷写确定性 root | ✅ 需用户授权 |
| H4 | `PANIC_ON_OOPS` 弱 | 容错 | 相对友好 |
| H5 | SLAB freelist harden + usercopy | 堆洞更难 | ✅ 已开 |

---

### 1.5 明确死亡 / 不排期（联用视角）

| ID | 原因 |
|----|------|
| L1 nf_tables（CVE-2024-1086 等） | `CONFIG_NF_TABLES is not set` |
| L2 DirtyPipe / io_uring | 4.19 无对应面 |
| L3 USER_NS 经典链 | `CONFIG_USER_NS is not set` |
| L4 BPF LPE（当前 shell） | `bpf` errno=**13**（SELinux） |
| L9 重打终局 B ashmem 矩阵 | 无新理论 |
| I 栈×slab 交叉 | `VMAP_STACK=y`，极难 |

---

## 2. 独立 LPE CVE / 攻击面清单（可不依赖 GhostLock）

> 目标：回答「**没有其它 CVE 可用么？**」  
> 答案：**有大量候选面**；是否「可用」= 代码在 + 未修 + shell 可达 + 可武器化。  
> 下列按 **本设备静态闸门** 分类。版本线 4.19.157 **极老**，vendor cherry-pick 是最大不确定性。

### 2.1 闸门 ❌ — 本机当前不做（配置/上下文已否）

| CVE / 类 | 组件 | 否决原因 |
|----------|------|----------|
| **CVE-2024-1086** | nf_tables double-free | 无 `NF_TABLES`；公开 exploit 还要 USER_NS |
| **CVE-2023-32233** 等 nf_tables 批处理 UAF | nf_tables | 同上 |
| **CVE-2022-32250 / CVE-2022-1966** 等 | nft | 同上 |
| **CVE-2021-22555** 等 iptables compat OOB | netfilter | 需 **CAP_NET_ADMIN**（常靠 USER_NS）；本机 USER_NS=n 且 shell 无该 cap |
| **CVE-2022-25636** 等 | nft/offload | 依赖 nft 路径 |
| **DirtyPipe CVE-2022-0847** | pipe | 引入/利用窗口在 5.8+ 主流路径；4.19 不适用常规 PoC |
| **io_uring 系列**（如 CVE-2022-29582 等） | io_uring | 4.19 无 io_uring |
| **GameOver(lay) 等 overlayfs+USER_NS** | userns | USER_NS=n |
| **Dirty Frag（xfrm-ESP + RxRPC 双 page-cache）** | xfrm + AF_RXRPC | **`AF_RXRPC is not set`** → 该公开 **双洞链** 不完整（见 2.2 单边 xfrm） |
| **Rust binder CVE-2025-68260** | rust_binder | 本机为 C binder，无 rust_binder |
| **BPF verifier LPE 族（shell 直打）** | bpf | shell `BPF_PROG_LOAD/MAP_CREATE` → EACCES |

### 2.2 闸门 ⚠️ — 代码面存在，需 patch-gap + 触达验证

#### A. Qualcomm GPU / KGSL（强烈建议独立项目）

| CVE / 族 | 简述 | 本机面 | 与 GhostLock |
|----------|------|--------|--------------|
| **CVE-2024-23380** 及 VBO 相关（23381/23384/23372、CVE-2024-33034 等） | KGSL 内存管理 / VBO 损坏 → 页复用改 cred | KGSL 符号齐全；shell open 历史 OK | 独立 I；leak 可复用 S02 |
| **CVE-2025-21479 / CVE-2025-21480** | GPU micronode 未授权命令 → 内存破坏；有在野利用报道 | 依赖 GPU 固件与 OEM 补丁（SPL 2026-04 可能相关） | 独立 I |
| **CVE-2026-21385** 等 Graphics 整数溢出族 | 本地内存破坏 | SPL 2026-03 起公告；设备 SPL=2026-04 **可能已带**，仍需固件/二进制确认 | 独立 I |
| 更早 **CVE-2020-11239** 等 kgsl UAF | 历史 root 链组件 | 大概率已修，但 4.19.157 基线 + 厂商树仍值得抽查 | 独立 |

**思路（独立）**：不碰 GhostLock 栈；从 `kgsl_ioctl_gpuobj_*` / sparse / submit 路径做 **补丁对照 + 最小 crash PoC**，再谈页复用。

#### B. Binder

| CVE / 族 | 简述 | 本机面 |
|----------|------|--------|
| **CVE-2023-20938** | binder 事务 buffer 释放校验 → UAF | binder 在；是否修 = patch-gap |
| **CVE-2024-46740** | binder offsets 覆盖 → UAF | 同上；公告涉及 4.19 修复线（如 4.19.312 类）而本机 **.157** |
| **CVE-2019-2215** 等极老 binder | 多已修 | 低优先抽查 |

**思路**：对 fix commit 的关键检查（offset 校验、`binder_transaction_buffer_release` 分支）在 vmlinux 反汇编比对；有缺口再写最小触发。

#### C. 网络路由 / 通用内核（无 USER_NS 时仍可能 shell 可达）

| CVE / 族 | 简述 | 本机面 | 注意 |
|----------|------|--------|------|
| **CVE-2024-36971** | 路由/dst 缓存 RCU UAF（有 KEV/在野讨论） | 通用 net；inet 能力 shell 常有（inet 组） | 利用难度高；需确认 4.19 是否含引入与修复 |
| **CVE-2024-36978** | Net 子系统 EoP（Android 公告） | 同上 | patch-gap |
| 其它 **4.19 stable 上大量 net/mm** 洞 | 随 4.19.158–4.19.3xx 修复 | 基线 .157 **理论暴露面大** | 不能当「一定未修」：OEM 会 cherry-pick |

**思路**：不要扫全部 CVE 编号；按 **「Android bulletin Kernel 段 + Qualcomm 段 + KEV」** 缩表，再对 #245 做 gap。

#### D. XFRM（半边 Dirty Frag / 其它 IPsec 洞）

| 项 | 内容 |
|----|------|
| **CONFIG** | `XFRM=y` `XFRM_USER=y` 等齐全；符号 `xfrm_state_*` / `xfrm_policy_*` 在 |
| **触达** | 配置 xfrm 通常要 **CAP_NET_ADMIN** → shell 直接 ❌；USER_NS=n 无法自抬 |
| **Dirty Frag 全链** | 缺 RxRPC → **完整公开链 ❌** |
| **思路** | 单洞 xfrm page-cache 写若存在，仍可能被 CAP 挡住。仅当发现 **无 CAP 触发路径** 或 Context+ 后再评 |
| **判定** | ⚠️ 代码在、权限紧 |

#### E. 无线 / wlan 模块

| 项 | 内容 |
|----|------|
| **面** | `wlan` 模块已加载（~7MB）；`CFG80211=y` |
| **思路** | 厂商 wlan 驱动是 Android 富矿；需模块符号/版本 + 公开 QC WLAN CVE 对照 |
| **触达** | 部分 ioctl 需 net admin 或特定 socket |
| **判定** | ⚠️ 中优先（独立项目） |

#### F. 媒体 / V4L2 / UVC

| 项 | 内容 |
|----|------|
| **CONFIG** | `VIDEO_V4L2=y`；UVC 类需再查具体驱动 |
| **CVE-2024-53104** 等 uvcvideo OOB | 电纸书未必启用摄像头节点 |
| **判定** | 低，除非 `/dev/video*` shell 可达 |

#### G. 输入 / UHID / EVDEV

| 项 | 内容 |
|----|------|
| **CONFIG** | `UHID=y` `INPUT_EVDEV=y`；shell 在 `input`/`uhid` 组 |
| **思路** | 历史 evdev/uhid 洞较少直接 root；可作辅助 |
| **判定** | 低 |

#### H. ashmem

| 项 | 内容 |
|----|------|
| **面** | `/dev/ashmem` 0666；`CONFIG_ASHMEM=y` |
| **思路** | 除 fops 劫持 oracle 外，ashmem 自身历史洞（pin/unpin 等）可独立挖；当前主要当 **写目标/oracle** |
| **判定** | ⚠️ 作目标优先于作第二 CVE |

#### I. QSEECOM / 安全侧

| 项 | 内容 |
|----|------|
| **CONFIG** | `QSEECOM=y` |
| **触达** | 通常 system/drmrpc |
| **判定** | 低（shell）；Context+ 后中 |

### 2.3 闸门 ✅ 面存在且与「提权目的」强相关的 **优先独立 CVE 工作包**

按建议投入排序（**不是**已确认未修）：

| 优先级 | 工作包 | 代表 CVE / 入口 | 第一动作 |
|--------|--------|-----------------|----------|
| **P0** | KGSL 独立 LPE | CVE-2024-23380 族；历史 kgsl UAF | 补丁字符串/逻辑 vs `kgsl_ioctl_*` |
| **P0** | Binder patch-gap | CVE-2023-20938、CVE-2024-46740 | fix 检查点反汇编 |
| **P1** | Qualcomm Graphics/GPU 在野族 | CVE-2025-21480 等 | 固件版本 + SPL 对照 |
| **P1** | 4.19.157 → 4.19.latest **未合入** 的 Android Kernel bulletin 子集 | 按公告缩表 | 只对 High EoP + shell 可达组件 |
| **P2** | wlan 模块公开 QC CVE | bulletin WLAN | 模块版本 + 符号 |
| **P2** | FastRPC / DIAG | 厂商 ioctl 史 | 节点 ls -lZ |
| **P3** | XFRM 单洞 | 无 RxRPC 的 dirty 变体 | 先 CAP 触达探针 |
| **P3** | 路由 UAF | CVE-2024-36971 | 引入/修复是否在树 |

### 2.4 与 GhostLock 的组合方式（独立洞打通后）

```text
独立洞已给任意写/页复用
  → 可不碰 GhostLock，直接 cred / SELinux / physmap

独立洞只给任意读
  → + GhostLock 受限写（S1/S2）填 G1
  → 或 + 继续挖写

独立洞只给 Context+
  → 打开 ION/qce/fastrpc/BPF
  → 再跑对应 CVE 或复活部分旧 S05 权限死路

GhostLock 只当 leak（S02）
  → 加速上述任一独立链的 KASLR/堆地址
```

---

## 3. 推荐路径总图

```text
                    ┌─────────────────────────────┐
                    │  目标：uid=0 或等价 physrw   │
                    └─────────────┬───────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
  路径 α 联用               路径 β 独立                路径 γ 工程
  GhostLock 写引擎          第二 CVE 自己 root         授权 Magisk/刷写
  S1/S2/S5/S6+S7 oracle     P0: KGSL / Binder gap      H3 用户确认
        │                         │
        │                   P1: GPU 在野 / bulletin
        ▼                         ▼
  证明 store → S07           页复用/任意写 → cred
```

**明确不排期**：nf_tables / DirtyPipe / io_uring / USER_NS / shell BPF / 终局 B 同矩阵。

---

## 4. 建议落地顺序（可执行，仍属研究）

| 步 | 动作 | 产出文件建议 |
|----|------|----------------|
| 1 | 枚举 shell 可 open 节点 + fops 邻接（S1） | `analysis/write_targets_shell_devs.md` |
| 2 | Binder 2–3 条 CVE fix 反汇编对照（Q5/P0） | `analysis/patch_gap_binder.md` |
| 3 | KGSL 公开 VBO/UAF 补丁对照（Q1/P0） | `analysis/patch_gap_kgsl.md` |
| 4 | `service list` + 节点 `ls -lZ`（U1/Q6） | `analysis/context_surface.md` |
| 5 | GPU 固件版本 / SPL 与 21480 等对照 | `analysis/gpu_fw_cve.md` |
| 6 | （可选）Android Kernel bulletin 2024–2026 High EoP 缩表 vs 4.19.157 | `analysis/bulletin_gap_419.md` |

每步 **先静态后探针**；探针落 `probes/`，结论回写本文件状态列。

---

## 5. 与既有文档关系

| 文档 | 关系 |
|------|------|
| `POST_B_ALTERNATIVES.md` | 方向 A–I 总表；本文展开 **CVE 级** 与 **闸门** |
| `PI_STORE_CONSUMERS.md` | 支撑 S5 / oracle |
| `RESULTS_2026-07-26_oracle_bpf.md` | BPF❌ perf✅ 事实源 |
| `CHAIN_MATRIX.md` | popsicle vs Leaf5；不替代本文 |
| 路由 10 README | 终局 B 权威；本文不重开已关矩阵 |

---

## 6. 结论（给决策用）

1. **有第二条件可用**：优先 **S1/S2/S5/S7**（仍吃 GhostLock），不是再适配原版 ashmem 链。  
2. **有独立 CVE 面可用**：最值得挖的是 **KGSL（Q1/P0）** 与 **Binder patch-gap（Q5/P0）**；其次 GPU 在野族与 4.19 公告缩表。  
3. **没有**「开箱即用、已证明未修」的公开 PoC 可直接 root 本机——**必须过 patch-gap**。  
4. 网红桌面洞（nf_tables、DirtyPipe、io_uring、完整 Dirty Frag）在本机 **配置级死亡或 CAP 死亡**。  
5. 确定性 root 仍是 **用户授权** 的 H3；漏洞路径是研究选项，不是保证。

---

## 7. 修订记录

| 日期 | 变更 |
|------|------|
| 2026-07-26 | 初版：联用清单（思路）+ 独立 CVE 闸门表 + P0–P3 工作包 |
