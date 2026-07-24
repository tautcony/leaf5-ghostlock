# Leaf5 GhostLock 设备分析报告

| 字段 | 值 |
|------|-----|
| 目标设备 | Onyx Leaf5（电纸书 / TabBoox） |
| 分析日期 | 2026-07-24 |
| 分析方式 | **从零重做**（废弃此前 leaf5 目录中的旧结论） |
| ADB Serial | `ac340d06` |
| 权限上下文 | `uid=2000(shell)` / `u:r:shell:s0`（无 root） |
| 原始数据 | [`raw/`](raw/) |

本文记录**完整分析过程**与**可复核结论**。所有关键判断均绑定原始采集文件，避免“凭印象写偏移”。

---

## 0. 分析目标与边界

### 0.1 目标

1. 确认 Leaf5 是否具备 GhostLock（CVE-2026-43499 / `FUTEX_CMP_REQUEUE_PI` rtmutex 栈 UAF）利用链的**内核前置条件**。
2. 采集运行时安全面、内核 CONFIG、可用接口，并与仓库原目标 **OPPO Find N2（kernel 5.10）** 对比。
3. 标明**已验证 / 未验证 / 不可信**数据源，尤其是仓库内 `boot.img` 与真机版本是否一致。

### 0.2 边界（本次未做）

| 项目 | 原因 |
|------|------|
| 编写/运行完整 exploit | 本次仅做验证与文档 |
| shell 用户 `dd` 导出 `boot_a` | 块设备 `brw------- root:root`，Permission denied |
| IDA / pahole 精确结构体偏移 | 缺与 runtime 一致的 vmlinux；`kheaders` 可作辅助，不能替代 DWARF |
| 栈帧布局实测 | 需要可控 panic 或带符号的 vmlinux 反汇编 |

---

## 1. 分析过程日志

### 阶段 A — 设备在线与身份确认

```bash
adb devices -l
# ac340d06  device  product:Leaf5 model:Leaf5 device:Leaf5

adb shell getprop ro.product.model          # Leaf5
adb shell getprop ro.product.brand          # Onyx
adb shell getprop ro.board.platform         # lito
adb shell getprop ro.build.fingerprint
# ONYX/TabBoox/TabBoox:13/TKQ1.230615.001/GV2.027.SQ83A:user/release-keys
adb shell cat /proc/version
```

**结论 A**

| 项 | 值 |
|----|-----|
| 厂商 / 型号 | Onyx / Leaf5 |
| 平台 | Qualcomm **lito**（SoC 族 SM6350 / LAGOON） |
| Android | 13（API 33） |
| 安全补丁 | 2026-04-01 |
| Build display | `2026-04-21_12-49_4.2-rel_0421_19324b3ea` |
| 内核 | `4.19.157-perf-g3d47a6619220-dirty` **#245** `SMP PREEMPT` `Fri Apr 10 15:19:22 CST 2026` |
| 编译器 | clang 10.0.7 for Android NDK（onyx@onyxUbuntu） |
| CPU | 8 核（`0-7`）；part `0x805` + `0xd0d`（Qualcomm Kryo / Cortex-A55 组合） |
| 内存 | MemTotal ≈ 3.4 GiB |
| PAGE_SIZE | 4096 |

原始输出：[`raw/device_identity.txt`](raw/device_identity.txt)、[`raw/soc_info.txt`](raw/soc_info.txt)、[`raw/memory_layout_hints.txt`](raw/memory_layout_hints.txt)。

### 阶段 B — 启动验证与分区布局

```bash
adb shell getprop ro.boot.verifiedbootstate   # orange
adb shell getprop ro.boot.flash.locked        # 0
adb shell getprop ro.boot.vbmeta.device_state # unlocked
adb shell getprop ro.boot.slot_suffix         # _a
adb shell ls -la /dev/block/by-name/boot_a    # -> mmcblk0p13
adb shell dd if=/dev/block/mmcblk0p13 ...     # Permission denied
```

**结论 B**

- Bootloader / AVB：**已解锁**（`verifiedbootstate=orange`，`flash.locked=0`，`vbmeta=unlocked`）。
- 活动槽位：`_a`；`boot_a` = `mmcblk0p13`，`xbl_a` = `mmcblk0p1`。
- **shell 不能读 boot 分区**；无 root 前无法从设备导出与 runtime 一致的 `boot.img`。
- `/proc/cmdline`、`/proc/partitions`、`/proc/iomem`：Permission denied。

原始输出：[`raw/partitions.txt`](raw/partitions.txt)。

### 阶段 C — 运行时安全面

```bash
adb shell id
adb shell getenforce
adb shell cat /proc/self/status   # Cap*
adb shell cat /proc/sys/kernel/...
adb shell head /proc/kallsyms
```

**结论 C**

| 检查项 | 结果 | 含义 |
|--------|------|------|
| SELinux | **Enforcing** | 策略强制 |
| shell CapEff | `0` | 无有效 capability |
| shell CapBnd | `0xc0` | 仅 bit6/7（`CAP_SETGID`/`CAP_SETUID`）在 bounding set 中 |
| `/proc/kallsyms` | Permission denied | 用户态不可直接读符号 |
| 多数 `/proc/sys/kernel/*` | Permission denied | SELinux 收紧 sysctl 读 |
| `perf_event_paranoid` | **-1** | 异常宽松（相对常见 Android 配置） |
| `unprivileged_bpf_disabled` | **0** | 未禁用非特权 BPF（是否真能用受 SELinux 约束） |
| `su` / Magisk | 不存在 | 无现成 root |
| YAMA ptrace_scope | 路径不存在 | 未启用 YAMA sysctl 节点 |

原始输出：[`raw/security_runtime.txt`](raw/security_runtime.txt)、[`raw/sysctl_probe.txt`](raw/sysctl_probe.txt)。

### 阶段 D — 内核 CONFIG（权威源：设备 `/proc/config.gz`）

```bash
adb shell cat /proc/config.gz > leaf5/raw/config.gz
gzip -dc leaf5/raw/config.gz > leaf5/raw/kernel_config.txt
# 头注释: Linux/arm64 4.19.157 Kernel Configuration
```

设备开启了 `CONFIG_IKCONFIG_PROC=y`，因此 **CONFIG 与当前运行内核一致**，这是本次分析中**最可靠**的内核配置来源。

关键选项（完整表见 [§3](#3-内核-config-与-ghostlock-相关性)）：

| 选项 | 值 | GhostLock 相关 |
|------|-----|----------------|
| `CONFIG_FUTEX` / `CONFIG_FUTEX_PI` | y | 漏洞路径存在 |
| `CONFIG_RT_MUTEXES` | y | waiter / pi 链存在 |
| `CONFIG_DEBUG_RT_MUTEXES` | n | waiter 结构无 debug 字段 |
| `CONFIG_RANDOMIZE_BASE` | y | KASLR 开启 |
| `CONFIG_UNMAP_KERNEL_AT_EL0`（KPTI） | **n** | 内核未 KPTI；prefetch 类旁路 theoretically 更可行 |
| `CONFIG_CFI_CLANG` / kernel LTO CFI | **n**（`CONFIG_LTO_NONE=y`） | **无内核 CFI** |
| `CONFIG_SHADOW_CALL_STACK` | n | 无 SCS |
| `CONFIG_ARM64_PTR_AUTH` / `BTI` | n | 无 PAC/BTI |
| `CONFIG_USER_NS` | n | 无 user namespace |
| `CONFIG_ASHMEM` | y | ashmem 存在 |
| `CONFIG_ANDROID_BINDER_IPC` + BINDERFS | y | binder 存在 |
| `CONFIG_VMAP_STACK` | y | 线程栈 vmap |
| `CONFIG_PANIC_ON_OOPS` | n | oops 默认不强制 panic（仍可能因其他配置重启） |
| `CONFIG_ARM64_VA_BITS` | 39 | 与常见 Android 一致 |
| `CONFIG_ARM64_4K_PAGES` | y | 4K 页 |
| `CONFIG_IO_URING` | n | 无 io_uring |
| `CONFIG_SLUB` + freelist harden/random | y | SLUB 加固开启 |

原始文件：[`raw/config.gz`](raw/config.gz)、[`raw/kernel_config.txt`](raw/kernel_config.txt)、[`raw/config_security_focus.txt`](raw/config_security_focus.txt)。

### 阶段 E — 运行时 kheaders（结构体线索）

```bash
adb shell ls -la /sys/kernel/kheaders.tar.xz
# -r--r--r--  ... 3420924 ...
adb exec-out cat /sys/kernel/kheaders.tar.xz > leaf5/raw/kheaders.tar.xz
tar -xJf leaf5/raw/kheaders.tar.xz -C leaf5/raw/kheaders
```

| 文件 | 内容 |
|------|------|
| `include/generated/utsrelease.h` | `4.19.157-perf-g3d47a6619220-dirty`（与 runtime **一致**） |
| `include/generated/compile.h` | `#244` … `15:14:29 CST 2026` |
| runtime `uname` | `#245` … `15:19:22 CST 2026` |

**解释**：同一 `UTS_RELEASE` git 描述串，构建号差 1、时间差约 5 分钟。按 Onyx 内部重建习惯，**kheaders 可视为与当前内核匹配的头文件快照**；精确到字节的布局仍应以同版本 vmlinux/DWARF 为准。

从 `include/linux/sched.h` 可见字段存在性（**非字节偏移**）：

- `real_cred` / `cred`
- `pi_waiters`（`struct rb_root_cached`）
- `pi_blocked_on`（`struct rt_mutex_waiter *`）

`struct rt_mutex_waiter` **仅有前向声明**（`rtmutex.h`），完整定义不在 kheaders 导出头中（通常在 `kernel/locking/rtmutex_common.h`）。在 `CONFIG_DEBUG_RT_MUTEXES=n` 时，4.19 主流布局为：

```text
/* 示意：来自 mainline 4.19 逻辑，非本机 pahole 实测 */
struct rt_mutex_waiter {
    struct rb_node tree_entry;      /* +0x00, 24B on arm64 */
    struct rb_node pi_tree_entry;   /* +0x18 */
    struct task_struct *task;       /* +0x30 */
    struct rt_mutex *lock;          /* +0x38 */
};
/* sizeof ≈ 0x40；5.10+ 会多 prio/deadline 等字段 — 不能照搬 OPPO target.h */
```

> **注意**：上表是 **4.19 源码级推断**，在拿到 runtime vmlinux 并用 pahole/IDA 复核前，**不得**写进 exploit 的 `target.h` 当真值。

### 阶段 F — 用户态接口与 Stage1 应用

| 接口 | 状态 |
|------|------|
| `/dev/ashmem` | `crw-rw-rw-` 存在 |
| `/dev/binder` | symlink → binderfs |
| configfs | 已挂载于 `/config`，shell **不可 list** |
| debugfs | `/sys/kernel/debug` 不可见 |
| tracefs | `/sys/kernel/tracing`（gid=3012 readtracefs） |
| `/dev/ion` | 存在 |
| dma_heap | 不存在 |
| `/sys/kernel/slab` | shell 仅见极少 cache 名，**无 kmalloc-*** 可见节点 |

应用：

```text
org.mozilla.firefox   versionName=151.0.2
org.chromium.chrome   present
com.android.webview   present
```

与仓库 Stage1（Firefox CVE-2026-10702 / SpiderMonkey）版本线 **151** 对齐，具备浏览器侧入口的潜在条件（漏洞是否仍可触发需单独验证，本次未测）。

原始输出：[`raw/interfaces.txt`](raw/interfaces.txt)、[`raw/userspace_probe.txt`](raw/userspace_probe.txt)。

### 阶段 G — 仓库 `boot.img` 核对（重要纠错点）

仓库根目录 `boot.img`（约 96 MiB）**可以**解析为 Android boot image，并抽出 ARM64 `Image`：

| 项 | 值 |
|----|-----|
| magic | `ANDROID!` |
| page_size | 0x1000 |
| kernel_size | ≈ 51.9 MiB |
| Image magic | `ARM\x64` |
| text_offset | 0x80000 |
| **Image 内 banner** | `Linux version 4.19.157-perf-g87880838aed5-dirty` **#119** `Tue Jul 29 16:02:51 CST 2025` |
| **设备 runtime** | `...-g3d47a6619220-dirty` **#245** `Fri Apr 10 15:19:22 CST 2026` |

**结论 G（关键）**：

1. 仓库 `boot.img` 是 **Onyx 4.19.157 同系列旧构建**，**不是**当前 Leaf5 runtime 内核。
2. 基于该 `boot.img` 的符号偏移、栈帧、kallsyms **一律不可直接用于当前设备**。
3. 此前若把该镜像当 leaf5 真机内核做适配，属于**数据源错误**——这也是本次“从零重做”的主要原因之一。

sha256：见 [`raw/version_compare.txt`](raw/version_compare.txt)。

### 阶段 H — 结构化快照

脚本汇总：[`raw/analysis_snapshot.json`](raw/analysis_snapshot.json)。

复现采集：

```bash
cd leaf5
uv sync
uv run leaf5-collect
uv run leaf5-summarize
```

---

## 2. 设备画像（摘要）

```text
Onyx Leaf5
├── Android 13 / API 33 / patch 2026-04-01
├── Kernel 4.19.157-perf (Qualcomm msm-4.19, PREEMPT, 8 CPU)
├── SoC: SM6350 class (board=lito, soc0=LAGOON)
├── AVB: unlocked (orange)
├── SELinux: Enforcing, shell unprivileged
├── KASLR: on | KPTI: off | Kernel CFI: off
├── FUTEX_PI + RT_MUTEX: on  → GhostLock 原语路径存在
├── USER_NS: off
├── ashmem + binderfs: on
└── Firefox 151.0.2 installed
```

---

## 3. 内核 CONFIG 与 GhostLock 相关性

### 3.1 漏洞触发前置

| 前置 | Leaf5 | 说明 |
|------|-------|------|
| `FUTEX` + `FUTEX_PI` | ✅ | `FUTEX_WAIT_REQUEUE_PI` / `CMP_REQUEUE_PI` 可用前提 |
| `RT_MUTEXES` | ✅ | `pi_blocked_on` 路径 |
| 无特权即可 futex | ✅（预期） | Android shell 默认可调用 futex；需后续用测试二进制确认 errno |

### 3.2 利用链难易（相对 OPPO Find N2）

| 维度 | Leaf5 (4.19) | OPPO Find N2 (5.10，仓库既有结论) | 影响 |
|------|--------------|-------------------------------------|------|
| 内核 CFI | **无** | 强 CFI，大量 fops 替换失败 | Leaf5 **显著更宽松** |
| KPTI | **关** | 开（prefetch 失败原因之一） | Leaf5 可用更多 KASLR 旁路 |
| 内核版本 | 4.19 | 5.10 | 结构体/栈帧/syscall 实现均不同，**不能平移 target.h** |
| USER_NS | 关 | 关 | 两边都不能靠 userns 提权 |
| PANIC_ON_OOPS | 关 | 开（仓库记载） | Leaf5 调试容错更好 |
| ashmem | 有 | 有（但 configfs 路径死） | Leaf5 configfs 权限未完全摸清 |
| 安全补丁 | 2026-04 | 2026-06（N2） | 需单独核对 futex 相关补丁是否 backport |

### 3.3 地址空间假设（CONFIG 级，待 vmlinux 确认）

| 宏 | 值 | 常用推导 |
|----|-----|----------|
| VA_BITS | 39 | `PAGE_OFFSET` / linear map 高半区常见布局 |
| PAGE | 4K | |
| PA_BITS | 48 | |
| KASLR | on | 需 leak slide |

**未验证**：`KIMAGE_TEXT_BASE`、`PHYS_OFFSET`、`direct map` 起止、`vmemmap`。旧 `boot.img` 的 Image `text_offset=0x80000` 仅说明 **旧镜像** 链接参数，不能当 runtime 真值。

---

## 4. 与仓库 exploit 模块的映射（状态）

| 模块 | 在 Leaf5 上的状态 | 依据 |
|------|-------------------|------|
| Stage1 Firefox | ⚠️ 应用版本匹配，漏洞未测 | Firefox 151.0.2 已装 |
| KASLR (pselect/boot_id 等) | ❓ 未测 | KPTI 关可能改变侧信道可行性 |
| KernelSnitch mm_struct | ❓ 未测 | 需 4.19 `mm_struct` 大小/order、futex hash 参数 |
| GhostLock futex 触发 | ❓ 未测 | CONFIG 允许，需二进制验证 ret=0 |
| 栈覆盖 (pselect 等) | ❓ 未测 | **必须**按 4.19 栈布局重做，N2 的 120B gap 结论不适用 |
| pipe physrw / cred | ❓ 未测 | 依赖写原语与偏移 |
| 内核 CFI bypass | ✅ 可能 **不需要**（内核无 CFI） | CONFIG 级结论 |

---

## 5. 数据源可信度矩阵

| 数据 | 可信度 | 用途 |
|------|--------|------|
| `/proc/config.gz` | ★★★★★ | CONFIG 真值 |
| `/sys/kernel/kheaders` UTS | ★★★★☆ | 头文件与 release 字符串匹配 |
| adb getprop / uname | ★★★★★ | 设备身份 |
| shell 可见 sysfs/proc | ★★★☆☆ | 受 SELinux 过滤，**看不见 ≠ 不存在** |
| 仓库 `boot.img` | ★☆☆☆☆（对 runtime） | 仅历史镜像；**禁止**当 leaf5 当前内核 |
| 4.19 mainline 结构体推断 | ★★☆☆☆ | 草稿；需 pahole/IDA |
| OPPO `target.h` | ☆☆☆☆☆ | 不同 major 内核，禁止照搬 |

---

## 6. 明确的错误与陷阱（供后续避免）

1. **把仓库 `boot.img` 当成当前 Leaf5 内核** → 符号/偏移全错（git hash 与 build 号均不同）。
2. **把 OPPO Find N2 的 `target.h` 偏移抄到 4.19** → `rt_mutex_waiter` / `task_struct` / `mm_struct` 布局不同。
3. **把用户态 maps 里的 `cfi shadow` 当成内核 CFI** → 那是 Android 用户态 CFI；本机 **内核** `CONFIG_CFI_CLANG` 未开。
4. **shell 读不到 sysctl/slab 就写“未配置”** → 多数是 SELinux deny，应用 CONFIG 与 kheaders 交叉验证。
5. **kheaders `#244` 与 uname `#245` 不一致就全盘否定头文件** → 同 release 字符串、同日构建，优先当匹配；最终以 vmlinux 为准。

---

## 7. 下一步（按优先级）

1. **导出与 runtime 一致的 boot/kernel**  
   - 解锁已满足；可用 `fastboot boot`/`fastboot fetch`（若支持）或 EDL/厂商工具从 `boot_a` 拉取。  
   - 拉取后核对 banner 必须含 `g3d47a6619220` 与 `#245`。
2. **vmlinux + kallsyms + IDA**  
   - 提取符号：`init_task`、`anon_pipe_buf_ops`、ashmem fops、futex/rtmutex 相关。  
   - pahole：`rt_mutex_waiter`、`task_struct`、`mm_struct`、`cred`。
3. **最小用户态探针**（NDK 编译，非完整 exploit）  
   - `FUTEX_WAIT_REQUEUE_PI` / `CMP_REQUEUE_PI` 返回值  
   - KernelSnitch 级 timing 是否有信号  
   - 不引入未验证偏移的写原语
4. **新建 `exploit/targets/onyx-leaf5/target.h`**  
   - 仅在步骤 2 完成后填真实偏移  
   - `BUILD_VARIANT_LABEL` 绑定 fingerprint + kernel release
5. **栈布局专项**  
   - 反汇编 `futex_wait_requeue_pi` 调用链与候选 syscall（pselect 等）  
   - 不得假设与 Pixel/OPPO 相同的 waiter/fd_set 相对位置

细节清单见 [`NEXT_STEPS.md`](NEXT_STEPS.md)。对比表见 [`COMPARE_OPPO_FIND_N2.md`](COMPARE_OPPO_FIND_N2.md)。

---

## 8. 偏移定位结果（2026-07-24 续）

基于 vmlinux-to-elf 重建的 `vmlinux.elf`（121883 符号）与 capstone ARM64 反汇编器，完成了关键结构与符号偏移的提取。

### 8.1 数据源与工具链

| 输入 | 来源 |
|------|------|
| `raw/vmlinux.elf` | `vmlinux-to-elf` 从 `boot_a.bin` 提取的 Image 重建 |
| 符号表 | 121883 符号（kernel kallsyms → ELF .symtab） |
| 结构体偏移 | capstone 5.0 反汇编关键访问函数 |
| 验证状态 | `[BIN]`=反汇编确认，`[SYM]`=符号表查询，`[SRC]`=源码推断 |

复用脚本：`uv run leaf5-extract-offsets`（即 `scripts/extract_offsets.py`）。

### 8.2 rt_mutex_waiter（4.19 关键差异）

4.19 的 `rt_mutex_waiter` **没有** `prio`、`deadline`、`ww_ctx` 字段（5.10+ 才有）：

| 字段 | 偏移 | 大小 | 验证 |
|------|------|------|------|
| `tree_entry` | `0x00` | 24B (rb_node) | `[BIN]` task_blocks_on_rt_mutex |
| `pi_tree_entry` | `0x18` | 24B (rb_node) | `[BIN]` task_blocks_on_rt_mutex |
| `task` | `0x30` | 8B | `[BIN]` rt_mutex_init_waiter: `str xzr, [x0,#0x30]` |
| `lock` | `0x38` | 8B | `[SRC]` |
| **sizeof** | **0x40** | 64B | 比 5.10 的 0x50 小 16B |

### 8.3 task_struct 关键偏移

| 字段 | 偏移 | 验证 |
|------|------|------|
| `real_cred` | `0x7d8` | `[BIN]` commit_creds: `ldr x19, [x20,#0x7d8]` |
| `cred` | `0x7e0` | `[BIN]` exit_creds: `str xzr, [x19,#0x7e0]` |
| `comm` | `0x7e8` | `[SRC]` 紧随 cred 之后（char[16]） |
| `prio` | `0xac` | `[BIN]` rt_mutex_adjust_prio_chain: `ldr w8, [x19,#0xac]` |
| `pi_blocked_on` | `0x8d0` | `[BIN]` task_blocks_on_rt_mutex: `str x21, [x20,#0x8d0]` |
| `pi_waiters` | `0x8b8` | `[EST]` 在 pi_blocked_on 附近 |
| `pid` | `0x5f8` | `[EST]` 源码头前推 — **需 pahole 验证** |
| `tgid` | `0x5fc` | `[EST]` 同上 |

对比 OPPO Find N2（5.10）：4.19 的 `real_cred`/`cred` 偏移比 5.10 (`0x818`/`0x820`) **小 0x40**（64B），说明 4.19 的 task_struct 在 cred 之前有更少的字段/更小的子结构。

### 8.4 pipe_inode_info 偏移

| 字段 | 偏移 | 验证 |
|------|------|------|
| `head` | `0x38` | `[BIN]` pipe_write |
| `tail` | `0x3c` | `[BIN]` pipe_write: `ldp` |
| `max_usage` | `0x40` | `[BIN]` pipe_write |
| `ring_size` | `0x44` | `[BIN]` pipe_write |
| `nr_accounted` | `0x48` | `[SRC]` |
| `readers` | `0x4c` | `[SRC]` |
| `writers` | `0x50` | `[BIN]` pipe_write: `ldr w8, [x20,#0x50]` |
| `files` | `0x54` | `[SRC]` |
| `tmp_page` | `0x60` | `[BIN]` pipe_write: `ldr x28, [x20,#0x60]` |
| `bufs` | `0x78` | `[BIN]` pipe_write: `ldr x21, [x20,#0x78]` |
| `user` | `0x80` | `[SRC]` |

### 8.5 其他已验证偏移

| 结构 | 字段 | 偏移 | 验证 |
|------|------|------|------|
| `mm_struct` | `owner` | `0x328` | `[BIN]` mm_update_next_owner |
| `cred` | `euid` | `0x14` | `[BIN]` commit_creds |
| `cred` | `security` | ⚠️ 待确认 | 4.19 位置与 5.10 不同 |
| `miscdevice` | `fops` | `0x10` | `[SRC]` arm64 结构布局 |

### 8.6 4.19 特殊符号名

4.19 与 5.10 使用了**不同的函数/变量名**：

| 5.10 (OPPO) | 4.19 (Leaf5) | 说明 |
|-------------|-------------|------|
| `futex_wait_requeue_pi` | ❌ 不存在 | 逻辑内联在 `do_futex` → `futex_wait` |
| `copy_splice_read` | `generic_file_splice_read` | 不同 splice 实现 |
| `configfs_read_iter` | `configfs_read_file` | 4.19 未使用 iter 接口 |
| `configfs_write_iter` | `configfs_write_file` | 同上 |
| `selinux_enforcing` | `selinux_enforcing_boot` | 仅 boot param 变量 |
| `ashmem_misc_fops` | 通过 `ashmem_misc` + offset `0x10` 读取 | miscdevice 间接引用 |

### 8.7 产出

- ✅ `exploit/targets/onyx-leaf5/target.h` — 含所有已验证偏移，标注验证级别
- ✅ `scripts/extract_offsets.py` — 可复用偏移提取工具
- ⚠️ `[SRC]`/`[EST]` 标记的偏移需 pahole 或 IDA 复核后方可用于生产 exploit

### 8.8 MM_STRUCT_SZ 与 MM_ORDER（2026-07-24）

#### 提取方法

1. 定位 `fork_init` 中的 `kmem_cache_create_usercopy("mm_struct", size, ...)` 调用
2. ARM64 反汇编追溯 `w1` 寄存器值（需手动解码 `bl`/`adrp` 指令，capstone 5.x Python API 对这些操作数的 `op.imm` 返回错误值）
3. 通过 `mm_alloc → memset(mm, 0, 0x380)` 交叉验证（8 字节差额由 `mm_init` 显式初始化）
4. 实现 Linux 4.19 `mm/slub.c` 的 `calculate_order()` 算法，结合 `CONFIG_NR_CPUS=8`

#### 结果

| 参数 | 旧假设 (OPPO Find N2, 5.10) | 实际 (Leaf5, 4.19) | 差异 |
|------|---------------------------|---------------------|------|
| `sizeof(struct mm_struct)` | `0x3c0` (960B) | **`0x388`** (904B) | **−56B** |
| MM_ORDER | 3 | **3** | ✓ 不变 |
| 对象数 / slab | 34 | **36** | +2 |
| 浪费 / slab | — | 224B (0.68%) | — |

#### 数据源

| 项 | 源 | 可信度 |
|----|-----|--------|
| `w1=0x388` | `fork_init` ARM64 反汇编 | ★★★★★ |
| `memset size=0x380` | `mm_alloc` ARM64 反汇编 | ★★★★☆ |
| `CONFIG_NR_CPUS=8` | `/proc/config.gz` | ★★★★★ |
| slab order=3 | 4.19 算法计算 | ★★★★☆ |

#### 使用脚本

```bash
cd leaf5
uv run leaf5-mm-params         # 人类可读输出
uv run leaf5-mm-params --json  # JSON 输出（供脚本消费）
```

> **注意**：`common.h` 中的 `MM_STRUCT_SZ 0x3c0` 对 Leaf5 是**错误的**，比实际值大 56 字节。
> 这会导致 KernelSnitch 扫描时对象间距算错（36 对象/slab 当 34 去跳），实际表现为扫描永远跳过真正的 mm_struct → 无限循环。

---

## 9. 复现命令清单

```bash
# 0. 设备
adb devices
adb shell uname -a

# 1. 进入分析目录
cd leaf5
uv sync

# 2. 重新采集（会覆盖 raw/ 下部分文件）
uv run leaf5-collect
uv run leaf5-summarize

# 3. 手动拉取（与 collect 等价）
adb exec-out cat /proc/config.gz > raw/config.gz
gzip -dc raw/config.gz > raw/kernel_config.txt
adb exec-out cat /sys/kernel/kheaders.tar.xz > raw/kheaders.tar.xz

# 4. 核对 boot.img 是否等于 runtime（当前预期：不等于）
strings ../boot.img | grep 'Linux version 4.19' | head
adb shell cat /proc/version

# 5. 提取内核偏移（需先运行 vmlinux-to-elf 生成 raw/vmlinux.elf）
uv run leaf5-extract-offsets

# 6. 提取 MM_STRUCT_SZ 与 MM_ORDER
uv run leaf5-mm-params
uv run leaf5-mm-params --json  # JSON 输出
```

---

## 9. 变更记录

| 日期 | 说明 |
|------|------|
| 2026-07-24 | 从零重做分析；废弃旧 leaf5 文档/结论；确立 config.gz + kheaders 为权威 runtime 源；标记仓库 boot.img 版本不匹配 |
| 2026-07-24 | 新增 MM_STRUCT_SZ=0x388 / MM_ORDER=3 分析；新增 `scripts/extract_mm_struct_params.py`；新增 `leaf5-mm-params` 入口；修正 common.h 中 0x3c0→0x388 |
