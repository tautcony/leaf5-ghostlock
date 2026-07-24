> **文档类型**: 索引文档（主入口） | **状态**: ✅ 有效 | **最后更新**: 2026-07-24

# Leaf5 分析工作区

针对 **Onyx Leaf5** 的 GhostLock（CVE-2026-43499）适配调研目录。

> 本目录文档于 **2026-07-24 从零重写**。此前基于错误/过期数据源的结论已废弃，请以本文及 [`ANALYSIS.md`](ANALYSIS.md) 为准。

---

## 项目概述

### 项目背景

GhostLock (CVE-2026-43499) 是一个影响 Linux 2.6.39 至 7.1-rc1 的内核栈 UAF 漏洞，通过 `FUTEX_CMP_REQUEUE_PI` 竞态条件触发。本目录是对 **Onyx Leaf5**（TabBoox 电纸书，kernel 4.19.157，Android 13）的 GhostLock 适配分析，目标是评估其利用链可行性并完成 exploit 适配。

### 当前项目状态

**新路径发现** — KernelSnitch 泄漏、sk_buff 喷射、GhostLock 触发均已验证通过。pselect 栈覆盖路由确认不可行，但 **全局 copy_from_user 扫描发现了新的可行栈覆盖路由**：Qualcomm `qcedev_ioctl`（`/dev/qcedev`）的 328 字节用户缓冲区在标准 ioctl 深度下与 waiter **完全重叠**（64 字节全覆盖），且 `/dev/qcedev` 在设备上存在（`crw-rw-rw-`）。下一步应优先验证 qcedev_ioctl 路由。

---

## 设备快照

| 项 | 值 |
|----|-----|
| 型号 | Onyx Leaf5（fingerprint: `ONYX/TabBoox/TabBoox:13/...`） |
| Android | 13 / API 33 / patch 2026-04-01 |
| Kernel | `4.19.157-perf-g3d47a6619220-dirty` #245 SMP PREEMPT aarch64 |
| 平台 | Qualcomm lito / SM6350 (LAGOON), 8 核 |
| 内存 | ~3.4 GiB, PAGE_SIZE=4096 |
| AVB | unlocked（orange, flash.locked=0） |
| SELinux | Enforcing；shell uid=2000 CapEff=0 |
| GhostLock CONFIG | `FUTEX_PI=y`, `RT_MUTEXES=y`，**无内核 CFI**，**无 KPTI** |
| Stage1 应用 | Firefox **151.0.2** 已安装 |
| ADB Serial | `ac340d06` |

### 安全加固画像

| 机制 | 状态 | 对利用的影响 |
|------|------|-------------|
| 内核 CFI (`CONFIG_CFI_CLANG`) | **关闭** | ✅ 无需 CFI bypass — 最大优势 |
| KPTI (`CONFIG_UNMAP_KERNEL_AT_EL0`) | **关闭** | ✅ 无 trampoline 开销，栈帧更简单 |
| KASLR (`CONFIG_RANDOMIZE_BASE`) | 开启 | 需 leak（已解决：direct-map 直接计算） |
| USER_NS | 关闭 | 不能依赖 userns 提权 |
| PANIC_ON_OOPS | 关闭 | 调试容错更好 |
| PAC / BTI / SCS | 全部关闭 | 控制流保护极弱 |
| SLUB freelist harden/random | 开启 | 堆利用需考虑 |
| VMAP_STACK | 开启 | 栈溢出检测（当前未触发） |
| SELinux | Enforcing | 部分接口受限 |

---

## 一、已完成的阶段 ✅

| 阶段 | 状态 | 说明 |
|------|------|------|
| 设备信息采集 | ✅ | 完整设备画像，所有原始数据在 `raw/` |
| 内核 CONFIG 分析 | ✅ | `/proc/config.gz` 为权威配置源 |
| 内核镜像提取 | ✅ | `boot_a.bin` 确认匹配 runtime (#245, g3d47a6619220) |
| 符号表重建 | ✅ | `vmlinux.elf`: 121883 symbols（vmlinux-to-elf） |
| 结构体偏移提取 | ✅ | capstone 5.0 反汇编验证关键偏移 |
| `target.h` 编写 | ✅ | `exploit/targets/onyx-leaf5/target.h` |
| Docker 编译 | ✅ | 通过，产出 preload.so + test programs |
| Futex 哈希自检 | ✅ | 用户态 hash 自一致性通过 |
| Futex 碰撞时序探测 | ✅ | 时序侧信道有效 (pile-up 26x baseline) |
| **KernelSnitch mm_struct 泄漏** | ✅ | **KSNITCH_COLLISIONS=2 时可靠泄漏 (< 1 秒)** |
| **sk_buff reclaim** | ✅ | **4/4 send 成功 (ret=65536)** |
| KASLR bypass | ✅ | Direct-map 直接计算，无需 slide |
| PSELECT_WAITER_WORD_SHIFT 计算 | ✅ | capstone 精确计算 = **-46** |
| 多路由栈覆盖比较 | ✅ | 5 路由分析完成（pselect/sendmsg/recvmsg/binder/do_select） |
| 全局 copy_from_user 扫描 | ✅ | 309 函数 / 724 调用点，**无函数直接重叠** |

---

## 二、栈覆盖路由分析

### 2.1 pselect 栈覆盖：❌ 不可行

通过 capstone 精确反汇编 `vmlinux.elf` 确认：

| 参数 | 值 | 说明 |
|------|-----|------|
| futex_wait 帧大小 | 0x140 (320B) | waiter 所在帧 |
| waiter 在 futex_wait 中位置 | SP+0x50 | futex_q + 0x48 |
| waiter **绝对**栈偏移 | **-0x380** | 含 do_futex(0x220) + sys_futex(0x70) |
| core_sys_select 帧大小 | 0x1c0 (448B) | fd_set 所在帧 |
| fd_set (stack_fds) 位置 | SP+0x50 | core_sys_select 帧内 |
| fd_set **绝对**栈偏移 | **-0x210** | 含 sys_pselect6(0xa0) |
| **Δ 字节** | **-368** | waiter 比 fd_set 深 368 字节 |
| **PSELECT_WAITER_WORD_SHIFT** | **-46** | Δ字节 / 8 |

**结论**：waiter 在 fd_set 下方 368 字节处，fd_set 正向索引无法到达 waiter 位置。

### 2.2 四路并行分析结果

2026-07-24 针对栈覆盖阻塞，启动了四个方向的系统分析：

| # | 方向 | 结论 | 原因 |
|---|------|------|------|
| 1 | **pselect 栈覆盖** | ❌ 不可行 | SHIFT=-46 |
| 2 | **binder_thread_write** | ❌ 不可行 | Δ=0 但值为内核指针，非用户可控 |
| 3 | **do_select 缓冲区** | ❌ 无重叠 | 帧内 344B 间隙，无 CFU 调用 |
| 4 | **sendmsg/recvmsg 栈覆盖** | ❌ 不可行 | Δ ≥44 词 |
| 5 | **堆喷射绕过** | ❌ 循环依赖 | 需内核 R/W → 需 fops 覆写 → 需栈覆盖 |
| 6 | **全局 copy_from_user 扫描** | ✅ **发现新路由!** | 见下方 §2.3 |

### 2.3 全局 copy_from_user 扫描：✅ 发现可行路由 ⭐

**关键洞察**：最初的 BFS 分析只追踪了直接 BL 调用（71/724 个 CFU 调用点），漏掉了所有通过**函数指针间接调用**的 ioctl/read/write 处理函数。优化后的扫描器对所有 309 个候选函数逐一计算绝对栈偏移，使用已知的 syscall 链帧大小：

| syscall 路径 | 累计帧 |
|-------------|--------|
| ioctl | sys_ioctl(0x40) + ksys_ioctl(0x40) + vfs_ioctl(0x20) = **0xA0** |
| read | sys_read(0x10) + ksys_read(0x40) + vfs_read(0x40) = **0x90** |

**扫描统计**：

| 指标 | 值 |
|------|-----|
| 候选函数（含 CFU） | 309 |
| CFU 调用点总数 | 724 |
| BFS 可达（直接 BL） | 71 |
| **任意深度下有重叠** | **715** |
| **完整 64B waiter 覆盖** | **143** |

#### 最佳候选：qcedev_ioctl ⭐⭐⭐

| 属性 | 值 |
|------|-----|
| 函数 | `qcedev_ioctl` |
| 帧大小 | **0x360** (864B) |
| CFU 缓冲区 | **SP+0x50, 328 字节** |
| 设备节点 | `/dev/qcedev` (Qualcomm crypto engine) |
| 设备权限 | `crw-rw-rw-` ✅ (shell 可访问) |
| 调用路径 | ioctl(fd, QCEDEV_IOCTL_ENC_REQ, &user_arg) |

**栈重叠计算**（标准 ioctl 深度 0xA0）：

```
dest_abs  = -(0xA0 + 0x360) + 0x50 = -0x3B0
buf_end   = -0x3B0 + 328 = -0x268
waiter    = [-0x380, -0x340)
重叠       = [-0x380, -0x340) 完全在 [-0x3B0, -0x268) 内
覆盖率     = FULL (64/64 字节) ✅
容差范围   = depth 0x70-0x100 均可达全覆盖 (宽裕)
```

**利用路径**：
1. `fd = open("/dev/qcedev", O_RDWR)` — shell 可访问
2. `ioctl(fd, QCEDEV_IOCTL_ENC_REQ, &user_arg)` — 328 字节用户数据
3. 内核路径: `sys_ioctl → ksys_ioctl → vfs_ioctl → qcedev_ioctl`（通过 `f_op->unlocked_ioctl` 函数指针）
4. `copy_from_user` 将 328 字节从 `user_arg` 复制到内核栈 SP+0x50
5. 该缓冲区完全覆盖悬垂 waiter 的 64 字节

#### 次选候选：ipa3_ioctl

| 属性 | 值 |
|------|-----|
| 函数 | `ipa3_ioctl` |
| 帧大小 | 0x330 (816B) |
| CFU 缓冲区 | SP+0x30, 108 字节 |
| 设备节点 | `/dev/ipa` (Qualcomm IP Accelerator) |
| 覆盖率 | FULL (64B)，但深度容差较窄 (0x80-0x84) |

### 2.4 binder 路由详情（Δ=0 但不可用）

binder_thread_write 是唯一精确对齐的路由（Δ=0），但存在根本性障碍：

- SP+0x20..SP+0x58 的局部结构体恰好覆盖 waiter 字节 0x00..0x38
- 但这些位置存储的是 `binder_proc+offset` / `binder_thread+offset`（内核堆指针）
- binder_thread_write 仅 2 处 copy_from_user，目标均在 SP+0xa8（waiter 范围外 72B）
- 12 个 BC_* 命令中无一将用户数据写入 waiter 范围

### 2.5 循环依赖：qcedev_ioctl 可解

之前认为的循环依赖：
```
需要内核 R/W → 需要 configfs/ashmem fops 覆写 → 需要栈覆盖 → ❌ 死锁
```

qcedev_ioctl 提供了缺失的栈覆盖环节：
```
需要内核 R/W → 需要 configfs/ashmem fops 覆写 → qcedev_ioctl 栈覆盖 ✅ → 可解!
```

---

## 三、关键 4.19 vs 5.10 差异

| 维度 | 4.19 (Leaf5) | 5.10 (OPPO Find N2) | 影响 |
|------|-------------|---------------------|------|
| `rt_mutex_waiter` sizeof | **0x40** (64B) | 0x50 (80B) | 无 prio/deadline 字段 |
| `task_struct.real_cred` | **0x7d8** | 0x818 | cred 覆写偏移 |
| `task_struct.cred` | **0x7e0** | 0x820 | cred 覆写偏移 |
| `task_struct.pi_blocked_on` | **0x8d0** | 0x898 | PI 链操作 |
| `pipe_inode_info.head/tail` | **0x38/0x3c** | 0x60/0x64 | pipe 结构访问 |
| `pipe_inode_info.bufs` | **0x78** | 0xa8 | pipe buffer 访问 |
| `mm_struct.owner` | **0x328** | 0x408 | mm owner 覆写 |
| `MM_STRUCT_SZ` | **0x388** (904B) | 0x3c0 (960B) | mm_struct 扫描步长 |
| `MM_ORDER` | **3** | 3 | 对象数/slab: **36** vs 34 |
| futex_key 布局 | **V1** (addr+0, mm+8) | non-V1 (mm+0, addr+8) | hash 计算顺序不同 |
| `futex_wait_requeue_pi` 符号 | ❌ 不存在 | 存在 | do_futex 内联处理 |
| `configfs_read_file/write_file` | ✅ (非 iter) | `configfs_read_iter/write_iter` | configfs 函数名 |
| `selinux_enforcing` | `selinux_enforcing_boot` | `selinux_enforcing` | SELinux 变量名 |
| 内核 CFI | ❌ **无** | ✅ 强 CFI | **Leaf5 最大优势** |
| KPTI | ❌ **无** | ✅ 有 | 无 trampoline 开销 |

---

## 四、已验证的内核偏移

### 4.1 结构体偏移（capstone 反汇编确认）

| 结构 | 字段 | 偏移 | 验证级别 |
|------|------|------|---------|
| `rt_mutex_waiter` | sizeof | **0x40** | `[BIN]` |
| `rt_mutex_waiter` | `tree_entry` | 0x00 | `[BIN]` |
| `rt_mutex_waiter` | `pi_tree_entry` | 0x18 | `[BIN]` |
| `rt_mutex_waiter` | `task` | 0x30 | `[BIN]` |
| `rt_mutex_waiter` | `lock` | 0x38 | `[SRC]` |
| `task_struct` | `real_cred` | 0x7d8 | `[BIN]` |
| `task_struct` | `cred` | 0x7e0 | `[BIN]` |
| `task_struct` | `prio` | 0xac | `[BIN]` |
| `task_struct` | `pi_blocked_on` | 0x8d0 | `[BIN]` |
| `task_struct` | `pi_waiters` | 0x8b8 | `[EST]` |
| `task_struct` | `pid` | 0x5f8 | `[EST]` |
| `task_struct` | `tgid` | 0x5fc | `[EST]` |
| `pipe_inode_info` | `head` | 0x38 | `[BIN]` |
| `pipe_inode_info` | `tail` | 0x3c | `[BIN]` |
| `pipe_inode_info` | `bufs` | 0x78 | `[BIN]` |
| `pipe_inode_info` | `tmp_page` | 0x60 | `[BIN]` |
| `mm_struct` | `owner` | 0x328 | `[BIN]` |
| `cred` | `euid` | 0x14 | `[BIN]` |

> `[BIN]` = capstone 反汇编确认, `[SYM]` = 符号表查询, `[SRC]` = 源码推断, `[EST]` = 估计值

### 4.2 栈帧深度参考

| 函数 | 帧大小 | 从 syscall entry 累计深度 |
|------|--------|--------------------------|
| `__arm64_sys_futex` | 0x70 | 0x70 |
| `do_futex` | 0x220 | 0x290 |
| `futex_wait` | 0x140 | **0x3d0** |
| `__arm64_sys_pselect6` | 0xa0 | 0xa0 |
| `core_sys_select` | 0x1c0 | **0x260** |
| `do_select` | **0x370** | **0x5d0** |
| `__arm64_sys_sendmsg` | 0x90 | 0x90 |
| `___sys_sendmsg` | 0x190 | 0x220 |
| `binder_ioctl` | 0xa0 | 0xa0 |
| `binder_ioctl_write_read` | 0x1a0 | 0x240 |
| `binder_thread_write` | 0x160 | **0x3a0** |
| `binder_transaction` | 0x210 | 0x5b0 |
| **waiter (目标)** | — | **0x380** |

---

## 五、KernelSnitch mm_struct 泄漏

### 5.1 已修复的 Bug

| Bug | 症状 | 修复 |
|-----|------|------|
| futex_key V1 布局 | bruteforce 最佳匹配仅 4/16 | 启用 `FUTEX_KEY_LAYOUT_V1`，交换 address/mm 顺序 |
| 孤儿 `#endif` | 编译错误 | 删除残留预处理指令 |
| MM_STRUCT_SZ 默认值 | preload.so 启动时 `mm_struct sz (0)` | 全局变量从 target.h 默认值初始化 |
| futex_hash 页对齐 | hash 输入不一致 | 使用完整地址 + offset |
| futex_hashsize CPU 数 | `sysconf` 返回 16，实际 8 | 从 `/sys/devices/system/cpu/possible` 读取 |

### 5.2 泄漏性能

| 参数 | 值 |
|------|-----|
| KSNITCH_COLLISIONS | **2**（唯一可靠配置） |
| 搜索空间 | 8 线程 × 16GB direct map |
| 平均候选数 | **< 200** 即命中 |
| 耗时 | **< 1 秒** |
| MM_STRUCT_SZ | **0x388** |
| MM_ORDER | **3** |

---

## 六、推荐实施优先级

基于 qcedev_ioctl 发现，重新排序：

### 🔴 P0 — qcedev_ioctl 栈覆盖验证（1-2h）

1. **确认 `/dev/qcedev` 可访问性** — 设备上已确认 `crw-rw-rw-`，shell 可 open
2. **逆向 QCEDEV_IOCTL_ENC_REQ 命令码** — 从 vmlinux.elf 反汇编提取 ioctl 命令号
3. **编写最小 NDK 探针** — 向 `/dev/qcedev` 发送 ioctl，验证 328 字节可被复制到内核栈
4. **集成到 fops.c** — 将 pselect 栈覆盖替换为 qcedev_ioctl 栈覆盖
5. **端到端测试** — 完整 GhostLock 触发 → qcedev_ioctl 覆盖 → configfs/ashmem fops 覆写

### 🟠 P1 — 备用路由（1-2h）

6. **ipa3_ioctl 栈覆盖** — 深度容差较窄但可作为后备
7. **compat_qcedev_ioctl** — 328B 复制变体，同样全覆盖

### 🟡 P2 — 偏移验证（1-2h）

8. **[EST] 偏移 pahole/IDA 验证** — TASK_PID_OFF, TASK_TASKS_OFF, CRED_SECURITY_OFF 等
9. **SKB_DATA_DELTA 实测** — 4.19 sk_buff 布局可能与 5.10 不同
10. **Stage1 浏览器验证** — Firefox 151.0.2 CVE-2026-10702 触发测试

---

## 七、工具链

Python 使用 **uv** 管理：

```bash
cd leaf5
uv sync
uv run leaf5-collect           # adb 重新采集到 raw/
uv run leaf5-summarize         # 打印 GhostLock 相关 CONFIG
uv run leaf5-extract-offsets   # 提取符号 + 结构体偏移
uv run leaf5-mm-params         # 提取 MM_STRUCT_SZ + MM_ORDER
uv run leaf5-mm-params --json  # JSON 输出
```

分析脚本：

```bash
# 计算 PSELECT_WAITER_WORD_SHIFT
uv run python -m scripts.compute_pselect_shift -v

# 多路由栈覆盖比较
uv run python -m scripts.compute_stack_routes -v

# 全局 copy_from_user 扫描
uv run python ghostlock-analysis/copy-from-user-scan/scanner.py --verbose

# do_select 缓冲区分析
uv run python ghostlock-analysis/do-select-buffers/analyze_do_select.py -v

# Binder 命令深度分析
uv run python ghostlock-analysis/binder-commands/analyze_binder_commands.py -v
```

编译与部署：

```bash
# Docker 编译
cd exploit
./docker-build.sh TARGET_DIR=targets/onyx-leaf5

# 部署
adb push preload.so /data/local/tmp/

# 运行 exploit（当前阻塞在 pselect 阶段）
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so KSNITCH_COLLISIONS=2 /system/bin/toybox ls /dev/null'

# 运行时二分搜索 PSELECT_SHIFT_OVERRIDE
for shift in $(seq -64 4 64); do
  echo "=== SHIFT=$shift ==="
  adb shell "PSELECT_SHIFT_OVERRIDE=$shift LD_PRELOAD=/data/local/tmp/preload.so ls /dev/null" 2>&1 | grep -E 'pselect returned|write'
done
```

---

## 八、文档索引

| 文档 | 内容 |
|------|------|
| **[ANALYSIS.md](ANALYSIS.md)** | 完整分析过程 + 结论 + 可信度矩阵（主报告，含偏移定位结果） |
| **[VERIFICATION_REPORT.md](VERIFICATION_REPORT.md)** | 逐项验证报告（参照 OPPO Find N2 方法论，含修复补丁清单） |
| **[GHOSTLOCK_EXPLOIT_PLAN.md](GHOSTLOCK_EXPLOIT_PLAN.md)** | 完整利用计划 + 各阶段阻塞点分析 + 方案 A-F |
| **[STACK_LAYOUT.md](STACK_LAYOUT.md)** | 栈帧布局分析（futex_wait/do_futex/task_blocks_on_rt_mutex） |
| **[PSELECT_STACK_ANALYSIS_PLAN.md](PSELECT_STACK_ANALYSIS_PLAN.md)** | PSELECT_WAITER_WORD_SHIFT 计算计划（含 4.19 vs 5.10 栈帧对比） |
| **[COMPARE_OPPO_FIND_N2.md](COMPARE_OPPO_FIND_N2.md)** | 与仓库原目标 OPPO Find N2 的全维度对比 |
| **[NEXT_STEPS.md](NEXT_STEPS.md)** | 后续工作清单（P0-P5，含已完成项和待办项） |
| **[PROCESS_LOG.md](PROCESS_LOG.md)** | 按时间顺序的操作流水（便于审计与复现） |
| **[HANDOFF.md](HANDOFF.md)** | 轮次交接文档（含深度问题 P0/P1/P2 分析 + 修复建议） |
| **[ghostlock-analysis/README.md](ghostlock-analysis/README.md)** | 四路并行分析汇总（堆喷射/CFU扫描/Binder/do_select） |
| [ghostlock-analysis/copy-from-user-scan/ANALYSIS.md](ghostlock-analysis/copy-from-user-scan/ANALYSIS.md) | 全局 CFU 扫描结果：**发现 qcedev_ioctl 等 143 个可行栈覆盖路由** |
| [ghostlock-analysis/binder-commands/ANALYSIS.md](ghostlock-analysis/binder-commands/ANALYSIS.md) | Binder 命令分发深度分析 |
| [ghostlock-analysis/do-select-buffers/ANALYSIS.md](ghostlock-analysis/do-select-buffers/ANALYSIS.md) | do_select 帧缓冲区分析 |
| [ghostlock-analysis/heap-spray/ANALYSIS.md](ghostlock-analysis/heap-spray/ANALYSIS.md) | 堆喷射循环依赖分析 |
| [raw/](raw/) | adb 原始采集数据（可复核） |

---

## 九、关键警告

1. 仓库根目录 `boot.img` 的内核 banner 是 **#119 / g87880838aed5（2025-07）**，**不是**当前设备 #245 / g3d47a6619220。禁止将其用于偏移提取。
2. 禁止将 `exploit/targets/oppo-find_n2/target.h` 偏移直接用于 Leaf5 — 4.19 与 5.10 结构体布局差异显著。
3. shell 无法 `dd` boot 分区；需 fastboot/厂商方式导出与 runtime 一致的镜像。
4. OPPO Find N2 的 DEAD END 清单**不能**原样套到 Leaf5 — 内核版本不同，部分死路可能复活，也可能出现新死路。
5. `[SRC]`/`[EST]` 标记的偏移需 pahole 或 IDA 复核后方可用于生产 exploit。

---

## 十、一句话总结

> Leaf5 在 **GhostLock 触发条件**上具备 CONFIG 级可行性，且在 **CFI/KPTI** 上明显弱于 Find N2；KernelSnitch 泄漏 / sk_buff 喷射 / GhostLock 触发均已验证通过。pselect 栈覆盖确认不可行（Δ=-46 词），但 **全局 copy_from_user 扫描发现 qcedev_ioctl**（`/dev/qcedev`）的 328 字节用户缓冲区在标准 ioctl 深度下与 waiter **完全重叠**（64B 全覆盖），打破了"需要内核写原语 ↔ 需要栈覆盖"的循环依赖。**下一步：验证 qcedev_ioctl 栈覆盖路由并集成到 exploit 链。**

---

*最后更新: 2026-07-24*
