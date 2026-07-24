> **文档类型**: 过程文档（操作流水） | **状态**: ✅ 有效（历史记录） | **最后更新**: 2026-07-24

# Leaf5 分析过程流水（2026-07-24）

按时间顺序记录操作，便于审计与复现。详细结论见 [ANALYSIS.md](ANALYSIS.md)。

## 背景

- 用户要求：基于另一设备（OPPO Find N2）仓库，**重新分析** Leaf5；设备已 adb 连接；Python 用 uv；过程与结论写入 markdown。
- 既有 leaf5 目录曾被提交后又删除；用户明确 **先前分析不准确**，故不恢复旧结论，从零采集。

## 步骤记录

### 1. 连接确认

- `adb devices` → `ac340d06` Leaf5
- `uname` / `getprop` → Android 13，kernel `4.19.157-perf-g3d47a6619220-dirty` #245

### 2. 安全面与分区

- SELinux Enforcing，shell CapEff=0
- bootloader unlocked（orange / flash.locked=0）
- `boot_a` → `mmcblk0p13`，shell `dd` Permission denied
- 多数 sysctl / kallsyms / cmdline Permission denied

### 3. 拉取 CONFIG 与 kheaders

- `/proc/config.gz` → `raw/config.gz`（权威）
- `/sys/kernel/kheaders.tar.xz` → 与 runtime 同 `UTS_RELEASE`（build #244 vs uname #245）

### 4. 关键 CONFIG 解读

- `FUTEX_PI=y`，无内核 CFI，无 KPTI，`USER_NS` 关，`VMAP_STACK` 开
- 与 Find N2 加固画像差异大

### 5. 核对仓库 boot.img

- banner：`g87880838aed5` #119（2025-07）
- **不等于** runtime → 标记为不可用于偏移

### 6. 应用与接口

- Firefox 151.0.2、Chromium 存在
- ashmem/binder 存在；configfs 挂载但不可 list

### 7. 工具与文档

- `leaf5/pyproject.toml` + uv scripts：`leaf5-collect` / `leaf5-summarize`
- 撰写 `ANALYSIS.md`、`README.md`、`COMPARE_OPPO_FIND_N2.md`、`NEXT_STEPS.md`
- 原始数据落在 `raw/`

## 未执行（有意）

- 重启进 fastboot 拉 boot（需用户确认）
- 编译/推送 exploit 或攻击性 PoC
- 恢复 git 中旧 leaf5 文档内容

## 步骤记录（2026-07-24 续 — 偏移定位）

### 8. 确认 boot_a.bin 与 runtime 一致

- `strings leaf5/boot_a.bin | grep 'Linux version'` → `g3d47a6619220-dirty #245` ✅ 匹配
- `vmlinux_extracted`、`vmlinux.elf`（相对基址）、`vmlinux_abs.elf`（绝对基址）均已存在

### 9. 符号提取（vmlinux.elf）

- 121883 symbols from kallsyms → ELF .symtab
- 基址 `_text = 0xffffff8008080000`（39-bit VA, TEXT_OFFSET=0x80000）
- 确认关键符号：init_task、anon_pipe_buf_ops、ashmem_fops/misc、selinux_state 等
- 发现 4.19 与 5.10 符号名差异：无 futex_wait_requeue_pi、configfs_read_iter→configfs_read_file

### 10. 结构体偏移提取（capstone 5.0 反汇编）

- 安装 `capstone` + `pyelftools` 到 leaf5 venv（uv add）
- 编写 `scripts/extract_offsets.py` 可复用工具
- 反汇编关键访问函数：commit_creds、exit_creds、rt_mutex_adjust_prio_chain、task_blocks_on_rt_mutex、pipe_write 等
- 确认 rt_mutex_waiter sizeof=0x40（4.19 无 prio/deadline）
- 确认 task_struct：real_cred=0x7d8, cred=0x7e0, pi_blocked_on=0x8d0
- 确认 pipe_inode_info：head=0x38, tail=0x3c, ..., bufs=0x78

### 11. target.h 与文档

- 创建 `exploit/targets/onyx-leaf5/target.h`（含 [BIN]/[SYM]/[SRC]/[EST] 验证标记）
- 更新 `ANALYSIS.md` §8 加入偏移定位结果
- 更新 `pyproject.toml` 增加 `leaf5-extract-offsets` 入口
- [SRC]/[EST] 标记的偏移（TASK_PID_OFF、TASK_TASKS_OFF 等）需后续 pahole/IDA 验证

### 12. 已确认的关键 4.19 vs 5.10 差异

| 维度 | 4.19 (Leaf5) | 5.10 (OPPO) |
|------|-------------|------------|
| rt_mutex_waiter 大小 | 0x40 | 0x50 |
| prio/deadline 字段 | 无 | 有 |
| futex_wait_requeue_pi | 无（do_futex 内联） | 有 |
| cred 偏移 (real_cred/cred) | 0x7d8/0x7e0 | 0x818/0x820 |
| pipe head/tail 偏移 | 0x38/0x3c | 0x60/0x64 |
| mm->owner 偏移 | 0x328 | 0x408 |
| pi_blocked_on 偏移 | 0x8d0 | 0x898 |

### 13. 栈帧布局分析

- 完整反汇编 do_futex、futex_wait、task_blocks_on_rt_mutex、rt_mutex_init_waiter
- do_futex: 0x220 (544B) 栈帧，sub sp,sp,#0x60 + sub sp,sp,#0x1c0
- futex_wait: 0x140 (320B) 栈帧
- **futex_q（含 rt_mutex_waiter）位于 futex_wait 的 sp+0x80**
- waiter sizeof=0x40, waiter->task 在 sp+0xb0
- 写入 `STACK_LAYOUT.md`

### 14. 工具链与可复用脚本

- `scripts/extract_offsets.py` — 通用 ARM64 内核偏移提取（capstone 反汇编）
- `uv run leaf5-extract-offsets` — 入口命令
- 依赖：`capstone` + `pyelftools`（通过 uv 管理）

### 15. MM_STRUCT_SZ 与 MM_ORDER 提取

- 反汇编 `fork_init`，定位 `kmem_cache_create_usercopy("mm_struct", size, ...)` 调用点
- **发现 capstone 5.x 的 bl/adrp op.imm 返回错误值**（是 capstone 内部编码而非目标地址）
- 改用手动 ARM64 指令解码：`decode_bl_target()` 解码 imm26 字段、`decode_adrp_page()` 解码 imm21 字段
- `mov w1/w4/w5, #imm` 的 op.imm 正常可用
- 追溯寄存器值：`w1=0x388`, `w4=0x150` (useroffset), `w5=0x170` (usersize)
- 交叉验证：`mm_alloc` 中 `memset(mm, 0, 0x380)` — 8 字节差额由 mm_init 显式初始化
- 实现 Linux 4.19 SLUB `calculate_order()` 算法，输入 object_size=904 + CONFIG_NR_CPUS=8
- min_objects=20, order-3 (32KB) fits 36 objects, waste 0.68% → **MM_ORDER=3**

### 16. 提取工具脚本化

- 编写 `scripts/extract_mm_struct_params.py` — 可复用 MM_STRUCT_SZ/MM_ORDER 提取工具
- 注册 `leaf5-mm-params` 入口（`pyproject.toml`）
- 支持 `--json` 输出供脚本消费
- 支持 `--elf` / `--config` 参数指定非默认路径

### 17. [EST] 偏移批量验证（2026-07-24 续3）

- 通过 capstone 反汇编验证所有 [EST] 标记的偏移
- **CORRECTED**: TASK_PID_OFF: 0x5f8→0x630, TASK_TGID_OFF: 0x5fc→0x634, TASK_SECCOMP_OFF: 0x8e8→0x888, CRED_SECURITY_OFF: 0x80→0x78
- **CORRECTED**: FAKE_TASK_PI_LOCK_OFF: 0x8a0→0x8ac, FAKE_TASK_PI_TOP_TASK_OFF: 0x8c0→0x8c8
- **CONFIRMED**: TASK_TASKS_OFF (0x530), TASK_PI_WAITERS_OFF (0x8b8), PIPE_INODE_INFO_STRUCT_SIZE (0x88), TASK_NORMAL_PRIO_OFF (0xb4)
- 更新 target.h 所有验证标记为 [BIN]

### 18. qcedev_ioctl 逆向 + 路由验证（2026-07-24 续4）

- 从 vmlinux.elf 反汇编 qcedev_ioctl，提取 ioctl 命令码:
  - `0xc148870a` = QCEDEV_IOCTL_ENC_REQ (328B @ SP+0x50, _IOC(RW, 0x87, 0x0a, 328))
  - `0xc044870b` = QCEDEV_IOCTL (68B, _IOC(RW, 0x87, 0x0b, 68))
- 确认 frame=0x360, 9个 CFU 调用点, 328B 在 depth 0x80-0x100 下 FULL waiter 覆盖
- **关键阻塞**: /dev/qcedev 不存在! 实际设备节点为 /dev/qce (234:0)
- /dev/qce 权限: 0660 system:drmrpc + SELinux vendor_qce_device
- Shell (uid=2000) 不在 drmrpc(1026) 组, Firefox (uid=10127) 也不在
- **qcedev_ioctl 路由被设备权限阻塞**

### 19. 全路由扫描分析（2026-07-24 续5）

- 重新运行全局 CFU 扫描器: 309 函数/724 CFU 调用点
- 在标准 ioctl 深度 (0x80-0x100) 下 FULL 覆盖仅 4 函数:
  1. qcedev_ioctl — /dev/qce 权限阻塞
  2. ipa3_ioctl — /dev/ipa 不存在
  3. lo_ioctl — /dev/loop-control root-only
  4. __arm64_sys_rt_sigreturn — 天然深度仅~0, 需额外 0x100 深度
- 分析 12+ 备选路由: 全部因深度不足或权限问题阻塞
- **kgsl compat ioctl 为最有希望备选**:
  - /dev/kgsl-3d0 世界可读写 (crw-rw-rw-)
  - kgsl_drawobj_cmd_add_ibdesc_list: 16B @ SP+0x28, 覆盖 TASK+LOCK
  - 需要 caller depth 0x2E8, 标准深度 ~0x2A0 (差 0x48)
  - compat ioctl 路径额外深度 0xA0 (超出 0x350, 可能过深)
- uinput_ioctl_handler: 92B @ SP+0x60, 需 depth 0x2C0 (标准仅 0xA0, 差 0x220)

### 20. kgsl compat 深度精确验证 + /dev/qce 间接访问（2026-07-24 续6）

**compat 深度纠正**:
- 原估算 compat 额外 0xA0 深度有误：`security_file_ioctl`、`do_ioctl_trans`、`ioctl_preallocate` 为顺序调用，帧不累加
- 实际 compat 到 kgsl_ioctl_helper 仅 0x100（regular 0xD0），差异 0x30

**kgsl dispatch 链帧分析**:
- kgsl_ioctl: 0x30, 仅调用 kgsl_ioctl_helper
- kgsl_ioctl_helper: 0xD0, 内部调用 kgsl_ioctl_copy_in 等
- kgsl_compat_ioctl: 0x30, blr x8 分派（部分命令有 _compat wrapper）
- kgsl_ioctl_rb_issueibcmds: 0x70, 调用 create(0x40) → add_ibdesc(0x40) → add_ibdesc_list(0x90)
- kgsl_ioctl_submit_commands: 0x70, 直接调用 add_ibdesc_list(0x90)（跳过 add_ibdesc）

**关键发现 — TIF_32BIT 触发正确路径**:
- `kgsl_drawobj_cmd_add_ibdesc_list` 中有两个 CFU 路径，由 `sp_el0[0] & (1<<22)` 即 `TIF_32BIT` 选择:
  - TIF_32BIT 置位（32-bit 进程）: 16B CFU @ SP+0x28 (x29-0x18) ← **目标路径!**
  - TIF_32BIT 未置位（64-bit 进程）: 32B CFU @ SP+0x08
- CFU 前仅 `access_ok` 检查，无语义数据验证

**精确深度计算**:
```
Compat 路径 via rb_issueibcmds (含中间帧):
  __arm64_compat_sys_ioctl(0x40) + do_vfs_ioctl(0x90) + kgsl_compat_ioctl(0x30)
  + kgsl_ioctl_helper(0xD0) + rb_issueibcmds(0x70)
  + kgsl_drawobj_cmd_create(0x40) + kgsl_drawobj_cmd_add_ibdesc(0x40)
  = D = 0x2C0 (caller depth above ibdesc_list)

CFU 16B @ SP+0x28, frame=0x90:
  abs = -(0x2C0 + 0x90) + 0x28 = -0x328
  Buffer: [-0x328, -0x318)
  Waiter TASK: [-0x320, -0x318)  ✅ 精确覆盖!
  Waiter LOCK: [-0x318, -0x310)   保留脏数据

覆盖映射:
  ibdesc.gpuaddr [0:8]     → waiter +0x28 (pi_tree.rb_left) — 设为 0
  ibdesc.sizedwords [8:16] → waiter +0x30 (TASK)            — fake task_struct
```

**/dev/qce 间接访问探索（8 种方法，全部阻塞）**:
- Binder 服务: 17 进程有 drmrpc GID, SELinux 阻止跨域交互
- 进程 fd 泄漏: 无任何进程当前打开 /dev/qce
- SELinux 策略: 无法提取分析
- setuid/setgid: **零** — 设备上无任何此类二进制
- Unix socket/sysfs: 无相关接口
- Keystore CLI: ✅ 可从 shell 使用，但走 /dev/qseecom (TEE)，不调 qcedev_ioctl
- **新发现**: `/dev/dri/card0`, `/dev/dri/renderD128` 均为 0666

### 21. 最终路线确认 + 文档更新（2026-07-24 续7）

- ✅ **确认 kgsl compat ioctl 为唯一可行栈覆盖路由**
- 设备: `/dev/kgsl-3d0` (0666 世界可读写)
- 条件: 必须编译为 32-bit ARM 可执行文件以触发 TIF_32BIT
- 覆盖: 16B → pi_tree.left (可控) + TASK 指针 (可控), LOCK (脏数据)
- 更新 NEXT_STEPS.md: 路由矩阵、Phase 1-6 规划、偏移验证结果
- 更新 target.h: 所有 [EST] → [BIN], 去除重复定义
- 更新 PROCESS_LOG.md: 步骤 17-21

## 下一步

- Phase 2: 集成 kgsl compat 路径到 fops.c，端到端测试

### 22. Phase 1 kgsl 探针验证（2026-07-24 续8）

- 编写 32-bit ARM NDK 探针 `leaf5/probes/kgsl_probe/kgsl_probe.c`
- Docker 编译: `armv7a-linux-androideabi33-clang -static` → ELF 32-bit ARM EABI5
- **设备验证结果**:
  - ✅ `/dev/kgsl-3d0` open O_RDWR 成功 (fd=3)
  - ✅ RB_ISSUEIBCMDS (`0xc0200910`): EINVAL (已分派，非 ENOTTY)
  - ✅ SUBMIT_COMMANDS (`0xc060093d`): EINVAL
  - ✅ GPU_AUX_COMMAND (`0xc0140957`): EINVAL
  - ✅ 9/9 测试命令均为 EINVAL（已分派），无 ENOTTY
- **ioctl 命令码提取**: 从 vmlinux kgsl_ioctl_funcs 表确认 type=0x09
  - 表位于 0xffffff80099d2540，每项 16B，索引 = `cmd & 0xFF`
- **Compat wrapper 逆向**: 反汇编 `kgsl_ioctl_rb_issueibcmds_compat`
  - 输入 struct: +0x00 drawctxt_id, +0x04 flags, +0x08 ibdesc_addr(32-bit ptr), +0x0c timestamp, +0x10 numibs
- **EINVAL 根因**: `cbz x0, error` — GPU context lookup 失败（exploit 需先创建 context）
### 23. Phase 2 exploit 集成（2026-07-24 续9）

- **架构决策**: 编译为 32-bit ARM 独立 PIE（非 LD_PRELOAD），直接触发 compat ioctl
- **新增文件**: `exploit/src/kgsl_route.c`
  - `do_kgsl_fake_lock_route()`: open /dev/kgsl-3d0 → create GPU context → build ibdesc → ioctl
  - `install_embedded_wallpaper()` stub（32-bit 无汇编支持）
  - `main()` 入口包装 `run_exploit()`
- **修改文件**:
  - `main.c`: `do_pselect_fake_lock_route()` → `do_kgsl_fake_lock_route()`
  - `common.h`: 添加 `do_kgsl_fake_lock_route()`, `kgsl_cleanup()` 声明
  - `Makefile`: 新增 `arm32`/`arm32-pie` 构建目标，添加 kgsl_route.c
  - `target.h`: 新增 KGSL ioctl 宏、ibdesc 布局、路由选择
  - `kernelsnitch/timeutils.h`: ARM32 `__arm__` 回退（clock_gettime 替代 cntvct_el0）
- **Docker 编译**: `armv7a-linux-androideabi33-clang -pie` → ghostlock32 (111K)
- **设备测试结果**:
  - ✅ 启动成功: pid=16784 uid=2000, label=onyx_leaf5_gv2.027
  - ✅ KASLR base 正确: direct-map base=ffffff8080080000 slide=0
  - ✅ init_task=ffffff800b81c180 正确
  - ⚠️ mmap MAP_NORESERVE 失败 (EINVAL) — 32-bit 兼容性问题，待修复
- **待修复**: MAP_NORESERVE 在 ARM32 上可能不支持，需改用 MAP_ANONYMOUS

### 24. 最小化 PoC + 32-bit 移植进展（2026-07-24 续10）

- 编写 `kgsl_ghostlock_poc.c`: GhostLock + KGSL 最小验证
  - 设备运行无崩溃（竞态未触发 + GPU context 创建失败）
  - FUTEX_CMP_REQUEUE_PI 返回 EINVAL — 32-bit 参数传递差异
  - DRAWCTXT_CREATE ioctl 返回 EINVAL — compat struct 布局待确认
- **32-bit exploit 编译**: ghostlock32 119K PIE，编译通过，启动正确
  - 修复: FUTEX_SZ 512MB, futex_hash uint64_t, ks_addr_t typedef, timeutils ARM32 fallback
  - ⚠️ `prepare_good_kernel_page()` 崩溃 — Kernelsnitch 64位地址在32位下截断
- **两条前进路径**:
  A. 64位构建 + `personality(PER_LINUX32)` 仅切换 kgsl ioctl 为32位
  B. 完成32位移植（需全面审计 size_t/uintptr_t → uint64_t）

### 25. Path A 验证: personality(PER_LINUX32) 测试（2026-07-24 续11）

- 编写 `test_personality.c`: 64-bit ARM 程序，测试 personality(PER_LINUX32) 对 KGSL ioctl dispatch 的影响
- **结论: ❌ personality(PER_LINUX32) 无法触发 compat ioctl 路径**
  - `personality()` 设置 `current->personality`，但不设置 `TIF_32BIT`
  - `kgsl_drawobj_cmd_add_ibdesc_list` 中的路径选择由 `TIF_32BIT` (thread_info.flags bit 22) 控制
  - 所有 ioctl 在有/无 PER_LINUX32 时返回相同 errno，dispatch 行为无差异
  - **Path A 不可行！**

### 26. 32-bit 构建修复（2026-07-24 续12）

- **修复 MAP_NORESERVE**: `kernelsnitch.h:345` — 改为 `MAP_ANON|MAP_PRIVATE`（移除 MAP_NORESERVE，ARM32 不支持）
- **修复 PROT_NONE 双步 mmap**: 改为单步 `PROT_READ|PROT_WRITE` mmap，移除 sub-mmap 循环
- **修复 FUTEX_SZ**: ARM32 从 512MB→128MB（避免地址空间不足）
- **修复 64-bit 地址截断**:
  - `kernelsnitch_cleanup` 返回类型: `size_t` → `ks_addr_t`
  - `kernelsnitch_param`、`kernelsnitch` 返回类型: `size_t` → `ks_addr_t`
  - `prepare_kernel_page`、`prepare_good_kernel_page` 返回类型: `uintptr_t` → `uint64_t`
  - `page_base`、`fake_lock`、`fake_task` 等全局变量: `uintptr_t` → `uint64_t`
  - `(size_t)-1` 哨兵比较修正为 `(ks_addr_t)-1`
- **修复 sed 引入的代码破坏**: 之前的 sed 命令打乱了 `kernelsnitch_setup` 函数中的初始化顺序，`total_futexes` 在使用前未初始化。手动重写恢复正确顺序。
- ⚠️ ghostlock32 仍在 `kernelsnitch_setup` 中崩溃（SIGSEGV），crash 点在 mmap 调用附近
- 未抵达 `kernelsnitch_setup` 的 debug 输出，说明 crash 发生在第一行 mmap 或之前

### 27. 最小化 32-bit GhostLock + KGSL PoC（2026-07-24 续13）

- 编写 `ghostlock32_minimal.c`: 跳过 Kernelsnitch，使用硬编码内核地址
- **设备测试结果**:
  - ✅ **FUTEX 操作完全正常**: `FUTEX_LOCK_PI` 成功，`FUTEX_WAIT_REQUEUE_PI` 正确阻塞
  - ✅ **GhostLock 竞态触发成功**: `FUTEX_CMP_REQUEUE_PI` 返回 `ret=1`（1个 waiter 被 requeue）
  - ✅ **KGSL ioctl dispatch 正常**: `/dev/kgsl-3d0` open 成功，ioctl 到达 handler（EINVAL，非 ENOTTY）
  - ❌ **GPU context 创建失败**: `DRAWCTXT_CREATE` 所有 flag 组合均返回 EINVAL
  - ❌ **CFU 路径未到达**: 因 context validation 在 CFU 之前，EINVAL 提前返回
- **无内核 panic**: ioctl 调用安全返回，无 oops/panic

### 28. GPU Context 创建深入排查（2026-07-24 续14）

- 测试所有 `KGSL_CONTEXT_*` flag 组合（GL/CL/VK/NO_GMEM_ALLOC/PREAMBLE）：全部 EINVAL
- GPU 状态: `gpubusy=0 0`（空闲/挂起）
- 从 kheaders `msm_kgsl.h` 确认 struct 布局正确: `{uint32_t flags; uint32_t drawctxt_id;}`
- **根因推测**: GPU 处于 suspend/低功耗状态，kgsl 驱动在 context 创建前需要设备初始化序列
- **阻塞性质**: 核心阻塞 — CFU 路径需要有效 GPU context 否则提前返回 EINVAL

### 29. 解锁后重新验证（2026-07-25）

- 用户解锁设备后重新测试 GPU context 创建
- GPU 状态变化: `gpubusy=0 0` → `gpubusy=340121 1019065`（GPU 已唤醒）
- **结果**: 所有 DRAWCTXT_CREATE flag 组合仍然 EINVAL
- GETPROPERTY: 所有 type 值返回 ENOTTY（无 handler 注册）
- SETPROPERTY: 返回 ENODEV（设备未就绪）
- **结论**: GPU context 创建失败与锁屏/电源状态无关，设备 GPU 子系统可能处于有限功能模式

### 30. GPU 子系统深度分析与确定性结论（2026-07-25）

**GPU 硬件确认**:
- 型号: Adreno 619v1 (Qualcomm Snapdragon SM6350/Lagoon)
- 最大时钟: 565 MHz
- 驱动包: `com.qualcomm.qti.gpudrivers.lito.api30`
- GLES 版本: 3.2 (196610), Vulkan 版本: 1.1 (4198400)
- 状态: **完全正常** — 3个GL上下文 + 1个VK上下文已由其他进程创建
- GPU 活跃: `gpubusy=340121 1019065`

**compat SET_PROPERTY 成功列表**:
- ✅ MMU_ENABLE (0x6) — MMU 已启用
- ✅ INT_WAITS (0x7) — 中断等待已配置
- ✅ UCHE_GMEM_VADDR (0x13) — GMEM 虚拟地址已设置
- ✅ DEVICE_BITNESS (0x18) — 设备位数已配置
- ✅ MIN_ACCESS_LEN (0x1A) — 最小访问长度
- ✅ UBWC_MODE (0x1B) — UBWC 模式
- ✅ DEVICE_QTIMER (0x20) — QTimer 已配置
- ✅ SPEED_BIN (0x25) — 速度分级

**仍然失败的关键操作**:
- ❌ DEVICE_POWER (0x3) → ENODEV — GPU 电源管理不可用（可能由 GMU 固件管理）
- ❌ PWRCTRL (0xE) → ENODEV — 电源控制接口不存在
- ❌ PWR_CONSTRAINT (0x12) → ENODEV
- ❌ QUERY_CAPABILITIES (0x27) → EINVAL
- ❌ mmap(SHARED) → EINVAL — 无法映射设备内存
- ❌ DRAWCTXT_CREATE → EINVAL — **持续失败**

**逆向工程发现**:
- `kgsl_ioctl_drawctxt_create` 入口通过间接调用检查设备状态:
  `[device+0x3d8] → [table+0xa0] → blr x8 → IS_ERR 检查`
- 该间接调用失败导致 EINVAL
- 设备偏移 0x3d8 有 101 处代码引用，多数有 NULL 检查
- adreno_a6xx_gpudev 表中的函数指针在运行时赋值（非静态初始化）

**根本原因分析**:
- GPU context 创建需要完整的 GPU 初始化序列，包括：
  1. GMU/RGMU 固件加载（由专有用户态驱动处理）
  2. GPU 核心上电序列
  3. 命令缓冲区映射（需要成功的 mmap）
- 这些步骤由 `libEGL_adreno.so` / `vulkan.adreno.so` 在应用初始化时完成
- 从 shell 通过原始 ioctl 调用无法复制此序列
- compat (32-bit) 路径与 native (64-bit) 路径行为一致，均失败

**⚠️ 确定性结论: KGSL 路线在当前执行上下文（shell, uid=2000）下不可行。**

GPU context 创建需要专有用户态驱动（libEGL_adreno.so / vulkan.adreno.so）的初始化序列，
无法通过原始 ioctl 从 shell 完成。这不意味着 KGSL 路线从根本上不可能，但需要
应用级执行上下文和专有 GPU 库支持。

**建议**: 转向备选 CFU 路由（DRM render node 被 SELinux 阻止，需评估 uinput/setsockopt/binder 等方案）。
