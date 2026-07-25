> **文档类型**: 过程文档（操作流水） | **状态**: ✅ 有效（历史记录） | **最后更新**: 2026-07-25

# Leaf5 分析过程流水（2026-07-24）

按时间顺序记录操作，便于审计与复现。详细结论见 [docs/ANALYSIS.md](docs/ANALYSIS.md)。

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
- 撰写 `docs/ANALYSIS.md`、`README.md`、`docs/COMPARE_OPPO_FIND_N2.md`、`docs/NEXT_STEPS.md`
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
- 更新 `docs/ANALYSIS.md` §8 加入偏移定位结果
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
- 写入 `docs/STACK_LAYOUT.md`

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
- 更新 docs/NEXT_STEPS.md: 路由矩阵、Phase 1-6 规划、偏移验证结果
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

### 31. GPU Context 创建突破！（2026-07-25）

**关键发现**: `KGSL_CONTEXT_PREAMBLE (0x10) | KGSL_CONTEXT_NO_GMEM_ALLOC (0x02) = 0x12`

- freedreno 源码揭示: "Modern kernels require BOTH PREAMBLE and NO_GMEM_ALLOC to be set"
- 之前分别尝试了 0x02 和 0x10，但从未组合 0x12！
- **context 创建成功**: `DRAWCTXT_CREATE(flags=0x12) → ctx_id=7 ✅`
- 同样成功的组合: `0x13` (SAVE_GMEM|NO_GMEM|PREAMBLE), `0x00100012` (TYPE_GL|...)

**KGSL 路线状态更新**: Context 创建不再是阻塞点！但命令提交仍有问题。

### 32. 命令提交与内存分配的排查（2026-07-25）

- RB_ISSUEIBCMDS: 有效 context (id=7) 下仍 EINVAL
  - 所有 ibdesc 参数组合（gpuaddr=0/有效/sizedwords=0/1/N）均失败
  - 所有 flags 组合均失败
- SUBMIT_COMMANDS: 同样 EINVAL
- GPUMEM_ALLOC_ID: 所有 flags 组合 EINVAL（包括正确的 USE_CPU_MAP=0x10000000）
- 反汇编分析: 两个 handler 均调用 `idr_find` + `refcount_inc_not_zero_checked` 查找 context
  - EINVAL 可能来自: (1) idr_find 未找到 context (2) refcount 为零 (3) 后续验证失败
- 待确定: context 是否被正确添加到 IDR 树？PREAMBLE 上下文是否需要首次提交后完全激活？

**GPUMEM flags 纠正**:
- `KGSL_MEMFLAGS_USE_CPU_MAP = 0x10000000` (bit 28, 不是 0x1000!)
- `KGSL_MEMTYPE_SHIFT = 8`
- `KGSL_MEMALIGN_SHIFT = 16`

### 33. 64-bit 原生路径对比 + 内存模型发现（2026-07-25 续）

**64-bit vs 32-bit 对比**:
- DRAWCTXT_CREATE(0x12): 64-bit ✅ / 32-bit ✅ — 两者均成功
- SETPROPERTY: 64-bit ✅ / 32-bit ✅
- GPUMEM_ALLOC (nr=0x20): 64-bit EOPNOTSUPP (95) — **不支持**
- GPUMEM_ALLOC_ID: 64-bit EINVAL / 32-bit EINVAL
- RB_ISSUEIBCMDS: 64-bit EINVAL / 32-bit EINVAL — 一致
- SUBMIT_COMMANDS: 64-bit EINVAL / 32-bit EINVAL — 一致

**新发现**:
- `GPUMEM_ALLOC` (nr=0x20): **EOPNOTSUPP** — 此 ioctl 在此设备上不被支持
- `MAP_USER_MEM`: **EOPNOTSUPP** — 不支持
- `mmap(/dev/kgsl-3d0)`: **EINVAL** — 无法对 kgsl 设备做 mmap
- `SETPROP(CONTEXT_PROPERTY, ctx=7)`: **✅ 成功!** — 可以设置上下文属性
- 所有 GPUOBJ_* / SYNCSOURCE ioctl 均返回 EINVAL 或 ENOTTY

**内存模型分析**:
- Adreno 619 使用 RGMU (Reduced Graphics Management Unit)
- 传统 GPUMEM_ALLOC/MAP_USER_MEM 在此设备上编译为返回 EOPNOTSUPP
- GPU 内存管理可能通过 ION/DMA-BUF 接口（需要应用级上下文）
- 这解释了为何 freedreno 的 GPUMEM_ALLOC_ID 也无法使用

**当前状态**: Context 创建 ✅ | 命令提交 ❌ | 内存分配 ❌(EOPNOTSUPP)

### 34. RB_ISSUEIBCMDS 架构差异发现（2026-07-25 续）

**关键发现**: 64-bit 进程可以成功调用 RB_ISSUEIBCMDS，32-bit 进程不行！

| 进程架构 | ioctl cmd | 结果 |
|-----------|-----------|------|
| 64-bit | 0xc0140910 (compat) | ✅ ret=0 SUCCESS |
| 64-bit | 0xc0200910 (native) | ❌ EINVAL |
| 32-bit | 0xc0140910 (compat) | ❌ EINVAL |
| 32-bit | 0xc0200910 (native) | ❌ EINVAL |

**分析**:
- 64-bit 进程调用 compat 命令成功（所有 flags 组合）
  - 原因: 从 64-bit 进程，ioctl 直接进入 regular handler（无 compat wrapper）
  - 20字节 compat struct 被当作 32字节 native struct 读取
  - ibdesc_addr (4B) 和 timestamp (4B) 组合成 64-bit 指针
  - 巧合: timestamp=0 → 指针恰好有效
- 32-bit 进程调用同一命令失败
  - 原因: compat wrapper (`kgsl_ioctl_rb_issueibcmds_compat`) 做额外验证
  - 可能 context lookup 或 struct validation 失败

**GhostLock + KGSL 端到端**:
- GhostLock 触发 ✅ (CMP_REQUEUE_PI ret=1)
- KGSL context 创建 ✅ (0x12 标志)
- KGSL 命令提交: 32-bit ❌ / 64-bit ✅ (但有结构体布局问题)
- 内核未崩溃: 64-bit 路径的 CFU 位置与 GhostLock waiter 位置可能不匹配

**下一步需求**:
- 修复 32-bit compat 路径的 RB_ISSUEIBCMDS（定位 compat wrapper 中 EINVAL 来源）
- 或找到从 32-bit 进程绕过 compat wrapper 调用 regular handler 的方法

### 35. kgsl_compat_ioctl 分派链深度逆向 + NR=0x10 穷举扫描（2026-07-25）

**kgsl_ioctl_helper 完整逆向**:
- 函数位于 `0xffffff80087a2a90`，帧 0xD0
- 逻辑: `nr = cmd & 0xFF` → `if (nr >= table_size) ENOTTY` → `handler = table[nr][1]` → `if (!handler) ENOTTY` → `size = (table[nr][0] >> 16) & 0x3FFF` → `copy_from_user` → `blr handler` → `copy_to_user` (方向位)
- **关键发现**: table[nr][1]（handler 函数指针）在 compat 表和 regular 表中均为 NULL！
  - Compat 表 (0xffffff80099d3018): 所有 entry[1] = 0
  - Regular 表 (0xffffff80099d2540): 所有 entry[1] = 0
  - 真正的 handler 分派通过 runtime 初始化的函数指针（ext+0xc0 / ext+0xc8）

**64-bit vs 32-bit 分派路径确认**:
```
64-bit: sys_ioctl → kgsl_ioctl → kgsl_ioctl_helper(regular_table) → ENOTTY
        → TIF_32BIT not set → fallback handler(ext+0xc0) → SUCCESS (for 0xc0140910)

32-bit: compat_sys_ioctl → kgsl_compat_ioctl → kgsl_ioctl_helper(compat_table) → ENOTTY
        → compat handler(ext+0xc8) → compat wrapper → EINVAL (for 0xc0140910)
```

**NR=0x10 穷举扫描结果**:
- 所有方向 (0-3) × 所有大小 (0-64, step=4) → **全部 EINVAL**
- 3 种备选字段布局 (Layout A/B/C) → **全部 EINVAL 或 ENOTTY**
- Swap workaround (预补偿 wrapper 字段交换) → **仍然 EINVAL**

**NR=0x3d (SUBMIT_COMMANDS) 对比**:
- **所有大小 (20-56, step=4) 全部成功!** ✅
- SUBMIT_COMMANDS compat 路径完全正常，NR=0x10 特定失败

**结论**: RB_ISSUEIBCMDS (NR=0x10) 在 32-bit compat 路径下被 compat dispatch function (ext+0xc8) 特定拒绝。
- 可能原因1: compat wrapper `kgsl_ioctl_rb_issueibcmds_compat` 的字段交换 bug 导致总是返回 EINVAL
- 可能原因2: compat dispatch function 对 NR=0x10 有特殊限制
- Swap workaround 无效 → 说明问题不在字段映射层面，或在更深层验证

### 36. EFAULT probe 确认：compat wrapper 从未到达 native handler (2026-07-25)

**测试设计**: 使用 swap workaround 将 compat.flags 设置为不同值（valid ptr / bad ptr 0x1 / NULL），观察 errno 变化
- 如果 native handler 被调用: bad ptr (0x1) → EFAULT (14)，NULL → EFAULT/EINVAL
- 如果 wrapper 提前返回: 所有测试均 EINVAL (22)

**结果**: **所有 6 种测试均返回 EINVAL (22)**
- valid_ptr: EINVAL ❌ (应该成功或至少不是 EINVAL)
- bad_ptr_0x1: EINVAL ❌ (应该是 EFAULT)
- null_ptr: EINVAL ❌ (应该是 EFAULT)
- numibs=0: EINVAL ❌
- normal (unswapped): EINVAL ❌
- dual_ptr: EINVAL ❌

**结论**: **compat wrapper / native handler 从未被调用!** EINVAL 来自 compat dispatch function (ext+0xc8) 对 NR=0x10 的特殊处理。

**与 SUBMIT_COMMANDS 对比**:
- NR=0x3d (SUBMIT_COMMANDS): 所有大小 (20-56) → SUCCESS ✅
- NR=0x10 (RB_ISSUEIBCMDS): 所有变化 → EINVAL ❌

**KGSL 路线确定性结论**:
- 32-bit RB_ISSUEIBCMDS: **不可行** — compat dispatch 在到达 wrapper 前就拒绝
- 32-bit SUBMIT_COMMANDS: 可行但 CFU 位置不匹配 (差 120B)
- 64-bit RB_ISSUEIBCMDS: 可行但 CFU 位置不匹配 (差 88B)

### 37. Native handler 逆向与验证链 (2026-07-25)

**kgsl_ioctl_rb_issueibcmds 验证逻辑**:
```c
flags = data[0x18];
if (flags & 0x402) → EINVAL;           // 未知标志位检查
if (flags & 4) {                        // SUBMIT_IB_LIST
    if (((numibs-1) >> 5) > 0xc34) → EINVAL;  // numibs 上限
}
context = idr_find(device->ctx_idr, drawctxt_id);
if (!context) → EINVAL;                // context 查找失败
if (context->flags & 2) → EINVAL;      // context 状态检查
if (!refcount_inc_not_zero(context)) → EINVAL;
if (context->dev_priv != dev_priv) → 额外检查;
// ... 通过所有检查后到达 CFU 路径
```

**Compat wrapper vs native handler 字段映射对比**:
```
Native struct:  +0x00:drawctxt_id +0x08:ibdesc_addr +0x10:numibs +0x18:flags
Compat struct:  +0x00:drawctxt_id +0x04:flags +0x08:ibdesc_addr(64b) +0x10:numibs
Wrapper builds: +0x00:drawctxt_id +0x08:flags(x10) +0x10:ibdesc(x11) +0x18:numibs(w9)
                                                ↑BUG!           ↑BUG!         ↑BUG!
```

**分派路径差异 (64-bit vs 32-bit)**:
```
64-bit: sys_ioctl → kgsl_ioctl → kgsl_ioctl_helper → ENOTTY
        → fallback_handler(ext+0xc0) → SUCCESS ✅

32-bit: compat_sys_ioctl → kgsl_compat_ioctl → kgsl_ioctl_helper → ENOTTY
        → compat_handler(ext+0xc8) → EINVAL ❌ (wrapper never called!)
```

### 38. 64-bit GhostLock + KGSL CFU 实测 (2026-07-25)

**ghostlock64_v2 测试结果**:
- GhostLock ✅ (CMP_REQUEUE_PI ret=1)
- KGSL context 创建 ✅ (id=7)
- RB_ISSUEIBCMDS compat cmd (0xc0140910): **ret=0 ✅ CFU FIRED!**
- ALL 8 种 flag 组合 (0x01-0x80): 全部 ret=0 ✅
- 内核存活 — **CFU 位置与 waiter 不重叠**

**ghostlock64_scan 测试结果** (多路径扫描):
- RB_ISSUEIBCMDS numibs=1: CFU fired, kernel survived
- RB_ISSUEIBCMDS numibs=2: CFU fired, kernel survived
- RB_ISSUEIBCMDS flag=0x1000 (alt path): CFU fired, kernel survived
- SUBMIT_COMMANDS (64-bit): EINVAL (不支持)
- GPU_COMMAND/AUX_COMMAND: ENOTTY/EINVAL

**ghostlock64_opt 测试结果** (预创建资源,最小化栈干扰):
- CFU fired, kernel survived — 5次循环均一致

**确定性结论**: 64-bit KGSL CFU 位置与 GhostLock waiter 存在~88字节偏移，所有变体均无法重叠。

### 39. 备选 CFU 路由设备可访问性 (2026-07-25)

| 设备 | 权限 | 实际可访问 | 原因 |
|------|------|-----------|------|
| `/dev/uinput` | 0660 uhid:uhid | ✅ 可读可写 | shell 可以打开 |
| `/dev/dri/card0` | 0666 | ❌ Permission denied | SELinux 阻止 |
| `/dev/dri/renderD128` | 0666 | ❌ Permission denied | SELinux 阻止 |

**uinput CFU 位置**: 92B@SP+0x60, 绝对位置 ~KSP0-0x150, waiter task @ KSP0-0x2B0, **差 352B (比 KGSL 更差)**

### 40. CFU 位置精算与最终结论 (2026-07-25)

**GhostLock waiter 精确位置**:
```
KSP0 = sys_futex 入口栈指针
do_futex 帧: 0x220 → SP = KSP0 - 0x220
futex_wait 帧: 0x140 → SP = KSP0 - 0x360
futex_q (含 waiter) @ futex_wait SP + 0x80 = KSP0 - 0x2E0
waiter->task @ KSP0 - 0x2E0 + 0x30 = KSP0 - 0x2B0  ← 目标位置
```

**64-bit KGSL CFU 范围**: [KSP0 - 0x238 - FF, KSP0 - 0x218 - FF), FF = fallback_handler 帧
- 覆盖 waiter->task 条件: FF ∈ [0x78, 0x98) = [120, 152)
- 实测: 内核存活 → FF < 120 或 FF ≥ 152 → **CFU 不重叠**

**32-bit KGSL CFU 范围**: [KSP0 - 0x2A8 - CF, KSP0 - 0x298 - CF), CF = compat_handler 帧
- 覆盖 waiter->task 条件: CF ∈ [8, 24)
- compat_handler 帧不可能 < 24 字节 → **CFU 过深，必然不重叠**

**结论**: GhostLock waiter->task @ KSP0-0x2B0 位于两个 CFU 位置之间:
```
64-bit CFU: ~KSP0-0x228  (太浅，差距 ~88B)
waiter task: KSP0-0x2B0  (目标)
32-bit CFU: ~KSP0-0x2A0+ (太深，超出)
```

**此前进程日志中"32-bit CFU 完美重叠"的分析存在计算误差。实际 32-bit CFU 需要 compat_handler 帧 < 24 字节才可能重叠，这在现实中不可行。**

### 41. 最终路线确定

经过完整分析，Leaf5 (kernel 4.19.157) 与 OPPO Find N2 (kernel 5.10) 的关键差异导致标准 GhostLock 利用链在此设备上不可行:

| 差异 | Find N2 (5.10) | Leaf5 (4.19) | 影响 |
|------|---------------|-------------|------|
| rt_mutex_waiter 大小 | 0x50 (80B) | 0x40 (64B) | waiter 位置不同 |
| futex 栈帧深度 | 不同 | do_futex 0x220 + futex_wait 0x140 | waiter @ -0x2B0 |
| KGSL CFU 深度 | 匹配 | 32-bit 过深 / 64-bit 过浅 | 无一匹配 |
| qcedev_ioctl | 未测试 | 权限阻塞 (drmrpc) | 不可访问 |

**唯一位置正确且可到达的 CFU 不存在于此设备上。需要探索非 CFU 的利用路径。**

### 42. 64-bit exploit 端到端循环测试 (2026-07-25)

**10 次循环结果**: 全部一致 — `cfi write ret=-1 errno=22`, `done=0 root=0`
- Kernelsnitch ✅ / Heap spray ✅ / GhostLock ✅ / KGSL CFU ✅
- PI trigger (sched_setattr): EPERM (shell 无 CAP_SYS_NICE)
- Configfs write: EINVAL (ashmem fops 未覆盖)
- CFU 位置无任何随机波动 — 100% 不匹配

**最终确定性结论**: 在 Leaf5 (kernel 4.19.157, build #245) 上，GhostLock 标准利用链的核心步骤——通过 CFU 覆盖 stale waiter 的 task 指针——因内核栈布局差异而不可行。此设备的 do_futex/futex_wait 帧布局导致 waiter @ KSP0-0x2B0，该位置恰好位于 64-bit CFU (太浅) 和 32-bit CFU (太深) 之间，无法被任何可到达的 KGSL CFU 路径覆盖。

**可行的前进方向**:
1. 寻找非 KGSL 的 CFU 源 (qcedev_ioctl 位置正确但权限阻塞 — 需 binder 代理)
2. 寻找绕过 compat dispatch 的方法 (运行时修改 ext+0xc8 函数指针?)
3. 利用此设备无 CFI/无 KPTI 的特点寻找替代攻击向量
4. 开发不依赖栈覆盖的全新利用技术

### 43. FUTEX_LOCK_PI 触发测试 — 最终确认 (2026-07-25)

**修复 trigger_pi_read 的 64-bit 地址截断 bug**，直接调用 FUTEX_LOCK_PI:
- `PI trigger ret=0 errno=110` — FUTEX_LOCK_PI 成功获取锁
- 内核存活 — PI chain walk 未导致 crash
- `cfi write ret=-1 errno=22` — fops 仍未覆盖

**完整 10 次循环测试**: 64-bit KGSL CFU 每次均触发成功，但 PI chain walk 后 fops 均未覆盖。

**最终确定性结论**: 10 次循环 + FUTEX_LOCK_PI 触发 = 内核均存活。CFU 位置与 waiter->task 的偏移在此内核构建中是固定的，不受栈随机化影响。

**Leaf5 (kernel 4.19.157 build #245) GhostLock 利用链完成度**:

| 步骤 | 状态 | 备注 |
|------|------|------|
| Kernelsnitch | ✅ 100% | <1秒可靠泄漏 mm_struct |
| 堆喷射 | ✅ 100% | sk_buff reclaim 4/4, ret=65536 |
| GhostLock 触发 | ✅ 100% | FUTEX_CMP_REQUEUE_PI ret=1 |
| KGSL context | ✅ 100% | flags=0x12, ctx_id=7 |
| RB_ISSUEIBCMDS CFU | ✅ 100% | 64-bit 路径 ret=0 |
| CFU 覆盖 waiter->task | ❌ 0% | 位置偏差固定，10次无变化 |
| PI chain walk | 🔄 — | 可触发但无效应 (waiter->task 未变) |
| Fops overwrite | ❌ | 依赖上一步 |
| Configfs R/W | ❌ | 依赖上一步 |
| Pipe physrw | ❌ | 依赖上一步 |
| Root | ❌ | 依赖上一步 |

**总完成度: ~70%** (Kernelsnitch + Heap spray + GhostLock + CFU 均可正常工作，仅栈覆盖位置不匹配)

### 44. 备选 syscall 栈覆盖暴力测试 (2026-07-25)

**测试方法**: GhostLock 后尝试不同内核路径 (writev/sendmsg/splice)，用 crash pattern 填充数据，然后触发 PI chain walk 检验是否覆盖 waiter->task。

**测试结果**: 内核存活 — writev(64K) / sendmsg(64K) / splice(64K) 均无法自然覆盖 waiter 位置。

**结论**: 常见的深度内核路径 (pipe write, socket sendmsg, splice) 的栈帧深度不足以覆盖此设备上 GhostLock waiter 的位置 (KSP0-0x2B0)。需要 ~0x2B0 字节以上的栈帧深度加上可控数据写入，满足此条件的用户态可达路径在此内核上不存在。



### 45. 仓库整理为 Leaf5-only (2026-07-25)

将仓库收敛为 **仅 Leaf5 分析内容**：

- 移除: `docs/`、`analysis-scripts/`、`exploit-server/`、`test-programs/`、多设备 targets、根目录测试二进制、`.github`、`.mimocode`、FAQ 等
- 保留: `leaf5/` 分析工作区 + `exploit/`（仅 `targets/onyx-leaf5`）
- 探针: 仅保留 `.c` / Makefile 源码，ELF 产物 gitignore
- 文档: 根 `README.md`、`leaf5/README.md`、`NEXT_STEPS`/`KGSL_STACK_OVERWRITE` 与终局结论对齐



### 46. 流水线归档 stages/ (2026-07-25)

将探针、分析脚本与 ghostlock-analysis 按利用顺序迁入 `leaf5/stages/`：

- S00–S07 主阶段；S05 下 `routes/01`–`09` 并列栈覆盖候选；KGSL 再分子节点 a–g
- 每个节点 `README.md` 记录文件级效果（成功/失败/原因）
- `leaf5/scripts/*.py` 保留为 uv 入口 shim
- 旧 `probes/kgsl_probe`、`ghostlock-analysis/*` 内容已迁移，目录仅留跳转说明

### 最终结论

在 Onyx Leaf5 (kernel 4.19.157-perf-g3d47a6619220-dirty #245) 上，GhostLock (CVE-2026-43499) 标准利用链因内核栈布局差异而不可行。此结论基于:

1. **完整的 compat dispatch 逆向**: 确认 32-bit KGSL RB_ISSUEIBCMDS 被 compat dispatch (ext+0xc8) 在到达 wrapper 前拒绝
2. **EFAULT 探针**: 证实 wrapper/native handler 从未被调用
3. **64-bit CFU 实测**: 10+ 次循环测试 + PI chain walk 触发，CFU 均成功但 fops 从未覆盖
4. **备选路由验证**: DRM (SELinux), uinput (位置差 352B), qcedev (权限), 其他路由均不可行
5. **备选 syscall 测试**: writev/sendmsg/splice 均无法自然覆盖 waiter

**设备特殊性**: 此设备的 do_futex/futex_wait 栈帧布局导致 waiter->task @ KSP0-0x2B0，恰好位于 64-bit CFU (太浅 ~88B) 和 32-bit CFU (太深) 之间。这是内核编译时的栈布局决定的，无法从用户态改变。

### 45. 文档整理（2026-07-25）

- 一层杂乱 md 迁入 `docs/`（参考）与 `docs/archive/`（过时计划）
- EDL 独立为 `edl/`：**只读提取**流程；删除 P6 Pro Magisk/改镜像指南
- 移除空 stub：`probes/`、`ghostlock-analysis/`（内容已在 stages）
- 入口：`leaf5/README.md` + `docs/README.md` + `edl/README.md`

### 46. 全量复测（2026-07-25）

- Docker-only NDK：stages 探针 90/92 初编通过；修 `test_egl`（headers + pie/ldl）、`test_kernelsnitch_minimal` 非阻塞 futex、`test_ctx_flags` 补测 0x12
- 设备 #245：`test_mm_leak` FOUND mm；GhostLock requeue ret=1；64-bit CFU ret=0 内核存活；32-bit RB_ISSUEIBCMDS 全 EINVAL；qce/DRM 权限失败；ctx 0x12=OK
- 文档 CORRECTED：S02 stages 探针≠真泄漏；S03 无 stage sk_buff 探针；S04 无独立二进制（见 e2e）
- 报告：`docs/REVERIFY_2026-07-25.md`

### 47. CORRECTED — list CFU 路径 + WAIT_REQUEUE_PI waiter 位置 (2026-07-25)

**设备**: #245 g3d47a6619220 匹配。

#### A. ISSUEIBCMDS 是否真的 CFU 拷贝 ibdesc

反汇编 `kgsl_ioctl_rb_issueibcmds`:
- `ldrb w8,[cmd+0x18]; tbnz #2` → list 路径 `kgsl_drawobj_cmd_add_ibdesc_list`（CFU 0x20 @ SP+8）
- bit2=0 → `kgsl_drawobj_cmd_add_ibdesc`，**无** ibdesc CFU

探针 `test_list_cfu_path`（arm64）:
- native size≥0x1c 且 flags2@+0x18=0x4 + bad ptr → **EFAULT**
- flags=0 + bad ptr → EINVAL
- 旧 compat `0xc0140910` flags=0 good → ret=0（**无 list CFU**）

→ 既有 ghostlock64_opt / test_cfu_trigger 的「CFU 触发」**不**等于用户 ibdesc 写入内核栈。

#### B. WAIT_REQUEUE_PI waiter 不在 futex_wait

- 符号表无 `futex_wait_requeue_pi`
- do_futex 跳表 cmd=11 → 内联路径
- `rt_mutex_init_waiter(x29 - 0xc8)` @ do_futex+0x1120

```
waiter @ do_futex x29-0xc8
task  @ waiter+0x30 = do_futex_entry - 0xF8
      = stack_top - 0x70 - 0xF8 = stack_top - 0x168
```

旧 **KSP0−0x2B0（futex_wait 模型）对 WAIT_REQUEUE_PI 作废**。

#### C. 真 list CFU 与正确 waiter 比较

```
list CFU: [stack_top-0x308, stack_top-0x328)   // 过深 ~0x1A0
task:     stack_top-0x168
```

`ghostlock64_list_cfu`: GhostLock ret=1，list CFU errno=22，pattern@+0x18，内核存活。

#### D. 近邻候选（相对新目标 −0x168）

| 路径 | CFU 约 | vs −0x168 | shell |
|------|--------|-----------|-------|
| kgsl list | −0x308 | 过深 0x1A0 | ✅ |
| kgsl single (无 CFU) | — | — | ✅ |
| uinput UI_SET / setup | −0x190 | 过深 ~0x28 | ✅ open |
| qcedev 328B | −0x3B0 起 | 过深且权限 | ❌ drmrpc |

#### E. 前进方向

1. 以 **−0x168** 重扫 shell 可达 CFU（优先缩小 uinput 0x28 缝）
2. drmrpc 进程注入打开 `/dev/qce` 仅当深度也对齐新 waiter 后再投
3. 禁止用 flags=0 ghostlock64 当栈覆盖证据


### 48. Round — re-score @ −0x168 + binder/evdev shell CFU (2026-07-25)

**uname**: 4.19.157 #245 g3d47a6619220 match.

#### Rescore
- Target: `task @ stack_top-0x168` (do_futex waiter).
- Direct syscalls (timer_create/setitimer/fcntl/…): CFU 均浅于 0x168。
- Device ioctl 含 thin wrapper 时需 +0x10。

#### evdev
- shell 在组 `input`；`/dev/input/event*` **O_RDONLY** OK，O_RDWR EACCES。
- `EVIOCGKEYCODE_V2` bad ptr → **EFAULT**（CFU）。
- 链：sys_ioctl+do_vfs+**evdev_ioctl(0x10)**+handler(0xa0) → CFU @ −0x178（**过深 0x10**）。
- GhostLock+evdev：存活。

#### binder（主候选）
- `/dev/binder` shell OPEN_RDWR。
- `binder_ioctl` frame 0xa0，CFU **0x18 @ SP+0x10** → abs **[0x160,0x178)**，**覆盖 task@0x168**（cookie@+8）。
- `GET_NODE_DEBUG_INFO` / `GET_NODE_INFO_FOR_REF` / `WRITE_READ`48：bad → **EFAULT**。
- GhostLock + GET_NODE_DEBUG_INFO（timeout 与 quick-unlock 两变体）：**ioctl OK，内核存活**。

#### 解释（暂定）
静态对齐的 shell CFU 已找到，但 GhostLock 返回后 PI/crash 无副作用 → 残差 waiter 可能在返回路径被清掉，或绝对深度仍有公共帧偏差。不宣称 cover。

#### 产物
- probes: test_evdev_cfu, ghostlock_evdev_cfu, test_binder_cfu, ghostlock_binder_cfu, ghostlock_binder_wake_cfu
- stages/08 README 更新


### 49. Round — adjtimex wide CFU; close post-return residual model (2026-07-25)

**adjtimex** [BIN]: `__arm64_sys_adjtimex` frame 0x120, CFU 208B @ SP+8 → [0x118,0x1e8).
- Device: valid ret=5; bad ptr **EFAULT**; sizeof(timex)=208.
- GhostLock ret=1, WAIT ret=0, adjtimex with 0x41 fill → EPERM (modes 特权位，**CFU 已发生**), 内核存活.

**signal CFU**: GhostLock + SIGUSR1 handler binder CFU ret=0, 存活.

**终局论断**:
- shell 可达 CFU 可精确/宽窗盖住 CORRECTED task@−0x168。
- 盖住后仍无 PI crash / fops → **返回后栈残差不被解引用**。
- 标准 GhostLock post-return 栈覆盖链在 Leaf5 #245 **关闭**（证据：adjtimex 宽窗）。

不宣称 root。未做 Magisk/刷写。


### 50. Live blocking-window CFU (2026-07-25)

Probe: `ghostlock_live_window_cfu` (adjtimex 208B 0x41 after GhostLock while owner holds PI).

Device log (abbrev):
```
[T] GhostLock CMP_REQUEUE_PI ret=1
[O] before signal, W stat=... S wait_returned=0   ← still blocked
[O] SIGUSR1 sent
[W] WAIT returned ret=-1 errno=11 cfu_done=1      ← wait aborted first
[W] adjtimex ret=-1 errno=1 (EPERM after CFU)
[O] unlocked f_pi_target (PI walk)
=== KERNEL SURVIVED ===
```

**结论**:
1. Live window 存在（requeue 后 W 保持 `S`）。
2. 用户态信号 **不能** 在 do_futex waiter 帧仍 nested 时跑 CFU；先 abort wait。
3. abort 后宽窗 0x41 CFU + PI unlock 仍无 OOPS → 与 §49 一致，残差不 live。
4. shell CFU 栈覆盖链（live 与 post-return）均 **关闭**；root 未达成。


### 51. CORRECTED — 真·GhostLock UAF（pi_blocked_on）+ EDEADLK + reclaim panic (2026-07-26)

**CVE 机制重述**（Nebula IonStack / AlmaLinux；Leaf5 反汇编一致）:
- 漏洞不在「阻塞时跨线程写栈」，而在 `remove_waiter()` 清 **`current->pi_blocked_on`**（应清 `waiter->task`）。
- 三 futex 死锁 → `CMP_REQUEUE_PI` 内部 **EDEADLK 回滚** → victim 的 `pi_blocked_on` 悬空指向 **已返回后释放的内核栈 waiter**。
- T3：同线程 CFU 回收该栈深度写 fake waiter；T4：`sched_setattr` PI walk。

**Leaf5 [BIN]**:
- `remove_waiter @ 0xffffff800814af10`: `mrs sp_el0` / `str xzr,[x20,#0x8d0]` → 仍 bug。
- 旧探针 `CMP ret=1` + W 仍 `S` = **成功 requeue**，**不是** GhostLock；且多条探针 **缺 owner `LOCK_PI(f_pi_chain)`** 环边。

**设备（#245 match）**:
```
ghostlock_edeadlk_detect:
  CMP_REQUEUE_PI ret=-1 errno=35 (EDEADLK)   ← 真触发
  WAIT ret=-1 errno=110 (ETIMEDOUT)            ← 4.19 失败路径不立即 wake
  KERNEL SURVIVED

ghostlock_edeadlk_adjtimex_only (无 consumer):
  EDEADLK + adjtimex 0x41 → SURVIVED

ghostlock_uaf_reclaim_consumer:
  CMP errno=35 → WAIT ETIMEDOUT → adjtimex EPERM(CFU) → 设备掉线
  bootreason: kernel_panic,null                ← 4A：UAF 内容可控后 PI walk 致 panic
```

**pselect 几何 CORRECTED**:
- 旧 `SHIFT=-46`（futex_wait 深度）作废。
- `waiter_base @ -0x198` vs `fdset @ -0x210` → **`PSELECT_WAITER_WORD_SHIFT = +15`**，8/8 字段可达（NFDS=640）。
- `target.h` 已更新。

**popsicle 对照**: 同 T1–T4；T3 用 pselect；T5 direct `init_cred`/SELinux。Leaf5 T5 仍待 shaped fake（非 0x41）。

**节点**: `stages/S05-.../10-ghostlock-true-uaf/`  
**日志**: implementer `C_reclaim_consumer/probe_*.log`，`B_pselect_shift/run.log`，`A_edeadlk/`。

**终局修正**:
- 「残差不 live / 栈覆盖链关闭」仅适用于 **未打 EDEADLK** 的旧模型。
- **真 UAF 链：EDEADLK ✅，reclaim+consumer → kernel_panic ✅（4A 原语）**；root / shaped write 未完成。


### 52. Shaped pselect reclaim integrated in exploit (2026-07-26)

**代码**:
- `main.c`: owner `LOCK_PI(f_pi_chain)`；CMP 记录 errno=35；WAIT 后 `do_pselect_fake_lock_route`
- `fops.c`: 4.19 waiter words **0–7**；SHIFT=+15；默认 Nebula `lock=target-8`
- `util.c`: write target = `data_addr(ASHMEM_MISC)+0x10`
- `kaslr_base = KIMAGE_TEXT_BASE`（修 INIT_TASK）

**设备**:
```
EDEADLK ✅ → pselect shaped ✅ → sched_setattr success=1 ✅
cfi pwrite errno=22 ❌（fops 未劫持）→ root=0
```

**阻塞**: 4.19 上 constrained write 仍未命中。下一步：SHIFT 二分 / 写路径对照 / `PSELECT_LOCK_FAKE=1`。

