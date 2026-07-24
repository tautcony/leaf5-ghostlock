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

## 未执行（本阶段）

- pahole / IDA 验证 [SRC]/[EST] 标记的偏移
- NDK 编译用户态 futex 烟雾测试
- 动态栈帧确认（需可控 oops 或 perf event）
