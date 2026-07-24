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
