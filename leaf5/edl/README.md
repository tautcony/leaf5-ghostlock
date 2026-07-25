> **文档类型**: 流程记录 | **状态**: ✅ 有效 | **范围**: **只读提取** 分区镜像（分析用） | **最后更新**: 2026-07-25

# EDL — 系统/启动分区镜像提取

本目录记录通过 **Qualcomm EDL**（Emergency Download / Sahara + Firehose）**读取**分区镜像的流程，服务于 Leaf5 GhostLock 分析所需的 `boot` / 相关分区真源。

## 范围（必读）

| 允许 | 禁止（本仓库不记录） |
|------|----------------------|
| 安装 EDL 工具、进 EDL 模式 | Magisk / 修补 boot 再刷回 |
| `printgpt` 查看分区表 | 改 `devinfo` / 解锁写分区 |
| `r` / `rl` **读出**分区到主机 | 写 `abl` / 临时替换 bootloader |
| 校验 banner 与 runtime 一致 | Root 指南、framework 补丁 |

写分区与 Root 与本分析仓库无关；需要备份时也只做 **读出落盘**，不在此文档展开刷写步骤。

---

## 与 Leaf5 的关系

| 项 | 说明 |
|----|------|
| 目标机 | Onyx **Leaf5**（SM6350 / LAGOON / `lito`），kernel `4.19.157` **#245** |
| 为何用 EDL | shell 下 `boot_a` 为 `root:root` `brw-------`，`dd` Permission denied；需 EDL 或 fastboot（后者另议且需用户确认） |
| 仓库已有产物 | `leaf5/boot_a.bin`（gitignore）— `strings` 已对齐 runtime `#245` / `g3d47a6619220`；`raw/vmlinux*.elf` 由此重建 |
| 参考 dump | [`printgpt-p6pro.md`](printgpt-p6pro.md) 来自**同厂相关机型** Boox P6 Pro（SM7225），**不是** Leaf5 分区表；仅作 `printgpt` 输出格式与命令示例 |

Leaf5 的 HWID / Firehose loader **可能与 P6 Pro 的 `palma2pro.bin` 不同**。下列命令中的 `--loader=` 以**本机实测**为准；未验证前不要照抄他机 loader 名。

---

## 1. 工具准备（macOS 示例）

使用 [bkerler/edl](https://github.com/bkerler/edl)：

```bash
brew install libusb git python3
git clone https://github.com/bkerler/edl.git
cd edl
git submodule update --init --recursive
pip3 install -r requirements.txt --break-system-packages

# 若 pylzma 编译失败（macOS 常见）：
grep -v pylzma requirements.txt | pip3 install -r /dev/stdin --break-system-packages
```

安装失败时可在仓库目录用 `python3 edl` 代替全局 `edl`。

准备与 SoC 匹配的 **programmer / loader**（`.bin` / `.mbn`）。文石系部分机型社区有现成 loader；Leaf5 需单独确认。

---

## 2. 进入 EDL

```bash
adb devices
adb reboot edl
```

屏幕常变黑，属正常。主机侧 `edl` 应检测到 Sahara。

退出 EDL 重启（**不写任何分区**）：

```bash
python3 edl --loader=<LOADER.bin> reset
# 或拔线 / 长按电源键强制重启（视机型）
```

---

## 3. 打印分区表（printgpt）

```bash
python3 edl --loader=<LOADER.bin> printgpt
# 存储类型不确定时依次试：
python3 edl --loader=<LOADER.bin> --memory=eMMC printgpt
python3 edl --loader=<LOADER.bin> --memory=ufs printgpt
```

关注：

- HWID / CPU 代号（应与 Leaf5 一致，而非他机 dump）
- `boot_a` / `boot_b`、`vbmeta_*`、活动槽位
- 存储类型（Leaf5 adb 侧为 **eMMC** 路径 `mmcblk0p*`）

格式参考：[`printgpt-p6pro.md`](printgpt-p6pro.md)（P6 Pro 样例）。**Leaf5 实测 printgpt 应另存本目录**，例如 `printgpt-leaf5.md`。

---

## 4. 只读提取分区

### 4.1 分析最小集（推荐）

```bash
mkdir -p stock_read
SLOT=a   # 与 adb: getprop ro.boot.slot_suffix 一致，去掉下划线

python3 edl --loader=<LOADER.bin> --memory=eMMC r boot_${SLOT} stock_read/boot_${SLOT}.img
# 可选：对照与校验
python3 edl --loader=<LOADER.bin> --memory=eMMC r vbmeta_${SLOT} stock_read/vbmeta_${SLOT}.img
```

### 4.2 更大范围备份（仍只读）

```bash
mkdir -p stock_partitions_backup
# 全盘读出、跳过 userdata（体积大、耗时长）
python3 edl --loader=<LOADER.bin> --memory=eMMC rl ./stock_partitions_backup --skip=userdata --genxml
```

分析链通常只需 **活动槽位 boot**；不必默认拉全盘。

---

## 5. 与 runtime 对齐（强制）

导出后必须与真机 `uname` / `/proc/version` 对齐，否则偏移全废：

```bash
adb shell cat /proc/version
# 期望含: 4.19.157-perf-g3d47a6619220-dirty #245

strings stock_read/boot_a.img | grep 'Linux version'
# 必须同一 git 短 hash 与 build 号
```

通过后拷贝/软链到分析路径（仓库约定）：

```bash
cp stock_read/boot_a.img leaf5/boot_a.bin   # gitignore，不入库
```

后续：`vmlinux-to-elf` → `raw/vmlinux.elf` → `uv run leaf5-extract-offsets`。  
设备 adb 采集见 [`../raw/README.md`](../raw/README.md)；流水线 S00/S01 见 [`../stages/`](../stages/)。

---

## 6. 与其它路径的关系

| 路径 | 说明 |
|------|------|
| shell `dd` `/dev/block/by-name/boot_a` | Leaf5 上 Permission denied（见 `raw/partitions.txt`） |
| fastboot `fetch` / `boot` | 可选；进 fastboot **须用户确认**（`AGENTS.md`） |
| 本目录 EDL | 只读 dump 的主记录处 |

---

## 7. 变更记录

| 日期 | 内容 |
|------|------|
| ~2025-12 | 曾误放 Boox P6 Pro 全套 Root/Magisk 指南与 printgpt 原始输出 |
| 2026-07-25 | 整理为 **只读提取** 流程；删除改镜像 / Magisk / 解锁写盘内容；P6 Pro printgpt 仅作样例归档 |

---

*本目录不提供、不鼓励对未授权设备的刷写或提权操作。*
