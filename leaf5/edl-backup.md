> **文档类型**: 无关文档 | **状态**: ⚠️ 与 Leaf5 GhostLock 分析无关 — 此为 Boox P6 Pro (SM7225) Root 指南，非 Leaf5 (SM6350) | **最后更新**: 2025-12

# Boox P6 Pro 小彩马 Root 指南 / Root Guide

> 大概是全网第一个文石 P6 Pro 小彩马（国内版）固件 4.1.x Root 及 Magisk 修复方案
>
> Root + Magisk fix for Boox P6 Pro 小彩马 (Chinese domestic version) on firmware 4.1.x

[![Device](https://img.shields.io/badge/Device-Boox_P6_Pro_小彩马-blue)]()
[![Android](https://img.shields.io/badge/Android-13-green)]()
[![SoC](https://img.shields.io/badge/SoC-SM7225_(Snapdragon_750G)-red)]()
[![Firmware](https://img.shields.io/badge/Firmware-4.1-orange)]()
[![Root](https://img.shields.io/badge/Root-Magisk-brightgreen)]()

**[English Guide](#english-guide)**

---

# 中文指南

## 目录

- [概述](#概述)
- [设备信息](#设备信息)
- [准备工作](#准备工作)
- [第一部分：备份](#第一部分备份)
- [第二部分：解锁 Bootloader](#第二部分解锁-bootloader)
- [第三部分：Magisk Root](#第三部分magisk-root)
- [第四部分：修复 Magisk App 崩溃](#第四部分修复-magisk-app-崩溃)
- [恢复方法](#恢复方法)
- [技术分析](#技术分析)
- [已知问题](#已知问题)
- [兼容性](#兼容性)
- [相关项目](#相关项目)
- [致谢](#致谢)

---

## 概述

本指南记录了在固件 4.1.1 (2025-12-27) 的文石 P6 Pro 小彩马（国内版，Android 13）上完成 Root 的完整过程。该设备在 Bootloader 模式下似乎不能使用标准的 `fastboot flashing unlock`，通过高通 EDL（紧急下载模式）直接修改 `devinfo` 分区来解锁 Bootloader，然后刷入 Magisk 修补过的 boot 镜像。

此外，文石 4.1 固件在 `ActivityManagerService` 中引入了一个 Bug，导致 Magisk App 启动时崩溃。本指南包含一个 Magisk 模块，通过对 framework 的单字节补丁修复此问题。

---

## 设备信息

| 属性 | 值 |
|---|---|
| 设备 | Boox P6 Pro 小彩马（国内版） |
| Android 版本 | 13 |
| 固件版本 | 4.1.1(2025-12-27) |
| SoC | Qualcomm SM7225 (Snapdragon 750G) |
| HWID | `0x0013f0e1` |
| 存储类型 | UFS |
| 分区方案 | A/B slots (LUN 4) |
| EDL Loader | `palma2pro.bin`（与 Palma 2 Pro 通用） |

---

## 准备工作

### 工具

- **[bkerler/edl](https://github.com/bkerler/edl)** — 高通 EDL 工具，用于读写分区
- **[Magisk](https://github.com/topjohnwu/Magisk/releases)** — Root 方案（已测试 v30.6）
- **ADB & Fastboot** — Android 平台工具
- **EDL Loader** — `palma2pro.bin`（来自 [Kisuke 的 Palma 2 Pro 指南](https://github.com/Kisuke-CZE/Palma_2_Pro-tips#rooting-palma-2-pro)）
- **FP4 ABL** — `abl-fp4.img`（Fairphone 4 的 Android Bootloader，用于临时替换）

### 在 macOS 上安装 edl

```bash
brew install libusb git python3
git clone https://github.com/bkerler/edl.git
cd edl
git submodule update --init --recursive
pip3 install -r requirements.txt --break-system-packages

# 如果 pylzma 编译失败（macOS 常见问题）：
grep -v pylzma requirements.txt | pip3 install -r /dev/stdin --break-system-packages
```

> **注意：** 如果 pip 安装失败，可在仓库目录下用 `python3 edl` 替代所有 `edl` 命令。安装成功就直接 `edl` 。

### 进入 EDL 模式

```bash
adb reboot edl
```

屏幕会变黑，这是正常的。

---

## 第一部分：备份

> ⚠️ **不要跳过此步骤。一定一定要备份。**

### 1.1 验证设备

```bash
adb reboot edl
python3 edl --loader=palma2pro.bin printgpt
```

确认能看到 LUN 4 上的分区，包括 `boot_a`、`boot_b`、`abl_a`、`abl_b`、`vbmeta_a`、`vbmeta_b`、`devinfo`。

### 1.2 检查活动槽位

```bash
adb shell getprop ro.boot.slot_suffix
# 预期输出: _a
```

### 1.3 全盘备份

```bash
mkdir stock_partitions_backup
uv run edl --loader=palma2pro.bin --memory=eMMC rl ./stock_partitions_backup --skip=userdata --genxml
```

大约需要 10 分钟，生成约 9GB 的分区镜像文件。

### 1.4 关键分区备份

```bash
mkdir stock_backup

python3 edl --loader=palma2pro.bin --memory=eMMC r abl_a stock_backup/abl_a.img
python3 edl --loader=palma2pro.bin --memory=eMMC r abl_b stock_backup/abl_b.img
python3 edl --loader=palma2pro.bin --memory=eMMC r boot_a stock_backup/boot_a.img
python3 edl --loader=palma2pro.bin --memory=eMMC r boot_b stock_backup/boot_b.img
python3 edl --loader=palma2pro.bin --memory=eMMC r vbmeta_a stock_backup/vbmeta_a.img
python3 edl --loader=palma2pro.bin --memory=eMMC r vbmeta_b stock_backup/vbmeta_b.img
python3 edl --loader=palma2pro.bin --memory=eMMC r vbmeta_system_a stock_backup/vbmeta_system_a.img
python3 edl --loader=palma2pro.bin --memory=eMMC r vbmeta_system_b stock_backup/vbmeta_system_b.img
python3 edl --loader=palma2pro.bin --memory=eMMC r recovery_a stock_backup/recovery_a.img
python3 edl --loader=palma2pro.bin --memory=eMMC r recovery_b stock_backup/recovery_b.img
python3 edl --loader=palma2pro.bin --memory=eMMC r devinfo stock_backup/devinfo.img
```

预期文件大小：

| 文件 | 大小 |
|---|---|
| abl_a/b.img | ~1.0 MB |
| boot_a/b.img | ~96 MB |
| recovery_a/b.img | ~96 MB |
| vbmeta_a/b.img | ~64 KB |
| vbmeta_system_a/b.img | ~64 KB |
| devinfo.img | ~4 KB |

> **继续操作前，务必将 `stock_backup/` 和 `stock_partitions_backup/` 备份好。**

---

## 第二部分：解锁 Bootloader

### 为什么不用 Fastboot？

文石 P6 Pro 小彩马在 Bootloader 模式似乎无法使用 `fastboot flashing unlock` ——无论在 macOS 还是 Windows 上，`fastboot devices` 都没有输出。通过 EDL 直接修改 `devinfo` 分区来绕过此限制，效果等同于 fastboot 解锁。

### 2.1 刷入 FP4 ABL（临时）

Fairphone 4 使用相同的 SM7225 SoC，其 ABL 可以在 Android 设置中启用 OEM 解锁开关。

```bash
# 进入 EDL
adb reboot edl

# 刷入 FP4 ABL 到两个槽位
python3 edl --loader=palma2pro.bin --memory=ufs w abl_a abl-fp4.img
python3 edl --loader=palma2pro.bin --memory=ufs w abl_b abl-fp4.img

# 重启
python3 edl --loader=palma2pro.bin reset
```

### 2.2 启用 OEM 解锁

重启后，进入 Android 原生设置（不是文石设置）：

```bash
adb shell am start -n com.android.settings/.DevelopmentSettingsDashboardActivity
```

进入 **System → Developer options → 打开 OEM unlocking**。

### 2.3 修改 devinfo 分区

`devinfo` 分区使用标准高通格式。偏移 `0x0D` 是 `is_unlocked` 标志位，`0x0E` 是 `is_unlock_critical`。将两者都设为 `0x01`。

```bash
# 复制并修改
cp stock_backup/devinfo.img devinfo_unlocked.img
printf '\x01' | dd of=devinfo_unlocked.img bs=1 seek=13 conv=notrunc
printf '\x01' | dd of=devinfo_unlocked.img bs=1 seek=14 conv=notrunc

# 验证 — 应显示 0x0D-0x0F 处为 01 01 01
xxd devinfo_unlocked.img | head -1
# 预期: 00000000: 414e 4452 4f49 442d 424f 4f54 2101 0101  ANDROID-BOOT!...
```

devinfo 结构：

```
偏移    字段                        出厂值   解锁后
0x00    Magic "ANDROID-BOOT!"       —       —
0x0D    is_unlocked                 0x00    0x01
0x0E    is_unlock_critical          0x00    0x01
0x0F    is_charger_screen_enabled   0x01    0x01
```

### 2.4 刷入修改后的 devinfo

```bash
adb reboot edl
python3 edl --loader=palma2pro.bin --memory=ufs w devinfo devinfo_unlocked.img
python3 edl --loader=palma2pro.bin reset
```

### 2.5 恢复出厂设置

修改 devinfo 后，设备会启动到 Android Recovery，显示"无法加载 Android 系统"。这是正常的——与标准 fastboot 解锁行为一致。选择 **Factory data reset**（恢复出厂设置）继续。

> ⚠️ **数据清除不可避免。开始前请务必务必备份重要数据。**

---

## 第三部分：Magisk Root

### 3.1 重置后设置

1. 完成初始设备设置
2. 启用开发者选项：**设置 → 关于设备 → 连续点击版本号 7 次**
3. 启用 USB 调试：**设置 → Developer options → USB debugging**

### 3.2 安装 Magisk 并修补 Boot

```bash
# 推送原始 boot 镜像到设备
adb push stock_backup/boot_a.img /sdcard/
```

在设备上安装 Magisk APK。

在 Magisk App 中：
1. 点击 **Install**
2. 选择 **Select and Patch a File**
3. 选择 `/sdcard/boot_a.img`
4. 等待修补完成

```bash
# 将修补后的镜像拉回电脑
adb pull /sdcard/Download/magisk_patched-*.img boot_a_patched.img
```

### 3.3 通过 EDL 刷入修补后的 Boot

```bash
adb reboot edl
python3 edl --loader=palma2pro.bin --memory=ufs w boot_a boot_a_patched.img
python3 edl --loader=palma2pro.bin reset
```

### 3.4 验证 Root

```bash
adb shell su -c id
# 预期: uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
```

设备屏幕上应该弹出超级用户授权弹窗。

### 3.5 恢复原版 ABL

> ⚠️ **确认 Root 成功后立即执行此步骤。FP4 ABL 仅临时需要。**

```bash
adb reboot edl
python3 edl --loader=palma2pro.bin --memory=ufs w abl_a stock_backup/abl_a.img
python3 edl --loader=palma2pro.bin --memory=ufs w abl_b stock_backup/abl_b.img
python3 edl --loader=palma2pro.bin reset
```

Root 已完成。`su` 正常工作，Magisk 守护进程运行中。但 Magisk App 会卡在启动画面——这是文石固件 4.1 的 Bug。修复方法见第四部分。

---

## 第四部分：修复 Magisk App 崩溃

### 问题

在文石固件 4.1 上，Magisk App 卡在启动画面。Root 本身正常工作（`su -c id` 返回 uid=0），但 Magisk 管理界面无法使用。这是影响多款文石设备的已知问题：
- [Magisk #9319](https://github.com/topjohnwu/Magisk/issues/9319) — Boox Note Air 3C，固件 4.1
- [BooxPalma2RootGuide #8](https://github.com/jdkruzr/BooxPalma2RootGuide/issues/8) — Palma 2，固件 4.1

### 安装修复

从 [Releases](https://github.com/dynamicfire/boox-ams-fix/releases/) 页面下载 `boox-ams-fix-v1.0.zip`，然后：

```bash
# 推送模块到设备
adb push boox-ams-fix-v1.0.zip /sdcard/

# 通过 Magisk 命令行安装（因为 Magisk App 无法使用）
adb shell su -c 'magisk --install-module /sdcard/boox-ams-fix-v1.0.zip'

# 重启
adb reboot
```

重启后，Magisk App 应该能正常启动。

### 模块详情

```
id=boox-ams-fix
name=Boox AMS NullPointerException Fix
version=v1.0
author=玄昼
```

模块使用 Magisk 的 systemless overlay 替换 `/system/framework/services.jar`，不修改实际的系统分区。启动时会清除 dalvik-cache 以确保加载修补后的 DEX。

### 卸载

```bash
adb shell su -c 'rm -rf /data/adb/modules/boox-ams-fix'
adb reboot
```

---

## 恢复方法

EDL 模式固化在高通 SoC 的 ROM 中，无论软件状态如何都可以进入。只要有备份和 EDL loader，就可以随时恢复。

### 完全恢复到出厂状态

```bash
adb reboot edl

python3 edl --loader=palma2pro.bin --memory=ufs w abl_a stock_backup/abl_a.img
python3 edl --loader=palma2pro.bin --memory=ufs w abl_b stock_backup/abl_b.img
python3 edl --loader=palma2pro.bin --memory=ufs w boot_a stock_backup/boot_a.img
python3 edl --loader=palma2pro.bin --memory=ufs w boot_b stock_backup/boot_b.img
python3 edl --loader=palma2pro.bin --memory=ufs w vbmeta_a stock_backup/vbmeta_a.img
python3 edl --loader=palma2pro.bin --memory=ufs w vbmeta_b stock_backup/vbmeta_b.img
python3 edl --loader=palma2pro.bin --memory=ufs w devinfo stock_backup/devinfo.img
python3 edl --loader=palma2pro.bin reset
```

### 仅移除 Magisk 模块

```bash
adb shell su -c 'rm -rf /data/adb/modules/boox-ams-fix'
adb reboot
```

### 禁用所有 Magisk 模块

```bash
adb shell su -c 'magisk --remove-modules'
adb reboot
```

---

## 技术分析

文石 P6 Pro 小彩马使用原版 ABL 时，进入 Bootloader 模式后不初始化 USB，即使刷入 FP4 ABL（可启用 OEM 解锁开关），Bootloader 的 USB 仍然不工作。

### devinfo 分区结构

```
偏移    大小   字段                        描述
0x00    13    Magic                      "ANDROID-BOOT!" 魔术头
0x0D    1     is_unlocked                0=锁定, 1=解锁
0x0E    1     is_unlock_critical         0=锁定, 1=解锁
0x0F    1     is_charger_screen_enabled  0=禁用, 1=启用
0x90    1     verity_mode                值为 0x01
```

这是标准的高通 devinfo 格式。修改偏移 0x0D 和 0x0E 处的字节等效于 `fastboot flashing unlock` + `fastboot flashing unlock_critical`。

### 文石 Framework Bug 分析

文石在 `services.jar` 的 `ActivityManagerService` 的 `addPackageDependency()` 方法末尾添加了 `UpdateWebViewUsedPkgsAction` 代码。该代码追踪哪些应用正在使用 WebView，可能是为了优化墨水屏刷新策略。Bug 在于 `ProcessRecord` 的 null 和非 null 两条代码路径都汇聚到这段追踪代码，而该代码无条件访问 `processRecord.info.packageName`，缺少空指针检查。

正常运行时，所有应用进程都在 PidMap 中有记录，所以 `ProcessRecord` 不会为 null。只有 Magisk 的 root 守护进程（uid 0，以 `RootServerMain` 运行）没有在 PidMap 中注册，从而暴露了这个空指针 Bug。

### DEX 字节码补丁详情

```
文件:     classes.dex（services.jar 内）
方法:     ActivityManagerService.addPackageDependency()
偏移:     0x002b2f14

原始字节码:
  38 01 33 00    if-eqz v1, +0x33    ; null → 跳转到文石 WebView 代码

修补后字节码:
  38 01 3F 00    if-eqz v1, +0x3F    ; null → 跳转到 return-void

变更:     1 字节 (0x33 → 0x3F)
效果:     当 ProcessRecord 为 null 时跳过文石 WebView 追踪代码
```

修补后，重新计算了 DEX 的 SHA-1 签名（偏移 0x0C，20 字节）和 Adler32 校验和（偏移 0x08，4 字节）以保持文件完整性。

---

## 已知问题

| 问题 | 状态 | 解决方案 |
|---|---|---|
| 固件 4.1 Magisk App 崩溃 | ✅ 已修复 | 安装 `boox-ams-fix` 模块 |
| fastboot USB 不工作 | ⚠️ 硬件限制（？） | 使用 EDL 进行所有分区操作 |

---

## 兼容性

本指南在文石 P6 Pro 小彩马（国内版）上开发和测试。它也可能适用于其他使用相同 SM7225 SoC 和固件 4.1 的文石设备，包括：

- Boox Palma 2 Pro（已确认相同 HWID `0x0013f0e1`）
- Boox Note Air 3C（已报告相同的 Magisk 崩溃 Bug）
- 其他使用 SM7225 且固件版本为 4.1 的文石设备

`boox-ams-fix` Magisk 模块专门针对固件 4.1 的 `services.jar`。在其他固件版本上使用可能无效或导致问题。

---

## 相关项目

- **[boox-ams-fix](https://github.com/dynamicfire/boox-ams-fix)** — 修复文石 4.1 固件上 Magisk App 崩溃的 Bug
- **[boox-telecom-fix](https://github.com/dynamicfire/boox-telecom-fix)** — 解锁被软件封锁的电话和短信功能（国内版小彩马）

---

## 致谢

- **[Kisuke](https://github.com/Kisuke-CZE/Palma_2_Pro-tips#rooting-palma-2-pro)** — 原始 Palma 2 Pro Root 方法和 EDL loader
- **[bkerler/edl](https://github.com/bkerler/edl)** — 高通 EDL 工具
- **[topjohnwu/Magisk](https://github.com/topjohnwu/Magisk)** — Root 方案
- **[jdkruzr/BooxPalma2RootGuide](https://github.com/jdkruzr/BooxPalma2RootGuide)** — 参考指南

---

使用本指南风险自负。作者不对任何设备损坏承担责任。
