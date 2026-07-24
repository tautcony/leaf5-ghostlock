# Leaf5 分析工作区

针对 **Onyx Leaf5** 的 GhostLock（CVE-2026-43499）适配调研目录。

> 本目录文档于 **2026-07-24 从零重写**。此前基于错误/过期数据源的结论已废弃，请以 [`ANALYSIS.md`](ANALYSIS.md) 为准。

## 文档索引

| 文档 | 内容 |
|------|------|
| **[ANALYSIS.md](ANALYSIS.md)** | 完整分析过程 + 结论 + 可信度矩阵（主报告） |
| [COMPARE_OPPO_FIND_N2.md](COMPARE_OPPO_FIND_N2.md) | 与仓库原目标 OPPO Find N2 对比 |
| [NEXT_STEPS.md](NEXT_STEPS.md) | 后续导出内核 / 偏移 / 探针计划 |
| [raw/](raw/) | adb 原始采集与快照（可复核） |

## 设备快照（2026-07-24）

| 项 | 值 |
|----|-----|
| 型号 | Onyx Leaf5（fingerprint: `ONYX/TabBoox/...`） |
| Android | 13 / API 33 / patch 2026-04-01 |
| Kernel | `4.19.157-perf-g3d47a6619220-dirty` #245 |
| 平台 | Qualcomm lito / SM6350 class |
| AVB | unlocked（orange） |
| SELinux | Enforcing；shell 无 root |
| GhostLock CONFIG | `FUTEX_PI=y`，**无内核 CFI**，**无 KPTI** |
| Stage1 | Firefox **151.0.2** 已安装 |

## 工具

Python 使用 **uv**：

```bash
cd leaf5
uv sync
uv run leaf5-collect      # adb 重新采集到 raw/
uv run leaf5-summarize    # 打印 GhostLock 相关 CONFIG
```

## 关键警告

1. 仓库根目录 `boot.img` 的内核 banner 是 **#119 / g87880838aed5（2025-07）**，**不是**当前设备 #245 / g3d47a6619220。  
2. 禁止将 `exploit/targets/oppo-find_n2/target.h` 偏移直接用于 Leaf5。  
3. shell 无法 `dd` boot 分区；需要 fastboot/厂商方式导出与 runtime 一致的镜像后再做 IDA。

## raw/ 说明

| 路径 | 说明 |
|------|------|
| `raw/config.gz` | 设备 `/proc/config.gz`（权威 CONFIG） |
| `raw/kernel_config.txt` | 解压后的配置文本 |
| `raw/kheaders.tar.xz` | 设备 kheaders（本地解压目录 gitignore） |
| `raw/analysis_snapshot.json` | 结构化摘要 |
| `raw/*.txt` | 各阶段 adb 原始日志 |
