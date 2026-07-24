> **文档类型**: 索引文档 | **状态**: ✅ 有效 | **最后更新**: 2026-07-24

# raw/ — 设备原始采集

本目录为 **2026-07-24** 起对 Leaf5 的 adb/主机分析原始输出，供 [ANALYSIS.md](../ANALYSIS.md) 复核。

| 文件 | 来源 |
|------|------|
| `config.gz` / `kernel_config.txt` | 设备 `/proc/config.gz` |
| `device_identity.txt` | getprop + uname + cpuinfo |
| `security_runtime.txt` | SELinux / caps / devices / mounts |
| `sysctl_probe.txt` | sysctl 读权限探测 |
| `partitions.txt` | by-name 分区与 dd 权限 |
| `interfaces.txt` | binder/ashmem/net/modules |
| `version_compare.txt` | runtime vs 仓库 boot.img |
| `analysis_snapshot.json` | 结构化摘要 |
| `kheaders.tar.xz` | 设备 kheaders（通常 gitignore，可重拉） |
| `kernel_payload.bin` | 从仓库**旧** boot.img 抽出的 Image（非 runtime） |

重新采集：

```bash
cd leaf5 && uv run leaf5-collect
```
