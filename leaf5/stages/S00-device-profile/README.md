> **阶段**: S00 | **状态**: ✅ 完成 | **最后更新**: 2026-07-25

# S00 — 设备画像与数据采集

## 目标
建立 Leaf5 运行时指纹：内核版本、CONFIG、安全面、分区/接口、与 boot 镜像一致性。

## 代码

| 文件 | 作用 | 效果 | 原因/备注 |
|------|------|------|-----------|
| `scripts/collect_device.py` | adb 采集 → `raw/` | ✅ 成功 | 产出 device_identity、security_runtime、config 等 |
| `scripts/summarize_config.py` | 解析 config.gz 安全相关项 | ✅ 成功 | 确认 FUTEX_PI、无 CFI、无 KPTI |

## 关键产物（`leaf5/raw/`）
- `config.gz` / `kernel_config.txt` — 权威 CONFIG
- `device_identity.txt` — uname/getprop
- `security_runtime.txt` — SELinux/caps/devices
- `analysis_snapshot.json`

## 下游
→ **S01** 依赖 vmlinux / kheaders / boot_a.bin（本地 gitignore）做偏移提取。

## 运行
```bash
cd leaf5 && uv run leaf5-collect && uv run leaf5-summarize
```
