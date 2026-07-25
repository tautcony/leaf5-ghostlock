# Leaf5 GhostLock 分析仓库

针对 **Onyx Leaf5**（TabBoox 电纸书）的 GhostLock（CVE-2026-43499）安全研究仓库。

> 本仓库**仅保留 Leaf5 相关**分析、探针与 exploit 代码。其它设备（OPPO Find N2、Xiaomi 等）与通用文档已移除。

---

## 结论摘要（2026-07-25）

| 项 | 状态 |
|----|------|
| 设备 | Onyx Leaf5 / Android 13 / kernel **4.19.157** #245 |
| 前半链 | Kernelsnitch + heap spray + GhostLock 触发 + KGSL CFU 均已验证 ✅ |
| 栈覆盖 | **CFU 无法覆盖 `waiter->task`** ❌（编译期栈布局，非随机） |
| 完成度 | ~70%（到 CFU 触发；fops / physrw / root 未打通） |

**根本原因**（详见 [`leaf5/PROCESS_LOG.md`](leaf5/PROCESS_LOG.md) 步骤 40–44）：

```
waiter->task     @ KSP0 - 0x2B0
64-bit KGSL CFU  @ ~KSP0 - 0x228   （太浅，~88B）
32-bit KGSL CFU  @ ~KSP0 - 0x2A0+  （太深，compat 帧无法 <24B）
```

标准 GhostLock「CFU 覆盖 stale waiter」链在此内核构建上**不可行**。

---

## 仓库布局

```
.
├── README.md                 # 本文件（入口）
├── AGENTS.md                 # 智能体/协作约定
├── exploit/                  # Leaf5 专用 exploit 源码（onyx-leaf5）
│   ├── src/
│   ├── targets/onyx-leaf5/
│   ├── Makefile
│   └── docker-build.sh
└── leaf5/                    # 分析工作区（主文档与探针）
    ├── README.md             # 分析总览
    ├── ANALYSIS.md           # 设备与内核分析
    ├── PROCESS_LOG.md        # 操作流水（权威过程记录）
    ├── NEXT_STEPS.md         # 路线与后续方向
    ├── VERIFICATION_REPORT.md
    ├── STACK_LAYOUT.md
    ├── docs/                 # 专题技术文档
    ├── scripts/              # Python 采集/偏移脚本（uv）
    ├── probes/kgsl_probe/    # KGSL / GhostLock 探针源码
    ├── ghostlock-analysis/   # CFU 扫描、binder、do_select 等分析
    └── raw/                  # 设备原始采集（小文本；大镜像本地保留）
```

---

## 快速使用

### 分析脚本

```bash
cd leaf5
uv sync
uv run leaf5-collect      # 需 adb 连接设备
uv run leaf5-summarize
```

### 编译 exploit（Docker + NDK）

```bash
cd exploit
./docker-build.sh                          # 64-bit preload.so
./docker-build.sh arm32-pie                # 32-bit ghostlock32 PIE
```

本地 NDK：

```bash
cd exploit
make TARGET_DIR=targets/onyx-leaf5
make arm32-pie
```

### 编译探针

```bash
cd leaf5/probes/kgsl_probe
# 见该目录 Makefile / README；产物为本地 ELF，不入库
```

---

## 文档导读

| 文档 | 用途 |
|------|------|
| [`leaf5/README.md`](leaf5/README.md) | 分析入口与状态总览 |
| [`leaf5/PROCESS_LOG.md`](leaf5/PROCESS_LOG.md) | 全过程操作与终局证据 |
| [`leaf5/NEXT_STEPS.md`](leaf5/NEXT_STEPS.md) | 已关闭路径与可选前进方向 |
| [`leaf5/ANALYSIS.md`](leaf5/ANALYSIS.md) | 设备画像与内核配置 |
| [`leaf5/docs/KGSL_STACK_OVERWRITE.md`](leaf5/docs/KGSL_STACK_OVERWRITE.md) | KGSL 栈覆盖技术笔记（以 PROCESS_LOG 终局为准） |

---

## 本地大文件（gitignore，不提交）

| 路径 | 说明 |
|------|------|
| `leaf5/boot_a.bin` | 与 runtime #245 匹配的 boot 镜像 |
| `leaf5/raw/vmlinux*` | 解包/重建的内核 |
| `leaf5/raw/kheaders/` | 设备 kheaders |
| `leaf5/probes/**/g32_*` 等 | 编译出的探针二进制 |

---

*最后更新: 2026-07-25*
