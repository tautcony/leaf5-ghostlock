> **文档类型**: 索引文档（分析入口） | **状态**: ✅ 有效 | **最后更新**: 2026-07-25

# Leaf5 分析工作区

针对 **Onyx Leaf5** 的 GhostLock（CVE-2026-43499）适配调研。

## 从哪里读起

| 优先级 | 文档 | 说明 |
|--------|------|------|
| 1 | **[`stages/README.md`](stages/README.md)** | **流水线主索引**：按利用顺序的代码 + 效果记录 |
| 2 | [`PROCESS_LOG.md`](PROCESS_LOG.md) | 时间线与原始证据（步骤 40–45 终局） |
| 3 | [`docs/README.md`](docs/README.md) | 画像 / 偏移 / 路线等参考与归档 |
| 4 | 本文件 | 设备快照与仓库地图 |

> 早期「qcedev 世界可写」「32-bit KGSL 完美重叠」等表述已废弃；以 **stages** 各节点 README 与 PROCESS_LOG 为准。

---

## 结论（2026-07-25）

标准 GhostLock 链在此设备上 **CFU 无法覆盖 `waiter->task`**（编译期栈布局）。

| 步骤 | 状态 | stages |
|------|------|--------|
| 设备画像 | ✅ | S00 |
| 偏移 / 栈布局 | ✅ | S01 |
| Kernelsnitch | ✅ | S02 |
| Heap spray | ✅ | S03 |
| GhostLock 触发 | ✅ | S04 |
| 栈覆盖 | ❌ | S05（全部候选关闭） |
| E2E 集成 | ⚠️ 到 CFU | S06 |
| fops / physrw / root | ⛔ | S07 |

```
waiter->task @ KSP0 - 0x2B0
64-bit KGSL CFU  太浅 ~88B
32-bit RB_ISSUE  compat 拒绝 / 理论过深
```

**完成度 ~70%**。剩余可选方向见 [`docs/NEXT_STEPS.md`](docs/NEXT_STEPS.md) **十二-G**（与终局冲突时以 stages / PROCESS_LOG 为准）。

---

## 设备快照

| 项 | 值 |
|----|-----|
| 型号 | Onyx Leaf5（`ONYX/TabBoox/...`） |
| Android | 13 / API 33 |
| Kernel | `4.19.157-perf-g3d47a6619220-dirty` #245 |
| 平台 | Qualcomm SM6350 (LAGOON) |
| AVB | unlocked |
| SELinux | Enforcing |
| GhostLock CONFIG | `FUTEX_PI=y`，**无 CFI**，**无 KPTI** |

---

## 目录结构

```
leaf5/
├── README.md              # 本文件
├── PROCESS_LOG.md         # 操作流水（终局权威过程）
├── stages/                # ★ 流水线（代码 + 节点效果文档）
│   ├── README.md
│   ├── Makefile
│   └── S00 … S07 …
├── docs/                  # 参考与历史文档（见 docs/README.md）
├── edl/                   # EDL 只读提取 boot/分区（见 edl/README.md）
├── raw/                   # 设备原始采集（config / kheaders / vmlinux*）
├── scripts/               # uv 入口 shim → stages/*/scripts
└── boot_a.bin             # gitignore；runtime 对齐的 boot 镜像
```

仓库根目录 `../exploit/`：Leaf5 专用 exploit（`targets/onyx-leaf5`），对应 S02–S07 集成实现。

---

## 工具

```bash
# 仓库根：顶层 uv / .venv
uv sync
uv run leaf5-collect
uv run leaf5-extract-offsets

# 探针 → out/stages/.../{arm32|arm64}/
make -C leaf5/stages \
  SRC=S05-stack-overwrite/routes/07-kgsl/e-rb-issueibcmds-64/probes/ghostlock64_opt.c \
  BITS=64
```

产物布局：[`../BUILD_OUTPUT.md`](../BUILD_OUTPUT.md)。  
boot / vmlinux 来源：[`edl/README.md`](edl/README.md)（只读 dump）→ `boot_a.bin` → `raw/vmlinux.elf`。

---

## 文档地图

| 位置 | 说明 |
|------|------|
| [stages/](stages/README.md) | **主索引** |
| [PROCESS_LOG.md](PROCESS_LOG.md) | 时间线 |
| [docs/](docs/README.md) | ANALYSIS、栈布局、验证报告、NEXT_STEPS、归档计划 |
| [edl/](edl/README.md) | EDL 提取流程（无改镜像 / Magisk） |
| [raw/](raw/README.md) | 原始采集 |

---

*最后更新: 2026-07-25 — 一层文档整理：历史 md 入 docs/，EDL 独立为只读提取目录*
