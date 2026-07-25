> **文档类型**: 索引文档（分析入口） | **状态**: ✅ 有效 | **最后更新**: 2026-07-25

# Leaf5 分析工作区

针对 **Onyx Leaf5** 的 GhostLock（CVE-2026-43499）适配调研。

## 从哪里读起

| 优先级 | 文档 | 说明 |
|--------|------|------|
| 1 | **[`stages/README.md`](stages/README.md)** | **流水线主索引**：按利用顺序的代码 + 效果记录 |
| 2 | [`PROCESS_LOG.md`](PROCESS_LOG.md) | 时间线与原始证据（步骤 40–45 终局） |
| 3 | [`NEXT_STEPS.md`](NEXT_STEPS.md) | 历史路线与剩余可选方向 |
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

**完成度 ~70%**。

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
├── README.md                 # 本文件
├── stages/                   # ★ 流水线（代码 + 节点效果文档）
│   ├── README.md
│   ├── Makefile              # 探针统一编译
│   ├── S00-device-profile/
│   ├── S01-offsets-stack/
│   ├── S02-kernelsnitch-leak/
│   ├── S03-heap-spray/
│   ├── S04-ghostlock-trigger/
│   ├── S05-stack-overwrite/routes/{01..09}/...
│   ├── S06-e2e-chain/
│   └── S07-post-cfu/
├── scripts/                  # uv 入口 shim → stages/*/scripts
├── raw/                      # 设备原始采集
├── docs/                     # 专题笔记（含 KGSL 勘误）
├── PROCESS_LOG.md            # 操作流水
├── NEXT_STEPS.md / ANALYSIS.md / ...
├── probes/                   # 已迁移，仅保留跳转说明
└── ghostlock-analysis/       # 已迁移，仅保留跳转说明
```

仓库根目录 `../exploit/`：Leaf5 专用 exploit（`targets/onyx-leaf5`），对应 S02–S07 集成实现。

---

## 工具

```bash
cd leaf5 && uv sync
uv run leaf5-collect
uv run leaf5-extract-offsets

# 编译某探针
cd stages
make SRC=S05-stack-overwrite/routes/07-kgsl/e-rb-issueibcmds-64/probes/ghostlock64_opt.c BITS=64
```

---

## 历史文档（审计用）

下列文件保留过程细节，**结论以 stages + PROCESS_LOG 为准**：

| 文档 | 说明 |
|------|------|
| [ANALYSIS.md](ANALYSIS.md) | 早期设备分析（部分路由结论已过时） |
| [GHOSTLOCK_EXPLOIT_PLAN.md](GHOSTLOCK_EXPLOIT_PLAN.md) | 早期计划 |
| [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) | 偏移验证报告 |
| [STACK_LAYOUT.md](STACK_LAYOUT.md) | 栈布局笔记 |
| [COMPARE_OPPO_FIND_N2.md](COMPARE_OPPO_FIND_N2.md) | 与 Find N2 对比 |
| [PSELECT_STACK_ANALYSIS_PLAN.md](PSELECT_STACK_ANALYSIS_PLAN.md) | pselect 计划 |
| [docs/KGSL_STACK_OVERWRITE.md](docs/KGSL_STACK_OVERWRITE.md) | KGSL 技术笔记 + 终局勘误 |
| [edl-backup.md](edl-backup.md) / [edl-printgpt.md](edl-printgpt.md) | EDL 相关 |

---

*最后更新: 2026-07-25 — 代码按 stages 流水线归档*
