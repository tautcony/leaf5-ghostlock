# Leaf5 GhostLock 分析仓库

**Onyx Leaf5**（kernel 4.19.157）上 GhostLock（CVE-2026-43499）的专项研究仓库。

---

## 结论摘要

| 项 | 状态 |
|----|------|
| 前半链（泄漏 / spray / GhostLock / KGSL CFU 触发） | ✅ |
| CFU 覆盖 `waiter->task` | ❌ 栈布局位差（固定） |
| 完成度 | ~70% |

权威过程证据：[`leaf5/PROCESS_LOG.md`](leaf5/PROCESS_LOG.md)。  
**按阶段阅读的代码与效果表**：[`leaf5/stages/README.md`](leaf5/stages/README.md)。

---

## 仓库布局

```
.
├── README.md
├── AGENTS.md
├── exploit/                 # Leaf5 exploit 源码（onyx-leaf5）
└── leaf5/
    ├── stages/              # ★ 利用/分析流水线（文档 ↔ 代码）
    │   ├── S00 … S07
    │   └── S05-stack-overwrite/routes/   # 并列栈覆盖候选
    ├── scripts/             # uv CLI shim
    ├── raw/
    └── *.md                 # 过程/历史文档
```

### 流水线一览

| 阶段 | 内容 | 结果 |
|------|------|------|
| S00 | 设备画像 | ✅ |
| S01 | 偏移与栈布局 | ✅ |
| S02 | Kernelsnitch | ✅ |
| S03 | Heap spray | ✅ |
| S04 | GhostLock 触发 | ✅ |
| S05 | 栈覆盖（多路由并列） | ❌ |
| S06 | E2E 集成 | ⚠️ 止于 CFU |
| S07 | fops / physrw / root | ⛔ 未达成 |

每个节点目录内 `README.md` 记录该处**每个文件**的作用、成功/失败与原因。

---

## 快速使用

```bash
# 分析脚本
cd leaf5 && uv sync
uv run leaf5-collect

# 编译 exploit
cd exploit && ./docker-build.sh

# 编译流水线探针
cd leaf5/stages
make SRC=S05-stack-overwrite/routes/07-kgsl/e-rb-issueibcmds-64/probes/ghostlock64_opt.c BITS=64
```

---

## 文档

| 文档 | 用途 |
|------|------|
| [leaf5/stages/README.md](leaf5/stages/README.md) | **主索引（推荐）** |
| [leaf5/README.md](leaf5/README.md) | 工作区说明 |
| [leaf5/PROCESS_LOG.md](leaf5/PROCESS_LOG.md) | 时间线证据 |
| [leaf5/NEXT_STEPS.md](leaf5/NEXT_STEPS.md) | 历史路线 / 剩余方向 |

---

*最后更新: 2026-07-25*
