> **文档类型**: 索引 | **状态**: ✅ 有效 | **最后更新**: 2026-07-25

# docs/ — 分析参考与历史文档

**结论与节点成败**以 [`../stages/README.md`](../stages/README.md) 与 [`../PROCESS_LOG.md`](../PROCESS_LOG.md) 为准。  
本目录存放设备画像、偏移验证、对比表与过程中的路线笔记；**中间结论可能已推翻**，阅读时先看文首状态与终局勘误。

## 参考文档（仍有用）

| 文档 | 内容 |
|------|------|
| [ANALYSIS.md](ANALYSIS.md) | 2026-07-24 设备从零采集与画像；§8 偏移结果仍可查 |
| [STACK_LAYOUT.md](STACK_LAYOUT.md) | futex/waiter 栈帧（vmlinux 反汇编） |
| [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) | KernelSnitch / spray / 偏移 bug 修复快照 |
| [REVERIFY_2026-07-25.md](REVERIFY_2026-07-25.md) | **全量编译 + 设备复测**对照表与 CORRECTED |
| [COMPARE_OPPO_FIND_N2.md](COMPARE_OPPO_FIND_N2.md) | Leaf5 4.19 vs OPPO Find N2 5.10 |
| [KGSL_STACK_OVERWRITE.md](KGSL_STACK_OVERWRITE.md) | KGSL 调用链笔记 + **终局勘误** |
| [NEXT_STEPS.md](NEXT_STEPS.md) | 历史路线矩阵与剩余可选方向（含乐观中间态） |

## 归档（计划已执行 / 被 stages 取代）

| 文档 | 说明 |
|------|------|
| [archive/GHOSTLOCK_EXPLOIT_PLAN.md](archive/GHOSTLOCK_EXPLOIT_PLAN.md) | 早期完整利用计划；栈覆盖章节过时 |
| [archive/PSELECT_STACK_ANALYSIS_PLAN.md](archive/PSELECT_STACK_ANALYSIS_PLAN.md) | pselect 适配计划；路由已关闭 |

## 其它目录

| 路径 | 用途 |
|------|------|
| [`../stages/`](../stages/) | **主索引**：代码 + 每节点效果 |
| [`../PROCESS_LOG.md`](../PROCESS_LOG.md) | 操作时间线与终局步骤编号 |
| [`../edl/`](../edl/) | EDL **只读**提取 boot/分区流程 |
| [`../raw/`](../raw/) | 设备原始采集 |

---

*整理日期: 2026-07-25 — 原 leaf5 一层杂乱 md 迁入本目录。*
