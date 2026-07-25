> **阶段**: S04 | **状态**: ✅ 完成 | **最后更新**: 2026-07-25（复测）

# S04 — GhostLock 竞态触发

## 目标
`FUTEX_CMP_REQUEUE_PI` 竞态使 `rt_mutex_waiter` 滞留内核栈（stale waiter），供后续 CFU 覆盖。

## 代码说明（**无本目录独立二进制**）

触发逻辑嵌在 S05 e2e 探针与 exploit 中，而非 `S04-ghostlock-trigger/probes/`。

| 来源 | 作用 | 效果 | 复测 2026-07-25 |
|------|------|------|-----------------|
| `S05/.../d/.../ghostlock32_minimal.c` | 32-bit GL + KGSL | requeue **ret=1** | ✅；issue 仍 EINVAL |
| `S05/.../e/.../ghostlock64_opt.c` | 64-bit GL + CFU | requeue **ret=1** | ✅ |
| `S05/.../e/.../test_cfu_trigger.c` | GL + CFU | requeue **ret=1** | ✅ |
| `S05/.../f/.../ghostlock_e2e.c` | GL + SUBMIT | requeue **ret=1** | ✅ |
| `exploit/src/main.c` | 完整编排 | ✅ | 未本轮单独跑 preload e2e |

## 结果摘要
- GhostLock **可稳定触发**（`FUTEX_CMP_REQUEUE_PI ret=1`，waiter 侧 errno=110 超时）
- **单独触发不崩溃内核**（无有效 task 覆盖时）
- 文档缺口已标明：本 stage 目录无 `.c`，以 S05 e2e 为执行入口

## 下游
→ S05 必须在 stale 窗口内执行 CFU；窗口内额外 syscall 可能污染栈。
