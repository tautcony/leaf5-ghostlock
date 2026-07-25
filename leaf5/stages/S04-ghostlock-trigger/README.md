> **阶段**: S04 | **状态**: ✅ 完成 | **最后更新**: 2026-07-25

# S04 — GhostLock 竞态触发

## 目标
`FUTEX_CMP_REQUEUE_PI` 竞态使 `rt_mutex_waiter` 滞留内核栈（stale waiter），供后续 CFU 覆盖。

## 代码说明
独立最小用例多嵌在 S05/S06 的 e2e 探针中（同一文件内 futex 线程 + 覆盖尝试）。  
生产路径：`exploit/src/main.c` 中的 GhostLock 编排。

| 来源 | 作用 | 效果 | 原因/备注 |
|------|------|------|-----------|
| 各 `ghostlock*.c` 中 waiter 线程 | 触发 WAIT_REQUEUE_PI + requeue | ✅ | `CMP_REQUEUE_PI ret=1` 稳定 |
| `exploit/src/main.c` | 完整触发编排 | ✅ | 32/64 均可触发 |
| FUTEX_LOCK_PI 触发链 | PI chain walk | ✅ 可调用 | 无覆盖时内核存活、无效应 |

## 结果摘要
- GhostLock **100% 可触发**
- 成功判据：requeue 返回成功 + waiter 侧超时/返回后仍可继续 ioctl
- **单独本阶段不崩溃内核**（无有效 task 覆盖时）

## 下游
→ S05 必须在 stale 窗口内执行 CFU；窗口内额外 syscall 可能污染栈。
