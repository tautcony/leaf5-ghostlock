> **阶段**: S04 | **状态**: ✅ 完成 | **最后更新**: 2026-07-26

# S04 — GhostLock 触发（EDEADLK 边）

## 目标
构造三 futex 死锁 + `FUTEX_CMP_REQUEUE_PI`，走内核 **EDEADLK 回滚**，使 victim `pi_blocked_on` 被误清 → 栈 UAF 前置条件成立。

链中位置见 [`../../README.md`](../../README.md)「整条利用链」；机制与矩阵见 [路由 10](../S05-stack-overwrite/routes/10-ghostlock-true-uaf/)。

## 代码说明（**无本目录独立二进制**）

触发逻辑嵌在 S05 探针与 exploit 中，而非 `S04-ghostlock-trigger/probes/`。

| 来源 | 作用 | 效果 |
|------|------|------|
| `S05/.../10/.../ghostlock_edeadlk_detect.c` | 真触发边 | ✅ `CMP ret=-1 errno=**35**` |
| `exploit/src/main.c` | 完整编排（owner `LOCK_PI` + 死锁图） | ✅ EDEADLK |
| 旧 S05-07 `ghostlock*.c` | requeue **ret=1** | ⚠️ 成功 requeue，**不是** clear-`pi_blocked_on` 边 |

## 结果摘要
- **真 GhostLock 边**：`CMP errno=35 (EDEADLK)` → 回滚路径误清 `pi_blocked_on`（[BIN]）
- **旧观测**：`CMP ret=1` 仅表示 requeue 成功，曾被误当作漏洞触发
- 单独 EDEADLK **不必**立刻 panic；UAF 活性见路由 10 的 0x41+consumer

## 下游
→ S05 路由 10：reclaim 悬空 waiter 槽 → 尝试 PI walk 写；旧「stale 窗口内 CFU 盖 task」模型已关闭。
