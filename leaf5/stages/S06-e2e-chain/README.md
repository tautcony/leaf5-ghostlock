> **阶段**: S06 | **状态**: ⚠️ 到 EDEADLK + reclaim；无 fops | **最后更新**: 2026-07-26

# S06 — 端到端集成链

## 目标
串联 S02–S05：泄漏 → spray → **EDEADLK 真 UAF** → shaped reclaim →（期望）fops → physrw → root。

链总览见 [`../../README.md`](../../README.md)「整条利用链」；写矩阵终局见 [路由 10](../S05-stack-overwrite/routes/10-ghostlock-true-uaf/)。

## 代码映射

| 组件 | 路径 | 效果 |
|------|------|------|
| 生产 exploit | `../../../../exploit/`（`main.c` + modules） | ⚠️ EDEADLK + pselect reclaim + sched；**无** fops / root |
| 路由 10 探针 | S05/.../10-ghostlock-true-uaf/probes | ✅ EDEADLK；✅ UAF panic 对照 |
| 旧 CFU e2e | S05-07 kgsl `ghostlock*.c` | ❌ 布局/覆盖 task 关闭（旧模型） |

## 端到端结果表

| 步骤 | 状态 | 效果 |
|------|------|------|
| Kernelsnitch | ✅ | mm 泄漏 |
| Heap spray | ✅ | sk_buff 占位 |
| GhostLock EDEADLK | ✅ | `CMP errno=35`；`pi_blocked_on` 悬空 |
| shaped pselect reclaim | ✅ | 栈槽可塑形 |
| `sched_setattr` | ⚠️ success=1 | **≠** fops store |
| 写 `ashmem_misc.fops` | ❌ | CFI oracle errno=22（终局 B） |
| pipe physrw / root | ❌ | 依赖写原语 |

## 完成度
前半链与 UAF 原语已集成；**阻塞点唯一**：S05 受控写（Outcome B），非「还差一次 CFU 偏移」。
