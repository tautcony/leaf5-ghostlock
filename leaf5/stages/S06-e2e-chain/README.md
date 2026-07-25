> **阶段**: S06 | **状态**: ⚠️ 到 CFU 为止成功 | **最后更新**: 2026-07-25

# S06 — 端到端集成链

## 目标
串联 S02–S05：泄漏 → spray → GhostLock → KGSL CFU →（期望）fops → physrw → root。

## 代码映射

| 组件 | 路径 | 效果 |
|------|------|------|
| 生产 exploit | `../../../../exploit/`（`main.c` + modules） | ⚠️ 到 CFU；root=0 |
| 32-bit e2e 探针 | S05/.../d 与 f 下 `ghostlock32_*` / `ghostlock_final.c` | ⚠️ |
| 64-bit e2e 探针 | S05/.../e 下 `ghostlock64*.c` | ⚠️ 10 次循环一致失败覆盖 |

## 端到端结果表

| 步骤 | 状态 |
|------|------|
| Kernelsnitch | ✅ |
| Heap spray | ✅ |
| GhostLock | ✅ |
| KGSL context | ✅ |
| CFU 触发 | ✅ |
| 覆盖 waiter->task | ❌ |
| fops / configfs | ❌ |
| pipe physrw | ❌ |
| root | ❌ |

## 完成度
**~70%**。阻塞点唯一且确定：S05 栈布局。
