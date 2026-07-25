> **阶段**: S01 | **状态**: ✅ 完成 | **最后更新**: 2026-07-25

# S01 — 偏移提取与栈布局

## 目标
从 vmlinux 反汇编得到 `rt_mutex_waiter` / `task_struct` / pipe 等偏移，并计算 GhostLock waiter 与各 CFU 的绝对栈位置。

## 代码

| 文件 | 作用 | 效果 | 原因/备注 |
|------|------|------|-----------|
| `scripts/extract_offsets.py` | capstone 提取关键偏移 | ✅ | 写入/核对 target.h 级偏移 |
| `scripts/extract_mm_struct_params.py` | mm_struct 相关参数 | ✅ | Kernelsnitch 用 |
| `scripts/compute_pselect_shift.py` | PSELECT_WAITER_WORD_SHIFT | ✅ | **结果 = -46** |
| `scripts/compute_stack_routes.py` | 多路由栈深度比较 | ✅ | 输出候选比较表 |
| `scripts/find_waiter_overlap.py` | waiter 与 CFU 重叠搜索 | ✅ | 早期扫描 |
| `scripts/find_waiter_overlap2.py` | 重叠搜索 v2 | ✅ | 改进启发式 |
| `scripts/search_params.py` | 参数搜索辅助 | ✅ | |

## 终局关键数字（Leaf5 4.19.157）
```
waiter->task @ KSP0 - 0x2B0
  do_futex 0x220 + futex_wait 0x140 + futex_q@+0x80 + task@+0x30
PSELECT_WAITER_WORD_SHIFT = -46
rt_mutex_waiter sizeof = 0x40（无 prio/deadline）
```

## 下游
→ S02 使用偏移；S05 各路由用栈布局判重叠。

## 文档交叉
- [`../../docs/STACK_LAYOUT.md`](../../docs/STACK_LAYOUT.md)
- [`../../docs/VERIFICATION_REPORT.md`](../../docs/VERIFICATION_REPORT.md)
