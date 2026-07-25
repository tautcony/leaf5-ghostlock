> **路由**: pselect / core_sys_select | **状态**: ❌ 关闭

# 01 — pselect fd_set 栈覆盖

## 目标
用 `pselect6`/`select` 栈上 `fd_set` 覆盖 waiter。

## 代码
| 文件 | 效果 | 原因 |
|------|------|------|
| `../../../../S01-offsets-stack/scripts/compute_pselect_shift.py` | ✅ 算出 SHIFT | **SHIFT = -46** |
| `../../../../PSELECT_STACK_ANALYSIS_PLAN.md`（文档） | 计划归档 | 历史 |
| `../../../../STACK_LAYOUT.md` | 布局记录 | waiter 比 fd_set 深 368B |

## 结论
waiter 在 fd_set **下方** 368 字节，正向 bitmap 索引无法触达 → **不可行**。
