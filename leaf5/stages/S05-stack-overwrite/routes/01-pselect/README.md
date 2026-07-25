> **路由**: pselect / core_sys_select | **状态**: ⚠️ 几何 CORRECTED（见路由 10）

# 01 — pselect fd_set 栈覆盖

## 目标
用 `pselect6`/`select` 栈上 `fd_set` 覆盖 waiter。

## 代码
| 文件 | 效果 | 原因 |
|------|------|------|
| `../../../../S01-offsets-stack/scripts/compute_pselect_shift.py` | ⚠ 旧模型 | **SHIFT = -46**（futex_wait 深度，对 GhostLock **作废**） |
| `../10-ghostlock-true-uaf/analysis/recompute_pselect_shift_corrected.py` | ✅ CORRECTED | **SHIFT = +15**；task@−0x168 / waiter_base@−0x198 |
| `../../../../docs/STACK_LAYOUT.md` | 历史 | 旧 −0x2B0 叙事 |

## 结论
- **旧** ❌：SHIFT=−46 因用错 waiter 深度（futex_wait），字段全部 OOR。
- **CORRECTED 几何** ✅：8/8 waiter 字段落入 fd_set（NFDS=640）；`target.h` `PSELECT_WAITER_WORD_SHIFT=15`。
- **利用**仍依赖路由 10 的 EDEADLK priming + 返回后 reclaim（非阻塞 live 写栈）。
