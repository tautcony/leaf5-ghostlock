# Leaf5 constants quick ref

Source of truth: `exploit/targets/onyx-leaf5/target.h`.
This file is a **read-only cheat sheet** for the skill; if conflict, trust target.h + stages.

## Identity

- Kernel: 4.19.157-perf-g3d47a6619220-dirty **#245**
- Device: Onyx Leaf5 (TabBoox), aarch64

## Critical

| Item | Value |
|------|-------|
| rt_mutex_waiter | 0x40 |
| waiter->task | KSP0 - 0x2B0 |
| real_cred / cred | 0x7d8 / 0x7e0 |
| pi_blocked_on | 0x8d0 |
| pipe head/tail | 0x38 / 0x3c |
| mm->owner | 0x328 |
| MM_STRUCT_SZ / MM_ORDER | 0x388 / 3 |
| futex_key | V1 |
| pselect SHIFT | -46 |

## Endgame (standard CFU cover)

```
前半链 ✅
CFU 覆盖 waiter->task ❌ 栈布局位差
64-bit CFU often ~KSP0-0x228 (too shallow ~88B)
```
