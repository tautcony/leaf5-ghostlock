# 设备矩阵：WRITE_ORACLE=uts + multi-consumer（2026-07-26）

runtime: `#245` match · spray `fake_lock` · SHIFT=+15 · logs: `run_logs_2026-07-26/`

## 工程修复（同批）

| 项 | 说明 |
|----|------|
| `open_selected_fds` | **不再 dup2 到 fd 0/1/2**（painted 位图会弄死 stdout/adb） |
| `PSELECT_ROUTE_ATTEMPTS` | env 可调 1–16 |
| `WRITE_ORACLE` / `PI_CONSUMER` | exploit 已集成 |

修 stdio 前 shape0 常在 pselect 前「假死」；修后 shape0/1/2 **完整存活**。

## UTS oracle（目标 `data_addr(init_uts_ns)+4`，value=`GLORACLE` LE）

| 变体 | EDEADLK | pselect | consumer success | **uname hit** | panic |
|------|---------|---------|------------------|---------------|-------|
| LOCK_SHAPE=0 + sched_setattr | ✅ | ✅ | ✅ | **0** | no |
| LOCK_SHAPE=1 + sched_setattr | ✅ | ✅ | ✅ | **0** | no |
| LOCK_SHAPE=2 + sched_setattr | ✅ | ✅ | ✅ | **0** | no |
| shape0 + setpriority | ✅ | ✅ | ✅ | **0** | no |
| shape0 + nice | ✅ | ✅ | ✅ | **0** | no |
| shape0 + sched_setscheduler | ✅ | ✅ | ✅ | **0** | no |
| shape0 + futex_lock_pi | ✅ | ✅ | ✅ | **0** | no |
| shape0 + PI_CONSUMER=**all** | ✅ | partial | — | — | **yes** |
| PSELECT_SIMPLE_LAYOUT=1 shape0 | ✅ | ✅ | ✅ | **0** | no |
| USE_FAKE_TASK=1 + shape0 | ✅ | ✅ | ✅ | **0**（ex1=spray fake_task） | no |

**结论**: 在 spray + 既有 rb craft 下，**没有**对 `init_uts_ns.name.sysname` 的可观测 8B store。  
`sched_setattr/setpriority/… success=1` 仍 **≠** 目标写（与终局 B 对 fops 一致）。  
`USE_FAKE_TASK=1` 可存活且 residual.task 指向 spray，仍无 uname 变化。

## 对照 fops（stdio 修复后）

| 项 | 结果 |
|----|------|
| EDEADLK | ✅ |
| CFI pwrite | **errno=22**（与 §53 一致） |
| root | 0 |

## 不重跑

- 同构 UTS LOCK_SHAPE×sched 矩阵（已闭合）
- 无新 [BIN] 的 SHIFT 二分
- `PI_CONSUMER=all`（同窗多 consumer → panic，无信息增益）

## 仍开放（需新理论）

1. chain 内 **实际 str 目标表达式** 与 residual 字段重新对应（success 路径可能 early-out 未 erase）  
2. residual.`task` = spray `fake_task` 的最小存活 + 可观测副作用  
3. perf 侧信道增强泄漏（BPF 已 ❌）  
