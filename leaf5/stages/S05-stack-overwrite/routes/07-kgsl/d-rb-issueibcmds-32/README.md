> **节点**: 32-bit RB_ISSUEIBCMDS (NR=0x10) | **状态**: ❌ 关闭

# d — 32-bit RB_ISSUEIBCMDS

早期理论：16B CFU @ 深栈与 `waiter->task` 重叠。  
**实测：compat dispatch 在 wrapper 前返回 EINVAL，CFU 从未执行。**

## 代码

| 文件 | 作用 | 效果 | 原因 |
|------|------|------|------|
| `probes/test_compat_offsets.c` | 字段偏移扫描 | ❌ 全 EINVAL | 未进 handler |
| `probes/test_compat_exhaustive.c` | 方向×大小穷举 | ❌ | 同上 |
| `probes/test_compat_crash.c` | crash pattern 布局 | ❌ | 内核存活 |
| `probes/test_cmd_variants.c` | cmd 方向/大小变体 | ❌ | 全 EINVAL |
| `probes/test_swap_fix.c` | 字段交换修复 | ❌ | 无效 |
| `probes/test_swap_workaround.c` | swap workaround | ❌ | 仍 EINVAL |
| `probes/test_efault_probe.c` | 坏指针区分路径 | ✅ 关键证据 | 全 EINVAL 而非 EFAULT → **未到 native** |
| `probes/test_offset_scan.c` | 偏移扫描 | ❌ | |
| `probes/ghostlock32_minimal.c` | 最小 GL+KGSL | ⚠️ GL✅ 提交❌ | requeue 成功，issue 失败 |
| `probes/ghostlock32_final.c` | 完整 32-bit 链 | ❌ | 无覆盖 |
| `probes/kgsl_ghostlock_poc.c` | 早期 PoC | ❌ | 同上 |

## 结论
**路径关闭**。对比：同进程 SUBMIT_COMMANDS (NR=0x3d) 可成功（见 f）。
