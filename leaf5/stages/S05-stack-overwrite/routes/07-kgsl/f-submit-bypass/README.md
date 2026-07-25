> **节点**: SUBMIT_COMMANDS / compat 绕过 | **状态**: ⚠️ 可达，位置更差

# f — SUBMIT_COMMANDS 与 native bypass

## 代码

| 文件 | 作用 | 效果 | 原因 |
|------|------|------|------|
| `probes/test_native_bypass.c` | 32-bit 发 native 结构 | ⚠️ | 探索 fallback |
| `probes/test_bypass_compat.c` | compat 绕过尝试 | ⚠️ | |
| `probes/test_bypass2.c` | native SUBMIT 结构 | ⚠️ | 可达 handler |
| `probes/test_bypass3.c` | 修 EFAULT + GL | ⚠️ | 无 task 覆盖 |
| `probes/test_verify_cfu.c` | 验证 CFU 行为 | ⚠️ | |
| `probes/ghostlock_e2e.c` | GL + compat SUBMIT | ⚠️ | CFU 偏浅 ~120B |
| `probes/ghostlock_final.c` | 最终 bypass 策略 | ⚠️ | 内核存活 |

## 结论
NR=0x3d 在 32-bit **成功**，但 CFU 绝对位置比 RB_ISSUEIBCMDS 更不重叠 → **关闭为有效覆盖路径**。
