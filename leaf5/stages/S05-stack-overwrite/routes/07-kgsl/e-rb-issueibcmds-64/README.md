> **节点**: 64-bit RB_ISSUEIBCMDS | **状态**: ⚠️ CFU 触发但未覆盖 task

# e — 64-bit RB_ISSUEIBCMDS

## 代码

| 文件 | 作用 | 效果 | 原因 |
|------|------|------|------|
| `probes/test_64bit.c` | 64-bit 基线 ioctl | ✅ issue 成功 | compat cmd `0xc0140910` 走 fallback |
| `probes/test_submit64.c` | submit 调试 | ✅/⚠️ | |
| `probes/test_ib_flags.c` | ib/flags 组合 | ✅ | |
| `probes/test_submit_debug.c` | 提交调试 | ✅ | |
| `probes/test_cfu_trigger.c` | GhostLock 后立即 CFU | ⚠️ CFU✅ 无 crash | 位差 |
| `probes/ghostlock64.c` | e2e v1 | ⚠️ | 内核存活 |
| `probes/ghostlock64_v2.c` | e2e v2 | ⚠️ | 同上 |
| `probes/ghostlock64_opt.c` | 预创建资源减栈干扰 | ⚠️ CFU 稳定 | 仍无重叠 |
| `probes/ghostlock64_scan.c` | 多命令深度扫描 | ⚠️ | 无一 crash |

## 结果摘要
- CFU **100% 可触发**（ret=0）  
- 10+ 次循环 + FUTEX_LOCK_PI：**无 fops 覆盖、无 OOPS**  
- 位差固定约 **88B**（CFU 太浅）

## 结论
**可观测 CFU，不可用覆盖** → 作为主路径失败关闭（除非加深栈，见 route 09）。
