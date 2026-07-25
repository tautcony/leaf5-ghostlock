> **节点**: personality(PER_LINUX32) | **状态**: ❌ 关闭

# g — 64-bit 进程模拟 32-bit

## 代码

| 文件 | 作用 | 效果 | 原因 |
|------|------|------|------|
| `probes/test_personality.c` | 设 PER_LINUX32 后 ioctl | ❌ | 仅改 `current->personality`，**不设 TIF_32BIT** |

## 结论
compat 分派不触发 → **Path A 关闭**。TIF_32BIT 仅 32-bit ELF exec 设置。
