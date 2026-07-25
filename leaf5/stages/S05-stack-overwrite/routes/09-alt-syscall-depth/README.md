> **路由**: 加深栈 / 自然覆盖 syscall | **状态**: ❌ 关闭

# 09 — writev / sendmsg / splice / pipe

## 目标
GhostLock 后用大缓冲 syscall 自然扫过 waiter 栈槽。

## 代码

| 文件 | 作用 | 效果 | 原因 |
|------|------|------|------|
| `probes/ghostlock64_bruteforce.c` | writev/sendmsg/splice 暴力 | ❌ | 内核存活，无 crash pattern 命中 |
| `probes/test_pipe.c` | pipe 路径 | ❌ | 深度不足 |
| `probes/test_pipe2.c` | pipe 变体 | ❌ | |
| `probes/test_pipe_limit.c` | pipe 限制 | ℹ️ | 信息收集 |

## 结论
常见路径栈深度 **&lt; 0x2B0 需求** → **关闭**。
