> **路由**: sendmsg / recvmsg / 相关 socket | **状态**: ❌ 关闭

# 04 — sendmsg / recvmsg 栈覆盖

## 目标
利用 socket 消息路径的栈上缓冲区。

## 代码
| 来源 | 效果 | 原因 |
|------|------|------|
| S01 `compute_stack_routes.py` | ✅ 分析 | Δ 约 -44 / -47 词 |
| S09 `ghostlock64_bruteforce.c`（实测加深） | ❌ | 见 route 09 |

## 结论
分析深度不足；暴力实测亦无覆盖 → **关闭**。
