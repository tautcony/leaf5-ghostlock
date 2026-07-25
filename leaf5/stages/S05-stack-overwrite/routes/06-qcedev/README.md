> **路由**: qcedev_ioctl | **状态**: ❌ 权限关闭

# 06 — qcedev_ioctl

## 目标
`/dev/qce`（非文档早期写的 qcedev 节点名）上 328B CFU，理论与 waiter FULL 重叠。

## 代码
本路由以逆向/文档为主（见 PROCESS_LOG、NEXT_STEPS、global-cfu-scan ANALYSIS）。  
无稳定 shell 可达 PoC（open 即失败）。

| 检查项 | 效果 | 原因 |
|--------|------|------|
| 帧布局 / CFU 偏移逆向 | ✅ | SP+0x50, 328B, 帧 0x360 |
| shell open `/dev/qce` | ❌ | 0660 `system:drmrpc` + SELinux |
| 浏览器 UID 访问 | ❌ | 无 drmrpc 组 |

## 结论
**位置 theoretically 正确，权限不可达 → 关闭**（除非 binder 代理等未实现路径）。
