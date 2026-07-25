> **路由**: 非 KGSL 设备节点 | **状态**: ❌ 关闭

# 08 — DRM / fcntl·uinput 等

## 代码

| 文件 | 作用 | 效果 | 原因 |
|------|------|------|------|
| `probes/test_drm.c` | open card0/renderD128 | ❌ | SELinux **EACCES**（即使 0666） |
| `probes/test_fcntl.c` | fcntl/相关 fd 路径 | ❌/无关 | 未形成有效 CFU 重叠 |

## 其它（无独立探针，设备探测）
| 设备 | 效果 | 原因 |
|------|------|------|
| `/dev/uinput` | open ✅，覆盖 ❌ | CFU 比 waiter 浅 ~352B |
| `/dev/qce` | open ❌ | 见 route 06 |

## 结论
备选设备均不可用。
