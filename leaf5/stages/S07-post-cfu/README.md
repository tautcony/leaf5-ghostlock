> **阶段**: S07 | **状态**: ⛔ 未达成（依赖 S05） | **最后更新**: 2026-07-25

# S07 — CFU 之后：fops / physrw / root

## 目标
在 task 指针被劫持后：伪造 task → 覆写 ashmem/configfs fops → pipe 物理读写 → SELinux/cred → root。

## 代码（已实现但未在设备上生效）

| 文件 | 作用 | 设备效果 | 原因 |
|------|------|----------|------|
| `../../../../exploit/src/fops.c` | fops 覆写逻辑 | ❌ 未触发 | task 未改 |
| `../../../../exploit/src/pipe.c` | pipe physrw | ❌ | 依赖 fops |
| `../../../../exploit/src/root.c` | cred/SELinux | ❌ | 依赖 physrw |
| `../../../../exploit/src/preload.c` | LD_PRELOAD 入口 | ℹ️ | 部署方式 |

## 结论
代码存在且可编译；**在 Leaf5 上因 S05 失败而无有效运行结果**。  
勿将「源码存在」理解为「提权成功」。
