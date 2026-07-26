> **阶段**: S07 | **状态**: ⛔ 未达成（依赖 S05 写原语） | **最后更新**: 2026-07-26

# S07 — 写原语之后：fops / physrw / root

## 目标
在取得对关键内核对象的**受控写**之后：覆写 ashmem/configfs fops → pipe 物理读写 → SELinux/cred → root。

当前设计假设的写入口是：EDEADLK UAF + shaped reclaim + PI walk 擦写 `ashmem_misc.fops`（见路由 10）。  
该写入口在 shell 路径上 **终局 B 关闭** → 本阶段设备侧无有效运行。

链总览：[`../../README.md`](../../README.md)「整条利用链」。

## 代码（已实现但未在设备上生效）

| 文件 | 作用 | 设备效果 | 原因 |
|------|------|----------|------|
| `../../../../exploit/src/fops.c` | fops 覆写 / CFI oracle | ❌ 未触发成功写 | 无 fops 劫持（CFI 22） |
| `../../../../exploit/src/pipe.c` | pipe physrw | ❌ | 依赖 fops |
| `../../../../exploit/src/root.c` | cred/SELinux | ❌ | 依赖 physrw |
| `../../../../exploit/src/preload.c` | LD_PRELOAD 入口 | ℹ️ | 部署方式 |

## 结论
代码存在且可编译；**在 Leaf5 上因 S05 受控写未达成而无有效运行结果**。  
勿将「源码存在」理解为「提权成功」。
