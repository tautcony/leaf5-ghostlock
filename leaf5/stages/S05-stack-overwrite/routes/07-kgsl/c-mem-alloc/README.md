> **节点**: GPU 内存分配 | **状态**: ❌ 非通路 / 驱动限制

# c — GPUMEM / GPUOBJ

## 代码

| 文件 | 作用 | 效果 | 原因/备注 |
|------|------|------|-----------|
| `probes/test_gpumem64.c` | GPUMEM_ALLOC 等 | ❌ | **EOPNOTSUPP (95)** |
| `probes/test_gpuobj.c` | GPUOBJ_* | ❌ | EINVAL / ENOTTY |

## 结论
Adreno/RGMU 路径不支持传统 GPUMEM；**CFU 路径不依赖成功 alloc**（ibdesc 可为用户指针）。本节点关闭。
