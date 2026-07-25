> **阶段**: S02 | **状态**: ✅ 完成 | **最后更新**: 2026-07-25

# S02 — Kernelsnitch 内核地址泄漏

## 目标
通过 futex 哈希碰撞时序侧信道泄漏 `mm_struct`，并推算 direct-map / KASLR。

## 代码

| 文件 | 架构 | 作用 | 效果 | 原因/备注 |
|------|------|------|------|-----------|
| `probes/test_kernelsnitch_minimal.c` | 视编译 | 最小 Kernelsnitch 复现 | ✅ 成功 | 设备上可靠泄漏 |
| `probes/test_ks_minimal.c` | 视编译 | 精简碰撞探测 | ✅ 成功 | pile-up 时序有效 |

## 集成代码（仓库根 exploit/）
| 文件 | 效果 |
|------|------|
| `exploit/src/kernelsnitch/*` | ✅ 头文件实现 |
| `exploit/src/slide.c` | ✅ direct-map 计算，无需 slide 爆破 |

## 结果摘要
- `KSNITCH_COLLISIONS=2` 时 **&lt;1 秒** 可靠泄漏
- 无 KPTI → 侧信道更干净

## 下游
→ S03 heap spray 使用泄漏的内核地址定向 reclaim。
