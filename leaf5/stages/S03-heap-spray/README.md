> **阶段**: S03 | **状态**: ✅ 完成 | **最后更新**: 2026-07-25

# S03 — 堆喷射（sk_buff reclaim）

## 目标
在可控位置喷射/回收 sk_buff，为后续 fops 覆写与 physrw 铺路（标准链后半段）。

## 代码

| 文件 | 作用 | 效果 | 原因/备注 |
|------|------|------|-----------|
| `analysis/ANALYSIS.md` | 喷射可行性分析 | ✅ 分析完成 | 含 ION 等原始讨论 |
| `analysis/check_ion_primitive.sh` | ION 接口探测 | ⚠️ 设备相关 | 辅助，非主路径 |
| `../../../exploit/src/heap_spray.c` | 生产用 spray | ✅ | 4/4 send ret=65536 |

## 结果摘要
- sk_buff reclaim **4/4 成功**
- 本阶段**不依赖**栈覆盖成功即可独立验证

## 下游
→ S04 GhostLock；真正消费 spray 在 S07（需先 fops 覆写）。
