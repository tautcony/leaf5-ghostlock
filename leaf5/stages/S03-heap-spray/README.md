> **阶段**: S03 | **状态**: ✅ 完成（历史集成） / ⚠️ 无 stage 本地 spray 探针 | **最后更新**: 2026-07-25

# S03 — 堆喷射（sk_buff reclaim）

## 目标
在可控位置喷射/回收 sk_buff，为后续 fops 覆写与 physrw 铺路（标准链后半段）。

## 代码

| 文件 | 作用 | 效果 | 备注 |
|------|------|------|------|
| `analysis/ANALYSIS.md` | 喷射可行性分析 | ✅ 分析 | |
| `analysis/check_ion_primitive.sh` | ION 接口探测 | ⚠️ 2026-07-25 | `/dev/ion` 存在 (0664 system)，**shell open → Permission denied**；非主路径 |
| `../../../exploit/src/heap_spray.c` | 生产用 spray | ✅ 历史 | VERIFICATION_REPORT：**4/4 send ret=65536** |
| stages 本地 `probes/*.c` | — | **无** | **缺口**：无独立 sk_buff 复现探针 |

## 结果摘要
- 主路径 sk_buff reclaim 结论来自 **exploit 集成与历史报告**，本次复测**未**单独重跑 4/4 spray
- ION 辅助路径对 shell **不可 open**，与「非主路径」一致
- 本阶段不依赖栈覆盖即可独立验证；完整复测需在 exploit 路径加 env/日志开关，或补 stage 探针

## 下游
→ S04 GhostLock；真正消费 spray 在 S07（需先 fops 覆写）。
