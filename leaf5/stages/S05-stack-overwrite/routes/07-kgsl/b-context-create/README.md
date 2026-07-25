> **节点**: GPU context 创建 | **状态**: ✅ | **复测**: 2026-07-25

# b — DRAWCTXT_CREATE

## 代码

| 文件 | 作用 | 效果 | 原因/备注 |
|------|------|------|-----------|
| `probes/test_ctx_flags.c` | 穷举 context flags | ✅ 2026-07-25 | **flags=0x12**（PREAMBLE\|NO_GMEM_ALLOC）→ `ctx_id=7`；0x10/0x02 单独 → EINVAL。探针已显式包含 0x12 |
| 其它探针内嵌 CREATE | 复用 0x12 | ✅ | 成为标准前置步骤 |

## 结果
- 错误 flags → EINVAL  
- `0x12` → 返回有效 `ctx_id`（如 7）  
- 32-bit 与 64-bit 均可创建

## 下游
所有 RB_ISSUEIBCMDS / SUBMIT 测试依赖本节点。
