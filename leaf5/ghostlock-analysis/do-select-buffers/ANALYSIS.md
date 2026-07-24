> **文档类型**: 结论文档 | **状态**: ✅ 有效 — 确定结论：do_select 不可用于 waiter 栈覆盖 | **最后更新**: 2026-07-24

# do_select Buffer Analysis — GhostLock 分析

**日期**: 2026-07-24
**状态**: 分析完成 — 无重叠

---

## 一、核心发现

**do_select 中无任何栈变量或 copy_from_user 目标与 waiter 重叠。**

### 修正后的帧大小

原计划估算 do_select 帧为 0x310。实际测量:

```
do_select 帧序言:
  [0] stp x29, x30, [sp, #-0x60]!     # SP -= 0x60 (预索引)
  [1-6] stp x28,x27..x20,x19           # 保存 callee-saved 寄存器
  [7] sub sp, sp, #0x310               # 局部变量 (0x310B)
总计: 0x60 + 0x310 = 0x370 (880B)
```

### 深度链

| 函数 | 帧大小 | 累计深度 | SP 绝对位置 |
|------|--------|---------|------------|
| `__arm64_sys_pselect6` | 0xa0 (160B) | 0xa0 | -0xa0 |
| `core_sys_select` | 0x1c0 (448B) | 0x260 | -0x260 |
| `do_select` | **0x370 (880B)** | **0x5d0 (1488B)** | **-0x5d0** |

原计划估算累计深度 -0x570 差了 0x60 (96 字节)。

### Waiter 位置

```
waiter 绝对位置:          -0x380 (-896)
do_select SP 绝对位置:     -0x5d0 (-1488)
waiter 相对 do_select SP:  SP + 0x250 .. SP + 0x290  (字节 592-656)
```

原计划估算 waiter 在 SP+0x1f0，实际在 SP+0x250。差了 0x60 (do_select 帧比预期大 0x60)。

## 二、栈布局分析

do_select 帧内共 **29 个唯一 SP 相对偏移**，全部分布在 **SP+0x000 .. SP+0x0f8**。

```
SP+0x000 .. SP+0x0d0: 局部变量 / 临时值
SP+0x0d0 .. SP+0x0f8: poll_wqueues 结构体 (_qproc, _key, table, ...)
SP+0x0f8 .. SP+0x250: ← 344 字节完全未使用的栈空间
SP+0x250 .. SP+0x290: ← WAITER 位置 (waiter 在此!)
SP+0x290 .. SP+0x370: 保存的寄存器 (x19-x28, fp, lr)
```

**关键: SP+0x0f8 到 SP+0x250 之间有 344 字节 (0x158) 的间隙，完全无栈访问。waiter 恰好落在这片未使用区域之后。**

## 三、copy_from_user 检查

**do_select 不包含任何 `__arch_copy_from_user` 调用。** 所有 copy_from_user 发生在 `core_sys_select` 中:

- **栈路径** (nfds ≤ 320): `core_sys_select SP+0x50` (绝对 -0x210, waiter 上方 0x170 字节)
- **堆路径** (nfds > 320): kmalloc 分配, 不在栈上

两条路径均无法到达 waiter。

## 四、poll_wqueues 结构体

do_select 在 **SP+0xd0** 构建自己的 poll_wqueues:

```
SP+0xd0: _qproc 函数指针 (内核数据段地址, 非用户可控)
SP+0xe0: _key 字段 (被清零)
结构体数据结束于 ~SP+0x100
```

waiter 在 SP+0x250, poll_wqueues 数据最远到 SP+0x100。**即使用满 inline_entries 也无法延伸 0x150 字节到 waiter 位置。**

## 五、原计划错误修正

| 参数 | 原计划值 | 实际值 | 差异 |
|------|---------|--------|------|
| do_select 帧大小 | 0x310 | **0x370** | +0x60 |
| 累计深度 | 0x570 | **0x5d0** | +0x60 |
| waiter 相对 do_select | SP+0x1f0 | **SP+0x250** | +0x60 |
| 帧内最大访问偏移 | — | **SP+0x0f8** | — |
| 到 waiter 的间隙 | — | **344B (0x158)** | — |

## 六、结论

**do_select 不可用于 GhostLock waiter 栈覆盖。**
- Waiter 落在帧内大段未使用空间之后 (344B 间隙)
- 无 copy_from_user 调用
- 最远的用户可控数据 (poll_wqueues) 距 waiter 0x150 字节

## 七、验证脚本

- `analyze_do_select.py` (736行) — 完整帧分析器, 34 个 SP 偏移枚举
- `deep_trace.py` (446行) — core_sys_select 参数追踪和 poll_wqueues 位置分析
- `analysis_results.json` — 机器可读结果

运行:
```bash
uv run python ghostlock-analysis/do-select-buffers/analyze_do_select.py -v
```
