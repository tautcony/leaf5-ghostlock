> **文档类型**: 结论文档 | **状态**: ✅ 有效 | **最后更新**: 2026-07-24


> ⚠️ **文档导航更新 (2026-07-25)**：代码与节点效果已按利用顺序归档至 [`stages/README.md`](stages/README.md)。本文保留历史分析细节；可行性终局以 stages 各节点 README 与 [`PROCESS_LOG.md`](PROCESS_LOG.md) 为准。
# Leaf5 Stack Layout — GhostLock 栈帧分析

基于 2026-07-24 capstone 反汇编 `vmlinux.elf`。

## 调用链

```
__arm64_sys_futex → do_futex → futex_wait → futex_wait_setup
                                    ↓
                         rt_mutex_slowlock → task_blocks_on_rt_mutex
```

## 各函数栈帧

### do_futex (0x220 = 544 bytes)

```asm
stp  x29, x30, [sp, #-0x60]!   ; save fp/lr, alloc 0x60
stp  x28, x27, [sp, #0x10]     ; callee-saved at +0x10..+0x58
mov  x29, sp                    ; fp = sp
...
sub  sp, sp, #0x1c0             ; LOCAL alloc 0x1c0 more
```

栈布局（从高地址到低地址）:
```
+0x50: x20, x19
+0x40: x22, x21
+0x30: x24, x23
+0x20: x26, x25
+0x10: x28, x27
+0x00: x29(sp), x30(lr)
------- 0x60 byte boundary --------
+0x68: local vars (w5, w2)
+0x70: x0 (saved uaddr)
+0x7c: w6 (saved val3)
+0x80: xzr (futex_q placeholder?)
+0x88: xzr, xzr (more init)
... up to +0x1c0 of locals
```

### futex_wait (0x140 = 320 bytes)

```asm
sub  sp, sp, #0x140            ; alloc 0x140
stp  x29, x30, [sp, #0xe0]     ; fp/lr at +0xe0
add  x29, sp, #0xe0            ; fp = sp + 0xe0
stp  x28, x27, [sp, #0xf0]     ; callee-saved at +0xf0..+0x138
...
sub  x0, x29, #0x60            ; x0 = fp - 0x60 = sp + 0x80
                                ; THIS IS &futex_q (contains waiter)
sub  x24, x29, #0x60           ; saved in x24
bl   plist_init                ; init plist in futex_q
bl   futex_q_init              ; init rest of futex_q
```

**关键发现**：`futex_q（含 rt_mutex_waiter）位于 sp + 0x80**

栈布局：
```
+0x138: x20, x19
+0x130: x22, x21
+0x120: x24, x23
+0x110: x26, x25
+0x100: x28, x27
+0xf0:  fp(sp+0xe0), lr
+0xe0:  (fp/lr saved)
...
+0x80:  futex_q.begin → rt_mutex_waiter.tree_entry (24B)
+0x98:  rt_mutex_waiter.pi_tree_entry (24B)
+0xb0:  rt_mutex_waiter.task (8B)       ← task_blocks_on_rt_mutex 写入 current
+0xb8:  rt_mutex_waiter.lock (8B)
+0xc0:  futex_q 其他字段
...
+0x70:  w4 (saved bitset?)
+0x58:  local copies (from futex key?)
+0x48:  
+0x38:  
+0x28:  
+0x18:  
+0x08:  
+0x00:  sp (bottom of frame)
```

### task_blocks_on_rt_mutex (0x50 = 80 bytes)

```asm
stp  x29, x30, [sp, #-0x50]!   ; compact frame, no extra locals
```

此函数不分配额外局部变量，仅有被调用者保存的寄存器。

## GhostLock 关联分析

### waiter 栈内位置

- `rt_mutex_waiter` 在 `futex_wait` 栈帧中的 **sp+0x80** 处
- waiter 总大小：**0x40**（vs 5.10 的 0x50）
- `waiter->task` 在 **sp+0xb0**（task_blocks_on_rt_mutex 写入）
- `waiter->tree_entry` 在 **sp+0x80**
- `waiter->pi_tree_entry` 在 **sp+0x98**

### 栈覆盖考量

与 OPPO Find N2 (5.10) 对比：

| 参数 | Leaf5 (4.19) | OPPO (5.10) |
|------|-------------|-------------|
| waiter 大小 | 0x40 | 0x50 |
| futex_wait 栈帧 | 0x140 | 更大（CFI 相关帧） |
| waiter 位置 | sp+0x80 | 待定 |
| KPTI | 关 | 开 |
| 内核 CFI | 关 | 强 CFI |

Leaf5 的 **KPTI 关闭** 和 **无内核 CFI** 意味着：
1. 无 trampoline 栈切换 → 栈帧更简单
2. fops 覆写等攻击向量**可能**可行（在 OPPO 上因 CFI 阻塞）
3. 但具体栈覆盖策略仍需动态测试验证

### FUTEX_WAIT_REQUEUE_PI 特殊说明

4.19 的 `do_futex` 处理 `FUTEX_WAIT_REQUEUE_PI` op 时：
1. 调用 `futex_wait` 创建 waiter
2. waiter 在 `futex_wait` 返回前被清理
3. requeue 操作在 `futex_requeue` 中处理（非独立函数）

**与 5.10+ 的关键差异**：4.19 没有 `futex_wait_requeue_pi` 函数，这意味着 exploit 中对函数符号的引用和栈偏移假设必须调整。

## 下一步（动态验证）

1. **NDK 编译最小探针**：`adb push` 到 `/data/local/tmp`
   - 调用 `FUTEX_WAIT_REQUEUE_PI` / `FUTEX_CMP_REQUEUE_PI`
   - 记录返回值和 errno
2. **KernelSnitch 适配**：futex hash bucket 参数是否与 4.19 匹配
3. **栈帧精确确认**：如果有可控 oops/panic 或 perf event，打印 `sp` 值确认 waiter 相对位置
4. **pselect/fd_set 栈覆盖评估**：因 4.19 栈帧更紧凑，120B 间隙假设需重新计算

## 验证

| 项目 | 状态 | 方法 |
|------|------|------|
| waiter sizeof=0x40 | ✅ | capstone 反汇编 + 源码 |
| futex_q @ sp+0x80 | ✅ | capstone 追踪 |
| 无 KPTI 影响 | ✅ | CONFIG_UNMAP_KERNEL_AT_EL0=n |
| 无内核 CFI | ✅ | CONFIG_CFI_CLANG=n, CONFIG_LTO_NONE=y |
| 精确栈溢出偏移 | ❌ | 需动态测试 |
| fd_set 间隙 | ❌ | 需计算 4.19 pselect 帧 |
