> **文档类型**: 结论文档 | **状态**: ✅ 有效 — 确定结论：binder 路由不可用于栈覆盖 | **最后更新**: 2026-07-24

# Binder Commands Deep Dive — GhostLock 分析

**日期**: 2026-07-24
**状态**: 分析完成 — 无直接用户数据重叠

---

## 一、核心发现

**binder_thread_write 有完美的栈对齐 (Δ=0)**，但重叠区域内无用户可控数据。

```
binder_thread_write SP = -0x3a0 (总深度 0x3a0)
Waiter 位置: SP+0x20 到 SP+0x60 (绝对 -0x380 到 -0x340)

SP+0x20..SP+0x58 的局部结构体恰好覆盖 waiter 字节 0x00..0x38:
  SP+0x20 → waiter+0x00: tree_entry.__rb_parent_color
  SP+0x28 → waiter+0x08: tree_entry.rb_right
  SP+0x30 → waiter+0x10: tree_entry.rb_left
  SP+0x38 → waiter+0x18: pi_tree_entry.__rb_parent_color
  SP+0x40 → waiter+0x20: pi_tree_entry.rb_right
  SP+0x48 → waiter+0x28: pi_tree_entry.rb_left
  SP+0x50 → waiter+0x30: task ← 存储 binder_thread+0x48
  SP+0x58 → waiter+0x38: lock ← 存储 binder_proc+0x228
```

## 二、存储值分析

| SP偏移 | 存储的值 | 来源 |
|--------|---------|------|
| SP+0x20 | x0+0x30 | binder_proc + 0x30 |
| SP+0x28 | x1+0x60 | binder_thread + 0x60 |
| SP+0x30 | x0+0x90 | binder_proc + 0x90 |
| SP+0x38 | x1+0x20 | binder_thread + 0x20 |
| SP+0x40 | x1+0x30 | binder_thread + 0x30 |
| SP+0x48 | x0+0x40 | binder_proc + 0x40 |
| SP+0x50 | x1+0x48 | binder_thread + 0x48 |
| SP+0x58 | x0+0x228 | binder_proc + 0x228 |

所有值均为内核堆指针（kmalloc 分配的 binder_proc/binder_thread 结构体偏移）。

## 三、copy_from_user 调用

**共 2 处，均在 SP+0xa8**（waiter 范围外 0x48 字节处）:

| # | 地址 | 目标 | 大小 | BC命令 | 与waiter重叠? |
|---|------|------|------|--------|--------------|
| 1 | 0x...dca808 | SP+0xa8 | 72B (0x48) | BC_TRANSACTION | ❌ |
| 2 | 0x...dca938 | SP+0xa8 | 64B (0x40) | BC_REPLY | ❌ |

**结论: 无 BC_* 命令将用户数据写入 waiter 范围内。**

## 四、命令分发分析

binder_thread_write 的命令分发 (w28) 支持以下 BC_* 命令:

| 命令码 | 名称 | copy_from_user? | 目标SP |
|--------|------|----------------|--------|
| 0x40046301 | BC_TRANSACTION | ✅ | SP+0xa8 |
| 0x40046302 | BC_REPLY | ✅ | SP+0xa8 |
| 0x40046304 | BC_FREE_BUFFER | ❌ | — |
| 0x4004630b | BC_REGISTER_LOOPER | ❌ | — |
| 0x4008630c | BC_ENTER_LOOPER | ❌ | — |
| 0x4008630d | BC_EXIT_LOOPER | ❌ | — |
| 0x400c630e | BC_REQUEST_DEATH_NOTIFICATION | ❌ | — |
| 0x4008630f | BC_CLEAR_DEATH_NOTIFICATION | ❌ | — |
| 0x40086310 | BC_DEAD_BINDER_DONE | ❌ | — |
| 0x40486312 | BC_ACQUIRE | ❌ | — |

## 五、间接控制可能性评估

### 5.1 binder_proc 结构体间接控制

binder_proc 通过 open("/dev/binder") 创建。其字段由 binder_ioctl 命令设置:
- BC_TRANSACTION 向 binder_proc 添加 transaction 记录
- binder_proc+0x228 对应什么字段需要进一步研究

**困难**: binder_proc 字段由内核管理，无法直接控制为特定值（如 fake_lock 地址）。

### 5.2 binder_thread 结构体间接控制

binder_thread 在首次 binder_ioctl 时分配。字段包括:
- 进程状态、优先级、transaction 栈等
- binder_thread+0x48 对应什么字段需要进一步研究

### 5.3 堆地址预测

即使能间接影响结构体字段，目标值（fake_task, fake_lock）是 sk_buff 喷射页的地址，位于 direct map 区域 (0xffffff80XXXXXXXX)。binder_proc 和 binder_thread 也在这同一区域。概率上不可能匹配。

## 六、结论

**binder 路由无法直接用于 GhostLock 栈覆盖。** 虽然栈对齐完美 (Δ=0)，但:
1. 重叠区域的值为内核堆指针，非用户可控
2. 所有 copy_from_user 目标均在 waiter 范围外
3. 间接控制需要极其精确的堆布局操纵，概率上不可行

binder 路由可作为辅助手段（如在 binder_proc 内布置辅助数据），但不能替代主覆盖路径。

## 七、验证脚本

`analyze_binder_commands.py` — 完整反汇编 binder_thread_write，映射所有:
- SP-相对存储（局部结构体初始化）
- __arch_copy_from_user 调用及目标
- BC_* 命令分发 switch case
- Waiter 字段与存储的对应关系
