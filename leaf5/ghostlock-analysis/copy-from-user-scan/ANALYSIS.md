# Global copy_from_user Scanner — GhostLock 分析

**日期**: 2026-07-24
**状态**: 完成 — 无函数直接重叠

---

## 一、扫描方法

### 优化策略

1. **预过滤**: 直接在 .kernel 段二进制中扫描所有 BL 指令，仅提取目标为 `__arch_copy_from_user` 的函数 (~500 候选，而非 59K)
2. **按需反汇编**: 仅对候选函数使用 capstone 反汇编提取帧大小和目标 SP 偏移
3. **逆向调用图**: 从原始 BL 扫描数据构建逆向调用图
4. **BFS 深度计算**: 从 syscall entry 向候选函数 BFS，计算最小调用深度

### 性能

- 原始 BL 扫描: ~2 秒
- BFS: ~2 秒 (5018 边, 3142 可达函数)
- 候选函数反汇编: ~2 秒

**总计 < 10 秒** (vs 原始版本的无法完成)

---

## 二、扫描结果

```
函数总数 (含 copy_from_user):    309
调用点总数:                      724
从 syscall 可达:                  71
直接重叠 (>0B):                  0   ← 关键!
深度范围匹配:                     0
接近 (|Δ| ≤ 32 词):              4
```

### 最接近的候选

| 函数 | Δ词 | 深度 | 帧大小 | Dest@SP | 大小 |
|------|-----|------|--------|---------|------|
| `__arm64_sys_rt_sigreturn` | +29 | 0x2a0 | 0x2a0 | 0x0008 | 16B |
| `__arm64_sys_rt_sigreturn` | +31 | 0x2a0 | 0x2a0 | 0x0018 | 8B |
| `__arm64_sys_rt_sigreturn` | +32 | 0x2a0 | 0x2a0 | 0x0020 | 512B |
| `__arm64_sys_rt_sigreturn` | +32 | 0x2a0 | 0x2a0 | 0x0020 | 512B |

**所有候选的 Δ 均为正值** — 意味着缓冲区在 waiter 上方，无法向下延伸覆盖。

---

## 三、关键发现

### 3.1 __arm64_sys_rt_sigreturn 分析

这是最接近的函数 (Δ=+32 词, dest@SP+0x20, 512B):

```
__arm64_sys_rt_sigreturn 深度: 0x2a0
缓冲区绝对位置: -(0x2a0) + 0x20 = -0x280
Waiter 绝对位置: -0x380
Δ = 0x100 字节 = 32 词 (256 字节)

缓冲区: [-0x280, -0x80)  (向上延伸 512B)
Waiter:  [-0x380, -0x340) (缓冲区下方 256B)
```

**缓冲区在 waiter 上方，无法覆盖。** sigframe 数据从用户栈复制，用户完全可控（所有寄存器值），但方向错误。

### 3.2 为何无函数重叠

所有 syscall 可到达的 copy_from_user 目标均在较浅的栈深度 (≤0x2a0)。waiter 在深度 0x380。需要满足以下条件的函数:

```
caller_depth + frame_size - dest_sp ≈ 0x380
```

而大多数函数的 `frame_size - dest_sp` 在 0x100-0x280 范围，加上 caller_depth (0-0x100) 仍达不到 0x380。

### 3.3 唯一例外: binder_thread_write

binder_thread_write 不是通过 copy_from_user 匹配的（它不直接调用 __arch_copy_from_user），而是通过局部结构体初始化匹配的。其深度恰好 0x3a0，Δ=0。

---

## 四、结论

**在 vmlinux.elf 的 309 个 copy_from_user 调用函数中，无一能与 waiter 位置直接重叠。** 这证实了 pselect 栈覆盖路由不可行的结论是系统性的，而非 pselect 特有的问题。

binder_thread_write 是唯一 Δ=0 的路由，但其重叠区域存储内核指针，非用户数据。

### 这意味着什么

对于 Leaf5 4.19 内核，**GhostLock 的标准栈覆盖利用链不可行**。需要以下替代方案之一:

1. **发现新的内核写原语** (不依赖 configfs/ashmem fops 覆写)
2. **利用 GhostLock UAF 的其他方式** (不通过栈覆盖修改 waiter)
3. **结合其他漏洞** (例如: 使用另一个漏洞建立 R/W，再用 GhostLock 提权)

---

## 五、验证脚本

**`scanner.py`** — 优化的全局 copy_from_user 扫描器:
- 原始 BL 二进制扫描预过滤
- 按需 capstone 反汇编
- 逆向调用图 + BFS 深度计算
- 输出所有候选及与 waiter 的距离

运行:
```bash
uv run python ghostlock-analysis/copy-from-user-scan/scanner.py --verbose
```
