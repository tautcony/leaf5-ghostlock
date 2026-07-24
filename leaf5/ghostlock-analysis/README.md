# GhostLock 四路并行分析 — 汇总

**日期**: 2026-07-24
**漏洞**: CVE-2026-43499 GhostLock — futex PI 栈 UAF
**目标**: Onyx Leaf5 (TabBoox), kernel 4.19.157

---

## 分析结果一览

| # | 方向 | 状态 | 核心结论 |
|---|------|------|---------|
| 1 | 堆喷射绕过 | ✅ 完成 | 循环依赖阻塞：需要先有内核 R/W 才能建立堆喷射 |
| 2 | 全局 copy_from_user 扫描 | 🔄 进行中 | 优化扫描器开发中 |
| 3 | Binder 命令深度分析 | ✅ 完成 | Δ=0 完美对齐, 但 SP+0x20..SP+0x60 全为内核指针; 2处CFU均在SP+0xa8; 12个BC_*命令无一写入waiter范围 |
| 4 | do_select 缓冲区分析 | ✅ 完成 | 无用户可控缓冲区在 waiter 位置 |

---

## 总体结论

### 阻塞点: pselect 栈覆盖不可行

所有 4 个方向的分析确认了一个核心问题：**Leaf5 4.19 内核的栈帧布局导致 pselect fd_set 无法与 GhostLock 悬垂 waiter 重叠**。

```
Waiter 位置 (绝对):     -0x380  (futex_wait 帧内, futex_q+0x48)
Fd_set 位置 (绝对):     -0x210  (core_sys_select 帧内, stack_fds)
Δ                       -0x170  (-368 字节 = -46 词)

PSELECT_WAITER_WORD_SHIFT = -46
```

### 栈覆盖路由比较

| 路由 | Δ词 | 对齐? | 用户数据? | 结论 |
|------|-----|-------|----------|------|
| pselect | -46 | ❌ | ✅ | 不可行 |
| binder_thread_write | 0 | ✅ | ❌ (内核指针) | 对齐完美, 数据不可控 |
| sendmsg | -44 | ❌ | ✅ | 不可行 |
| recvmsg | -47 | ❌ | ✅ | 不可行 |
| do_select | +ve | ❌ | ❌ | 不可行 |

### 关键洞察

**存在一个"先有鸡还是先有蛋"的循环依赖**:

```
要建立堆喷射绕过 → 需要内核 R/W (pipe physrw)
要建立内核 R/W → 需要 configfs/ashmem fops 覆写
要覆写 fops → 需要 pselect 栈覆盖 (CFI stage)
要栈覆盖 → 需要 SHIFT=0 对齐
但 SHIFT=-46 → 不可行!
```

### 唯一的例外: Binder

binder_thread_write 是**唯一** Δ=0 完美对齐的路由，但:
- 对齐位置的值是 `binder_proc+N` / `binder_thread+N` (内核堆指针)
- 所有 copy_from_user 目标均在 SP+0xa8 (waiter 范围外 0x48 字节)
- BC_TRANSACTION 和 BC_REPLY 的用户数据无法直接落入 waiter 区域
- 间接控制需要极精确的堆布局 (概率上不可行)

---

## 各方向详细发现

### 1. 堆喷射绕过 (`heap-spray/`)

**脚本**: `check_ion_primitive.sh`
**结论**: 循环依赖阻塞。即使 sk_buff 喷射和 KernelSnitch 工作正常，无法建立初始内核 R/W 原语来启动堆喷射链。

/dev/ion 不可用 (Leaf5 msm-4.19 使用 DMA-heap)。无替代物理写入原语。

### 2. 全局扫描 (`copy-from-user-scan/`)

**脚本**: 优化扫描器开发中
**目标**: 扫描 vmlinux.elf 中 685 个 copy_from_user 调用，寻找任意与 waiter 重叠的目标

### 3. Binder 命令 (`binder-commands/`)

**脚本**: `analyze_binder_commands.py` (542行), `binder_command_mapper.py` (395行)
**发现**:
- binder_thread_write 有 **2 处** copy_from_user，均在 SP+0xa8 (waiter 范围外 72B)
- 局部结构体 (SP+0x18..SP+0x78) 恰好覆盖 waiter，但值来源:
  - waiter+0x30 (task) ← `binder_thread+0x48` (thread→looper 字段)
  - waiter+0x38 (lock) ← `binder_proc+0x170` (proc 内部字段)
- **12 个 BC_* 命令**中仅 BC_TRANSACTION 和 BC_REPLY 有 CFU，无一写入 waiter 范围
- 值在函数入口一次性初始化，后续无 BC 命令修改
- 间接控制不可行 (指针值为内核堆地址，无法通过 ioctl 序列控制为特定值)

### 4. do_select 缓冲区 (`do-select-buffers/`)

**脚本**: `analyze_do_select.py` (31KB)
**发现**: do_select 帧 0x370B，waiter 位于 SP+0x250..SP+0x290 (保存寄存器区)
- 34 个 SP 相对访问，无一在 waiter 范围
- 无 copy_from_user 调用
- poll_wqueues 结构不延伸到 waiter 位置

---

## 前进方向

### 短期 (可操作)

1. **完成全局 copy_from_user 扫描** — 这是唯一尚未穷尽的系统化方法
2. **运行时二分搜索** — 使用 `PSELECT_SHIFT_OVERRIDE=-64..64` 验证理论值
3. **研究 do_futex 的不同代码路径** — 是否存在产生不同栈深度的 futex 操作?

### 中期 (需要深入)

4. **探索非 configfs 内核写原语** — 寻找不依赖 fops 覆写的替代路径
5. **研究 GhostLock UAF 的替代利用方式** — 不一定需要栈覆盖

### 长期 (备选)

6. **接受栈覆盖不可行，转向纯堆方法** — 但这需要一个独立的内核写原语
7. **等待/寻找新漏洞** — 结合 GhostLock UAF 与其他漏洞
