> **文档类型**: 结论文档（分析汇总） | **状态**: ⚠️ 需更新 — CFU 扫描已从"进行中"→"完成"，发现 qcedev_ioctl 等 143 个可行路由；总体结论需修正 | **最后更新**: 2026-07-24

# GhostLock 四路并行分析 — 汇总

**日期**: 2026-07-24
**漏洞**: CVE-2026-43499 GhostLock — futex PI 栈 UAF
**目标**: Onyx Leaf5 (TabBoox), kernel 4.19.157

---

## 分析结果一览

| # | 方向 | 状态 | 核心结论 |
|---|------|------|---------|
| 1 | 堆喷射绕过 | ✅ 完成 | 原判定为循环依赖阻塞；CFU 扫描发现 qcedev_ioctl 后可打破此依赖 |
| 2 | 全局 copy_from_user 扫描 | ✅ 完成 | 309 函数/724 调用点；**发现 qcedev_ioctl 等 143 个可行路由**，waitor 全覆盖 64B |
| 3 | Binder 命令深度分析 | ✅ 完成 | Δ=0 完美对齐, 但 SP+0x20..SP+0x60 全为内核指针; 2处CFU均在SP+0xa8; 不可行 |
| 4 | do_select 缓冲区分析 | ✅ 完成 | 无用户可控缓冲区在 waiter 位置 |

---

## 总体结论

### 原结论（已修正）

~~所有 4 个方向的分析确认了一个核心问题：Leaf5 4.19 内核的栈帧布局导致 pselect fd_set 无法与 GhostLock 悬垂 waiter 重叠。~~

### 修正结论（2026-07-24 CFU 扫描完成后）

pselect/binder/sendmsg/recvmsg/do_select 五条常规路由均不可行。但**全局 copy_from_user 扫描发现了新的可行栈覆盖路由**：

- **qcedev_ioctl**（`/dev/qcedev`, `crw-rw-rw-`）：328 字节用户缓冲区在标准 ioctl 深度下与 waiter **完全重叠**（64/64 字节），深度容差 0x70-0x100
- **ipa3_ioctl**（`/dev/ipa`）：108 字节，全覆盖但容差较窄
- 共 **143 个调用点**可实现完整 waiter 覆盖

**循环依赖已可解**: `qcedev_ioctl 栈覆盖 → configfs/ashmem fops 覆写 → 内核 R/W 原语 → 堆喷射 → 提权`

详见 [copy-from-user-scan/ANALYSIS.md](copy-from-user-scan/ANALYSIS.md)。

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

**脚本**: `scanner.py` (优化版，~7.5s 完成)
**结果**: 309 候选函数、724 CFU 调用点。**发现 qcedev_ioctl (328B@SP+0x50, 帧0x360) 在 ioctl 深度 0xA0 下与 waiter 完全重叠 (64B)。ipa3_ioctl 同样全覆盖。143 个调用点可实现完整 waiter 覆盖。**
详见 [copy-from-user-scan/ANALYSIS.md](copy-from-user-scan/ANALYSIS.md)。

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

## 前进方向（更新后）

### 短期（推荐优先）

1. **验证 qcedev_ioctl 栈覆盖路由** — 确认 `/dev/qcedev` 可访问性、逆向 ioctl 命令码、编写 NDK 探针
2. **集成到 fops.c** — 将 pselect 栈覆盖替换为 qcedev_ioctl 路径
3. **端到端测试** — GhostLock 触发 → qcedev_ioctl 覆盖 → configfs/ashmem fops 覆写 → pipe physrw → 提权

### 中期（备选）

4. **ipa3_ioctl** — 如果 qcedev_ioctl 不可用，作为备用路由
5. **[EST] 偏移 pahole/IDA 验证** — TASK_PID_OFF, TASK_TASKS_OFF, CRED_SECURITY_OFF 等
