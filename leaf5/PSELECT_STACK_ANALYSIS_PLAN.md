# PSELECT_WAITER_WORD_SHIFT 适配计划 — Leaf5 4.19 内核

**日期**: 2026-07-24  
**阻塞问题**: exploit 在 pselect fake lock route 阶段失败 (`write: Invalid argument`)  
**根因**: 4.19 内核的 `__arm64_sys_pselect6` / `futex_wait` 栈帧布局与 OPPO 5.10 不同，导致 fd_set 位掩码与 `rt_mutex_waiter` 在栈上的重叠偏移不匹配  
**目标**: 计算正确的 `PSELECT_WAITER_WORD_SHIFT` 值及 fd_set word 索引映射

---

## 一、攻击原理回顾

### 1.1 GhostLock 栈覆盖机制

```
Thread A (waiter):
  1. FUTEX_WAIT_REQUEUE_PI → futex_wait() → rt_mutex_waiter 分配在内核栈上
  2. 阻塞等待...
  3. 被唤醒后，waiter 变为"悬垂"结构（GhostLock UAF 特性）
  4. 调用 pselect() → fd_set 被复制到内核栈

关键点:
  ┌─────────────────────────────────────────────┐
  │  futex_wait() 栈帧                           │
  │  ┌──────────────────────────┐                │
  │  │ struct futex_q {         │                │
  │  │   ...                    │                │
  │  │   struct rt_mutex_waiter │ ← 悬垂引用      │
  │  │     waiter;              │                │
  │  │ }                        │                │
  │  └──────────────────────────┘                │
  └─────────────────────────────────────────────┘
                      ↓ 栈帧复用
  ┌─────────────────────────────────────────────┐
  │  core_sys_select() 栈帧                      │
  │  ┌──────────────────────────┐                │
  │  │ fd_set bitmasks          │ ← 覆盖旧waiter │
  │  │ (stack_fds[])            │   位置         │
  │  └──────────────────────────┘                │
  └─────────────────────────────────────────────┘
```

如果 fd_set 在 core_sys_select 栈帧中的偏移与 waiter 在 futex_wait 栈帧中的偏移对齐，则通过 fd_set 字写入的值会被内核当作 waiter 字段读取。

### 1.2 当前 fake waiter 数据布局

来自 `exploit/src/fops.c:prepare_pselect_fdsets()`：

| waiter_word | fd_set 全局词 | 对应字段 | 值 |
|:-----------:|:------------:|---------|----|
| 2 | in[2] | tree_entry.__rb_parent_color | pselect_write_value() |
| 3 | in[3] | tree_entry.rb_right | 0 |
| 4 | in[4] | tree_entry.rb_left | pselect_write_target() |
| 5 | in[5] | pi_tree_entry.__rb_parent_color | pselect_write_value() |
| 6 | in[6] | pi_tree_entry.rb_right | 0 |
| 7 | in[7] | pi_tree_entry.rb_left | pselect_write_target() |
| 8 | in[8] | task | fake_task / INIT_TASK |
| 9 | in[9] | lock | fake_lock |
| 10 | out[0] | prio \| 3 (4.19 不存在→溢出) | (FAKE_WAITER_PRIO<<32) \| 3 |
| 11 | out[1] | deadline (4.19 不存在) | 0 |
| 12 | out[2] | ww_ctx (4.19 不存在) | 0 |

**注意**: 4.19 的 `rt_mutex_waiter` 只有 0x40 字节（无 prio/deadline/ww_ctx），但当前代码仍在 word 10-12 写入这些 5.10 字段。

### 1.3 PSELECT_WAITER_WORD_SHIFT 的含义

```c
// fops.c:93-105
static void pselect_put_waiter_word(..., int waiter_word, ...) {
    int global_word = waiter_word;  // ← PSELECT_WAITER_WORD_SHIFT 在此作用
    pselect_put_global_word(in, out, ex, words_per_set, global_word, value);
}
```

`waiter_word` 直接等于 `global_word`（当前 SHIFT=0）。如果 fd_set 与 waiter 在栈上的对齐偏移不同，则需要通过 SHIFT 值调整映射关系：

```
实际 waiter 字段在栈上的位置 = fd_set 起始位置 + (waiter_word + SHIFT) * 8
```

即：**PSELECT_WAITER_WORD_SHIFT 补偿 fd_set 与 waiter 在栈上的起始偏移差。**

---

## 二、已获取的关键数据

### 2.1 4.19 内核栈帧大小（从 vmlinux.elf 反汇编提取）

| 函数 | 栈帧大小 | 说明 |
|------|---------|------|
| `__arm64_sys_pselect6` | **0xa0** (160B) | pselect 系统调用入口 |
| `core_sys_select` | **0x1c0** (448B) | **fd_set bitmask 在此分配** |
| `do_select` | **0x310** (784B) | 被 core_sys_select 调用 |
| `__arm64_sys_futex` | **0x70** (112B) | futex 系统调用入口 |
| `do_futex` | **0x1c0** (448B) | futex 命令分发 |
| `futex_wait` | **0x140** (320B) | **futex_q（含 waiter）在此分配** |
| `futex_wait_setup` | **0x70** (112B) | 被 futex_wait 调用 |
| `rt_mutex_slowlock` | **0xb0** (176B) | rtmutex 慢路径 |

### 2.2 关键结构体布局特征

#### core_sys_select 栈帧 (0x1c0)

```
SP+0x000 ───────────── 局部变量区 (fd_set stack_fds, fd_set_bits 等)
         ...
SP+0x050  ← x19 指向此处 (可能是 fd_set_bits 结构体地址)
         ...
SP+0x160 ───────────── 保存的 x29, x30  (x29 ← SP+0x160)
SP+0x170              保存的 x28, x27
SP+0x180              保存的 x26, x25
SP+0x190              保存的 x24, x23
SP+0x1a0              保存的 x22, x21
SP+0x1b0              保存的 x20, x19
SP+0x1c0 ───────────── 栈帧顶部 (= 调用者 SP)
```

- `add x29, sp, #0x160` — 帧指针指向保存的 x29/x30
- `add x19, sp, #0x50` — x19 指向局部变量区偏移 0x50 处
- `mov w1, #0xc0` — 192 (= 3 × 64)，可能与 fd_set 大小相关

#### futex_wait 栈帧 (0x140)

```
SP+0x000 ───────────── 局部变量区
SP+0x008  ← futex_q 结构体基址 (多次作为参数传递)
         ...
SP+0x058  stp x10,x11 — futex_q 字段初始化（进入 waiter 区域）
SP+0x068  stp x8, x10
SP+0x070  str w4      — 可能已超出 waiter，进入 futex_q 其他字段
         ...
SP+0x0e0 ───────────── 保存的 x29, x30  (x29 ← SP+0xe0)
SP+0x0f0              保存的 x28, x27
SP+0x100              保存的 x26, x25
SP+0x110              保存的 x24, x23
SP+0x120              保存的 x22, x21
SP+0x130              保存的 x20, x19
SP+0x140 ───────────── 栈帧顶部
```

- `add x29, sp, #0xe0` — 帧指针
- `add x8/x3/x1/x0, sp, #8` — **futex_q 结构体位于 SP+8**

### 2.3 4.19 vs 5.10 对比（来自 OPPO 参考）

| 维度 | 4.19 (Leaf5) | 5.10 (OPPO Find N2) |
|------|-------------|---------------------|
| `rt_mutex_waiter` sizeof | **0x40** (64B) | 0x50 (80B) |
| waiter 含 prio/deadline | ❌ 无 | ✅ 有 |
| `futex_wait_requeue_pi` 符号 | ❌ 不存在 | ✅ 存在 |
| PSELECT_WAITER_WORD_SHIFT | **?** (当前 0 不工作) | 0 (验证通过) |
| VMAP_STACK | on | on |
| 内核 CFI | 无 | 有 |

---

## 三、精确计算步骤

### Step 1: 确定 futex_q 中 rt_mutex_waiter 的偏移

**输入**: vmlinux.elf 中 `futex_wait` 的完整反汇编

**方法**:
```python
# 1. 找到 futex_wait 中对 SP+8 偏移区域的访问模式
# 2. 根据 struct futex_q 在 4.19 的布局计算 waiter 偏移
#
# struct futex_q 布局 (4.19):
#   +0x00: plist_node list.prio_list (struct list_head, 16B)
#   +0x10: plist_node list.node_list (struct list_head, 16B)
#   +0x20: struct task_struct *task (8B)
#   +0x28: spinlock_t *lock_ptr (8B)
#   +0x30: union futex_key key (16B: u64 both[2])
#   +0x40: struct futex_pi_state *pi_state (8B)
#   +0x48: struct rt_mutex_waiter waiter (0x40 = 64B)
#   +0x88: union futex_key *requeue_pi_key (8B)
#
# 因此 waiter 在 futex_q 中偏移 = 0x48
```

**验证点**:
- `SP+0x50` (= 0x08 + 0x48) 应该是 `waiter.tree_entry.__rb_parent_color` 的第一次写入位置
- `SP+0x68` (= 0x08 + 0x60) 应该是 `waiter.pi_tree_entry` 区域
- 检查 `task_blocks_on_rt_mutex` 中对 waiter 的访问偏移，交叉验证

**结论**:
```
waiter 在 futex_wait 栈帧中的绝对偏移:
  A_waiter = 0x08 (futex_q) + 0x48 (waiter in futex_q) = 0x50
```

### Step 2: 确定 fd_set bitmasks 在 core_sys_select 中的偏移

**输入**: vmlinux.elf 中 `core_sys_select` 的完整反汇编 + 4.19 源码

**方法**:
```python
# 1. core_sys_select 源码中 fd_set 的分配:
#    fd_set_bits fds;
#    long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];
#    // SELECT_STACK_ALLOC = 256
#    // stack_fds 占用 256 字节
#
# 2. struct fd_set_bits 包含:
#    unsigned long *in, *out, *ex;   // 3×8 = 24B
#    unsigned long *res_in, *res_out, *res_ex;  // 3×8 = 24B
#    // 总计 48B
#
# 3. 编译器布局: fd_set_bits 在低地址，stack_fds 紧随其后
#    或者 stack_fds 在低地址，指针指向它
#
# 4. 通过反汇编追踪:
#    - 找到传递给 do_select 的 fd_set 指针参数
#    - 跟踪 do_select 调用前的 x0-x3 设置
#    - 确定 stack_fds 数组的基址
```

**具体追踪方法**:
```python
# 在 core_sys_select 中:
# - add x19, sp, #0x50  ← 关键线索！x19 指向 SP+0x50
# - 检查 x19 是否被用于构建 fd_set 指针
# - 检查所有传递给 do_select 的地址参数是否基于 x19 计算
```

**初步结论**:
```
stack_fds 在 core_sys_select 栈帧中的偏移:
  A_fdset = 0x50 (根据 add x19, sp, #0x50 推断)
  
验证: 0x50 + 0xc0 = 0x110，在 0x1c0 帧内合理
  (0xc0 = 192B = 3 fd_sets × 64B 对齐)
```

### Step 3: 计算栈偏移差

两个函数在同一内核栈上执行，但调用链深度不同：

```
pselect6 调用链栈深度:
  __arm64_sys_pselect6 (0xa0)
    → core_sys_select (0x1c0) ← fd_set 在此
      → do_select (0x310)

futex 调用链栈深度:
  __arm64_sys_futex (0x70)
    → do_futex (0x1c0)
      → futex_wait (0x140) ← waiter 在此
```

**关键假设**: 两次调用中，各自调用链的帧总和决定了相同 SP 偏移（内核栈基址固定）。

```
对于 pselect6 路径:
  fd_set 距内核栈底的偏移 = 
    sys_pselect6_frame(0xa0) + 其他调用者帧 + A_fdset

对于 futex 路径:
  waiter 距内核栈底的偏移 = 
    sys_futex_frame(0x70) + do_futex_frame(0x1c0) + A_waiter
```

由于两个路径的 syscall 入口点都在内核栈的同一位置（task 的内核栈顶），中间可能还有其他公共调用帧。最保守的方法：

**通过实验确定**: 编写诊断代码，在不同 SHIFT 值下运行 exploit，观测 pselect 的行为变化。

**理论计算**:
```
Δstack = A_waiter_in_total - A_fdset_in_total

其中:
  A_waiter_in_total = futex_wait 帧内 A_waiter + do_futex 帧大小 + sys_futex 帧大小
  A_fdset_in_total  = core_sys_select 帧内 A_fdset + sys_pselect6 帧大小

PSELECT_WAITER_WORD_SHIFT = Δstack / 8 (转换为 8 字节词)
```

### Step 4: 提取精确偏移的 Python 脚本

编写 `leaf5/scripts/compute_pselect_shift.py`，基于 capstone 精确提取：

```python
#!/usr/bin/env python3
"""
精确计算 PSELECT_WAITER_WORD_SHIFT。

策略:
1. 反汇编 core_sys_select → 找到 stack_fds 的 SP 相对偏移
2. 反汇编 futex_wait → 找到 futex_q.waiter 的 SP 相对偏移
3. 比较调用链深度 → 计算绝对栈偏移差
4. 输出 PSELECT_WAITER_WORD_SHIFT 值
"""

# 分析步骤:
# a) 在 core_sys_select 中，追踪 do_select 的 x0-x3 参数
#    找到 fd_set_bits 指针 → 找到 stack_fds 基址的 SP 偏移
#
# b) 在 futex_wait 中，追踪对 SP+8 的写入模式
#    通过已知的 struct futex_q 布局验证 waiter 偏移
#
# c) 构建调用链帧大小表，计算总的栈偏移差
#
# d) 输出: PSELECT_WAITER_WORD_SHIFT, fd_set word 映射表
```

### Step 5: 验证方法

#### 5a. 编译时验证
在 exploit 中添加编译时断言或诊断日志：
```c
// 添加诊断代码
#define PSELECT_DIAG 1
// 在 do_pselect_fake_lock_route 中打印更多栈布局信息
```

#### 5b. 运行时二分搜索
使用 shell 环境变量覆盖 SHIFT 值进行二分搜索：
```bash
# 测试不同 SHIFT 值
for shift in -4 -3 -2 -1 0 1 2 3 4; do
  adb shell 'PSELECT_SHIFT_OVERRIDE='$shift' LD_PRELOAD=/data/local/tmp/preload.so ls /dev/null'
done
```

#### 5c. 内核栈 dump 比较
如果可以获取内核栈内容（如通过 /proc/self/task/*/stat 或其他泄漏），直接比较两次调用的栈布局。

---

## 四、实施计划

### Phase A: 精确反汇编分析 (1-2h)

- [ ] **A1**: 编写 `leaf5/scripts/compute_pselect_shift.py`
  - 完整反汇编 `core_sys_select`，追踪所有 SP-相对访问
  - 完整反汇编 `futex_wait`，验证 `struct futex_q` 各字段偏移
  - 反汇编 `task_blocks_on_rt_mutex` 交叉验证 waiter 访问偏移
  - 输出所有证据和初步 SHIFT 值

- [ ] **A2**: 运行脚本并审查输出
  - 验证 `futex_q` 布局（与 4.19 源码对比）
  - 验证 `stack_fds` 位置（与 SELECT_STACK_ALLOC=256 一致性检查）
  - 计算理论 SHIFT 值

### Phase B: 代码适配 (1h)

- [ ] **B1**: 更新 `exploit/targets/onyx-leaf5/target.h`
  - 更新 `PSELECT_WAITER_WORD_SHIFT`
  - 针对 4.19 waiter 仅 0x40 字节，调整 waiter word 映射
  - 移除 word 10-12 的 prio/deadline/ww_ctx 写入

- [ ] **B2**: 更新 `exploit/src/fops.c` 中的 `prepare_pselect_fdsets`
  - 添加 `#if WAITER_PRIO_OFF < 0` 条件跳过 4.19 不存在的字段
  - 或设计 4.19 专用的简化 waiter 布局

- [ ] **B3**: 添加 `PSELECT_SHIFT_OVERRIDE` 环境变量支持
  - 允许运行时通过环境变量覆盖 SHIFT 值，便于诊断

- [ ] **B4**: 添加诊断日志
  - 在 pselect 调用前后打印更多栈布局信息
  - 跟踪实际写入的目标地址

### Phase C: 测试验证 (1h)

- [ ] **C1**: Docker 编译
  ```bash
  cd exploit && ./docker-build.sh TARGET_DIR=targets/onyx-leaf5
  ```

- [ ] **C2**: 部署并运行
  ```bash
  adb push preload.so /data/local/tmp/
  adb shell 'LD_PRELOAD=/data/local/tmp/preload.so ls /dev/null'
  ```

- [ ] **C3**: 如果仍失败，使用二分搜索测试不同 SHIFT 值
  - 在 fops.c 中添加 PSELECT_SHIFT_OVERRIDE 支持
  - 在 [-8, +8] 区间二分搜索

- [ ] **C4**: 记录验证结果到 VERIFICATION_REPORT.md
  - 最终 SHIFT 值
  - pselect 返回值
  - 是否通过 configfs write 阶段

### Phase D: 后备方案 (如果 Phase A-C 仍不工作)

- [ ] **D1**: sendmsg/recvmsg 栈覆盖路由
  - 分析 `__arm64_sys_sendmsg` 栈帧布局
  - 比较其 fd_set 或 iovec 是否能与 waiter 对齐

- [ ] **D2**: binder ioctl 栈覆盖
  - 分析 `binder_ioctl` 栈帧，确认是否能覆盖 waiter 位置

- [ ] **D3**: 堆喷射绕过（不依赖栈覆盖）
  - 验证当前的 heap_spray.c 代码
  - 确认 sk_buff 喷射 + pipe physrw 路径可以绕过 pselect 栈覆盖

---

## 五、关键技术细节

### 5.1 struct futex_q 在 4.19 的布局验证

需要确认 `waiter` 字段在 `futex_q` 中的精确偏移。参考 4.19 源码：
```c
// include/linux/futex.h (4.19)
struct futex_q {
    struct plist_node list;          //  0x00: 32B (2×list_head)
    struct task_struct *task;        //  0x20: 8B
    spinlock_t *lock_ptr;            //  0x28: 8B
    union futex_key key;             //  0x30: 16B
    struct futex_pi_state *pi_state; //  0x40: 8B
    struct rt_mutex_waiter waiter;   //  0x48: 64B (0x40)
    union futex_key *requeue_pi_key; //  0x88: 8B
};
// sizeof(struct futex_q) ≈ 0x90
```

验证方法：追踪 `futex_wait_setup` 中对 `&q->key` 的引用，通过 key 的偏移反推 futex_q 布局。

### 5.2 SELECT_STACK_ALLOC 在 4.19 的值

```c
// include/linux/poll.h
#define FRONTEND_STACK_ALLOC  256
#define SELECT_STACK_ALLOC  FRONTEND_STACK_ALLOC
```

这意味着 stack_fds 数组占用 256 字节（32 个 unsigned long）。在 core_sys_select 栈帧中，加上 fd_set_bits 结构体（~48B），总局部变量约 304B。

core_sys_select 帧 = 0x1c0 (448B)，减去保存寄存器区域 (12 × 8 = 96B) = 352B 局部变量空间，与预期一致。

### 5.3 4.19 与 5.10 的核心差异影响

由于 4.19 的 `rt_mutex_waiter` 仅为 0x40 字节（vs 5.10 的 0x50），在 exploit 中：
1. fd_set 覆盖的字节数减少 16 字节
2. 不需要写入 prio/deadline 字段（它们不是 waiter 的一部分）
3. waiter 周围的 padding 可能不同，影响 fd_set word 对齐

### 5.4 调用链帧累积计算

两个 syscall 共享的内核栈入口帧由架构代码（`el0_sync` 等）建立。从各自 syscall handler 开始累积：

```
完整 pselect6 路径:
  [el0 入口帧: ~0x140]
    → __arm64_sys_pselect6 (0xa0)
      → core_sys_select (0x1c0)
        → do_select (0x310, 但在 core_sys_select 帧内分配 fd_set)
  总帧需求: ~0x140 + 0xa0 + 0x1c0 + 0x310 ≈ 0x6b0

完整 futex 路径:
  [el0 入口帧: ~0x140]
    → __arm64_sys_futex (0x70)
      → do_futex (0x1c0)
        → futex_wait (0x140)
  总帧需求: ~0x140 + 0x70 + 0x1c0 + 0x140 ≈ 0x4b0
```

两个路径的绝对栈偏移差 = 0x6b0 - 0x4b0 = 0x200（512 字节）= 64 个 8 字节词。

加上各自帧内偏移差，总的词偏移约为 `(0x50 - 实际_fdset_偏移) / 8 + 调用链帧差/8`。

---

## 六、输出物

1. **`leaf5/scripts/compute_pselect_shift.py`** — 自动从 vmlinux.elf 计算 SHIFT 值的 Python 脚本
2. **`exploit/targets/onyx-leaf5/target.h`** — 更新后的 PSELECT_WAITER_WORD_SHIFT 值
3. **`exploit/src/fops.c`** — 适配 4.19 waiter 大小的 fd_set 布局
4. **`leaf5/VERIFICATION_REPORT.md`** — 更新验证状态

---

## 七、风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| 栈帧布局因编译器优化而异 | 中 | 高 | 在目标设备编译的内核二进制上直接分析 |
| 两个 syscall 间的入口帧差异 | 低 | 中 | 使用运行时二分搜索验证 |
| VMAP_STACK 导致栈地址不连续 | 低 | 高 | 已确认 VMAP_STACK=on 但溢出检测未触发 |
| fd_set 与 waiter 完全不对齐 | 中 | 高 | 使用后备方案（sendmsg/binder 路由或堆喷射） |

---

*计划制定: 2026-07-24，基于 vmlinux.elf capstone 反汇编分析*
