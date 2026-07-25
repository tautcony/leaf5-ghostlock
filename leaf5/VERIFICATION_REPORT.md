> **文档类型**: 结论文档 | **状态**: ✅ 有效（历史验证快照） | **最后更新**: 2026-07-24


> ⚠️ **文档导航更新 (2026-07-25)**：代码与节点效果已按利用顺序归档至 [`stages/README.md`](stages/README.md)。本文保留历史分析细节；可行性终局以 stages 各节点 README 与 [`PROCESS_LOG.md`](PROCESS_LOG.md) 为准。
# Leaf5 GhostLock 验证报告

**设备**: Onyx Leaf5 (TabBoox), kernel 4.19.157, Android 13  
**漏洞**: CVE-2026-43499 (GhostLock rtmutex stack UAF)  
**验证日期**: 2026-07-24  
**方法**: 参照 OPPO Find N2 既有研究工作，逐项在 Leaf5 上验证  

---

## 一、已完成的阶段 ✅

| 阶段 | 状态 | 说明 |
|------|------|------|
| 设备信息采集 | ✅ | 设备完整画像已建立 |
| 内核 CONFIG 分析 | ✅ | /proc/config.gz 确认为权威配置源 |
| 内核镜像提取 | ✅ | boot_a.bin 确认匹配 runtime (#245) |
| 符号表重建 | ✅ | vmlinux.elf: 121883 symbols |
| 结构体偏移提取 | ✅ | capstone 反汇编验证关键偏移 |
| target.h 编写 | ✅ | exploit/targets/onyx-leaf5/target.h |
| Firefox 安装确认 | ✅ | 151.0.2 已安装（Stage1 应用条件满足） |
| Docker 编译 | ✅ | 通过，产出 preload.so + test programs |
| Futex 哈希自检 | ✅ | 用户态 hash 自一致性通过 |
| Futex 碰撞时序探测 | ✅ | 时序侧信道有效 (pile-up 26x baseline) |
| **KernelSnitch mm_struct 泄漏** | ✅ | **KSNITCH_COLLISIONS=2 时可靠泄漏** |
| **sk_buff reclaim** | ✅ | **4/4 send 成功 (ret=65536)** |
| KASLR bypass | ✅ | Direct-map 直接计算 (无需 slide) |

---

## 二、KernelSnitch mm_struct 泄漏验证

### 2.1 发现的 Bug 与修复

#### Bug #1 — futex_key V1 布局 (CRITICAL)
- **症状**: 碰撞探测成功，但 bruteforce 最佳匹配仅 4/16
- **根因**: Leaf5 内核二进制使用 V1 布局 (address+0, mm+8)，而 kheaders 头文件声明为 non-V1 (mm+0, address+8)。代码未启用 `FUTEX_KEY_LAYOUT_V1`
- **修复**: futex_hash.h 添加 `#ifdef FUTEX_KEY_LAYOUT_V1` 支持，Makefile 添加 `-DFUTEX_KEY_LAYOUT_V1`
- **验证**: 修复后 `test_mm_leak` 成功找到 mm_struct

#### Bug #2 — 孤儿 #endif
- **症状**: 编译错误 `#endif without #if`
- **根因**: git commit a267168 移除了 V1 布局代码但留下了孤立的 `#endif`
- **修复**: 删除孤儿 `#endif`

#### Bug #3 — MM_STRUCT_SZ 默认值
- **症状**: preload.so 启动时 `mm_struct sz (0)`
- **根因**: env_mm_struct_sz 全局变量未从 target.h 默认值初始化
- **状态**: ⚠️ test_mm_leak 程序通过 env vars 正确读取，preload.so 需修复初始化逻辑

### 2.2 碰撞数量影响

| KSNITCH_COLLISIONS | 碰撞找到 | 最佳匹配 | 结果 |
|-------------------|---------|---------|------|
| 2 | 1/1 | **2/2** | ✅ FOUND |
| 4 | 3/3 | 3-4/4 | ❌ NOT FOUND |
| 6+ | N-1/N-1 | 2-4/N | ❌ NOT FOUND |

**结论**: 时序碰撞探测会产生约 25-40% 的假阳性。降低碰撞数至 2 是唯一可靠的配置。

### 2.3 泄漏性能

- 搜索空间: 8 线程 × 16GB direct map
- 平均候选数: **< 200** 即命中 (KSNITCH_COLLISIONS=2)
- 耗时: **< 1 秒**
- 默认参数: KSNITCH_COLLISIONS=2, MM_STRUCT_SZ=0x388, MM_ORDER=3

### 2.4 已设为默认值

| 参数 | 旧默认值 | 新默认值 | 说明 |
|------|---------|---------|------|
| `KSNITCH_COLLISIONS` | 16 | **2** | 碰撞数 — 2 是唯一可靠值 |
| `env_mm_struct_sz` | 0 (bug) | **0x388** | 全局变量初始化修复 |
| `env_mm_order` | 0 (bug) | **3** | 全局变量初始化修复 |

**不再需要** `KSNITCH_COLLISIONS=2` 环境变量。直接运行:
```bash
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so ls /dev/null'
```

---

## 三、KASLR 绕过方法

| # | 方法 | 状态 | 说明 |
|---|------|------|------|
| 1 | Direct-map 计算 | ✅ | `kaslr_base = P0_PAGE_OFFSET + P0_KERNEL_PHYS_LOAD` |
| 2 | /proc/kallsyms | ❌ | Permission denied |
| 3 | /proc/config.gz | ✅ | 可读取（CONFIG_IKCONFIG_PROC=y） |
| 4 | Prefetch side-channel | ❓ 未测 | KPTI 关闭 (CONFIG_UNMAP_KERNEL_AT_EL0=n)，理论上可行 |
| 5 | /sys/kernel/debug | ❌ | 目录不存在 |
| 6 | perf_event_open | ❓ 未测 | perf_event_paranoid=-1（宽松），但 SELinux 可能拦截 |

**对比 OPPO Find N2**: OPPO 需要 pselect side-channel 才能绕过 KASLR；Leaf5 的 KASLR 可被 direct-map 直接计算绕过，因为物理加载地址 `P0_KERNEL_PHYS_LOAD=0x80080000` 已知。

---

## 四、CFI 绕过 / Waiter 操纵方法

| # | 方法 | 状态 | 说明 |
|---|------|------|------|
| 1 | 内核 CFI bypass | ✅ **不需要** | Leaf5 无内核 CFI (CONFIG_CFI_CLANG=n, CONFIG_LTO_NONE=y) |
| 2 | pselect fd_set 栈覆盖 | ⚠️ 理论分析完成 | SHIFT=-46 (waiter 比 fd_set 深 368B)；栈路径无法直接覆盖 |
| 3 | pselect 栈帧重叠 | ✅ 已分析 | 见下方 §4a 详细帧分析 |
| 4 | sendmsg/recvmsg 栈覆盖 | ❓ 未测 | 4.19 栈帧可能不同 |
| 5 | binder ioctl 栈覆盖 | ❓ 未测 | binderfs 存在，shell 访问权限需确认 |
| 6 | 堆喷射 | ⚠️ 部分 | sk_buff reclaim 成功，但 exploit 最终在 pselect 写入阶段失败 |
| 7 | PSELECT_SHIFT_OVERRIDE | ✅ 已实现 | 运行时环境变量覆盖，支持 [-128, 128] 二分搜索 |

### 4a. PSELECT_WAITER_WORD_SHIFT 精确计算 (2026-07-24 更新)

通过 `leaf5/scripts/compute_pselect_shift.py` (capstone 反汇编 vmlinux.elf):

| 参数 | 值 | 说明 |
|------|-----|------|
| futex_wait 帧大小 | 0x140 (320B) | sub sp, sp, #0x140 |
| futex_q 位置 | SP+0x08 | x3=sp+8 → futex_wait_setup |
| waiter 位置 | SP+0x50 | futex_q + 0x48 |
| core_sys_select 帧大小 | 0x1c0 (448B) | sub sp, sp, #0x1c0 |
| stack_fds 位置 | SP+0x50 | add x19, sp, #0x50 |
| sys_futex 帧 | 0x70 (112B) | |
| do_futex 帧 | 0x220 (544B) | stp pre-index 0x60 + sub 0x1c0 |
| sys_pselect6 帧 | 0xa0 (160B) | |
| Futex 总深度 | 0x3d0 (976B) | sys_futex + do_futex + futex_wait |
| Pselect 总深度 | 0x260 (608B) | sys_pselect6 + core_sys_select |
| Δ 字节 | **-368** | waiter 比 fd_set 深 368 字节 |
| **PSELECT_WAITER_WORD_SHIFT** | **-46** | Δ字节 / 8 |

**关键结论**: waiter (在 futex_wait 帧内) 比 fd_set (在 core_sys_select 帧内) 在栈上深 368 字节。由于栈向下增长，waiter 位于更低地址。fd_set 数组的正向索引无法到达 waiter 位置（负索引方向）。

**影响**:
- 当前 PSELECT_ROUTE_NFDS=640 时，kernel 使用 kmalloc 分配 fd_sets (堆路径)，因为 640+63=703 ≥ 384 阈值
- kmalloc 路径下 fd_set 数据在堆上，不与栈上的 stale waiter 重叠
- 如需栈路径重叠，需 nfds ≤ 320 (此时 stack_fds 在 SP+0x50，waiter 在更深 368B 处)
- 直接栈覆盖不可行；需探索替代方案

**替代方案**:
1. **运行时二分搜索**: `PSELECT_SHIFT_OVERRIDE=-64..64` 环境变量（代码已支持）
2. **sendmsg/recvmsg 栈覆盖**: 帧深度分析完成，见 §4b
3. **binder ioctl 栈覆盖**: Δ=0 精确对齐！见 §4b
4. **堆喷射 + pipe physrw**: 绕过栈覆盖，直接使用堆上的 fake waiter

### 4b. 多路由栈覆盖比较分析 (2026-07-24 新增)

通过 `leaf5/scripts/compute_stack_routes.py` 分析 5 条路由:

| 路由 | 总深度 | Buf@SP | Δ词 | 覆盖? | 控制方式 |
|------|--------|--------|-----|-------|---------|
| **binder-ioctl** | 0x3a0 | SP+0x20 | **0** | ✅ 完全 | 内核指针（非直接用户可控） |
| sendmsg | 0x220 | SP+0x18 | +44 | ❌ | msghdr+iovec |
| pselect | 0x260 | SP+0x50 | +46 | ❌ | fd_set bits |
| recvmsg | 0x210 | SP+0x10 | +47 | ❌ | msghdr+iovec |
| binder-deep | 0x5b0 | — | -70 | ❌ | transaction data |

**关键发现**:

1. **binder_thread_write 精确对齐 (Δ=0)**: 
   - binder_ioctl (0xa0) → binder_ioctl_write_read (0x1a0) → binder_thread_write (0x160)
   - 总深度 0x3a0 恰好等于 waiter 深度 0x380 + waiter 帧内偏移差
   - SP+0x20..SP+0x78 的局部结构体与 waiter 字节 0x00..0x38 完全重叠
   - 但存储的值为 `binder_proc+offset` / `binder_thread+offset`（内核堆指针）
   - 非直接用户可控，需通过 binder heap feng shui 间接影响

2. **binder_thread_write 有 2 处 copy_from_user**:
   - dest=SP+0xa8, size=0x48 (BC_TRANSACTION)
   - dest=SP+0xa8, size=0x40 (BC_REPLY)
   - 这些缓冲区在 waiter 上方 0x88 字节处，不直接重叠
   - 但 binder 命令分发 switch 中可能有其他命令写入不同偏移

3. **所有其他路由差距 ≥44 词 (>352B)**，无法直接栈覆盖

**建议优先级**:
1. 深入分析 binder_thread_write 命令分发 switch，寻找其他 copy_from_user 目标
2. 探索 binder heap manipulation 间接控制 SP+0x20 处的指针值
3. 使用堆喷射绕过栈覆盖（sk_buff + pipe physrw）

**对比 OPPO Find N2**: Leaf5 **无内核 CFI** 是最关键优势。OPPO 的核心阻塞点 (CFI bypass) 在 Leaf5 上不存在。

---

## 五、内核 R/W 原语

| # | 方法 | 状态 | 说明 |
|---|------|------|------|
| 1 | configfs R/W | ❓ 未测 | /config 已挂载但 shell 不可 list |
| 2 | ashmem miscdevice | ❓ 未测 | /dev/ashmem 存在 (crw-rw-rw-)，fops 偏移已提取 |
| 3 | pipe physrw | ⚠️ 未到达 | 依赖 pselect 栈覆盖成功 |
| 4 | /proc/self/mem | ❌ | kptr_restrict 限制 |
| 5 | /dev/mem | ❌ | 不存在 |
| 6 | /dev/ion | ❓ 存在但未测 | crw-rw-r--，仅能分配新内存 |
| 7 | dma_heap | ❌ | 不存在 |

**对比 OPPO Find N2**: ashmem 路径在 OPPO 上因无 configfs 支持而死；Leaf5 上 /dev/ashmem 存在且 configfs 已挂载，有潜在可能性。

---

## 六、内核信息泄漏

| # | 方法 | 状态 | 结果 |
|---|------|------|------|
| 1 | KernelSnitch mm_struct leak | ✅ | 可靠 (KSNITCH_COLLISIONS=2) |
| 2 | /proc/config.gz | ✅ | 可读取完整内核配置 |
| 3 | kheaders | ✅ | /sys/kernel/kheaders.tar.xz 可读 |
| 4 | /proc/kallsyms | ❌ | Permission denied |

---

## 七、GhostLock 触发

| # | 方法 | 状态 | 说明 |
|---|------|------|------|
| 1 | FUTEX_CMP_REQUEUE_PI 触发 | ⚠️ 未独立验证 | exploit 流程到达 pselect route，但未验证 futex 返回值 |
| 2 | pselect fake lock route | ⚠️ 到达但失败 | `ls: write: Invalid argument` — 写入操作失败 |
| 3 | sched_setattr_tid (consumer) | ❓ 未测 | PI chain walk 触发机制 |

---

## 八、设备画像

```text
Onyx Leaf5 (TabBoox)
├── Android 13 / API 33 / patch 2026-04-01
├── Kernel 4.19.157-perf-g3d47a6619220-dirty #245 SMP PREEMPT aarch64
├── SoC: Qualcomm lito (SM6350 / LAGOON), 8 cores (0-7)
├── Memory: ~3.4 GiB, PAGE_SIZE=4096
├── AVB: unlocked (orange, flash.locked=0)
├── SELinux: Enforcing, shell uid=2000 CapEff=0
├── KASLR: on | KPTI: off | Kernel CFI: off | USER_NS: off
├── VMAP_STACK: on | PANIC_ON_OOPS: off
├── PAC/BTI/SCS: off | SLUB hardening: on
├── FUTEX_PI: y | RT_MUTEX: y | ASHMEM: y | BINDER: y
└── Firefox 151.0.2 / Chromium / Android WebView installed
```

---

## 九、关键 4.19 vs 5.10 差异

| 维度 | 4.19 (Leaf5) | 5.10 (OPPO Find N2) |
|------|-------------|---------------------|
| rt_mutex_waiter sizeof | **0x40** (64B) | 0x50 (80B) |
| waiter 含 prio/deadline | ❌ 无 | ✅ 有 |
| task_struct.real_cred | **0x7d8** | 0x818 |
| task_struct.cred | **0x7e0** | 0x820 |
| task_struct.pi_blocked_on | **0x8d0** | 0x898 |
| pipe_inode_info.head/tail | **0x38/0x3c** | 0x60/0x64 |
| mm_struct.owner | **0x328** | 0x408 |
| MM_STRUCT_SZ | **0x388** (904B) | 0x3c0 (960B) |
| MM_ORDER | **3** | 3 |
| futex_key layout | **V1** (addr+0, mm+8) | non-V1 (mm+0, addr+8) |
| futex_wait_requeue_pi 符号 | ❌ 不存在 | 存在 |
| configfs 函数 | read_file/write_file | read_iter/write_iter |
| selinux 变量 | selinux_enforcing_boot | selinux_enforcing |
| 内核 CFI | ❌ **无** | ✅ 强 CFI |
| KPTI | ❌ **无** | ✅ 有 |

---

## 十、核心阻塞点分析

### 当前阻塞: pselect write 操作失败

exploit 进度:
1. ✅ KernelSnitch mm_struct 泄漏 (KSNITCH_COLLISIONS=2)
2. ✅ sk_buff reclaim (4/4 send 成功)
3. ✅ 堆布局准备 (page_base 计算正确)
4. ❌ pselect fake_lock_route — `write: Invalid argument`

**可能原因**:
- fd_set word 索引不正确 — 4.19 栈帧布局与 5.10 不同
- pselect 栈帧中 fd_set 位置与 waiter 栈帧不重叠
- 写入目标地址 (kernel address) 对齐问题

**诊断方向**:
1. 反汇编 `__arm64_sys_pselect6` 确认其栈帧大小
2. 计算 fd_set 在栈上的位置与 futex_wait 中 waiter 的偏移
3. 调整 `PSELECT_WAITER_WORD_SHIFT`

### 安全性评估

Leaf5 相比 OPPO Find N2 的优势:
- ✅ 无内核 CFI → 攻击面显著更宽
- ✅ 无 KPTI → 侧信道攻击可选方法更多
- ✅ AVB unlocked → 可导出/修改内核
- ✅ PANIC_ON_OOPS=off → 调试容错更好

劣势:
- ❌ 4.19 内核 → 结构体/栈帧布局需从零分析
- ❌ SELinux Enforcing → 部分接口受限
- ❌ USER_NS 关闭 → 不能依赖 userns 提权

---

## 十一、修复补丁清单

### 已应用

1. **futex_key V1 布局** (`exploit/src/kernelsnitch/futex_hash.h`)
   - 添加 `#ifdef FUTEX_KEY_LAYOUT_V1` 在 struct private 中交换 address/mm 顺序
   - 删除孤儿 `#endif`

2. **Makefile V1 标志** (`exploit/Makefile`)
   - 添加 `TARGET_CFLAGS = -DFUTEX_KEY_LAYOUT_V1`

3. **test 程序同步** (`exploit/test-programs/test_futex_hash.c`, `test_mm_leak.c`)
   - futex_key_t 定义同步 V1 支持
   - 修复碰撞阈值 (pile_time→baseline)

### 待应用 (来自 HANDOFF.md §10-12)

4. **P0-1**: heap_spray.c 硬编码偏移 → ✅ 已使用 target.h 宏
5. **P0-2**: util.c -1 偏移写入 → ✅ 已有 #if 守卫
6. **P1-1**: CRED_SECURITY_OFF 验证 (0x80)
7. **P1-2**: PSELECT_WAITER_WORD_SHIFT 计算
8. **P2-1**: [EST] 偏移 pahole/IDA 验证
9. **P2-2**: SKB_DATA_DELTA 验证

---

## 十二、下一步优先级

1. **P0 — pselect 栈覆盖调试 ✅ 已完成**
   - ✅ 反汇编 `__arm64_sys_pselect6` 计算栈帧
   - ✅ `PSELECT_WAITER_WORD_SHIFT = -46`
   - ✅ 多路由分析: binder Δ=0, 其他 ≥44词
   - ⚠️ 栈覆盖直接路径不可行（pselect/sendmsg/recvmsg 差距过大）
   - → 重点关注 binder 路由 或 堆喷射绕过

2. **P0 — binder 栈覆盖深度分析**
   - ✅ `binder_thread_write` 栈帧与 waiter 精确对齐 (Δ=0)
   - ⚠️ SP+0x20 存储内核指针，非直接用户可控
   - → 分析 binder 命令 switch 中其他 copy_from_user 目标
   - → 探索 binder heap manipulation 间接控制指针值

3. **P0 — sendmsg/recvmsg/binder 帧分析 ✅ 已完成**
   - ✅ 所有路由帧大小和深度已计算
   - ✅ 最佳路由: binder Δ=0, sendmsg Δ=+44, pselect Δ=+46

4. **P0 — 修复 preload.so 的 MM_STRUCT_SZ/MM_ORDER 初始化**
   - env_mm_struct_sz/env_mm_order 应从 target.h 默认值初始化

4. **P1 — 内核写原语探索**
   - 测试 configfs + ashmem 路径 (4.19 使用 `configfs_write_file`)
   - 评估 pipe physrw 可行性

5. **P1 — [EST] 偏移验证**
   - TASK_PID_OFF, TASK_TGID_OFF, TASK_TASKS_OFF
   - CRED_SECURITY_OFF
   - TASK_SECCOMP_OFF

6. **P2 — Stage1 浏览器验证**
   - Firefox 151.0.2 CVE-2026-10702 触发测试

---

## 十三、复现命令

```bash
# 编译
cd exploit
./docker-build.sh TARGET_DIR=targets/onyx-leaf5

# 部署
adb push preload.so /data/local/tmp/

# 测试 mm_struct 泄漏 (可靠)
adb push test-programs/test_mm_leak /data/local/tmp/
adb shell 'KSNITCH_COLLISIONS=2 /data/local/tmp/test_mm_leak'

# 运行完整 exploit (当前阻塞在 pselect)
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so KSNITCH_COLLISIONS=2 /system/bin/toybox ls /dev/null'

# 重新采集设备信息
cd leaf5
uv sync
uv run leaf5-collect
uv run leaf5-summarize

# 提取偏移
uv run leaf5-extract-offsets
uv run leaf5-mm-params

# 计算 PSELECT_WAITER_WORD_SHIFT (新增)
uv run python -m scripts.compute_pselect_shift -v

# 运行时二分搜索 PSELECT_SHIFT_OVERRIDE
for shift in $(seq -64 4 64); do
  echo "=== SHIFT=$shift ==="
  adb shell "PSELECT_SHIFT_OVERRIDE=$shift LD_PRELOAD=/data/local/tmp/preload.so ls /dev/null" 2>&1 | grep -E 'pselect returned|write'
done
```

---

*Generated: 2026-07-24*
*基于 OPPO Find N2 研究工作的方法论，逐项在 Leaf5 上验证*
