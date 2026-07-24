# Heap Spray Bypass — GhostLock 堆喷射绕过分析

**日期**: 2026-07-24
**状态**: 代码完整但被循环依赖阻塞

---

## 一、核心发现：循环依赖（Bootstrap Problem）

```
heap_spray.c:redirect_pi_blocked_on()
  → pipe_write64() → pipe_phys_write_data()
    → kernel_write_data() → configfs_write_once()
      → 需要 fops hijack (CFI stage) → try_cfi_stage()
        → 需要 pselect 栈覆盖 → PSELECT_WAITER_WORD_SHIFT = -46
          → **阻塞点** — Leaf5 4.19 不可行
```

**所有内核读写路径最终汇集到 pselect 栈覆盖路由。**

## 二、已确认工作

| 组件 | 状态 | 说明 |
|------|------|------|
| KernelSnitch mm_struct 泄漏 | ✅ | KSNITCH_COLLISIONS=2，<1秒可靠泄漏 |
| sk_buff 喷射 + 回收 | ✅ | 4/4 send 成功 (ret=65536) |
| KASLR 绕过 | ✅ | direct-map 直接计算 |
| GhostLock 触发 | ✅ | FUTEX_WAIT_REQUEUE_PI → CMP_REQUEUE_PI → 悬垂waiter |

## 三、代码评估

- **heap_spray.c (318行)**: 逻辑完整正确。fake waiter 构建、pi_blocked_on 重定向、PI 触发函数均正确，仅需工作的 pipe physrw。
- **fake waiter 大小**: heap_spray.c 使用 0x50 (5.10 布局)，4.19 仅需 0x40。额外的 prio/deadline 字段被无害忽略。
- **pipe.c (1723行)**: pipe physrw 实现复杂但正确。`install_pipe_physrw()` 需要 configfs/ashmem R/W 作为前置条件。
- **util.c `prepare_skb_payload()`**: fake lock (LOCK_OFF=0x1350)、fake waiter (W0_OFF=0x2220)、fake task (FAKE_TASK_OFF=0x3200)、fake fops table (FOPS_TABLE_OFF=0x1000) 均在喷射页上正确构建。
- **main.c `consumer_thread()`**: 已有 heap spray 集成代码 (L99-130)，但因 `install_pipe_physrw()` 返回 0 而不可达。

## 四、替代 R/W 原语探索

| 原语 | 可用? | 说明 |
|------|-------|------|
| /dev/ashmem fops hijack | ❌ 阻塞 | 需要 CFI stage |
| pipe physrw | ❌ 阻塞 | 需要 configfs/ashmem R/W |
| /dev/ion | ❓ 未知 | 需检查 Leaf5 上是否存在 |
| /dev/mem, /dev/kmem | ❌ 不可能 | 生产内核已移除/限制 |
| Binder copy_from_user 目标 | ❌ 不在范围 | 均在 waiter 范围之外 |
| Debug 文件系统 | ❌ 不存在 | CONFIG_DEBUG_FS=n |
| perf_event_open | ❌ 受限 | SELinux 拦截 |

## 五、解除阻塞的路径

1. **Binder 间接控制**: `binder_thread_write` Δ=0 完美对齐，但 SP+0x20 存储内核指针。需深入 binder 结构分析是否可通过 ioctl 间接控制。

2. **全局 copy_from_user 扫描**: 系统扫描 vmlinux.elf 中所有函数的 copy_from_user 目标，寻找与 waiter 重叠的路径。

3. **直接 pi_blocked_on 操纵**: GhostLock 漏洞本身能否直接写入可控值到 `pi_blocked_on`？当前内核代码总是写入内核自己的 waiter 指针。

## 六、两个子方向

### 6a. 绕过 pselect 直接建立 configfs/ashmem R/W

如果 GhostLock 悬垂 waiter 的 `lock` 字段（恰好是 futex PI 链在 futex_wait 返回后保留的有效值）能以某种方式定向到可控内存，则不需要 pselect 栈覆盖。

### 6b. 非 configfs 内核写原语

探索不依赖 configfs 的写路径：
- `/dev/ion` ioctl 能否写入任意物理地址？
- `binder_transaction` 能否通过精心构造的 transaction 触发内核写？
- `/proc/sys/net/core/wmem_max` 等 sysctl 能否触发对特定地址的写？

## 七、结论

**堆喷射方法是完整利用链的最终阶段，但不是起点。** 必须先解决 configfs/ashmem 内核 R/W 的 bootstrap 问题。这需要：
- 找到一个可行的栈覆盖路由（binder 间接控制 或 全局扫描发现新路径）
- 或 发现一个不依赖 configfs 的替代内核写原语
