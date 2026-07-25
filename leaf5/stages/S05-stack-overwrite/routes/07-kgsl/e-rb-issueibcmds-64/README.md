> **节点**: 64-bit RB_ISSUEIBCMDS | **状态**: ❌ 列表 CFU 过深（CORRECTED 2026-07-25）

# e — 64-bit RB_ISSUEIBCMDS

## 代码

| 文件 | 作用 | 效果 | 原因 |
|------|------|------|------|
| `probes/test_64bit.c` | 64-bit 基线 ioctl | ✅ issue 成功 | compat `0xc0140910` |
| `probes/test_ib_flags.c` | flags 组合 | ✅ | 未区分 list 位 |
| `probes/test_cfu_trigger.c` | GhostLock + crash pattern | ⚠️ 无效证据 | **flags=0 无 ibdesc CFU** |
| `probes/ghostlock64*.c` | 旧 e2e | ⚠️ 无效证据 | 同上 |
| `probes/test_list_cfu_path.c` | **list 路径 errno 矩阵** | ✅ | flags2@+0x18 bit2 → EFAULT |
| `probes/ghostlock64_list_cfu.c` | GhostLock + **真** list CFU | ❌ | 内核存活；CFU 相对 waiter 过深 |

## CORRECTED（2026-07-25 复验）

### 1. 两条 ISSUEIBCMDS 路径 [BIN]

`kgsl_ioctl_rb_issueibcmds`（vmlinux）:

| `*(u8*)(cmd+0x18)` bit2 | 调用 | ibdesc CFU |
|-------------------------|------|------------|
| 0 | `kgsl_drawobj_cmd_add_ibdesc` | **无**（仅用 cmd 字段在 rb 栈上拼局部） |
| 1 | `kgsl_drawobj_cmd_add_ibdesc_list` | **有** 0x20B @ list SP+8 |

设备矩阵（`test_list_cfu_path`）:

| 布局 | 结果 |
|------|------|
| native 0x20, flags2=0x4, bad ptr | **EFAULT**（CFU 到达） |
| native 0x20, flags=0, bad ptr | EINVAL（无 list CFU） |
| compat 0xc0140910 flags=0 good | ret=0（旧探针路径，**无** list CFU） |

### 2. WAIT_REQUEUE_PI waiter 位置 CORRECTED [BIN]

旧结论把 waiter 放在 `futex_wait` 帧（→ task @ KSP0−0x2B0）。  
**`FUTEX_WAIT_REQUEUE_PI` 在 4.19 上内联于 `do_futex`**，无独立 `futex_wait_requeue_pi` 符号。

证据：`do_futex+0x1120`：
```text
sub  x0, x29, #0xc8
bl   rt_mutex_init_waiter
```

| 项 | 值 |
|----|-----|
| waiter base | `x29 - 0xc8`（do_futex） |
| waiter->task | waiter+0x30 |
| 相对 do_futex 入口 | task @ −0xF8 |
| 相对栈顶（+`__arm64_sys_futex` 0x70） | task @ **−0x168** |

### 3. list CFU vs 正确 waiter

| 项 | 相对栈顶 |
|----|----------|
| list CFU（sys_ioctl→…→add_ibdesc_list SP+8, 0x20B） | **[−0x308, −0x328)** |
| waiter->task | **−0x168** |
| 关系 | CFU **过深 ~0x1A0** |

`ghostlock64_list_cfu`：GhostLock ret=1，list CFU EINVAL（与 EFAULT 对照一致已到 CFU），crash pattern 在 buf+0x18，**内核存活**。

## 结论

- 旧「flags=0 + crash pattern + 位差 88B」**不能**再作为关闭证据（从未 list CFU）。
- 真 list CFU **可达**，但对 WAIT_REQUEUE_PI waiter **过深**，不能盖 task。
- 标准 64-bit list 路径 **关闭**；需 **更浅** CFU（目标 ~栈顶−0x168），见 route 08 uinput 近失配与全局重扫。

## 下游

1. 以 **task @ −0x168** 重扫 shell 可达 CFU（优先 uinput：旧算 ~−0x190，差 ~0x28）。
2. 勿再跑 flags=0 的 ghostlock64_opt 当栈覆盖证据。
