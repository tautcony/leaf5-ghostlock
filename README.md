# README.md

# oppo-ghostlock

GhostLock CVE-2026-43499 — OPPO Find N2 Linux 内核提权研究

[![Version](https://img.shields.io/badge/version-1.0--research-blue)](https://github.com/pubglite55/oppo-ghostlock)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build](https://img.shields.io/badge/build-NDK%20r29-orange)]()

## 项目概述

### 项目背景

GhostLock (CVE-2026-43499) 是一个影响 Linux 2.6.39 至 7.1-rc1 的内核栈 UAF 漏洞，通过 `FUTEX_CMP_REQUEUE_PI` 竞态条件触发。本项目旨在将 NebuSec/CyberMeowfia 的 x86_64 exploit 适配到 OPPO Find N2 (ARM64, kernel 5.10.236)，实现无 root 环境下的内核提权。

### 核心痛点

- GhostLock exploit 原始实现基于 x86_64 架构，无法直接在 ARM64 设备上运行
- OPPO Find N2 内核安全配置极其严格，所有已知利用路径均被阻塞
- 缺少 root 权限和 user namespaces，无法触发需要特权的漏洞

### 适用场景

- Linux 内核安全研究与漏洞验证
- ARM64 架构 exploit 适配参考
- GhostLock (CVE-2026-43499) 漏洞利用链分析
- Android 设备内核安全评估

### 当前项目状态

**迭代中** — 多个利用阶段已验证通过，但核心阻塞点（CFI bypass / 内核写原语）尚未突破。



# GhostLock OPPO Find N2 — 所有测试方法汇总

**设备**: OPPO Find N2 (SM8475/CPH2413), kernel 5.10.236, Android 16  
**漏洞**: CVE-2026-43499 (GhostLock rtmutex stack UAF)  
**日期**: 2026-07-14  

---

## 一、已完成的阶段 ✅

| 阶段 | 状态 | 说明 |
|------|------|------|
| Firefox CVE-2026-10702 | ✅ | SpiderMonkey type confusion → AAW |
| KASLR bypass (slide) | ✅ | pselect side-channel leak nfulnl_logger |
| GhostLock FUTEX 触发 | ✅ | FUTEX_CMP_REQUEUE_PI ret=0 |
| KernelSnitch mm_struct 泄漏 | ✅ | futex hash timing, bruteforce 找到 mm_struct |
| sk_buff reclaim | ✅ | 4/4 send 成功 |
| PR #13 bypass slide | ✅ | 直接计算 kaslr_base |

---

## 二、KASLR 绕过方法（全部失败）

| # | 方法 | 状态 | 失败原因 |
|---|------|------|----------|
| 1 | pselect side-channel (boot_id leak) | ❌ | fd_set 在堆上，不在栈上 |
| 2 | Prefetch side-channel | ❌ | KPTI 启用 (CONFIG_UNMAP_KERNEL_AT_EL0=y) |
| 3 | /proc/kallsyms | ❌ | Permission denied |
| 4 | /proc/sys/kernel/kptr_restrict | ❌ | Permission denied |
| 5 | /proc/self/maps | ❌ | 只有用户态地址 |
| 6 | /proc/self/stack/wchan/syscall | ❌ | 空或无有用数据 |
| 7 | /proc/self/auxv | ❌ | 只有用户态地址 |
| 8 | /sys/kernel/debug/ | ❌ | Permission denied |
| 9 | keyctl KEYCTL_INSTANTIATE_IOV | ❌ | EOPNOTSUPP (errno=95) |
| 10 | perf_event_open | ❌ | SELinux deny |
| 11 | PR_SET_MM_MAP | ❌ | EPERM (Android blocks) |

---

## 三、CFI 绕过 / Waiter 操纵方法（全部失败）

| # | 方法 | 状态 | 失败原因 |
|---|------|------|----------|
| 12 | pselect fd_set 栈覆盖 (NFDS=320) | ❌ | waiter 在 fd_set 下方 120B |
| 13 | pselect fd_set 栈覆盖 (NFDS=321) | ❌ | kvmalloc 路径，fd_set 在堆上 |
| 14 | pselect fd_set 栈覆盖 (NFDS=344) | ❌ | kvmalloc 路径，fd_set 在堆上 |
| 15 | pselect fd_set 栈覆盖 (NFDS=640) | ❌ | kvmalloc 路径，fd_set 在堆上 |
| 16 | pselect fd_set 栈覆盖 (NFDS=1024) | ❌ | fd_set 在堆上 (bitmap_alloc) |
| 17 | pselect 栈帧重叠 | ❌ | futex_wait_requeue_pi 和 pselect 是独立调用链 |
| 18 | sendmsg 栈覆盖 | ❌ | 距 waiter 80B，不够近 |
| 19 | sendmmsg 栈覆盖 | ❌ | 距 waiter 112B，不够近 |
| 20 | binder ioctl 栈覆盖 | ❌ | EACCES (shell user 无法访问 /dev/binder) |
| 21 | poll 栈覆盖 | ❌ | pollfd 在堆上 |
| 22 | epoll_wait 栈覆盖 | ❌ | 帧太浅 (0xE0) |
| 23 | setsockopt 栈覆盖 | ❌ | 无栈上复制 |
| 24 | 堆喷射 (5轮测试) | ❌ | pselect 路径导致内核 panic |

---

## 四、内核 R/W 原语（全部失败）

| # | 方法 | 状态 | 失败原因 |
|---|------|------|----------|
| 25 | configfs R/W (ashmem SET_NAME) | ❌ | ashmem 无 configfs 支持，pread 返回 EOF |
| 26 | pipe physrw | ❌ | 依赖 configfs kernel_read/write_data |
| 27 | /proc/self/mem | ❌ | kptr_restrict 限制 |
| 28 | /dev/mem | ❌ | 不存在 |
| 29 | /dev/ion | ❌ | 只能分配新内存 |
| 30 | dma_heap | ❌ | 只能分配新内存 |

---

## 五、内核信息泄漏（部分成功）

| # | 方法 | 状态 | 结果 |
|---|------|------|------|
| 31 | KernelSnitch mm_struct leak | ✅ | mm_struct=0xffffff89807912c0 |
| 32 | PR_SET_MM_MAP auxv | ❌ | EPERM |
| 33 | /proc/config.gz | ✅ | 可读取内核配置 |

---

## 六、GhostLock 触发（成功但无法利用）

| # | 方法 | 状态 | 结果 |
|---|------|------|------|
| 34 | FUTEX_CMP_REQUEUE_PI | ✅ | ret=0，触发成功 |
| 35 | FUTEX_LOCK_PI (PI 触发) | ✅ | ret=0，触发成功 |
| 36 | sched_setattr_tid (consumer) | ✅ | PI chain walk 触发 |
| 37 | setpriority (consumer) | ✅ | PI chain walk 触发 |

---

## 七、根因总结

### 核心阻塞：没有可用的内核写原语

1. **pselect 在此内核上无法操纵 waiter 结构**（架构性原因）
   - NFDS > 336：fd_set 通过 bitmap_alloc() 分配在堆上
   - NFDS ≤ 336：futex_wait_requeue_pi 和 pselect 是独立调用链，栈帧不重叠
   - 120 字节偏移差无法通过任何 NFDS 值克服

2. **configfs/ashmem 在此内核上不支持**
   - ashmem SET_NAME 使用 strcpy 行为
   - 内核地址 LE 首字节为 NUL → 截断
   - pread 返回 EOF (errno=0)

3. **所有其他内核写入路径都被阻塞**
   - /proc/self/mem: kptr_restrict
   - /dev/mem, /dev/ion: 不存在或无任意访问
   - binder: EACCES (shell user)

### 结论

**这是一个内核安全配置问题，不是代码问题。** OPPO 5.10.236 内核的安全加固阻止了所有已知的 GhostLock 利用路径。

---

## 八、设备信息

- **Phone**: OPPO Find N2, serial=84cb96e2
- **Kernel**: 5.10.236-android12-9-o-g74d132f4467a
- **Build**: OPPO/CPH2413/CPH2413:16/UP1A.231005.007/V16.0.12.0.UNFCNXM:user/release-keys
- **CONFIG_FUTEX_PI=y** ✓
- **CONFIG_UNMAP_KERNEL_AT_EL0=y** (KPTI enabled)
- **kptr_restrict enforced** (/proc/kallsyms denied)
- **ashmem**: 无 configfs 支持

---

*Generated: 2026-07-14*





## 核心特性

- **Firefox CVE-2026-10702 exploit** — SpiderMonkey type confusion → AAW，已在设备上验证
- **KernelSnitch mm_struct 泄漏** — 通过 futex hash timing 泄漏内核地址，7-bug 修复已验证
- **GhostLock FUTEX 触发** — `FUTEX_CMP_REQUEUE_PI` ret=0，触发成功
- **sk_buff 堆喷射** — 4/4 send 成功，可用于堆布局控制
- **PR #13 KASLR bypass** — 绕过 slide，直接计算 kaslr_base
- **IDA Pro 全量偏移验证** — 70+ 内核偏移通过 output.elf 验证

## 技术栈全景

### 运行时层
- Android 16 (BP2A.250605.015)
- Linux kernel 5.10.236-android12-9-o-g74d132f4467a
- OPPO Find N2 (SM8475/CPH2413)

### 核心机制层
- GhostLock (CVE-2026-43499) rtmutex stack UAF
- FUTEX_CMP_REQUEUE_PI 竞态触发
- KernelSnitch futex hash timing 泄漏
- pselect fd_set 栈覆盖 / 堆喷射

### 工具链层
- Android NDK r29 (`aarch64-linux-android35-clang`)
- IDA Pro (output.elf.i64, MCP port 13337)
- pahole (结构体偏移验证)
- adb (设备调试)

### 依赖库层
- NebuSec/CyberMeowfia exploit 框架
- Firefox 151 (CVE-2026-10702)

## 快速开始

### 环境要求

- macOS / Linux (需要 Android NDK)
- Android NDK r29
- OPPO Find N2 设备 (serial=84cb96e2)
- Firefox 151 (用于 Stage 1)

### 安装部署

```bash
# 1. 克隆仓库
git clone https://github.com/pubglite55/oppo-ghostlock.git
cd oppo-ghostlock

# 2. 设置 NDK 路径
export NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK

# 3. 编译 exploit
cd exploit/
make clean && make NDK=$NDK

# 4. 推送到设备
adb push preload.so /data/local/tmp/
```

### 启动运行

```bash
# 运行 exploit
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1

# 验证成功: 输出 "preload starting pid=..." 表示加载成功
```

### 最简使用示例

```bash
# 编译
cd exploit/ && make clean && make NDK=/usr/local/Caskroom/android-ndk/29/AndroidNDK14206865.app/Contents/NDK

# 部署
adb push preload.so /data/local/tmp/

# 运行
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/ls /dev/null' 2>&1
```

## 仓库目录结构

```
oppo-ghostlock/
├── exploit/                          # 核心 exploit 代码
│   ├── src/
│   │   ├── main.c                    # 主入口，GhostLock 触发
│   │   ├── fops.c                    # pselect fake lock route + kernel base leak
│   │   ├── pipe.c                    # pipe 物理读写
│   │   ├── root.c                    # root 提权
│   │   ├── slide.c                   # KASLR bypass (已弃用)
│   │   ├── util.c                    # 工具函数 (text_addr, configfs)
│   │   ├── kernelsnitch/             # KernelSnitch mm_struct 泄漏
│   │   │   ├── kernelsnitch.h        # KernelSnitch 头文件
│   │   │   └── futex_hash.h          # futex hash 修复
│   │   └── targets/
│   │       └── oppo-find_n2/
│   │           └── target.h          # OPPO Find N2 偏移量定义
│   ├── Makefile                      # 编译脚本
│   └── out/                          # 编译输出
├── docs/                             # 文档目录
│   ├── architecture.md               # 架构设计文档
│   ├── setup.md                      # 环境搭建文档
│   ├── best-practice.md              # 开发最佳实践
│   └── knowledge-notes.md            # 技术知识沉淀
├── test-programs/                    # 测试程序
├── analysis-scripts/                 # 分析脚本
├── AGENTS.md                         # 智能体说明
├── TESTED_METHODS.md                 # 所有测试方法汇总
├── TROUBLESHOOTING.md                # 问题排查手册
├── FAQ.md                            # 常见问题
├── CHANGELOG.md                      # 版本更新日志
├── handoff.md                        # 项目交接文档
├── 问题描述.md                        # 项目问题梳理
└── README.md                         # 本文件
```

## 文档导航

- [架构设计文档](docs/architecture.md) — exploit chain 设计与实现
- [环境搭建文档](docs/setup.md) — 开发环境配置与部署
- [开发最佳实践](docs/best-practice.md) — 代码规范与核心原理
- [技术知识沉淀](docs/knowledge-notes.md) — 内核结构体与漏洞机制
- [问题排查手册](TROUBLESHOOTING.md) — 全量问题排查指南
- [常见问题](FAQ.md) — 高频问题速查
- [版本更新日志](CHANGELOG.md) — 项目迭代记录
- [项目交接文档](handoff.md) — 标准交接文档
- [智能体说明](AGENTS.md) — 智能体指令文档
- [所有测试方法](TESTED_METHODS.md) — 56+ 方法完整记录
- [项目问题梳理](问题描述.md) — 问题清单与状态

## 开源协议

本项目采用 MIT 协议。

## 致谢/参考

- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) — GhostLock exploit 原始实现
- [NebuSec IonStack Writeup](https://nebusec.ai/research/ionstack-part-2/) — GhostLock 技术分析
- [Dere3046/ElevateMe](https://github.com/Dere3046/ElevateMe) — rb_erase cred 覆写机制
- 52pojie OnePlus 13T 适配帖 — 偏移分类方法论
- brszzz.github.io 技术博客 — 内核符号还原方法
