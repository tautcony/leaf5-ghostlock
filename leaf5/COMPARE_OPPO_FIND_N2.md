> **文档类型**: 结论文档 | **状态**: ✅ 有效 | **最后更新**: 2026-07-24

# Leaf5 vs OPPO Find N2 对比

> Leaf5 侧数据：2026-07-24 真机采集（见 [ANALYSIS.md](ANALYSIS.md)）  
> Find N2 侧数据：仓库 `README.md` / `HANDOFF.md` / `exploit/targets/oppo-find_n2/` 既有研究结论

## 1. 平台与系统

| 维度 | Onyx Leaf5 | OPPO Find N2 |
|------|------------|--------------|
| 形态 | 电纸书 / 平板类（TabBoox） | 折叠旗舰手机 |
| SoC / board | SM6350 class / **lito** | SM8475 / CPH2413 |
| Android | **13** (API 33) | **16** |
| 安全补丁（采集时） | 2026-04-01 | 2026-06-01（文档记载） |
| Kernel | **4.19.157**-perf | **5.10.236**-android12 |
| 构建特征 | onyx@onyxUbuntu, clang 10.0.7 NDK | OPPO 量产签名链 |
| AVB | **已解锁** (orange) | 典型用户设备锁定（研究机以文档为准） |
| 内存 | ~3.4 GiB | 更高（旗舰） |

## 2. 安全加固（对 exploit 影响最大）

| 机制 | Leaf5 | Find N2（仓库结论） | 适配含义 |
|------|-------|---------------------|----------|
| 内核 CFI | **关闭** | 开启且极强 | Leaf5 可能不需要 N2 那套 CFI bypass 死磕 |
| KPTI (`UNMAP_KERNEL_AT_EL0`) | **关闭** | 开启 | Leaf5 prefetch 等旁路更有希望 |
| KASLR | 开启 | 开启 | 仍需 leak |
| SELinux | Enforcing | Enforcing | 两边都要考虑 SELinux |
| USER_NS | 关闭 | 关闭 | 不能依赖 userns |
| PANIC_ON_OOPS | 关闭 | 开启（文档） | Leaf5 调试更友好 |
| UBSAN_TRAP | 未见开启 | 文档称开启 | Leaf5 slide 路径约束更少 |
| Stack protector | STRONG | 有 | 两边都有 |
| Hardened usercopy | 开启 | 开启 | 两边都有 |
| SLUB freelist harden/random | 开启 | 开启 | 堆利用需考虑 |
| PAC / BTI / SCS | 关闭 | 视配置 | Leaf5 控制流保护更弱 |
| io_uring | 关闭 | 文档称受限/已修 | Leaf5 无此路径 |

## 3. GhostLock 原语路径

| 项 | Leaf5 | Find N2 |
|----|-------|---------|
| `CONFIG_FUTEX_PI` | y | y（已验证触发） |
| `CONFIG_RT_MUTEXES` | y | y |
| 触发验证 | **未做** | ✅ ret=0 |
| 结构体时代 | **4.19 waiter 更短** | 5.10 waiter 含 prio/deadline 等 |
| 栈覆盖结论 | **未做**；禁止套用 N2 gap | pselect 等路径标记 DEAD |

## 4. 用户态入口

| 项 | Leaf5 | Find N2 |
|----|-------|---------|
| Firefox | **151.0.2** 已装 | 文档要求 151 |
| ashmem | `/dev/ashmem` 666 | 有；configfs 路径失败 |
| binder | binderfs | 有；shell 访问受限 |
| configfs | 挂载但 shell 不可 list | 有；ashmem 无 configfs 支持（文档） |

## 5. 偏移与二进制资产

| 资产 | Leaf5 | Find N2 |
|------|-------|---------|
| 与 runtime 一致的 vmlinux | **缺失**（boot 不可 dd；仓库 boot.img 版本错误） | 研究过程中有 IDA `output.elf` |
| `target.h` | **尚未创建** | `exploit/targets/oppo-find_n2/target.h` |
| KIMAGE_TEXT_BASE 等 | 未验证 | 文档/IDA 验证过 |

## 6. 策略建议（高层）

1. **不要**把 N2 的失败路径清单原样当成 Leaf5 死路——Leaf5 内核更老、加固更弱，部分 N2 死路可能“复活”，也可能因 4.19 布局出现**新**死路。  
2. **优先**补齐 Leaf5 自己的 vmlinux 与 pahole，而不是调 N2 偏移。  
3. 利用链阶段顺序建议：CONFIG 已确认 → futex 触发探针 → KASLR/mm leak → 栈布局 → 写原语；内核 CFI 步骤可降级为验证性检查。  
4. 解锁 bootloader 是 Leaf5 相对优势：应用其获取真 kernel，而不是继续分析错误的 `boot.img`。

## 7. 一句话

> Leaf5 在 **GhostLock 触发条件**上具备 CONFIG 级可行性，且在 **CFI/KPTI** 上明显弱于 Find N2；但内核 **4.19 vs 5.10** 使既有 ARM64 适配成果无法直接复用，当前最大缺口是 **与 runtime 一致的内核镜像与偏移**。
