# agents.md

# 智能体说明文档

> 本文档同时服务 **Claude / Grok / 其它智能体**。  
> 下半部分「踩坑与经验」提炼自 2026-07-24～25 在本仓库的多轮分析 session；**先读终局，再动手**。

---

## 智能体概述

| 项目 | 详情 |
|------|------|
| 定位 | GhostLock CVE-2026-43499 — **Onyx Leaf5 专用** 安全研究智能体 |
| 核心能力 | 内核漏洞分析、偏移验证（capstone/IDA）、探针/exploit 调试、adb 实机验证 |
| 适用场景 | Leaf5 (kernel **4.19.157** `#245`) 适配评估；**本仓库不包含其它机型** |
| 终局状态 | 前半链（泄漏 / spray / GhostLock / KGSL CFU 触发）✅；**CFU 覆盖 `waiter->task` ❌**（栈布局位差）；完成度 ~70% |

## 角色设定

### 身份定义
- 安全研究助手，专注 Leaf5 上 GhostLock 利用链分析与验证
- 擅长：vmlinux 反汇编偏移提取、路由深度精算、最小探针迭代、文档与 `stages/` 对齐

### 能力边界
- ✅ 支持: 反汇编/偏移验证、代码编写、Docker NDK 编译、adb 设备调试、markdown 结论归档
- ❌ 禁止: 破坏性操作、未经授权的攻击、敏感信息泄露、修改系统配置
- ⚠️ 重启进 fastboot / 刷写分区 / 破坏性 `dd`：**必须先征得用户确认**

## 仓库范围与权威源

| 路径 | 内容 | 权威性 |
|------|------|--------|
| `leaf5/stages/` | **按利用顺序的代码与节点效果（主索引）** | 节点成败以各 `README.md` 为准 |
| `leaf5/PROCESS_LOG.md` | 时间线证据、步骤编号 | **终局与历史操作的权威过程** |
| `leaf5/NEXT_STEPS.md` | 路线矩阵 / 剩余方向 | 含历史乐观估计；**与终局冲突时以 PROCESS_LOG + stages 为准** |
| `leaf5/VERIFICATION_REPORT.md` | 验证快照（含已修 bug） | 历史有效；导航见文首 |
| `leaf5/ANALYSIS.md` / `STACK_LAYOUT.md` | 画像与栈布局细节 | 分析参考 |
| `leaf5/scripts/` | uv CLI **shim** → `stages/S*/scripts/` | 实现改 stages 侧 |
| `exploit/` | Leaf5 专用 exploit（`targets/onyx-leaf5`） | 集成链；探针优先放 stages |
| `leaf5/raw/` | config.gz、kheaders、vmlinux*、boot_a.bin | **runtime 真源** |

### 文档冲突处理（必读）

1. **终局优先**：标准 CFU 覆盖链因栈布局在 Leaf5 上不可行；细节见 `PROCESS_LOG.md` 步骤 40–44 与 `stages/README.md`。
2. 中途文档里出现过的「qcedev 完美覆盖」「32-bit CFU 完美重叠」「KGSL shell 不可行」等**中间结论**，多数已被后续步骤修正或推翻——**禁止把中间结论当终局复述**。
3. 历史文档可保留作审计，但新增结论必须写清日期、证据路径（vmlinux 地址 / 探针输出 / adb 日志）。

### 终局数字（写进脑子）

```
waiter->task @ KSP0 - 0x2B0
64-bit KGSL CFU   @ ~KSP0 - 0x228   （太浅 ~88B）
32-bit 理论 CFU   @ ~KSP0 - 0x2A0+  （更深；但 RB_ISSUEIBCMDS compat 路径不可达）
```

---

## 核心指令集

### 工作方法论（session 最大教训）

| 原则 | 说明 |
|------|------|
| **禁止靠猜** | 用户明确要求：不得用「可能/大概」替代二进制证据。偏移、深度、ioctl 布局必须以 **vmlinux 反汇编** 或 **实机探针** 验证。 |
| **先最小探针，再集成** | 新路径先写 `stages/.../probes/*.c` 单点验证，再改 `exploit/`。避免一次改整条链后无法定位失败点。 |
| **对照 OPPO 做差分，不要盲抄** | OPPO Find N2 是 5.10 参考实现；Leaf5 是 **4.19**。结构体大小、字段、栈帧、符号名、默认宏都可能不同。从 OPPO 拷来的硬编码 = 高概率 P0。 |
| **结论可逆：写证据** | 每个「可行/不可行」必须附：命令、errno、地址或帧公式。后来推翻旧结论时**显式标注 CORRECTED**，并改 stages README。 |
| **假阳性要主动制造对照** | 例：EFAULT vs EINVAL 探针区分「handler 是否到达」；有/无 context；valid/bad ptr。 |
| **不要过早宣布路线死亡** | 多次「确定性结论」被下一轮推翻（GPU flags=0x12、设备节点名、compat 深度累加错误）。宣布关闭前至少做：源码/freedreno 对照、穷举 flags/cmd、64 vs 32 对照。 |
| **文档与代码同批次更新** | 改偏移/路由后同步 `target.h`、相关 stages README、`PROCESS_LOG`（必要时）。避免 HANDOFF 写了修复却代码未改的历史问题。 |

### 编译规则
- Python：`cd leaf5 && uv sync`；入口见 `leaf5/pyproject.toml`（`leaf5-collect`、`leaf5-extract-offsets`、`leaf5-mm-params` 等）
- NDK：**优先 Docker**（`exploit/docker-build.sh`）；探针见 `leaf5/stages/Makefile`
- 32-bit：`armv7a-linux-androideabi*-clang`（`-static` 或 `-pie`）；64-bit：`aarch64-linux-android*-clang`
- 产物：`stages/build/`、`exploit` 输出 **不入库**
- 编辑器 LSP 缺 `-DTARGET_CONFIG_H` 的红线可忽略；以 **Docker 实编** 为准

### 提交规范
- 有意义的修改后：更新相关文档并 `git commit`
- Commit message：`<type>: <description>`（如 `fix:` / `docs:` / `feat:` / `refactor:`）
- 大范围移动文件后检查：相对链接、shim 路径、`stages` 索引

### 通信规范
- 与用户沟通使用 **中文**
- 技术术语保持 **English**（CFU、waiter、TIF_32BIT、ioctl 等）
- 汇报结构建议：`做了什么 → 证据 → 结论 → 下一步（可选）`

---

## 调用方式

### 触发场景
- 内核偏移验证 / 栈深度精算
- exploit / 探针编写与 adb 调试
- 路由可行性复盘、文档对齐、`stages` 归档

### 输入期望
- 明确任务、相关路径、成功判据（例如「ret=0 且覆盖 task」）
- 涉及设备操作时说明 adb 是否已连接

### 输出期望
- 可复现命令 + 关键输出摘要
- 代码 diff 说明（改了什么、为何）
- 结论写入/更新的 markdown 路径
- 与终局或既有结论冲突时**显式对照**

---

## 禁止的行为
- 未经确认的破坏性操作（`rm -rf` 用户数据、强制刷机、丢弃未提交工作等）
- 未经授权的攻击或扩大攻击面
- 敏感信息泄露
- 把 **OPPO 5.10 偏移** 静默写回 Leaf5 路径
- 在未验证 boot/vmlinux 与 runtime 一致时，把仓库旧镜像当偏移真源
- 输出 exploit PoC 武器化细节用于未授权目标（本仓库研究范围仅限已授权 Leaf5 设备）

### 兜底策略
1. 不确定 → 先读 `leaf5/stages/README.md` + `PROCESS_LOG.md` 终局节
2. 偏移/布局 → `vmlinux.elf` + capstone / 已有 `extract_*.py`，禁止纯头文件猜
3. 设备行为 → 最小 C 探针 + adb，禁止只靠静态「应该」
4. 权限不够 → 明确告知阻塞点（SELinux / 组 / 节点权限），列替代路由而非硬闯

---

# 踩坑与经验手册（Claude sessions 提炼）

以下条目均在本仓库真实踩过；**新 agent 应默认已知**。

## 0. 环境与真源

| 坑 | 正确做法 |
|----|----------|
| 仓库里旧 `boot.img` / 旧 banner 与 runtime 不一致 | 以设备 `uname` 与 `boot_a.bin` strings 的 `#245` / `g3d47a6619220` 对齐；不对齐则 **禁止** 用该镜像提偏移 |
| kheaders build 号与 uname 差 1（#244 vs #245） | 可参考布局，但关键常量仍以 **vmlinux 反汇编** 为准 |
| `/proc/config.gz` 可读 | 配置权威源；不要用通用 defconfig 推断 FUTEX_PI / VMAP_STACK 等 |
| shell `dd` boot 分区 Permission denied | 拉 boot 需 unlocked + 用户确认的 fastboot/其它路径；不要死磕 shell dd |
| 旧 leaf5 文档曾被判定不准确 | 用户要求从零采集；**不要恢复 git 历史旧结论当真理** |

## 1. 4.19 vs 5.10（从 OPPO 迁移时的必查表）

| 维度 | Leaf5 4.19 | OPPO 5.10 量级（对照） | 失配后果 |
|------|------------|----------------------|----------|
| `rt_mutex_waiter` | **0x40**，无 prio/deadline | 0x50，有额外字段 | spray/fake waiter 写穿或写错字段 |
| `task_struct` cred | real_cred **0x7d8** / cred **0x7e0** | 更大偏移 | 提权链写错 |
| `pi_blocked_on` | **0x8d0** | 0x898 量级 | redirect 完全无效 |
| `pipe_inode_info` head/tail | **0x38/0x3c** | 0x60/0x64 量级 | pipe 原语失败 |
| `mm->owner` | **0x328** | 0x408 量级 | 泄漏后利用偏移错 |
| `MM_STRUCT_SZ` | **0x388** | 常见 0x3c0 | KernelSnitch 步长错 → **永远扫不中** |
| `MM_ORDER` | **3** | 视配置 | 扫描对齐错 |
| `futex_key` 布局 | 二进制为 **V1**（addr+0, mm+8） | 常 non-V1 | 碰撞有、bruteforce 永不匹配 |
| `futex_wait_requeue_pi` 符号 | 可能内联进 `do_futex` | 独立符号 | 按符号找帧会 miss |
| pselect 栈 | SHIFT=**-46**（waiter 更深） | 旧 exploit 假定可重叠 | `write: Invalid argument` |

**规则**：`heap_spray.c` / `util.c` / `common.h` **禁止硬编码 5.10 常量**；一律走 `targets/onyx-leaf5/target.h`，且标记 `[BIN]`/`[EST]`。

## 2. 工具链坑

### capstone 5.x ARM64
- `bl` / `adrp` 的 `op.imm` **经常是错的**（内部编码而非目标地址）
- **做法**：手写 `decode_bl_target()` / `decode_adrp_page()`；`mov wN, #imm` 的 imm 一般可用
- 提取 `MM_STRUCT_SZ`：跟 `fork_init` → `kmem_cache_create_usercopy("mm_struct", size, ...)` 的 `w1`，并用 `mm_alloc` 的 `memset` 交叉验证

### 偏移标记纪律
- `[EST]` 不得当最终值进 exploit 关键路径
- 批量 capstone 验证后升级 `[BIN]`；本仓库曾 CORRECTED：`TASK_PID_OFF`、`TASK_SECCOMP_OFF`、`CRED_SECURITY_OFF`、`FAKE_TASK_PI_*` 等
- `CRED_SECURITY_OFF` 在 4.19 极易指到错误字段——必须反汇编验证

### Docker / 32-bit 移植
- ARM32 上 **`uintptr_t` / `size_t` 只有 32 位**，内核地址必须用 **`uint64_t` / `ks_addr_t`**
- `MAP_NORESERVE` 在 ARM32 可能 EINVAL → 用 `MAP_ANON|MAP_PRIVATE`
- ARM32 地址空间紧：FUTEX 映射尺寸要从 512MB 量级降到可承受（如 128MB）
- 避免用粗糙 `sed` 批量改类型：曾打乱 `kernelsnitch_setup` 初始化顺序导致 SIGSEGV
- 打印：`%zx` 配 `uint64_t` 会炸；类型与格式串一起改，或临时关 verbose
- `cntvct_el0` 在 32-bit 用户态不可用 → `timeutils` 回退 `clock_gettime`

## 3. KernelSnitch / 堆喷

| 现象 | 根因 | 修复/经验 |
|------|------|-----------|
| 碰撞侧信道强，bruteforce 0 命中 | 用户态 hash 与内核 `futex_key` 布局不一致；kheaders 可能 **骗你** | 以 **vmlinux 反汇编 `get_futex_key`** 为准；启用 `FUTEX_KEY_LAYOUT_V1` |
| `MM_STRUCT_SZ=0x3c0` | 抄 5.10/common 默认 | **0x388**；差 56B → 扫描步进永久偏移 |
| `KSNITCH_COLLISIONS` 大 | 假阳性 25–40% | **默认 2** 才稳定；越大越找不到 |
| preload `mm_struct sz (0)` | 全局未用 target 默认初始化 | 初始化 `env_mm_struct_sz/order`，或 env 注入 |
| sk_buff reclaim 依赖 `SKB_DATA_DELTA` | 偏移错则 payload 写飞 | 泄漏过了再调 delta；先确认 page_base |
| 碰撞用错误 hash、匹配用正确 hash | 自相矛盾的双路径 | 全链路统一 layout 与 jhash 常数 |

**技巧**：不要猜 layout——加诊断输出「差多远」（hash bucket 偏差、最佳匹配分数），再用 `search_params.py` 在设备上搜。

## 4. 栈覆盖路由

### 深度计算（反复踩坑）
- **顺序调用的帧不累加**。compat 路径上 `security_file_ioctl` / `do_ioctl_trans` / `ioctl_preallocate` 是 sequential，不是 nested。  
  曾误估 compat 额外 **0xA0**，实为约 **0x30**。
- 公式要落到 **KSP0 绝对偏移** 再与 `waiter->task` 比，而不是只比「本帧 SP+X」。
- 中间帧（如 `kgsl_drawobj_cmd_add_ibdesc`）可能存在也可能被另一 ioctl 跳过（`SUBMIT` vs `RB_ISSUEIBCMDS`）——**按实际 call graph 加**，不要按名字猜。

### 设备节点与权限
| 期望 | 现实 |
|------|------|
| `/dev/qcedev` | **不存在**；驱动绑在 `1de0000.qcedev`，节点常为 **`/dev/qce` (234:0)** |
| `/dev/qce` | `0660 system:drmrpc` + SELinux；shell/Firefox **不可直接 open** |
| `/dev/kgsl-3d0` | **0666**，shell 可 open — 主候选设备 |
| `/dev/dri/card0`、`renderD128` | 也是 0666，但 SELinux/深度另论 |
| `/dev/ipa`、loop、gpio 等 | 不存在或 root-only |

访问 `/dev/qce` 的间接路径（binder 蹭 drmrpc、fd 泄漏、setuid 二进制等）在 session 中 **穷举失败**——不要无新证据重复同一条死路。

### pselect
- 4.19 上 `PSELECT_WAITER_WORD_SHIFT = -46`：waiter 在 fd_set **下方**，标准 pselect 路由 **关闭**
- 仍写 5.10 的 prio/deadline 字段会污染错误栈词

## 5. KGSL 专题（耗时最长的 session 群）

### 5.1 已确认可用
- Open `/dev/kgsl-3d0` ✅
- **DRAWCTXT_CREATE flags = `0x12`**（`PREAMBLE|NO_GMEM_ALLOC`）✅  
  - 分别试 `0x02` / `0x10` 会失败；**组合才过**（freedreno: modern kernels require both）
- GhostLock 竞态（`FUTEX_CMP_REQUEUE_PI ret=1`）在 32-bit 最小 PoC 上 ✅
- 64-bit 路径可触发 RB_ISSUEIBCMDS CFU（ret=0），但 **盖不到 task**（~88B 浅）

### 5.2 废案与误判（勿复活）

| 想法 | 结果 | 原因 |
|------|------|------|
| `personality(PER_LINUX32)` 触发 compat CFU | ❌ **废案** | 只改 personality，**不设 `TIF_32BIT`**；ioctl 行为不变 |
| 「GPU 锁屏/低功耗导致 context 失败」 | ❌ 误判 | 解锁后 `gpubusy` 升高仍失败；真因是 flags |
| 「shell 永远无法建 context / 需 libEGL」 | ⚠️ 过早死亡声明 | flags=0x12 后 shell 可建 context；后续阻塞在 submit/compat |
| `KGSL_MEMFLAGS_USE_CPU_MAP = 0x1000` | ❌ | 真值 **`0x10000000`**（bit 28） |
| GPUMEM_ALLOC / MAP_USER_MEM | EOPNOTSUPP | 本机不支持传统 gpumem 路径 |
| 32-bit `RB_ISSUEIBCMDS` (NR=0x10) | ❌ | compat dispatch 在 wrapper **之前** EINVAL；EFAULT 探针证明 handler 未到 |
| 字段 swap workaround 修 compat | ❌ | 根因不在用户态可补的字段映射（或 dispatch 层直接拒） |
| 用 direction/size 穷举绕 NR=0x10 | ❌ | 全 EINVAL；对比 NR=0x3d SUBMIT 可成功 |

### 5.3 TIF_32BIT 与 CFU 路径
- `kgsl_drawobj_cmd_add_ibdesc_list` 用 `thread_info.flags` bit22（`TIF_32BIT`）选：
  - 置位：16B CFU @ SP+0x28（ theoretically 贴 task）
  - 未置位：32B CFU @ 更浅位置
- **只有真正的 32-bit 进程** 才置位；64-bit + personality 不行
- 32-bit 进程却走不通 RB_ISSUEIBCMDS compat；64-bit 走得通但位置不够 → **核心矛盾**

### 5.4 ioctl 调试技巧
- **ENOTTY** = 未进 handler / 表项空；**EINVAL** = 已分派但校验失败；**EFAULT** = 已到 copy_from_user
- 用 bad pointer 区分「是否到达 CFU」：若永远 EINVAL 而非 EFAULT，问题在更早的 dispatch/校验
- type 位：KGSL 表用 type **`0x09`**，不是 `'K'(0x4B)` 想当然
- 64-bit 调 **compat 大小的 cmd**（如 `0xc0140910`）可能「误打误撞」进 fallback handler；native size cmd 反而 EINVAL——以反汇编与表为准，不要只信头文件宏
- Context 创建成功 ≠ submit 成功；submit 前确认 `idr_find` 能拿到 context、flags 不被 `0x402` 等检查杀掉

## 6. 实机调试流程（推荐）

```text
1. adb devices && uname -a          # 确认 #245
2. 静态：vmlinux 反汇编出偏移/深度   # 写公式
3. 最小探针：只测一个 ioctl/一个假设
4. 对照矩阵：32 vs 64、有/无 context、valid/bad ptr
5. 记录 errno 矩阵 → 更新 stages 节点 README
6. 再考虑并入 exploit/
```

编译探针示例：
```bash
cd leaf5/stages
make SRC=S05-stack-overwrite/routes/07-kgsl/e-rb-issueibcmds-64/probes/ghostlock64_opt.c BITS=64
make SRC=.../probes/foo.c deploy   # 若 Makefile 支持
```

分析脚本：
```bash
cd leaf5 && uv sync
uv run leaf5-collect
uv run leaf5-extract-offsets
uv run leaf5-mm-params
```

## 7. 文档与 stages 约定

- **主索引**：`leaf5/stages/README.md`（S00–S07 + S05 路由矩阵）
- 新实验代码优先落入对应 `stages/Sxx/.../probes` 或 `analysis/`，并在该节点 README 写：
  - 目标 → 文件清单 → **成功/失败** → 原因 → 下游依赖
- `leaf5/scripts/*.py` 仅为兼容 shim；逻辑改动改 `stages/S*/scripts/`
- 全局 CFU 扫描结果要 **落盘**（历史曾只写在 ANALYSIS 描述里导致无法复核）
- 与终局冲突的旧段落：文首加导航警告，或标注「历史乐观估计」

## 8. 安全面速记（Leaf5 相对 OPPO 的优势/限制）

| 项 | Leaf5 |
|----|--------|
| 内核 CFI | **无**（无需 CFI bypass） |
| KPTI | **关** |
| KASLR | direct-map + 已知 `P0_KERNEL_PHYS_LOAD` 可算，**不必** pselect 侧信道 |
| AVB / bootloader | unlocked（orange）— 利于提镜像，仍勿擅自刷写 |
| SELinux | Enforcing；shell CapEff=0 |
| PANIC_ON_OOPS | off — 调试容错较好，仍避免无意义 panic 实验 |
| USER_NS | 关 |
| VMAP_STACK | 开 |

## 9. 剩余方向（若继续）

仅当用户要求推进时考虑；均 **未** 在标准链上打通 task 覆盖：

- 非标准深度操纵（额外嵌套、特殊 syscall 加深度）——`routes/09-alt-syscall-depth` 已试多种，无自然覆盖
- 其它 FULL CFU 但权限阻塞的设备（qce/ipa/loop）— 需新的权限原语
- 非 CFU 的 waiter 操纵或其它原语 — 超出当前 stages 主线

**不要**在没有新静态/动态证据时，重复已关闭的 pselect / personality / 32-bit RB_ISSUEIBCMDS / 无 flags 的 context 创建。

---

## 检查清单（开干前 30 秒）

- [ ] 读过 `stages/README.md` 终局矩阵与相关节点 README  
- [ ] 确认设备 kernel 仍为 4.19.157 `#245` / 镜像一致  
- [ ] 不从 OPPO target 复制偏移，只参考思路  
- [ ] 32-bit 代码审计：内核地址是否 `uint64_t`  
- [ ] KGSL context 是否使用 `flags=0x12`  
- [ ] 栈深度是否按「嵌套才累加」重算到 KSP0  
- [ ] 结论是否写回 markdown，并与旧结论冲突处已标注  

---

*最后整理: 2026-07-25 — 汇总会话踩坑、误判与可复用技巧。技术终局以 `leaf5/PROCESS_LOG.md` 与 `leaf5/stages/` 为准。*
