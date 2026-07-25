# agents.md

# 智能体说明文档

随时参考。技术结论与路由成败以 `leaf5/stages/`、`leaf5/PROCESS_LOG.md` 为准；过程细节不在本文展开。

---

## 概述

| 项目 | 详情 |
|------|------|
| 定位 | GhostLock CVE-2026-43499 — **Onyx Leaf5 专用** 安全研究 |
| 目标机 | kernel **4.19.157** `#245`（`g3d47a6619220`） |
| 能力 | 偏移验证、探针/exploit、adb 调试、文档与 `stages/` 对齐 |
| 范围 | **仅 Leaf5**；本仓库不维护其它机型 |

### 能力边界
- ✅ 反汇编/偏移、代码、Docker NDK、adb、markdown 归档
- ❌ 破坏性操作、未授权攻击、敏感信息泄露、擅自改系统配置
- ⚠️ fastboot / 刷写 / 破坏性 `dd`：**先征得用户确认**

---

## 仓库与权威源

| 路径 | 用途 |
|------|------|
| `leaf5/stages/` | **主索引**：按阶段代码与节点成败 |
| `leaf5/PROCESS_LOG.md` | 时间线证据 |
| `leaf5/docs/` | 画像 / 偏移 / 路线矩阵 / 归档计划（参考；冲突以 stages + PROCESS_LOG 为准） |
| `leaf5/edl/` | EDL **只读**提取 boot/分区（无改镜像 / Magisk） |
| `leaf5/raw/` | config.gz、kheaders、vmlinux*（runtime 真源）；`boot_a.bin` 在 `leaf5/` |
| `exploit/targets/onyx-leaf5/target.h` | 偏移与宏的代码侧真源 |
| `leaf5/scripts/` | uv 包 `scripts.*`（shim → stages） |
| `exploit/` | 集成 exploit；**新探针优先放 stages** |
| `out/` | 编译产物：`out/exploit/`、`out/stages/`（见 `BUILD_OUTPUT.md`） |
| `pyproject.toml` / `.venv` | **仓库顶层** Python（`uv sync`） |

### 文档纪律
1. 节点成败与终局以 **`stages/*/README.md` + `PROCESS_LOG.md`** 为准。
2. 其它 markdown 若与上述冲突，**不要复述冲突中的过时结论**；需要细节时去 stages / PROCESS_LOG 查。
3. 新增结论写清证据（反汇编地址、探针命令与输出、errno）。推翻旧结论时在 stages 节点标注 **CORRECTED**。
4. 过程流水、路线探索史写在 `PROCESS_LOG` / 节点 README，**不要堆进本文件**。

### 终局（摘要）

```
前半链（泄漏 / spray / GhostLock / CFU 触发）✅
CFU 覆盖 waiter->task                         ❌ 栈布局位差
waiter->task @ KSP0 - 0x2B0
```

完整矩阵见 `leaf5/stages/README.md`。

---

## 工作方法

| 原则 | 说明 |
|------|------|
| **禁止靠猜** | 偏移、栈深度、ioctl 布局以 **vmlinux 反汇编** 或 **实机探针** 为准；kheaders / 通用源码仅作线索。 |
| **先探针后集成** | 新路径先 `stages/.../probes/*.c`，再改 `exploit/`。 |
| **常量走 target.h** | 结构体偏移、waiter 大小、MM_* 等一律 `targets/onyx-leaf5/target.h`；禁止在 `.c` 里散落魔数。 |
| **[EST] 不上关键路径** | 估计值须 capstone/实机验证后标 `[BIN]`。 |
| **对照实验** | 用 EFAULT vs EINVAL、32 vs 64、有/无 context、valid/bad ptr 区分失败层。 |
| **嵌套才累加帧** | 顺序调用的函数帧 **不** 计入 caller depth；深度算到 **KSP0** 再与 waiter 比。 |
| **文档与代码同批** | 改偏移/路由时同步 `target.h` 与对应 stages README（必要时 PROCESS_LOG）。 |

### 编译
- Python：在**仓库根** `uv sync`（`pyproject.toml` → `./.venv`）；`uv run leaf5-collect` 等
- 二进制**只**写入 `out/`，见 `BUILD_OUTPUT.md`
- **NDK：仅 Docker**（镜像 `ghostlock-build` / `exploit/Dockerfile`）。**禁止本机安装 Android NDK**。
  - exploit：`make exploit` → `docker-build`；或 `exploit/docker-build.sh`
  - stages：`make -C leaf5/stages docker-build SRC=...` / `NODE=...`
- 32-bit：`armv7a-linux-androideabi*-clang`；64-bit：`aarch64-linux-android*-clang`（容器内）
- 编辑器缺 `-DTARGET_CONFIG_H` 的诊断可忽略；以实编为准

### 提交
- 有意义修改后更新相关文档并 commit
- 格式：`<type>: <description>`（`fix` / `docs` / `feat` / `refactor` 等）

### 通信
- 对用户用 **中文**；术语保持 **English**
- 汇报：`做了什么 → 证据 → 结论 → 下一步（可选）`

---

## 常驻技术要点（Leaf5）

### 真源与镜像
- 提偏移前确认：`uname` / `boot_a.bin` banner 与 `#245`、`g3d47a6619220` 一致；不一致则 **禁止** 用该镜像。
- kheaders 与 uname build 号可能差 1：布局可参考，关键常量仍以 **vmlinux** 为准。
- `/proc/config.gz` 可读时作为 CONFIG 权威源。

### 关键常量（见 `target.h`，此处防误抄）
| 项 | 值 |
|----|-----|
| `rt_mutex_waiter` | **0x40**（无 prio/deadline） |
| `real_cred` / `cred` | **0x7d8** / **0x7e0** |
| `pi_blocked_on` | **0x8d0** |
| pipe head/tail | **0x38** / **0x3c** |
| `mm->owner` | **0x328** |
| `MM_STRUCT_SZ` / `MM_ORDER` | **0x388** / **3** |
| `futex_key` | **V1**（addr+0, mm+8）；需 `FUTEX_KEY_LAYOUT_V1` |
| pselect SHIFT | **-46**（标准 pselect 栈覆盖不可用） |

### 工具
- capstone 5.x：ARM64 `bl` / `adrp` 的 `op.imm` **常错**；手写 imm 解码。`mov wN,#imm` 一般可用。
- `MM_STRUCT_SZ`：从 `fork_init` → `kmem_cache_create_usercopy("mm_struct",…)` 跟寄存器，并用 `mm_alloc` 交叉验证。

### Agent skills / MCP（本仓库）
| 类型 | 名称 | 用途 |
|------|------|------|
| Skill | `leaf5-image-elf` | boot/EDL 提取 → Image → vmlinux-to-elf → 批量偏移（数据源闸门） |
| Skill | `leaf5-stages-workflow` | stages 纪律、探针落点、❌ 不重打 |
| Skill | `arm64-kernel-re` | vmlinux 偏移/栈深/capstone 坑（ELF 就绪后） |
| Skill | `ndk-probe-loop` | 编译→push→errno 矩阵 |
| Skill | `leaf5-check-work` | 改完自检（优先于通用 check-work） |
| MCP | `leaf5-adb` | devices / uname 闸门 / push / run_probe / logcat |
| MCP | `leaf5-vmlinux` | symbol / disasm(fix bl·adrp) / frame / CFU / waiter 比 |

配置：`.grok/config.toml`；实现：`tools/mcp/`；说明：`tools/mcp/README.md`。  
镜像/ELF 流程细节：`.grok/skills/leaf5-image-elf/`（含 `references/`）。

### 32-bit 用户态
- 内核地址用 **`uint64_t` / `ks_addr_t`**，禁止 `uintptr_t`/`size_t` 存内核指针。
- ARM32 上 `MAP_NORESERVE` 可能 EINVAL；映射尺寸勿过大。
- `cntvct_el0` 不可用 → `clock_gettime`；printf 格式与 `uint64_t` 匹配。

### KernelSnitch
- 布局以 vmlinux `get_futex_key` 为准，**不要盲信 kheaders**。
- `KSNITCH_COLLISIONS` 默认 **2**（过大假阳性高）。
- `MM_STRUCT_SZ` 错误会导致扫描步进永久偏离。
- 碰撞探测与 bruteforce 必须用 **同一** hash/layout。

### 设备与权限（常见）
| 节点 | 注意 |
|------|------|
| `/dev/kgsl-3d0` | 0666，shell 可 open |
| `/dev/qce` | qcedev 类节点；**无** `/dev/qcedev`；0660 + drmrpc/SELinux，shell 通常不可 open |
| `/dev/dri/*` | 可能 0666，仍受 SELinux/深度约束 |

### KGSL（写探针时）
- Context：`KGSL_CONTEXT_PREAMBLE \| NO_GMEM_ALLOC` → **flags = 0x12**（单 flag 不够）。
- `TIF_32BIT` 才选 16B CFU 路径；**`personality(PER_LINUX32)` 不设该位**，不能当 compat 捷径。
- ioctl type 以表为准（本机为 **0x09**）。
- `KGSL_MEMFLAGS_USE_CPU_MAP` = **0x10000000**（非 0x1000）。
- errno 分层：**ENOTTY** 未进 handler；**EINVAL** 校验失败；**EFAULT** 已到 copy_from_user。用坏指针区分是否到达 CFU。
- 具体哪条 submit 路径可达、是否盖住 task：查 **S05 kgsl 子节点 README**，勿在此复述。

### 安全面速记
- 无内核 CFI；KPTI 关；SELinux Enforcing；shell CapEff=0
- KASLR：direct-map + 已知物理加载基可算（见 target / ANALYSIS）
- bootloader unlocked 便于提镜像；**勿擅自刷写**

---

## 日常流程

```text
adb devices && uname -a          # 确认 runtime
静态：vmlinux → 偏移/深度公式
最小探针：单假设 + errno 矩阵
更新对应 stages 节点 README
再考虑 exploit/ 集成
```

```bash
# 分析
cd leaf5 && uv sync
uv run leaf5-collect
uv run leaf5-extract-offsets

# 探针
cd leaf5/stages
make SRC=<path/to/probe.c> BITS=64   # 或 BITS=32
```

### stages 约定
- 新实验放 `stages/Sxx/.../probes` 或 `analysis/`
- 节点 README：目标 → 文件 → 成败 → 原因 → 下游
- 扫描/批量结果 **落盘**，勿只写在对话里

---

## 禁止

- 未确认的破坏性操作、未授权攻击、泄露敏感信息
- 未验证镜像与 runtime 一致就提偏移
- 把过程性探索长文写进本文件或冲淡 stages 结论
- 在无新证据时重复 stages 已标 ❌ 的路径

### 兜底
1. 不确定 → `stages/README.md` + 相关节点 + `PROCESS_LOG` 终局
2. 偏移 → vmlinux + 既有 `extract_*.py`
3. 设备行为 → 最小探针 + adb
4. 权限阻塞 → 说明 SELinux/组/节点，列替代而非硬闯

---

## 开干前检查

- [ ] 看过相关 `stages` 节点 README（成败与原因）
- [ ] runtime / 镜像版本一致
- [ ] 常量来自 `target.h`，无散落魔数
- [ ] 32-bit：内核地址 `uint64_t`
- [ ] KGSL context：`flags=0x12`（若涉及）
- [ ] 栈深度：仅嵌套累加，比到 KSP0
- [ ] 结论写回 stages（或 PROCESS_LOG），非只留在对话
