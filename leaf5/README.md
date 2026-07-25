> **文档类型**: 索引文档（分析入口） | **状态**: ✅ 有效 | **最后更新**: 2026-07-25

# Leaf5 分析工作区

针对 **Onyx Leaf5** 的 GhostLock（CVE-2026-43499）适配调研。

> **文档优先级**：过程证据与终局结论以 [`PROCESS_LOG.md`](PROCESS_LOG.md) 步骤 40–44 为准。  
> 早期文档中关于「qcedev 世界可写」「32-bit KGSL CFU 完美重叠」等表述已被后续实测推翻，见下文「已关闭路径」。

---

## 结论（2026-07-25）

在 Leaf5（kernel `4.19.157-perf-g3d47a6619220-dirty` #245）上，GhostLock **标准利用链**（CFU 覆盖 stale `rt_mutex_waiter->task`）因**内核栈布局**不可行。

| 步骤 | 状态 | 备注 |
|------|------|------|
| Kernelsnitch mm 泄漏 | ✅ | KSNITCH_COLLISIONS=2，&lt;1s |
| sk_buff heap spray | ✅ | reclaim 4/4 |
| GhostLock 触发 | ✅ | FUTEX_CMP_REQUEUE_PI ret=1 |
| KGSL context / CFU 触发 | ✅ | flags=0x12；64-bit RB_ISSUEIBCMDS |
| CFU 覆盖 `waiter->task` | ❌ | 固定位差，10+ 次循环无变化 |
| fops / configfs / pipe physrw / root | ❌ | 依赖上一步 |

**完成度 ~70%**（到 CFU 触发为止）。

### 栈布局（终局）

```
KSP0 = sys_futex 入口
waiter->task @ KSP0 - 0x2B0

64-bit KGSL CFU  @ ~KSP0 - 0x228   太浅（差 ~88B）
32-bit KGSL CFU  @ ~KSP0 - 0x2A0+  太深（需 compat 帧 ∈[8,24)，不可行）
```

这是编译期帧布局，无法从用户态改变。

---

## 设备快照

| 项 | 值 |
|----|-----|
| 型号 | Onyx Leaf5（`ONYX/TabBoox/TabBoox:13/...`） |
| Android | 13 / API 33 |
| Kernel | `4.19.157-perf-g3d47a6619220-dirty` #245 SMP PREEMPT aarch64 |
| 平台 | Qualcomm lito / SM6350 (LAGOON) |
| AVB | unlocked（orange） |
| SELinux | Enforcing；shell CapEff=0 |
| GhostLock CONFIG | `FUTEX_PI=y`，**无内核 CFI**，**无 KPTI** |
| Stage1 | Firefox 151.0.2 已安装 |
| ADB | `ac340d06`（以现场为准） |

### 安全加固（相对 Find N2 的优势）

| 机制 | 状态 | 影响 |
|------|------|------|
| 内核 CFI | 关 | 无需 CFI bypass |
| KPTI | 关 | 栈/侧信道更简单 |
| KASLR | 开 | 已用 direct-map 旁路 |
| USER_NS | 关 | 不可依赖 userns |
| PANIC_ON_OOPS | 关 | 调试容错更好 |
| PAC / BTI / SCS | 关 | 控制流保护弱 |

---

## 已关闭路径

| 路径 | 结论 | 证据位置 |
|------|------|----------|
| pselect fd_set 覆盖 | ❌ SHIFT=-46 | PROCESS_LOG / STACK_LAYOUT |
| binder_thread_write | ❌ 非用户可控数据 | ghostlock-analysis/binder-commands |
| sendmsg / writev / splice 自然覆盖 | ❌ 深度不足 | PROCESS_LOG §44 |
| qcedev_ioctl | ❌ 权限（`/dev/qce` 0660 drmrpc） | PROCESS_LOG / NEXT_STEPS |
| DRM card0/renderD128 | ❌ SELinux open 拒绝 | PROCESS_LOG §39 |
| uinput | ❌ CFU 比 waiter 浅 ~352B | PROCESS_LOG §39 |
| 32-bit RB_ISSUEIBCMDS | ❌ compat dispatch 在 wrapper 前 EINVAL | PROCESS_LOG / EFAULT 探针 |
| 64-bit RB_ISSUEIBCMDS 覆盖 task | ❌ CFU 太浅 ~88B | 10+ 次 e2e |
| personality(PER_LINUX32) | ❌ 不设 TIF_32BIT | NEXT_STEPS 十二-B |

---

## 可选前进方向（未实现）

1. **非 KGSL 的 CFU**，且 shell/浏览器可到达（binder 代理 qcedev 等）
2. **加深内核栈**后再发 KGSL CFU（signal / fuse 等嵌套路径）
3. 利用 **无 CFI / 无 KPTI** 的替代攻击面（非 GhostLock 标准链）
4. 不依赖栈覆盖的新原语

详见 [`NEXT_STEPS.md`](NEXT_STEPS.md) 十二-G。

---

## 目录结构

```
leaf5/
├── README.md                 # 本文件
├── ANALYSIS.md               # 设备与配置深度分析
├── PROCESS_LOG.md            # 操作流水（权威）
├── NEXT_STEPS.md             # 路线矩阵与后续
├── VERIFICATION_REPORT.md    # 偏移/探针验证报告
├── STACK_LAYOUT.md           # 栈布局笔记
├── GHOSTLOCK_EXPLOIT_PLAN.md # 早期利用计划（部分过时）
├── COMPARE_OPPO_FIND_N2.md   # 与 Find N2 对比
├── PSELECT_STACK_ANALYSIS_PLAN.md
├── edl-backup.md / edl-printgpt.md
├── docs/
│   └── KGSL_STACK_OVERWRITE.md
├── scripts/                  # uv 管理的 Python 工具
├── probes/kgsl_probe/        # 探针源码（仅 .c / Makefile）
├── ghostlock-analysis/       # CFU 扫描、binder、do_select 等
├── raw/                      # 设备原始采集
└── pyproject.toml
```

仓库根目录 `../exploit/` 为 **Leaf5 专用** exploit 源码（`targets/onyx-leaf5`）。

---

## 工具与编译

```bash
# 分析依赖
cd leaf5 && uv sync
uv run leaf5-collect
uv run leaf5-extract-offsets

# exploit（Docker）
cd ../exploit && ./docker-build.sh

# 探针
cd probes/kgsl_probe && make   # 需 NDK；产物不入库
```

---

## 相关文档索引

| 文档 | 说明 |
|------|------|
| [PROCESS_LOG.md](PROCESS_LOG.md) | 全流程与终局证据 |
| [NEXT_STEPS.md](NEXT_STEPS.md) | 路由矩阵、已关闭项、剩余方向 |
| [ANALYSIS.md](ANALYSIS.md) | 设备画像与 CONFIG |
| [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) | 偏移验证 |
| [STACK_LAYOUT.md](STACK_LAYOUT.md) | waiter / CFU 布局 |
| [docs/KGSL_STACK_OVERWRITE.md](docs/KGSL_STACK_OVERWRITE.md) | KGSL 技术笔记（以终局为准） |
| [ghostlock-analysis/README.md](ghostlock-analysis/README.md) | 子分析入口 |
| [raw/README.md](raw/README.md) | 原始数据采集说明 |
| [probes/README.md](probes/README.md) | 探针清单 |

---

*最后更新: 2026-07-25 — 仓库整理为 Leaf5-only；标准链结论：CFU 位差不可行*
