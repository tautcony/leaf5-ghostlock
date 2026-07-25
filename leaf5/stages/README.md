> **文档类型**: 流水线索引 | **状态**: ✅ 有效 | **最后更新**: 2026-07-25（设备复测）

# Leaf5 利用 / 分析流水线（stages）

代码与文档按 **分析与利用先后顺序** 分阶段归档；同一阶段的多条候选路径以子目录并列。  
每个节点的 `README.md` 记录：**目标 → 代码清单 → 效果（成功/失败）→ 原因 → 下游依赖**。

权威时间线证据仍见 [`../PROCESS_LOG.md`](../PROCESS_LOG.md)。  
**2026-07-25 全量编译 + 设备复测**：[`../docs/REVERIFY_2026-07-25.md`](../docs/REVERIFY_2026-07-25.md)。

参考文档与归档：[`../docs/README.md`](../docs/README.md)。EDL 镜像提取：[`../edl/README.md`](../edl/README.md)。

### 代码形态说明（避免「只有文档」误解）

| 阶段/路由 | 可执行代码 | 说明 |
|-----------|------------|------|
| S00–S01 | Python | 离线/adb 采集与反汇编，无 C 探针 |
| S02 stages `probes/` | 组件 C | **完整 mm 泄漏**在 `exploit/test-programs/` |
| S03 | shell + exploit | **无** stage 本地 sk_buff C；主路径 `heap_spray.c` |
| S04 | 无本目录 `.c` | 触发嵌在 S05 `ghostlock*.c` / exploit |
| S05-01/04/06 | 分析/权限 | 无成功 PoC（结论为关闭） |
| S05-02/03/05 | Python 分析 | 静态为主 |
| S05-07–09 | C 探针 | 本轮已 Docker 编译并设备抽测 |
| S06–S07 | 映射 exploit | 无独立 stages 二进制 |

---

## 总览矩阵

| 阶段 | 目录 | 结果 | 说明 |
|------|------|------|------|
| S00 | [device-profile](S00-device-profile/) | ✅ | 设备画像、CONFIG、raw 采集 |
| S01 | [offsets-stack](S01-offsets-stack/) | ✅ | 结构体偏移、waiter 栈位置、pselect SHIFT |
| S02 | [kernelsnitch-leak](S02-kernelsnitch-leak/) | ✅ | mm_struct 泄漏 |
| S03 | [heap-spray](S03-heap-spray/) | ✅ | sk_buff reclaim |
| S04 | [ghostlock-trigger](S04-ghostlock-trigger/) | ✅ | FUTEX_CMP_REQUEUE_PI 产生 stale waiter |
| S05 | [stack-overwrite](S05-stack-overwrite/) | ❌ | **可到达 CFU 均未覆盖 task**；waiter 位 CORRECTED 见下 |
| S06 | [e2e-chain](S06-e2e-chain/) | ⚠️ | 集成链到 CFU 触发；无 fops 覆盖 |
| S07 | [post-cfu](S07-post-cfu/) | ⛔ | 依赖 S05 成功，未打通 |

### S05 路由矩阵（并列候选）

| 路由 | 路径 | 结果 | 原因 |
|------|------|------|------|
| 01 pselect | [routes/01-pselect](S05-stack-overwrite/routes/01-pselect/) | ❌ | SHIFT=-46 |
| 02 binder | [routes/02-binder](S05-stack-overwrite/routes/02-binder/) | ❌ | 对齐但数据非用户可控 |
| 03 do_select | [routes/03-do-select](S05-stack-overwrite/routes/03-do-select/) | ❌ | 无重叠 CFU |
| 04 sendmsg 系 | [routes/04-sendmsg-recvmsg](S05-stack-overwrite/routes/04-sendmsg-recvmsg/) | ❌ | 深度不足 |
| 05 全局 CFU 扫描 | [routes/05-global-cfu-scan](S05-stack-overwrite/routes/05-global-cfu-scan/) | ✅ 分析 | 发现候选；落地另见 |
| 06 qcedev | [routes/06-qcedev](S05-stack-overwrite/routes/06-qcedev/) | ❌ | 位置 theoretically 对，权限 drmrpc |
| 07 kgsl | [routes/07-kgsl](S05-stack-overwrite/routes/07-kgsl/) | ⚠️ | 见子节点；无 task 覆盖 |
| 08 其它设备 | [routes/08-alt-devices](S05-stack-overwrite/routes/08-alt-devices/) | ❌ | DRM SELinux；uinput 位差 |
| 09 加深 syscall | [routes/09-alt-syscall-depth](S05-stack-overwrite/routes/09-alt-syscall-depth/) | ❌ | writev/sendmsg/splice 无自然覆盖 |

### KGSL 子节点（07）

| 子节点 | 结果 |
|--------|------|
| a-device-access | ✅ open/ioctl 可达 |
| b-context-create | ✅ flags=0x12 |
| c-mem-alloc | ❌ EOPNOTSUPP / 非必需 |
| d-rb-issueibcmds-32 | ❌ compat dispatch 拒绝 |
| e-rb-issueibcmds-64 | ❌ list CFU 过深（旧 flags=0 证据作废；见节点 CORRECTED） |
| f-submit-bypass | ⚠️ 可达，CFU 更浅 |
| g-personality | ❌ 不设 TIF_32BIT |

---

## 编译探针

**NDK 只走 Docker**（`ghostlock-build`，与 exploit 同镜像），本机不装 NDK。  
产物写入仓库根 **`out/stages/`**，路径镜像本树 + 架构子目录（**不入库**）：

```
out/stages/<相对 stages 的源码目录>/{arm32|arm64}/<basename>
```

```bash
cd leaf5/stages
make help
make docker-build SRC=S05-stack-overwrite/routes/07-kgsl/e-rb-issueibcmds-64/probes/ghostlock64_opt.c BITS=64
# → ../../../out/stages/S05-.../probes/arm64/ghostlock64_opt

make docker-build NODE=S02-kernelsnitch-leak BITS=32   # 批量
make deploy SRC=... BITS=...                           # 本机 adb（先 docker-build）
make list-out
```

详见 [`../../../BUILD_OUTPUT.md`](../../../BUILD_OUTPUT.md)。

## 分析脚本

```bash
# 仓库根（顶层 pyproject.toml / .venv）
uv sync
uv run leaf5-collect            # → S00
uv run leaf5-extract-offsets    # → S01
```

实现文件在各 `stages/S*/scripts/`；`leaf5/scripts/*.py` 为包入口 shim。

## 与 exploit/ 对应

| 阶段 | exploit 源 |
|------|------------|
| S02 | `exploit/src/slide.c` + kernelsnitch headers |
| S03 | `exploit/src/heap_spray.c` |
| S04–S05 | `exploit/src/kgsl_route.c`, `main.c` |
| S07 | `exploit/src/fops.c`, `pipe.c`, `root.c` |

---

### CORRECTED 终局要点（2026-07-25 晚）

```
WAIT_REQUEUE_PI waiter 在 do_futex（非 futex_wait）:
  rt_mutex_init_waiter(x29 - 0xc8) → task @ stack_top - 0x168
旧「task @ KSP0-0x2B0」仅适用于 futex_wait 模型，对 GhostLock 路径作废。

KGSL list CFU（flags2@+0x18 bit2）可达但 ~stack_top-0x308，过深 ~0x1A0。
旧 flags=0 探针从未 list-CFU 拷贝 ibdesc。
```

*流水线终局：标准 GhostLock + KGSL list CFU 在 Leaf5 4.19.157 #245 上因栈深度不匹配仍不可行；下一步以 −0x168 重扫更浅 shell 可达 CFU（uinput 近失配 ~0x28）。*
