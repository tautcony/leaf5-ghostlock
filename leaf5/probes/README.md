> **文档类型**: 索引 | **状态**: ✅ 有效 | **最后更新**: 2026-07-25

# probes — 设备侧探针

本目录存放 Leaf5 上验证 GhostLock / KGSL / 权限 / 栈深度 的 **C 源码**。  
**编译产物（ELF）不入库**，本地 `make` 后推送到 `/data/local/tmp` 运行。

---

## kgsl_probe/

主探针目录。默认 Makefile 目标：`kgsl_probe`（32-bit ARM static）。

```bash
cd leaf5/probes/kgsl_probe
make NDK=/path/to/android-ndk-r29
# 或 Docker（见 Makefile docker-build）
adb push kgsl_probe /data/local/tmp/
```

### 源码分组

| 类别 | 文件 | 用途 |
|------|------|------|
| 入口探针 | `kgsl_probe.c` | 早期 32-bit KGSL 兼容探测 |
| 端到端 | `ghostlock32_*.c`, `ghostlock64*.c`, `ghostlock_e2e.c`, `ghostlock_final.c`, `kgsl_ghostlock_poc.c` | GhostLock + KGSL 集成 / 暴力 / 扫描 |
| Compat 分派 | `test_compat_*.c`, `test_bypass*.c`, `test_native_bypass.c`, `test_efault_probe.c`, `test_swap_*.c` | 32-bit RB_ISSUEIBCMDS 阻塞与 workaround |
| Context / 命令 | `test_ctx_flags.c`, `test_cmd_variants.c`, `test_submit*.c`, `test_ib_flags.c`, `test_kgsl_*.c` | context 创建与 submit 路径 |
| 其它设备 | `test_drm.c`, `test_pipe*.c`, `test_fcntl.c`, `test_personality.c` | DRM / pipe / personality |
| 侧信道 | `test_kernelsnitch_minimal.c`, `test_ks_minimal.c` | Kernelsnitch 最小复现 |
| 验证 | `test_verify_cfu.c`, `test_cfu_trigger.c`, `test_offset_scan.c` | CFU 触发与偏移扫描 |

### 终局相关结果（摘要）

- **64-bit** `RB_ISSUEIBCMDS`：CFU 可触发，但与 `waiter->task` 固定偏 ~88B  
- **32-bit** `RB_ISSUEIBCMDS`：compat dispatch 拒绝（EFAULT 探针确认未进 wrapper）  
- **SUBMIT_COMMANDS**：可到达但 CFU 更浅  
- 详见仓库根 [`README.md`](../../README.md) 与 [`../PROCESS_LOG.md`](../PROCESS_LOG.md)

---

## 编译约定

- 32-bit 探针：`armv7a-linux-androideabi*-clang -static`（触发 `TIF_32BIT`）  
- 64-bit 探针：`aarch64-linux-android*-clang -static`  
- Python/分析工具在 `leaf5/scripts`（uv）；NDK 编译优先 Docker（见 `exploit/docker-build.sh`）
