> **阶段**: S02 | **状态**: ✅ 完成 | **最后更新**: 2026-07-25（复测 CORRECTED）

# S02 — Kernelsnitch 内核地址泄漏

## 目标
通过 futex 哈希碰撞时序侧信道泄漏 `mm_struct`，并推算 direct-map / KASLR。

## 代码

### stages 探针（组件预检，**不是**完整 mm 泄漏）

| 文件 | 架构 | 作用 | 效果 | 备注 |
|------|------|------|------|------|
| `probes/test_ks_minimal.c` | 32/64 | 大 mmap + touch | ✅ 2026-07-25 | 128MB mmap OK |
| `probes/test_kernelsnitch_minimal.c` | 32/64 | mmap + 非阻塞 futex | ✅ 2026-07-25 | 勿用会阻塞的 FUTEX_WAIT |

### 真正的 mm_struct 泄漏（在 exploit 测试 / 集成路径）

| 文件 | 效果 | 复测 2026-07-25 |
|------|------|-----------------|
| `exploit/test-programs/test_futex_hash.c` | 哈希自洽 + pile-up 时序 | ✅ pile-up ~6–8× baseline |
| `exploit/test-programs/test_mm_leak.c` | 碰撞 + bruteforce | ✅ **FOUND** mm @ `0xffffff8600181c40`（`KSNITCH_COLLISIONS=2`） |
| `exploit/src/kernelsnitch/*` + `slide.c` | 生产路径 | ✅ 同参 |

```bash
# 编译（Docker）
cd exploit && ./docker-build.sh tests

# 设备
adb push out/exploit/aarch64/tests/test_mm_leak /data/local/tmp/
adb shell 'KSNITCH_COLLISIONS=2 /data/local/tmp/test_mm_leak'
```

## 结果摘要
- **`KSNITCH_COLLISIONS=2` 时可靠泄漏**（&lt;1s 量级，候选数 ~1–2k）
- 无 KPTI → 侧信道更干净
- stages 下两个 `.c` 只证明运行环境可做大 mmap/futex，**不能**单独当作「泄漏成功」证据

## 下游
→ S03 heap spray 使用泄漏的内核地址定向 reclaim。
