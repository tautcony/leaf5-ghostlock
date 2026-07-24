# Leaf5 后续工作清单

基于 [ANALYSIS.md](ANALYSIS.md) 2026-07-24 结论。

## P0 — 获取与 runtime 一致的内核镜像

**验收标准**：镜像内 `Linux version` 字符串同时包含：

- `g3d47a6619220`
- `#245`（或与当时 `uname -a` 完全一致）

**可选路径**（需用户确认后再执行，可能重启设备）：

1. `fastboot` 拉取 / flash 读出 `boot_a`（设备已 `orange` / unlocked）
2. 厂商 OTA 包中提取与 `2026-04-21_12-49_4.2-rel_0421_19324b3ea` 匹配的 boot
3. 临时 root / 工程模式（若有）下 `dd if=/dev/block/by-name/boot_a`

**禁止**：继续用仓库根目录旧 `boot.img`（#119 / g87880838aed5）填偏移。

完成后：

```bash
./extract-vmlinux leaf5_boot.img > leaf5/raw/vmlinux
# 或直接使用 uncompressed ARM64 Image
strings leaf5/raw/vmlinux | grep 'Linux version 4.19'
```

## P1 — 符号与结构体

| 任务 | 工具 | 产出 |
|------|------|------|
| kallsyms / 符号表 | vmlinux-to-elf / IDA | `init_task`、ashmem fops、pipe ops、futex 相关 |
| 结构体偏移 | pahole + IDA | `rt_mutex_waiter`、`task_struct`、`mm_struct`、`cred` |
| VA 布局 | Image header + 源码/符号 | `KIMAGE_TEXT_BASE`、direct map、PHYS_OFFSET |
| 写入 target | 手写 | `exploit/targets/onyx-leaf5/target.h` |

`target.h` 必须包含：

```c
#define BUILD_VARIANT_LABEL "onyx_leaf5_<display_id>"
#define BUILD_FINGERPRINT "ONYX/TabBoox/..."
/* 以及经验证的 OFF 宏；每个宏旁注释验证来源：pahole/IDA/runtime */
```

## P2 — 最小运行时探针（非完整 exploit）

使用 NDK 编译小工具，`adb push` 到 `/data/local/tmp`：

1. **futex PI 烟雾测试**  
   - `FUTEX_WAIT_REQUEUE_PI` + `FUTEX_CMP_REQUEUE_PI`  
   - 记录返回值与 errno，确认非 `ENOSYS`/`EINVAL` 结构性失败  
2. **KernelSnitch 参数探测**  
   - 读取 `nr_cpu_ids`（已有 `0-7`）  
   - 在 4.19 上确认 futex hash 规模假设  
3. **KASLR 侧信道可行性**  
   - 因 KPTI=n，可重新评估 prefetch；仍受 SELinux/kptr 限制  

**不要**在无偏移验证时进行内核写或恶意覆盖。

## P3 — 栈布局专项

1. 反汇编 `do_futex` / `futex_wait_requeue_pi` / `rt_mutex` 路径，量栈帧。  
2. 枚举用户可控栈数据的 syscall（pselect、recvmsg、…）在 **4.19** 上的帧位置。  
3. 单独成文 `leaf5/STACK_LAYOUT.md`（有 vmlinux 后再写）。

## P4 — Stage1 浏览器

- 设备已装 Firefox 151.0.2。  
- 单独验证 CVE-2026-10702 是否仍可在该构建触发（与内核适配解耦）。

## P5 — 文档与仓库集成

- [ ] `exploit/targets/onyx-leaf5/target.h`（P1 完成后）
- [ ] 更新根 `README.md` 增加 Leaf5 目标说明
- [ ] Makefile / 编译时选择 target 的方式（若需要）

## 明确不做（当前阶段）

- 把 OPPO 的 DEAD END 列表直接标到 Leaf5  
- 在错误 boot.img 上跑 IDA 并提交偏移  
- 未确认栈布局前的大规模 heap spray / 写原语试验  

## 依赖安装（主机）

```bash
# Python 工具
cd leaf5 && uv sync

# 可选：结构体
# brew install pahole
# Android NDK：见 docs/setup.md
```
