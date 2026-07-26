# 验证记录：第二条件 / 独立 CVE 闸门（2026-07-26）

> **runtime**: `#245` `g3d47a6619220` match（`adb_uname_check`）  
> **清单源**: [`SECOND_BUG_AND_CVE_CANDIDATES.md`](SECOND_BUG_AND_CVE_CANDIDATES.md)  
> **本轮范围**: S1 设备触达 + fops 符号；P0 Binder 静态；P0 KGSL 符号/触达  
> **非本轮**: 武器化 PoC、重打终局 B 矩阵

---

## 摘要

| 项 | 结果 | 下一步 |
|----|------|--------|
| **S1** shell 可 open 写目标面 | **部分 ✅**：kgsl/uhid/uinput/binder/null/zero/urandom/ptmx 等 R/W OK；qce/diag/dri/vndbinder **FAIL**；ion **仅 R** | 优先评估 **kgsl 设备对象** / uhid 邻接；ashmem 终局 B 已关 |
| **S1** fops 符号 | ✅ 齐全（见下表） | BSS 运行时填充；静态 dump `ashmem_misc` 全 0 不可靠 |
| **Q5 / CVE-2024-46740** | ⚠️ **未证明已修**；`binder_alloc_copy_user_to_buffer` 路径在；无独立 `binder_validate_object` | 需最小 offsets-overwrite 触发探针（另开，勿混 GhostLock） |
| **Q5 / CVE-2023-20938** | ⚠️ 仅有 `binder_transaction_buffer_release`；校验是否合入 **未证** | 同上，单独 patch-gap 探针 |
| **Q1 / CVE-2024-23380 VBO 族** | ❌ **无 VBO 符号**（本树无 VBO 子系统） | **不**按 23380 复现；改看 **sparse/gpuobj/timeline** 面 |
| **Q1 KGSL 触达** | ✅ `/dev/kgsl-3d0` shell **R+W OK**；ioctl 符号丰富 | 独立 LPE 研究优先面 |
| **U1 vendor.perfservice** | ✅ `service list` 可见 | Context+ 候选保留 |
| BPF（复测背景） | ❌ EACCES | 仍关闭 |

---

## 1. S1 — shell 设备触达矩阵

### 1.1 方法

- `adb_uname_check` 通过。  
- 对候选节点：`(: <"$d")` / `(: >"$d")` 测 open（非 `dd`）。  
- 同步 `ls -lZ`。  
- **注意**: 本测是 **shell 重定向 open**；与 native `open(2)` 在 SELinux 上通常一致，但 ashmem 出现异常 FAIL（见下），以历史 C 探针为准。

### 1.2 结果

| 节点 | mode/owner | SELinux type | R | W | 备注 |
|------|------------|--------------|---|---|------|
| `/dev/kgsl-3d0` | 666 system:system | `gpu_device` | OK | OK | **P0 独立面** |
| `/dev/uhid` | 660 uhid:uhid | `uhid_device` | OK | OK | shell 在 uhid 组 |
| `/dev/uinput` | 660 uhid:uhid | `uhid_device` | OK | OK | 同上 |
| `/dev/binder` | symlink | `binder_device` | OK | OK | binderfs |
| `/dev/hwbinder` | symlink | `hwbinder_device` | OK | OK | |
| `/dev/vndbinder` | symlink | `vndbinder_device` | FAIL | FAIL | SELinux |
| `/dev/null` `/dev/zero` | 666 | null/zero | OK | OK | fops 在 `.text` 常量，作写目标价值低 |
| `/dev/urandom` `/dev/random` | 666 | random | OK | OK | 同上 |
| `/dev/ptmx` | 666 | ptmx | OK | OK | |
| `/dev/ion` | 664 system:system | `ion_device` | OK | **FAIL** | 只读 open；写需 Context+ |
| `/dev/adsprpc-smd` | 664 system | `vendor_qdsp_device` | OK | FAIL | FastRPC 入口；写拒 |
| `/dev/adsprpc-smd-secure` | 644 system | `vendor_xdsp_device` | FAIL | FAIL | |
| `/dev/msm_npu` | 644 system | `vendor_npu_device` | OK | FAIL | |
| `/dev/qce` | 660 system:drmrpc | `vendor_qce_device` | FAIL | FAIL | 与 stages 权限结论一致 |
| `/dev/diag` | 660 system:vendor_qti_diag | `vendor_diag_device` | FAIL | FAIL | |
| `/dev/dri/card0` `renderD128` | 666 root:graphics | `graphics_device` | FAIL | FAIL | mode 宽，SELinux 拒 shell |
| `/dev/ashmem` | 666 | `ashmem_device` | FAIL* | FAIL* | *shell 重定向 FAIL；**历史 C 探针/exploit 可 open** — 以 native 为准 |
| `/dev/full` `/dev/tty` | 666 | | FAIL | FAIL | |

### 1.3 fops / 设备对象符号 [BIN]

| 符号 | VA | 用途 |
|------|-----|------|
| `ashmem_fops` | `0xffffff8009a285d0` | ashmem 操作表 |
| `ashmem_misc` | `0xffffff800b970f68` | miscdevice（ELF BSS 静态全 0，**运行时**填 fops） |
| `kgsl_fops` | `0xffffff80099d2050` | KGSL |
| `kgsl_driver` | `0xffffff800b8da580` | 驱动全局（大结构） |
| `uhid_fops` | `0xffffff8009a24380` | |
| `uinput_fops` | `0xffffff8009a08a48` | |
| `evdev_fops` | `0xffffff8009a01a70` | input event* |
| `binder_fops` | `0xffffff8009a49300` | |
| `qcedev_fops` | `0xffffff80099ddf20` | 触达 ❌ |
| `ion_fops` | `0xffffff8009a28030` | 写触达 ❌ |
| `zero_fops` / `null_fops` / `full_fops` | `…99becf0` 等 | 邻接作 rb 目标通常无「可观测 hijack」 |

**S1 思路落地结论**

1. 终局 B 已排除 ashmem fops−8 邻接；**不要**再扫 ashmem SHIFT。  
2. 仍吃 GhostLock 时，更值得做 **runtime 读回** 的是：  
   - 能 open 且 hijack 后有 **用户态可观测副作用** 的对象（优先 **kgsl** 相关可写指针，需 [BIN] 定位 `file->f_op` 或 device 内嵌指针，而非盲猜 BSS）；  
   - 或 **S2** 堆上 pipe/skb（地址来自 S02/S03）。  
3. `zero`/`null` fops 可 open，但改 fops 后缺少「像 configfs ashmem」那样干净的用户态 oracle → **低优先**。

---

## 2. Q5 / Binder — CVE 静态

### 2.1 面

| 项 | 状态 |
|----|------|
| `CONFIG_ANDROID_BINDER_IPC` | y（既有） |
| shell open binder/hwbinder | ✅ |
| `binder_transaction` | `0xffffff8008dce258` |
| `binder_transaction_buffer_release` | `0xffffff8008dcd8a0`（约 0x9b8 字节） |
| `binder_alloc_copy_user_to_buffer` | `0xffffff8008dd7260` |
| 独立 `binder_validate_object` / `binder_get_object` | **无符号**（可能内联） |

### 2.2 CVE-2024-46740（offsets overwrite → UAF）

**公开 fix**（`f4e5b515…`）：在 raw data `copy_user_to_buffer` 前增加  
`object_offset > tr->data_size`。

**本机观察 [BIN]**

- `binder_transaction` 内多处 `bl binder_alloc_copy_user_to_buffer`。  
- BINDER_TYPE_PTR 路径（type imm `0x70742a85`）在 `0xffffff8008dcfdb0` 调用 copy 前有：  
  `sub x8,x9,x8` → `cmp x4,x8` → `b.hi` 失败路径 — **存在某种长度上界**，但是否等价于 fix 的 `object_offset > data_size` **未能静态证明**。  
- 镜像字符串 **无** `object offset exceeds`（fix 未必加字符串）。  
- 基线版本 **4.19.157** 远早于 2024-08 fix；SPL `2026-04-01` **可能** cherry-pick，**不能**当已修证据。

**判定**: ⚠️ **surface 在 + 触达在 + 未证明已修** → 保留 P0；下一步 = **最小 binder offsets 触发探针**（独立节点，非 GhostLock 矩阵）。

### 2.3 CVE-2023-20938（buffer release / PTR 校验）

- 有完整 `binder_transaction_buffer_release`。  
- 无独立 validate 符号；是否含 AOSP 补丁需对照 fix 的关键分支（parent/offset 检查）。  
**判定**: ⚠️ 同属 **待 PoC/对照**；优先级略低于 46740（46740 在野讨论与公告更近、条件更清晰）。

### 2.4 与 GhostLock 联用

- Binder **独立 LPE（I）** 或 **任意读（L）** 后接 GhostLock 写。  
- **不要**重开 S05-02「binder 作 CFU 盖 waiter」死路。

---

## 3. Q1 / KGSL — CVE 静态

### 3.1 触达

| 项 | 状态 |
|----|------|
| `/dev/kgsl-3d0` shell R+W | ✅ |
| `CONFIG_QCOM_KGSL` | y |
| 旧 S05-07 CFU 盖 task | ❌ 布局关闭（**不重打**） |

### 3.2 CVE-2024-23380（VBO）族

| 检查 | 结果 |
|------|------|
| 符号名含 `vbo`（kgsl） | **0** |
| `gpuobj_*` ioctl | ✅ alloc/free/import/info/sync |
| `sparse_*` | ✅ phys/virt alloc/free、`kgsl_sparse_bind`、`kgsl_ioctl_sparse_bind` |
| timeline / drawobj / syncsource | ✅ 大量符号 |

**判定**: **CVE-2024-23380 及「VBO 新内存管理」路径在本 4.19 树不存在** → 标 ❌ 对该 CVE 编号。  
**但** sparse/gpuobj/timeline 构成 **另一套** 历史富矿；应改为「KGSL 通用 ioctl 面审计 / 其它 QC bulletin CVE」，**不要**死磕 23380 PoC。

### 3.3 其它 GPU 在野（21480 等）

- 偏 **GPU 固件 / micronode**；本轮 **未** 取固件版本。  
- 状态：仍为清单 P1，**未验证**。

---

## 4. Context+ 抽样

| 项 | 结果 |
|----|------|
| `service list` 行数 | ~230 |
| `vendor.perfservice` | **在**（`com.qualcomm.qti.IPerfManager`） |
| media / SurfaceFlinger / gpu / power / installd | 在 |
| adsprpc 设备 | 只读或拒写 |

→ U1 仍有效；未做 `service call` 探测（避免误触）。

---

## 5. 更新后的优先序（本轮后）

```text
P0a  KGSL 独立（sparse/gpuobj/timeline 审计；非 23380 VBO）
P0b  Binder CVE-2024-46740 最小触发 / patch 对照深化
P1   GhostLock S2（写到 spray pipe/skb）+ S7 oracle
P1   vendor.perfservice / Context+（U1）
P2   GPU 固件 CVE（21480 等）— 先取版本
⛔   ashmem fops 终局 B 矩阵；VBO-23380 原样 PoC；qce/diag shell
```

---

## 6. 证据落盘

| 类型 | 位置 |
|------|------|
| 本文 | `analysis/VERIFY_2026-07-26_second_bug.md` |
| 设备 open 原始 | 本文件 §1.2（adb shell 2026-07-26） |
| binder copy 站点 | `binder_transaction` + `0xffffff8008dcfdb0` 等 [BIN] |
| kgsl 符号表 | nm 过滤 gpuobj/sparse/timeline |

---

## 7. 修订

| 日期 | 变更 |
|------|------|
| 2026-07-26 | 初版：S1 触达 + Binder/KGSL 静态闸门 |
