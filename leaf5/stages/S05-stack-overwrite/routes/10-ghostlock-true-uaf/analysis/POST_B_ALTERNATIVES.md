# Outcome B 之后：基于已达成原语的其它提权方向

> **日期**: 2026-07-26  
> **前提**: 路由 10 **终局 B** 已关闭「shell + shaped pselect → `ashmem_misc.fops`」矩阵。  
> **目的**: 在 **不重打已关闭 SHIFT/shape 行** 的前提下，枚举仍可能吃到已有能力的路径。  
> **权威冲突时**: 以本节点 README + `PROCESS_LOG` §51–§53 为准。

---

## 0. 已经拿到的原语（可复用资产）

| 资产 | 阶段 | 能力 | 不能直接做什么 |
|------|------|------|----------------|
| runtime / `vmlinux` 对齐 | S00–S01 | 全部偏移 `[BIN]` | — |
| `mm_struct` 泄漏 | S02 | 定向堆/对象地址、KASLR 相关推算 | 单独不提权 |
| sk_buff spray | S03 | 堆占位 | 无写原语时无法消费成 physrw |
| EDEADLK errno=35 | S04/S05-10 | victim `pi_blocked_on` 悬空 priming | ret=1 requeue ≠ 本原语 |
| 栈槽 reclaim | pselect / adjtimex | **控制 residual waiter 内容**（4A） | 控制内容 ≠ 任意地址写 |
| consumer 解引用 | `sched_setattr` 等 | 0x41 → panic；shaped → 常 success=1 | success≠store；fops CFI 全 22 |
| 无 CFI / 无 KPTI | CONFIG | 函数指针劫持后无 CFI 障碍 | 仍需先有写 |
| ashmem 0666 | 设备 | open / pwrite oracle | fops 未被改时只是普通 ashmem |
| S07 源码 | exploit | fops→pipe physrw→cred 流水线 | **未点燃** |

```text
已有 = 「可塑形的栈 UAF 对象」+「可触发的 PI walk 消费」+「地址泄漏」
缺的 = 「对安全敏感槽位的可证明 store」→ 才能接 S07
```

---

## 1. 不要再做的事（无新理论）

| 路径 | 原因 |
|------|------|
| SHIFT 13–17 × LOCK_SHAPE 0–2 同构矩阵 | §53 终局 B 已关 |
| `lock = ashmem_misc.fops−8` 当 wait_lock | name 槽 trylock 失败路径已证 |
| 旧 live CFU 盖 `waiter->task`（KGSL/binder/…） | 布局/权限关闭（S05-01–09） |
| 指望 `sched_setattr success=1` 当写成功 | 已否证 |
| USER_NS / 经典容器逃逸 | `CONFIG_USER_NS=n` |
| DirtyPipe / io_uring | 4.19 无对应代码面 |

---

## 2. 方向总表（可行性粗排）

| ID | 方向 | 依赖已有 | 新工作量 | 可行性（研究判断） | 阻塞 |
|----|------|----------|----------|-------------------|------|
| **A** | 同 UAF：换 **写 gadget / 写目标**（非 fops 或非当前 rb 几何） | EDEADLK+reclaim+consumer | 中：静态 store 清单 + 新 oracle | **最高（仍吃 GhostLock）** | 需新二进制几何 |
| **B** | 同 UAF：换 **consumer**（非 `sched_setattr`） | 同上 | 中：xref `pi_blocked_on` | 中高 | 路径可能更窄/更脆 |
| **C** | residual.`task` = **spray fake task_struct** → 间接改 cred / pi 树 | reclaim + spray | 高 | 中 | 布局与锁正确性极难 |
| **D** | 任意 store **oracle**（`init_uts_ns` / 可读 `.data`）先证明写再瞄准 | 同 A | 低–中 | 中高（验证手段） | 只是方法论，不自动 root |
| **E** | 受限写打 **字符串/策略槽**（`modprobe_path`/`core_pattern`/…） | 任意 指针或字节写 | 中 | **低（Android）** | SELinux/无 usermodehelper 触发 |
| **F** | BPF / perf 独立原语 | 泄漏可选 | 高 | **未知→先探针** | SELinux 可能直接拒 `bpf` |
| **G** | 其它驱动/ syscall LPE（KGSL 非 CFU、binder、…） | 设备面 | 很高 | 未知 | 新漏洞研究 |
| **H** | 授权改镜像（Magisk / 刷写 / EDL 写） | unlocked BL | 运维 | **工程可行** | **需用户明确授权** |
| **I** | 堆交叉缓存把栈 UAF 变成 slab UAF | VMAP_STACK | 很高 | 低 | 栈页难与 kmalloc 交叉 |

---

## 3. 方向展开

### A — 继续 GhostLock：换写 gadget / 写目标（优先）

**已失败的是「特定 craft → 特定槽」**，不是「PI walk 永不写内存」。

已知 4.19 链路上至少存在这些 **store 语义**（源码级，Leaf5 需对 `rt_mutex_adjust_prio_chain` / `rb_erase` / `plist` **再扫 store**）：

| 机制 | 典型效果 | 与现有 craft 关系 |
|------|----------|-------------------|
| `rb_erase` / `__rb_change_child` | 把 child 指针写入 parent 槽 | 现 fops 路径；shape0 未命中目标 |
| `rt_mutex_dequeue` / enqueue | 改 lock 的 waiter 树 | 依赖 residual.lock 可 trylock |
| prio / `pi_top_task` 更新 | 写 task 调度字段 |  alone 不够 root |
| owner / `lock->owner` 相关 | 指针写 | 需合法 lock 对象 |

**可尝试的新理论（需 [BIN] 后再探针，禁止盲扫 SHIFT）**：

1. **换写目标（同一 gadget）**  
   - 不选 `ashmem_misc+0x10`，而选：  
     - 其它 shell 可 `open` 的 `miscdevice.fops`（先枚举 `/dev` 0666 + 对应 `.data` 符号）；  
     - `init_task` 上 **对齐良好的指针槽**（`real_cred`/`cred` 在 `+0x7d8/+0x7e0`——若 gadget 只能写「树槽」则不一定够用）；  
     - 已喷出的 **pipe buffer / sk_buff 内指针**（地址来自 S02/S03），把「一次指针写」落在堆对象上再二次利用。  
   - Leaf5 符号已存在：`modprobe_path`、`poweroff_cmd`、`core_pattern`（见 vmlinux）——**见方向 E**。

2. **换 rb/PI 几何（新 shape，不是 0/1/2 微调）**  
   - 例如：多 waiter 链、只走 `pi_waiters` 半边、利用 `mark_wakeup_next_waiter` 的 store。  
   - 必须先 **反汇编** 出「唯一一次可控 `str` 的地址表达式」，再写探针。

3. **二次写**  
   - shape1 已证明可往 **spray 上的 fake_lock** 方向走 walk；若能证明 spray 页上出现预期 qword，可再把该页当作「已知内容内核缓冲」接第二 gadget（仍缺第一次可证明 store 的 oracle → 接 **D**）。

**验收**：任意一次对已知内核地址的 **读回差异**（见 D），再接到 S07 或直接 `cred`。

---

### B — 换 consumer（仍用悬空 `pi_blocked_on`）

`pi_blocked_on` 不只被 `sched_setattr` 碰。Leaf5 相关符号（nm）：

| 符号 | VA（kimage 未滑） | 备注 |
|------|-------------------|------|
| `rt_mutex_adjust_pi` | `0xffffff8008149e00` | 较短入口 |
| `rt_mutex_adjust_prio_chain` | `0xffffff8008149eb0` | 主 chain |
| `task_blocks_on_rt_mutex` | `0xffffff800814ab50` | 设置/使用 |
| `mark_wakeup_next_waiter` | `0xffffff800814a7a8` | wake 路径 |
| `futex_lock_pi` | `0xffffff800818f680` | 用户态 PI lock |

**研究步骤**：

1. 在 vmlinux 上找 **load** `task+0x8d0` 的站点；  
2. 每条路径列 **后续 store** 与所需 residual 不变量；  
3. 最小探针：EDEADLK → reclaim 固定 pattern → 只触发该 syscall → 观察 panic / 存活 / 副作用。

**可能收益**：不同路径对 `waiter->lock` / trylock 要求更松，或 store 对齐不同目标。

---

### C — fake `task_struct`（popsicle 风格 T5 变体）

popsicle 在 6.12 上 T5 可 **direct `init_cred`**。Leaf5 当前 craft 默认 `task_ptr = INIT_TASK`（见 `fops.c`），**并没有**验证「fake task → 改 current->cred」闭环。

思路：

1. 堆 spray 可控页，布局伪 `task_struct`（至少 `pi_lock`、`pi_blocked_on`、`prio`、`cred` 邻域）；  
2. residual.word6 = spray 地址；  
3. walk 时对 fake task 的写 **别名** 到真实 `current` 或 `init_cred` 槽。

**难点**：4.19 `task_struct` 巨大；`pi_lock` raw_spinlock 必须过关；一点不对即 panic（已有 0x41 对照）。  
**值得做的最小证伪**：spray 地址进入 residual.task 后，是否 **可稳定存活** 且 **某个已知字段被改**（D 类 oracle）。

---

### D — Store oracle（方法论，强烈建议先于乱改 shape）

CFI `pwrite` errno=22 **只**证明 ashmem fops 未换成 configfs 路径，**不**证明「内核零写」。

更灵敏的 oracle 候选：

| Oracle | 方法 | 备注 |
|--------|------|------|
| `init_uts_ns` 名称 | 写后 `uname` 变化 | Project Zero 类手法；符号在 `target.h` 有 `INIT_UTS_NS_OFF` |
| 自有 spray 页 | 写前后用户态可读映射内容（若 phys 同页可验） | 需确认 spray 与写目标别名 |
| 受控 panic PC/FAR | 0x41 对照已证明解引用 | 仅证明读，不证明目标写 |
| 自定义 `.data` 哨兵 | 若存在 shell 可读 sysfs | Android 上少 |

**建议**：任选 A/B 新 gadget 时，**第一目标改为可观测槽**，再瞄准 fops/cred。

---

### E — `modprobe_path` / `core_pattern` / `poweroff_cmd`

vmlinux 存在：

- `modprobe_path` @ `0xffffff800b82bdc8`
- `poweroff_cmd` @ `0xffffff800b82b8d8`
- `core_pattern` @ `0xffffff800b85a6e0`

在桌面 Linux 上，**任意写字符串** 可走 usermodehelper / core_pipe 提权。  
在 **Android 13 + SELinux Enforcing + 无模块热插** 场景：

- 多数设备 **不会** 从 shell 触发 `call_usermodehelper(modprobe)`；  
- `core_pattern` 写后仍要能产生 core 且策略允许 pipe；  
- sysctl 节点本身对 shell 常 **Permission denied**（`sysctl_probe.txt`）。

→ 仅当已有 **任意写** 且能构造触发面时再评估；**不应作为第一优先**。

---

### F — BPF / perf（独立面，与 GhostLock 并行）

设备画像：

| 项 | 值 | 含义 |
|----|-----|------|
| `unprivileged_bpf_disabled` | **0** | 内核未全局关非特权 BPF |
| `CONFIG_BPF_SYSCALL` | y | 有 syscall |
| `CONFIG_USER_NS` | **n** | 无 userns 辅助逃逸 |
| `perf_event_paranoid` | **-1** | 异常宽松 |
| SELinux | Enforcing | **很可能** 拒 shell 的 `bpf`/`perf_event_open` |

**最小探针（stages 新节点，勿塞进路由 10 写矩阵）**：

```text
bpf(BPF_PROG_LOAD, ...)  → errno?
perf_event_open(...)     → errno?
```

- 若 SELinux/EINVAL 直接杀 → 记 ❌，不深挖。  
- 若意外可达 → 另开 S0x 做 BPF 利用研究（与 GhostLock 脱钩，工作量大）。

---

### G — 其它漏洞 / 驱动面

| 面 | shell 可达性 | 与已有链关系 | 备注 |
|----|--------------|--------------|------|
| KGSL | `/dev/kgsl-3d0` 0666 | 旧 **栈 CFU 盖 task** 已关 | 仍可能有 **独立** GPU/内存漏洞，属新项目 |
| binder | 受 SELinux | 数据非用户可控（S05-02） | 旧结论勿重打 |
| ION | 存在，shell open 拒 | 无 | 需 system 上下文 |
| qcedev/qce | drmrpc | 栈深度 theoretically 好但权限 ❌ | 勿硬闯 |
| DRM/sde | 可能 0666 | 旧「深度过深」 | 仅当新深度公式针对 **UAF residual** 时才相关 |

无公开「只靠 mm 泄漏」的通用 LPE；**泄漏是加速器，不是 root**。

---

### H — 授权工程路径（非漏洞链）

| 操作 | 条件 | 效果 |
|------|------|------|
| Magisk / 自定义 boot | 用户确认；BL unlocked | 直接 root |
| fastboot flash | 用户确认 | 同左 |
| EDL **写** 分区 | 用户确认（现 edl 仅只读） | 同左 |

这与 CVE 利用无关，但是 **已有 EDL 读 + unlocked** 下唯一「确定性」提权。

---

### I — 栈页交叉缓存

`CONFIG_VMAP_STACK=y`：内核栈在 **vmalloc** 空间，与 kmalloc-32/64 交叉回收 **极难**。  
不推荐作为主路径。

---

## 4. 推荐研究顺序（可执行）

```text
1) D：给 exploit 加「非 CFI」oracle（init_uts_ns 或 spray 哨兵）
2) A：反汇编 adjust_prio_chain / rb_erase 全 store → 列 1–2 个新目标地址表达式
3) B：pi_blocked_on load 站点表 → 1 个新 consumer 探针
4) C：fake_task 最小存活 + 字段变化（依赖 D）
5) F：bpf/perf errno 一探针定生死
6) H：若研究时间耗尽且用户要 root → 授权刷写
```

**明确不排期**：重跑终局 B 矩阵；无新 VA 的 SHIFT 二分。

---

## 5. 与 exploit 代码的衔接

| 已有模块 | 新方向怎么用 |
|----------|----------------|
| `main.c` EDEADLK 编排 | 所有 A–C 复用 |
| `fops.c` pselect paint | 改 words[] / 目标宏；加 oracle |
| `heap_spray.c` / `pipe.c` | C 与「写到 pipe_buf」类目标 |
| `root.c` / physrw | 仅当 D 证明写成功后启用 |
| `kgsl_route.c` | 不接 UAF 写链；仅独立漏洞时用 |

---

## 6. 结论

- **最有希望继续「漏洞利用」的**：在已证明的 **栈 UAF + 可控 residual + PI consumer** 上，换 **store 几何/目标/consumer**，并用 **更好的 oracle** 证明写。  
- **不要** 在 ashmem fops 同一假设上重复矩阵。  
- **并行低成本**：BPF/perf 可达性探针；结果多半被 SELinux 否决。  
- **确定性 root**：仅 **用户授权** 的镜像/Magisk 路径。  
- **其它 CVE/驱动**：开放但等于新项目，不能算作「GhostLock 链还差一步」。
