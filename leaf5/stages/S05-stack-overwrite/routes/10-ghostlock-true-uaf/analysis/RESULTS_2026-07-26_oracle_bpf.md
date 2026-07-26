# 设备结果：非 CFI oracle + BPF/perf（2026-07-26）

runtime: `#245` `g3d47a6619220` match

## A. bpf_perf_reach

| 调用 | ret | errno | 结论 |
|------|-----|-------|------|
| `bpf(BPF_PROG_LOAD)` | -1 | **13 EACCES** | shell 不可 load |
| `bpf(BPF_MAP_CREATE)` | -1 | **13 EACCES** | shell 不可 create map |
| `perf_event_open(SW_CPU_CLOCK)` | **≥0** | 0 | **可达** |
| `perf_event_open(HW_CYCLES)` | **≥0** | 0 | **可达** |

**结论**: BPF 利用面对 shell **关闭**（SELinux/capability）。  
`perf_event_open` **意外开放**（与 `perf_event_paranoid=-1` 一致）— 可作为侧信道/采样增强，**不是**现成 LPE；若跟进需新节点，勿与 GhostLock 写矩阵混跑。

## B. ghostlock_uts_oracle

| 步骤 | 结果 |
|------|------|
| EDEADLK `CMP errno=35` | ✅ |
| WAIT `errno=110` | ✅ |
| pselect reclaim（fix zero page lock, UTS target） | ✅ ret=0（修 stdio dup2 后） |
| uname before/after **无 consumer** | `Linux` → `Linux`，**HIT=0** |
| consumer（sched 等）walk | **kernel_panic**（bootreason `kernel_panic,null`） |

**结论**:

1. 非 CFI oracle **管线可用**（采样 uname 前后）；本 craft **未**对 `sysname` 完成可观测 store。  
2. `empty_zero_page` 作 `waiter->lock` **不安全**（walk 即 panic）— 仅证明 residual 仍被解引用。  
3. 稳定 shaped walk 仍应使用 exploit **spray `fake_lock`** + `WRITE_ORACLE=uts`。

## C. exploit 集成（代码，待长跑）

```bash
# 部署 preload 后示例 env
WRITE_ORACLE=uts PI_CONSUMER=all SKIP_CFI_PROBE=1 \
  # … 既有 GhostLock 启动方式
```

- `WRITE_ORACLE=uts` → target=`data_addr(INIT_UTS_NS)+4`，value=`GLORACLE` LE  
- `PI_CONSUMER=sched_setattr|setpriority|nice|sched_setscheduler|futex_lock_pi|all`  
- uname 采样在 `do_pselect_fake_lock_route` 内
