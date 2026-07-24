> **文档类型**: 结论文档 | **状态**: ✅ 有效 — 关键发现：qcedev_ioctl 实现完整 64B waiter 覆盖 | **最后更新**: 2026-07-24

# GhostLock Global copy_from_user Scanner Analysis

## Executive Summary

The global copy_from_user scanner successfully identified multiple kernel
functions whose user-controlled stack buffers overlap with the rt_mutex_waiter
at absolute offset [-0x380, -0x340) from kernel_stack_top. The strongest
candidates are Qualcomm ioctl handlers (qcedev_ioctl, ipa3_ioctl) which, when
called through the standard ioctl() syscall path, achieve full 64-byte waiter
coverage.

## Optimized Scanner

File: scanner.py (in this directory)

### Key Optimization

Instead of disassembling all 63,490 kernel functions with Capstone, the scanner
uses a raw binary BL instruction scan across the 55MB .kernel section to
pre-filter functions that call __arch_copy_from_user. This reduces Capstone
disassembly from 63K functions to 309 candidate functions, achieving a total
scan time of ~7.5 seconds.

### Approach

1. Phase 1: ELF Loading - Parse symbol table, build function range table
2. Phase 2: Raw BL Scan - Scan 13.7M instruction words for BL patterns
   (403,750 BL instructions found, ~2s)
3. Phase 3: CFU Caller Discovery - Find 309 unique callers of
   __arch_copy_from_user
4. Phase 4: Candidate Analysis - Disassemble each candidate with Capstone
   to extract frame_size, dest_sp_offset, copy_size
5. Phase 5: BFS from syscall entries to compute min_depth for BL-reachable
   functions (3,775 reachable)
6. Phase 6: Overlap computation at various caller depths

### Call Graph Limitation

The static BFS only follows direct BL instructions. Most kernel I/O paths use
indirect calls (function pointers via BLR/BLRAA). Only 71/724 call sites are
BFS-reachable. To compensate, the scanner estimates actual depths using known
syscall chain frame sizes.

Standard call depths (from actual frame analysis of vmlinux.elf):
  ioctl path: sys_ioctl(0x40) + ksys_ioctl(0x40) + vfs_ioctl(0x20) = 0xA0
  read path:  sys_read(0x10)  + ksys_read(0x40)  + vfs_read(0x40)  = 0x90

---

## Results Summary

| Metric                       | Value |
|------------------------------|-------|
| Candidate functions          | 309   |
| CFU call sites               | 724   |
| BFS-reachable call sites     | 71    |
| Any overlap at some depth    | 715   |
| Full waiter coverage         | 143   |

---

## Top Candidates

### 1. qcedev_ioctl (STRONGEST)

| Property    | Value                                    |
|-------------|------------------------------------------|
| Frame       | 0x360 (864 bytes)                        |
| Buffer      | SP+0x50, 328 bytes                       |
| Device      | /dev/qcedev (Qualcomm crypto engine)     |
| Reachable   | Via ioctl() syscall (indirect)           |

At standard ioctl depth (0xA0):
  dest_abs = -(0xA0 + 0x360) + 0x50 = -0x3B0
  buf_end  = -0x3B0 + 328 = -0x268
  waiter   = [-0x380, -0x340)
  coverage = FULL (64 bytes)

The 328-byte buffer provides wide tolerance: full coverage at depths 0x70-0x100.

### 2. ipa3_ioctl

| Property    | Value                                    |
|-------------|------------------------------------------|
| Frame       | 0x330 (816 bytes)                        |
| Buffer      | SP+0x30, 108 bytes                       |
| Device      | /dev/ipa (Qualcomm IP Accelerator)       |
| Reachable   | Via ioctl() syscall (indirect)           |

Full 64-byte coverage at standard ioctl depth. Narrower tolerance (0x80-0x84).

### 3. compat_qcedev_ioctl (328B copy)

| Property    | Value                                    |
|-------------|------------------------------------------|
| Frame       | 0x430 (1072 bytes)                       |
| Buffer      | SP+0x120, 328 bytes                      |
| Reachable   | Via compat_ioctl() (indirect)            |

Full coverage at standard depth (0xA0) for the 328-byte copy variant.

---

## Exploitation Strategy: qcedev_ioctl

1. Open /dev/qcedev:  fd = open("/dev/qcedev", O_RDWR)
2. Call ioctl:         ioctl(fd, QCEDEV_IOCTL_ENC_REQ, &user_arg)
3. Kernel path:        sys_ioctl -> ksys_ioctl -> vfs_ioctl
                       -> qcedev_ioctl [via f_op->unlocked_ioctl]
4. copy_from_user copies 328 bytes from user_arg to stack at SP+0x50
5. This buffer spans absolute offset [-0x3B0, -0x268)
6. The waiter at [-0x380, -0x340) is fully covered

The attacker's user_arg data overwrites the rt_mutex_waiter structure,
enabling the exploit.

---

## Key Findings

1. Qualcomm ioctl handlers are the best targets due to their large frames
   (0x330-0x430) and large stack buffers (108-328 bytes). The ioctl path
   provides consistent caller depth (~0xA0).

2. Buffer size is critical. The 328-byte buffer in qcedev_ioctl provides a
   wide coverage window (depth 0x70-0x100 for full coverage). The 68-byte
   variant only achieves 20 bytes (31%) overlap.

3. BFS reachability is misleading. The 71 BFS-reachable call sites produce
   0 actual overlaps at their min_depth. All usable candidates are reached
   via indirect calls (function pointers), invisible to static BL analysis.

4. The scanner completes in ~7.5s. The key optimization (raw BL pre-filtering)
   reduces Capstone work from 63K to 309 functions, a 200x improvement.

---

## References

- scanner.py: The optimized scanner in this directory
- ../scripts/find_waiter_overlap.py: Original (slow) full call graph scanner
- ../scripts/find_waiter_overlap2.py: Direct mathematical approach
- ../scripts/compute_stack_routes.py: 5-route comparison analysis
- raw/vmlinux.elf: Leaf5 4.19 kernel binary (55MB .kernel section)
