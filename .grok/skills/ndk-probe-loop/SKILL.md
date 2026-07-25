---
name: ndk-probe-loop
description: >
  Build, deploy, and run Leaf5 stage probes (Android NDK arm32/arm64) with
  errno-matrix discipline. Use whenever compiling probes, make SRC=, BITS=32/64,
  adb push, deploy, out/stages, Docker NDK, KGSL ioctl probes, 32-bit TIF_32BIT
  tests, or validating device behavior. Slash: /ndk-probe-loop.
---

# NDK probe loop (Leaf5)

## Goal

One hypothesis per probe binary. Build → push → run → classify errno → write node README. Prefer stage probes over editing `exploit/` first.

## Preflight

1. Device online: `adb devices` (or MCP `leaf5-adb` `adb_devices`)
2. Runtime match: `uname -a` → **#245** / **g3d47a6619220**
3. Probe path under `leaf5/stages/.../probes/*.c`
4. No magic numbers: include/use constants from `target.h` or local `#define` tied to documented values

## Build

**NDK is Docker-only** (`ghostlock-build` image). Do **not** install a host Android NDK.

From `leaf5/stages/`:

```bash
# Single probe
make docker-build SRC=S05-stack-overwrite/routes/07-kgsl/e-rb-issueibcmds-64/probes/ghostlock64_opt.c BITS=64

# Batch node
make docker-build NODE=S02-kernelsnitch-leak BITS=32

# Deploy (host adb; binary must already exist under out/)
make deploy SRC=... BITS=64
```

Outputs:

```text
out/stages/<mirror-of-src-dir>/{arm32|arm64}/<basename>
```

Integrated exploit (after stage success):

```bash
# Repo root
make exploit
# or
cd exploit && ./docker-build.sh
```

## 32-bit vs 64-bit

| BITS | Arch tag | When |
|------|----------|------|
| 32 | arm32 | TIF_32BIT / compat ioctl paths |
| 64 | arm64 | native 64-bit CFU paths |

Rules for 32-bit userspace:

- Kernel addresses: **`uint64_t` / `ks_addr_t`**, never `uintptr_t`/`size_t`
- `personality(PER_LINUX32)` does **not** set `TIF_32BIT` — do not treat it as a compat shortcut
- `MAP_NORESERVE` may return EINVAL on ARM32; avoid oversized maps
- Match printf formats to `uint64_t`

## KGSL checklist (if relevant)

- Open `/dev/kgsl-3d0` (usually 0666 for shell)
- Context flags: **`KGSL_CONTEXT_PREAMBLE | NO_GMEM_ALLOC` → 0x12** (single flag is not enough)
- ioctl type on this device: **0x09**
- `KGSL_MEMFLAGS_USE_CPU_MAP` = **0x10000000** (not 0x1000)
- Use errno layering (below) before claiming CFU hit

## Run and classify

Prefer MCP:

```text
leaf5-adb.adb_run_probe  (push + chmod + run + capture)
leaf5-adb.adb_uname_check
```

Or:

```bash
adb push out/stages/.../arm64/probe /data/local/tmp/stages/.../probe
adb shell chmod 755 /data/local/tmp/stages/.../probe
adb shell /data/local/tmp/stages/.../probe
```

### Errno matrix (minimum)

| Case | Expect / record |
|------|-----------------|
| valid args | ret / success path |
| bad user pointer | **EFAULT** if CFU reached |
| wrong cmd / size | **EINVAL** |
| wrong ioctl type | **ENOTTY** if not in driver |
| ± context | with vs without GPU context |

Write a small table into the node README or `results.txt` under the node.

## Failure interpretation

1. Build fail → fix NDK/path/include first
2. open() EACCES / EPERM → SELinux or group; document node path + context; list alternatives (do not brute force)
3. ENOTTY → wrong ioctl encoding or not that driver
4. EINVAL → structure/flags wrong; fix userspace layout before talking about stack
5. EFAULT → reached copy; then measure depth vs waiter (static RE + arm64-kernel-re skill)
6. Crash / reboot → capture last dmesg if possible; do not loop-crash the device

## After a run

1. Update stage node README (结果 + 原因 + 证据)
2. If constants changed → `target.h` same batch
3. Milestone → short PROCESS_LOG entry
4. Only then consider `exploit/` integration

## Report format

```text
做了什么: build BITS=N SRC=... ; run on <serial>
证据: errno matrix / logs / addresses
结论: ✅/❌/⚠️ + one sentence
下一步: optional single next experiment
```
