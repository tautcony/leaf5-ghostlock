#!/system/bin/sh
# check_ion_primitive.sh
# Check /dev/ion availability and enumerate potential ioctl commands
# for physical memory write on Leaf5 (kernel 4.19, Android 13)
#
# ION is the Android kernel memory allocator used by GPU, camera, display,
# and other multimedia subsystems. On some kernels it provides:
#   - ION_IOC_ALLOC: allocate a DMA-buf-backed buffer
#   - ION_IOC_FREE: free a buffer
#   - ION_IOC_MAP: mmap a buffer into userspace
#   - ION_IOC_SHARE: share a buffer via fd
#   - ION_IOC_IMPORT: import a shared buffer
#   - ION_IOC_CUSTOM: vendor-specific custom ioctls (potential R/W primitive)
#
# OUTPUT: prints status of each check, SUMMARY at end

SHELL_UID=$(id -u)
SHELL_CONTEXT=$(cat /proc/self/attr/current 2>/dev/null)
echo "=== Heap Spray — ION Primitive Check ==="
echo "Date: $(date)"
echo "UID: $SHELL_UID  Context: $SHELL_CONTEXT"
echo ""

# ── 1. Check if /dev/ion exists and is accessible ──────────────────────
echo "--- [1] /dev/ion availability ---"

ION_DEV="/dev/ion"
if [ -c "$ION_DEV" ]; then
    STAT=$(stat -c "major=%t minor=%T perms=%a uid=%u gid=%g" "$ION_DEV" 2>/dev/null)
    echo "  EXISTS: $ION_DEV is a character device"
    echo "  $STAT"

    # Try to open
    exec 3<>"$ION_DEV" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  OPENABLE: Yes (fd=3)"
        exec 3>&-
    else
        echo "  OPENABLE: No ($?) — blocked by SELinux or DAC"
        # Check SELinux
        echo "  SELinux context check:"
        ls -Z "$ION_DEV" 2>/dev/null
    fi
else
    echo "  NOT FOUND: $ION_DEV does not exist"
fi

# Check aliases / alternative paths
for alt in /dev/ion1 /dev/ion-dummy /dev/dma_buf /dev/dma_heap /dev/dma-heap; do
    if [ -c "$alt" ]; then
        echo "  ALIAS: $alt exists"
    fi
done
echo ""

# ── 2. Search for ION kernel module / driver probes ────────────────────
echo "--- [2] ION kernel subsystem probes ---"

# Check dmesg for ION initialization
ION_DMESG=$(dmesg | grep -i ion 2>/dev/null | head -20)
if [ -n "$ION_DMESG" ]; then
    echo "  dmesg ION messages:"
    echo "$ION_DMESG" | while read line; do echo "    $line"; done
else
    echo "  dmesg: No ION messages found (dmesg_restrict may block)"
fi

# Check /proc/iomem for ION memory regions
ION_IOMEM=$(cat /proc/iomem 2>/dev/null | grep -i ion | head -10)
if [ -n "$ION_IOMEM" ]; then
    echo "  /proc/iomem ION regions:"
    echo "$ION_IOMEM" | while read line; do echo "    $line"; done
else
    echo "  /proc/iomem: No ION regions found (may be restricted)"
fi

# Check /sys/kernel/debug/ion (if debugfs is available)
for debug_ion in /sys/kernel/debug/ion /d/ion /sys/kernel/debug/ion/heaps; do
    if [ -d "$debug_ion" ]; then
        echo "  DEBUG ION found: $debug_ion"
        ls -la "$debug_ion" 2>/dev/null | head -10 | while read line; do echo "    $line"; done
    fi
done
echo ""

# ── 3. Check kernel config for ION ─────────────────────────────────────
echo "--- [3] Kernel config ---"

if [ -f /proc/config.gz ]; then
    ION_CONFIGS=$(zcat /proc/config.gz 2>/dev/null | grep -i "CONFIG_ION" | sort)
    if [ -n "$ION_CONFIGS" ]; then
        echo "  ION-related kernel configs:"
        echo "$ION_CONFIGS" | while read line; do echo "    $line"; done
    else
        echo "  No CONFIG_ION found in kernel config"
    fi
elif [ -f /proc/config ]; then
    ION_CONFIGS=$(grep -i "CONFIG_ION" /proc/config 2>/dev/null | sort)
    echo "  ION configs (from /proc/config):"
    echo "$ION_CONFIGS" | while read line; do echo "    $line"; done
else
    echo "  /proc/config.gz not available, cannot check ION config"
fi
echo ""

# ── 4. Check for DMA heaps (alternative to ION on newer kernels) ───────
echo "--- [4] DMA heap availability (CONFIG_DMA_HEAP replacement for ION) ---"

for heap_dir in /dev/dma_heap /dev/dma-heap; do
    if [ -d "$heap_dir" ]; then
        echo "  DMA heap dir: $heap_dir"
        ls -la "$heap_dir" 2>/dev/null | while read line; do echo "    $line"; done
    fi
done

# Check /sys/class/dma (legacy)
if [ -d /sys/class/dma ]; then
    echo "  /sys/class/dma exists (legacy DMA)"
    ls /sys/class/dma/ 2>/dev/null | head -5 | while read line; do echo "    $line"; done
fi
echo ""

# ── 5. Check for /dev/kgsl (Qualcomm GPU) ──────────────────────────────
echo "--- [5] Qualcomm kgsl GPU (alternative allocator with phys access) ---"

KGSL_DEV="/dev/kgsl-3d0"
if [ -c "$KGSL_DEV" ]; then
    STAT=$(stat -c "major=%t minor=%T perms=%a uid=%u gid=%g" "$KGSL_DEV" 2>/dev/null)
    echo "  EXISTS: $KGSL_DEV is a character device"
    echo "  $STAT"
    exec 3<>"$KGSL_DEV" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  OPENABLE: Yes (fd=3)"
        exec 3>&-
    else
        echo "  OPENABLE: No — blocked by SELinux or DAC"
    fi
else
    echo "  NOT FOUND: $KGSL_DEV"
fi

# Check other kgsl devices
for dev in /dev/kgsl*; do
    if [ -c "$dev" ] && [ "$dev" != "$KGSL_DEV" ]; then
        echo "  OTHER KGSL: $dev"
    fi
done
echo ""

# ── 6. ION ioctl reference ─────────────────────────────────────────────
echo "--- [6] ION ioctl reference (from UAPI headers) ---"

cat << 'IOCTL_REF'
ION-specific ioctls (include/uapi/linux/ion.h):

  #define ION_IOC_MAGIC           'I'

  ION_IOC_ALLOC:
    cmd  = _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
    size = 16 or 24 bytes on 4.19
    struct ion_allocation_data {
        __u64 len;          // buffer length
        __u32 align;        // alignment (0 = page-aligned)
        __u32 heap_id_mask; // bitmask of acceptable heap IDs
        __u32 flags;        // flags (cached/uncached, etc.)
        __u32 fd;           // output: fd for the allocated buffer
    };
    NOTE: returns a dma_buf fd. Userspace gets an fd pointing to the buffer.
    CANNOT directly write kernel memory via this call.

  ION_IOC_FREE:
    cmd  = _IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
    size = 8 bytes
    Frees a handle (obtained via ALLOC). No R/W primitive.

  ION_IOC_MAP:
    cmd  = _IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)
    Returns an fd for mmap. The mmap'd buffer is in userspace, not arbitrary.

  ION_IOC_SHARE:
    cmd  = _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
    Converts a handle to a shareable fd. No R/W primitive.

  ION_IOC_IMPORT:
    cmd  = _IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)
    Imports a shared fd. No R/W primitive.

  ION_IOC_SYNC:
    cmd  = _IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)
    Sync cache for a dma-buf fd. No R/W primitive.

  ION_IOC_CUSTOM:
    cmd  = _IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)
    struct ion_custom_data {
        __u64 cmd;    // custom command number (vendor-specific)
        __u64 arg;    // custom argument (vendor-specific)
    };
    THIS IS THE POTENTIAL R/W PRIMITIVE!
    Vendor-specific custom commands may allow:
      - Physical address queries (ION_IOC_CUSTOM + QC specific)
      - Direct memory operations
    Qualcomm-specific custom commands are not upstream; we need the
    downstream msm-4.19 kernel source to enumerate them.

  Standard IOCTL numbers for reference:
    ION_IOC_ALLOC  = _IOWR('I', 0, ...)  = 0xC0104C00 (on 64-bit)
    ION_IOC_FREE   = _IOWR('I', 1, ...)  = 0xC0084C01
    ION_IOC_MAP    = _IOWR('I', 2, ...)  = 0xC0104C02
    ION_IOC_SHARE  = _IOWR('I', 4, ...)  = 0xC0104C04
    ION_IOC_IMPORT = _IOWR('I', 5, ...)  = 0xC0104C05
    ION_IOC_CUSTOM = _IOWR('I', 6, ...)  = 0xC0104C06
    ION_IOC_SYNC   = _IOWR('I', 7, ...)  = 0xC0104C07

ION heap IDs (from kernel source):
    ION_HEAP_TYPE_SYSTEM    = 0  // page-allocated, no special properties
    ION_HEAP_TYPE_SYSTEM_CONTIG = 1  // contiguous physical pages
    ION_HEAP_TYPE_CARVEOUT  = 2  // pre-allocated memory carveout
    ION_HEAP_TYPE_CHUNK     = 3  // chunked allocation
    ION_HEAP_TYPE_DMA       = 4  // dma_alloc_coherent
    ION_HEAP_TYPE_SECURE    = 5  // secure / TZ-protected
    ION_HEAP_TYPE_CUSTOM    = 6  // vendor-specific

Qualcomm-specific custom ioctls that have been used in exploits:
    (ION_IOC_CUSTOM with vendor cmd = 1 or 2)
    These have been used in CVE-2019-2305, CVE-2020-11194, etc.
    On msm-4.19, QC may have removed ION entirely in favor of DMA-heap.

ION exploitation history:
    CVE-2019-2305: ION physical address leak via ION_IOC_CUSTOM
    CVE-2020-11194: ION heap overflow -> arbitrary write
    CVE-2021-3037: QC ION custom command issue
    Most post-4.19 kernels have deprecated ION or restricted permissions.
IOCTL_REF
echo ""

# ── 7. Qualcomm-specific ION (msm-4.19) — check if this is a QC ION ───
echo "--- [7] Qualcomm-specific ION heuristics ---"

# Check CPU for Qualcomm Kryo
CPU_PARTS=$(cat /proc/cpuinfo 2>/dev/null | grep "CPU part" | sort -u)
CPU_IMPLEMENTER=$(cat /proc/cpuinfo 2>/dev/null | grep "CPU implementer" | sort -u)
if echo "$CPU_IMPLEMENTER" | grep -q "0x51" || echo "$CPU_PARTS" | grep -q "0x805"; then
    echo "  CPU: Qualcomm Kryo detected (ARM implementer 0x51 / part 0x805)"
    echo "  Platform: Qualcomm SM6350 (LAGOON / lito)"
    echo "  Kernel: msm-4.19 (downstream Qualcomm kernel)"
    echo "  NOTE: Qualcomm msm-4.19 typically uses DMA-heap, not ION"
    echo "  Some early msm-4.19 builds still ship ION for backward compat"
fi
echo ""

# ── 8. Enumerate /dev interfaces that might offer physical access ──────
echo "--- [8] Other potential physical-memory-access interfaces ---"

for dev_name in mem kmem port; do
    dev="/dev/$dev_name"
    if [ -c "$dev" ]; then
        echo "  EXISTS: $dev"
        ls -la "$dev" 2>/dev/null
        stat -c "perms=%a uid=%u gid=%g" "$dev" 2>/dev/null
    fi
done

# Check for UIO (Userspace I/O) devices that might provide phys access
for uio in /dev/uio*; do
    if [ -c "$uio" ]; then
        echo "  UIO device: $uio"
    fi
done

# Check for VFIO
if [ -c /dev/vfio/vfio ] || [ -c /dev/vfio ]; then
    echo "  VFIO device exists"
fi
echo ""

# ── 9. Check SELinux policy for ION access ────────────────────────────
echo "--- [9] SELinux policy for ION ---"

# Try to check SELinux policy for ion_device
for selinux_check in "shell ion_device" "shell ion" "untrusted_app ion_device"; do
    set context=$selinux_check
    result=$(sesearch --allow -s "$context" -t ion_device -c chr_file -p open 2>/dev/null || echo "sesearch not available")
    if echo "$result" | grep -qv "not available"; then
        echo "  SELinux allow $selinux_check:"
        echo "$result" | head -3 | while read line; do echo "    $line"; done
    fi
done

# If sesearch not available, try reading the SELinux policy file
if command -v sesearch >/dev/null 2>&1; then
    echo "  (sesearch available)"
else
    echo "  sesearch not available (typical on production builds)"
    echo "  SELinux likely blocks shell from opening ion_device"
fi
echo ""

# ── 10. Check CONFIG_DMABUF (dma-buf based approach) ───────────────────
echo "--- [10] dma-buf / dmabuf syscalls availability ---"

# Check if we can use memfd_create (not dma-buf specific but can share)
MEMFD_TEST=$(python3 -c "
import ctypes, os
# Try memfd_create syscall (SYS_memfd_create = 385 on arm64)
try:
    libc = ctypes.CDLL('libc.so.6')
    SYS_memfd_create = 385
    fd = libc.syscall(SYS_memfd_create, b'test', 0)
    print(f'memfd_create fd={fd}')
    if fd >= 0:
        os.close(fd)
        print('memfd_create available')
    else:
        print('memfd_create failed (expected on Android)')
except:
    print('memfd_create: test skipped')
" 2>/dev/null)

if [ -n "$MEMFD_TEST" ]; then
    echo "  memfd_create: $MEMFD_TEST"
fi
echo ""

# ── Summary ────────────────────────────────────────────────────────────
echo "=== SUMMARY ==="
echo ""
echo "Path for physical memory access on Leaf5 4.19:"
echo ""
if [ -c "$ION_DEV" ]; then
    echo "  [CHECK] /dev/ion EXISTS — may provide allocation-based access"
    echo "  [CHECK] ION_IOC_CUSTOM may have vendor commands for phys access"
    echo "  [INFO] Requires SELinux domain that can open ion_device"
    echo "  [INFO] Even with ION, buffers give DMA access, not arbitrary phys R/W"
else
    echo "  [NEGATIVE] /dev/ion does not exist"
    echo "  [INFO] Leaf5 likely uses DMA-heap (CONFIG_DMA_HEAP) instead"
fi
echo ""
if [ -c "$KGSL_DEV" ]; then
    echo "  [CHECK] /dev/kgsl-3d0 EXISTS — Qualcomm GPU device"
    echo "  [INFO] kgsl provides GPU buffer allocation but not arbitrary phys R/W"
else
    echo "  [NEGATIVE] kgsl-3d0 not found or not accessible"
fi
echo ""
echo "  [CONCLUSION] ION-based physical memory write is UNLIKELY on Leaf5:"
echo "  - msm-4.19 Qualcomm kernels typically use DMA-heap, not ION"
echo "  - Even with ION, the allocator returns dma-buf fds for userspace"
echo "  - True arbitrary physical R/W would require a kernel bug in ION"
echo "    (overflow, UAF, or custom ioctl) — not just ION availability"
echo "  - The exploit chain should NOT depend on ION as a bootstrap path"
echo ""
echo "  [RECOMMENDATION] Focus on binder indirect control or finding a"
echo "  functional copy_from_user target that overlaps the waiter position."
echo "  See GHOSTLOCK_EXPLOIT_PLAN.md sections III-A, III-F for details."
echo ""

exit 0
