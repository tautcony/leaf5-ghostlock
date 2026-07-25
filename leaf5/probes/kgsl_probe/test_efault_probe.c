/**
 * test_efault_probe.c — Determine if compat wrapper is actually called
 *
 * Theory: If the compat wrapper is called and passes our data to the native
 * handler, setting compat.flags (which maps to native.ibdesc_addr via the
 * stp bug) to an invalid pointer like 0x1 should cause EFAULT (errno 14),
 * not EINVAL (errno 22).
 *
 * Similarly, setting it to a valid user pointer should cause the handler
 * to dereference it. If the ibdesc at that pointer has sizedwords=0,
 * the handler might return EINVAL. But if sizedwords=1 and ctrl=0,
 * it should succeed (or at least get past the initial checks).
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open failed: %d\n", errno); return 1; }

    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(fd, 0xc0080913, &ctx);
    printf("CREATE: ret=%d id=%u\n\n", ctx.id);
    if (r < 0) { close(fd); return 1; }

    /* Allocate a properly-sized ibdesc (28 bytes for 64-bit kernel) */
    struct kgsl_ibdesc_64 {
        uint64_t gpuaddr;
        uint64_t __pad;
        uint64_t sizedwords;
        uint32_t ctrl;
    } __attribute__((aligned(8))) ib;
    memset(&ib, 0, sizeof(ib));
    ib.gpuaddr = 0;
    ib.sizedwords = 1;
    ib.ctrl = 0;
    printf("ibdesc at %p, sizeof=%zu\n", &ib, sizeof(ib));

    /* Test 1: Swapped struct, valid ibdesc pointer → should succeed or get past EINVAL */
    printf("=== Test 1: Valid ibdesc ptr via swap ===\n");
    {
        uint8_t sw[20];
        memset(sw, 0, 20);
        *(uint32_t*)(sw+0x00) = ctx.id;
        *(uint32_t*)(sw+0x04) = (uint32_t)(uintptr_t)&ib;  /* → native.ibdesc_addr */
        *(uint64_t*)(sw+0x08) = 1;                          /* → native.numibs */
        *(uint32_t*)(sw+0x10) = 0;                          /* → native.flags */
        errno = 0;
        r = ioctl(fd, 0xc0140910, sw);
        printf("  valid_ptr: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* Test 2: Swapped struct, INVALID ibdesc pointer (0x1) → should be EFAULT */
    printf("=== Test 2: INVALID ibdesc ptr (0x1) via swap ===\n");
    {
        uint8_t sw[20];
        memset(sw, 0, 20);
        *(uint32_t*)(sw+0x00) = ctx.id;
        *(uint32_t*)(sw+0x04) = 0x1;     /* → native.ibdesc_addr = 0x1 (bad!) */
        *(uint64_t*)(sw+0x08) = 1;        /* → native.numibs */
        *(uint32_t*)(sw+0x10) = 0;        /* → native.flags */
        errno = 0;
        r = ioctl(fd, 0xc0140910, sw);
        printf("  bad_ptr_0x1: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* Test 3: Swapped struct, NULL ibdesc pointer → EINVAL or EFAULT? */
    printf("=== Test 3: NULL ibdesc ptr via swap ===\n");
    {
        uint8_t sw[20];
        memset(sw, 0, 20);
        *(uint32_t*)(sw+0x00) = ctx.id;
        *(uint32_t*)(sw+0x04) = 0;        /* → native.ibdesc_addr = 0 (NULL) */
        *(uint64_t*)(sw+0x08) = 1;        /* → native.numibs */
        *(uint32_t*)(sw+0x10) = 0;        /* → native.flags */
        errno = 0;
        r = ioctl(fd, 0xc0140910, sw);
        printf("  null_ptr: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* Test 4: Swapped struct, numibs=0 → should fail validation */
    printf("=== Test 4: numibs=0 via swap ===\n");
    {
        uint8_t sw[20];
        memset(sw, 0, 20);
        *(uint32_t*)(sw+0x00) = ctx.id;
        *(uint32_t*)(sw+0x04) = (uint32_t)(uintptr_t)&ib;  /* valid ptr */
        *(uint64_t*)(sw+0x08) = 0;        /* → native.numibs = 0 (invalid!) */
        *(uint32_t*)(sw+0x10) = 0;
        errno = 0;
        r = ioctl(fd, 0xc0140910, sw);
        printf("  numibs_0: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* Test 5: Unswapped (normal) struct with bad ibdesc ptr */
    printf("=== Test 5: NORMAL struct, bad ibdesc ptr ===\n");
    {
        uint8_t norm[20];
        memset(norm, 0, 20);
        *(uint32_t*)(norm+0x00) = ctx.id;
        *(uint32_t*)(norm+0x04) = 0;                          /* flags=0 */
        *(uint64_t*)(norm+0x08) = (uint64_t)(uintptr_t)&ib;   /* ibdesc_addr */
        *(uint32_t*)(norm+0x10) = 1;                          /* numibs=1 */
        errno = 0;
        r = ioctl(fd, 0xc0140910, norm);
        printf("  normal: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* Test 6: Don't swap, but set flags=ibdesc_ptr (partial swap) */
    printf("=== Test 6: flags=ibdesc_ptr, ibdesc_addr=1, numibs=flags ===\n");
    {
        uint8_t sw[20];
        memset(sw, 0, 20);
        *(uint32_t*)(sw+0x00) = ctx.id;
        *(uint32_t*)(sw+0x04) = (uint32_t)(uintptr_t)&ib;  /* flags = ib ptr */
        *(uint64_t*)(sw+0x08) = (uint64_t)(uintptr_t)&ib;   /* ibdesc_addr = ib ptr too! */
        *(uint32_t*)(sw+0x10) = 1;                          /* numibs = 1 */
        errno = 0;
        r = ioctl(fd, 0xc0140910, sw);
        printf("  dual_ptr: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);

    printf("\n── Analysis ──\n");
    printf("If all tests return EINVAL(22): compat wrapper is NOT called\n");
    printf("If bad ptr returns EFAULT(14):  compat wrapper IS called, swap works\n");
    return 0;
}
