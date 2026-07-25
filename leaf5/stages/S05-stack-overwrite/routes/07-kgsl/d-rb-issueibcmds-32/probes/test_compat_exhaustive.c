/**
 * test_compat_exhaustive.c — Exhaustive scan for RB_ISSUEIBCMDS from 32-bit
 *
 * Tests ALL command size/direction/flag combinations for NR=0x10
 * to find a working path from 32-bit compat.
 *
 * Also tests NR=0x3d (SUBMIT_COMMANDS) as a baseline since it WORKS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open failed: %d\n", errno); return 1; }
    printf("fd=%d\n\n", fd);

    /* Create context */
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(fd, 0xc0080913, &ctx);
    printf("CREATE(0x12): ret=%d id=%u\n\n", r, ctx.id);
    if (r < 0) { close(fd); return 1; }

    struct { uint64_t ga; uint64_t sw; } ib = {0x0ULL, 0x1ULL};
    printf("ibdesc at %p\n\n", &ib);

    /* ── NR=0x10 exhaustive scan ── */
    printf("══════════ NR=0x10 (RB_ISSUEIBCMDS) exhaustive ══════════\n");

    int found_working = 0;
    for (int dir = 0; dir <= 3; dir++) {
        for (int sz = 0; sz <= 64; sz += 4) {
            uint32_t cmd = ((uint32_t)dir << 30) |
                           (((uint32_t)sz) << 16) |
                           (((uint32_t)0x09) << 8) |
                           (0x10);

            /* Build a generous buffer */
            uint8_t buf[64];
            memset(buf, 0, 64);

            /* Fill in common fields at standard offsets */
            *(uint32_t*)(buf+0x00) = ctx.id;   /* drawctxt_id */
            /* For offset 0x04: could be flags or padding */
            *(uint32_t*)(buf+0x04) = 0;         /* flags=0 (or ibdesc ptr low32) */
            /* For offset 0x08: ibdesc_addr (may be 4 or 8 bytes) */
            *(uint64_t*)(buf+0x08) = (uint64_t)(uintptr_t)&ib;
            /* For offset 0x10: numibs */
            *(uint32_t*)(buf+0x10) = 1;

            errno = 0;
            r = ioctl(fd, cmd, buf);

            if (r == 0) {
                printf("✅ NR=0x10 dir=%d sz=%d cmd=0x%08x: SUCCESS!\n",
                       dir, sz, cmd);
                found_working = 1;
            } else if (errno != 22 && errno != 515 && errno != 25) {
                printf("⚠️  NR=0x10 dir=%d sz=%d cmd=0x%08x: errno=%d (%s)\n",
                       dir, sz, cmd, errno, strerror(errno));
            }
        }
    }

    /* ── Also try with alternative field placement ── */
    printf("\n── Alt layouts for dir=3 (RDWR) ──\n");
    for (int sz = 16; sz <= 48; sz += 4) {
        uint32_t cmd = (3u << 30) | (((uint32_t)sz) << 16) | (0x09u << 8) | 0x10;

        /* Layout A: ibdesc_addr as 32-bit at offset 8, numibs at offset 12 */
        uint8_t bufA[64] = {0};
        *(uint32_t*)(bufA+0x00) = ctx.id;
        *(uint32_t*)(bufA+0x08) = (uint32_t)(uintptr_t)&ib;  /* 32-bit ptr */
        *(uint32_t*)(bufA+0x0c) = 1;   /* numibs */
        errno = 0;
        r = ioctl(fd, cmd, bufA);
        if (r == 0 || (errno != 22 && errno != 515))
            printf("  LayoutA sz=%d: ret=%d errno=%d %s\n", sz, r, errno,
                   r==0?"✅":strerror(errno));

        /* Layout B: ibdesc_addr as 64-bit at offset 4, numibs at offset 12 */
        uint8_t bufB[64] = {0};
        *(uint32_t*)(bufB+0x00) = ctx.id;
        *(uint64_t*)(bufB+0x04) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(bufB+0x0c) = 1;
        errno = 0;
        r = ioctl(fd, cmd, bufB);
        if (r == 0 || (errno != 22 && errno != 515))
            printf("  LayoutB sz=%d: ret=%d errno=%d %s\n", sz, r, errno,
                   r==0?"✅":strerror(errno));

        /* Layout C: All fields shifted by 4 (ibdesc at offset 12) */
        uint8_t bufC[64] = {0};
        *(uint32_t*)(bufC+0x00) = ctx.id;
        *(uint32_t*)(bufC+0x04) = 0;  /* flags */
        *(uint64_t*)(bufC+0x0c) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(bufC+0x14) = 1;
        errno = 0;
        r = ioctl(fd, cmd, bufC);
        if (r == 0 || (errno != 22 && errno != 515))
            printf("  LayoutC sz=%d: ret=%d errno=%d %s\n", sz, r, errno,
                   r==0?"✅":strerror(errno));
    }

    /* ── NR=0x3d (SUBMIT_COMMANDS) baseline ── */
    printf("\n══════════ NR=0x3d (SUBMIT_COMMANDS) baseline ══════════\n");
    /* Known working: dir=3, sz=44 (compat cmd 0xc02c093d) */
    {
        uint8_t sbuf[56] = {0};
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+0x20) = (uint32_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+0x24) = 16;  /* cmdlist size */
        *(uint32_t*)(sbuf+0x28) = 1;   /* numcmds */

        for (int sz = 20; sz <= 56; sz += 4) {
            uint32_t cmd = (3u << 30) | (((uint32_t)sz) << 16) | (0x09u << 8) | 0x3d;
            errno = 0;
            r = ioctl(fd, cmd, sbuf);
            if (r == 0)
                printf("✅ NR=0x3d sz=%d cmd=0x%08x: SUCCESS!\n", sz, cmd);
            else if (errno != 22 && errno != 515)
                printf("   NR=0x3d sz=%d: errno=%d (%s)\n", sz, errno, strerror(errno));
        }
    }

    if (!found_working)
        printf("\n❌ No working NR=0x10 variant found from 32-bit\n");
    else
        printf("\n✅ Found working NR=0x10 variant(s)!\n");

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
