#include <stdio.h>
#include <stdlib.h>
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

    struct { uint64_t ga; uint64_t sw; } ib = {0x0, 0x1};
    printf("ibdesc at %p\n", &ib);

    /* THEORY: cmd=0xc0200910 (NOT in compat table, size=32)
     * Should fall through to regular handler with native struct */
    printf("=== Native bypass ===\n");
    {
        uint8_t nat[32];
        memset(nat, 0, 32);
        *(uint32_t*)(nat+0x00) = ctx.id;
        *(uint64_t*)(nat+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(nat+0x10) = 1;
        errno = 0; r = ioctl(fd, 0xc0200910, nat);
        printf("  0xc0200910: ret=%d errno=%d (%s)\n", r, errno, r<0?strerror(errno):"OK");
    }

    /* Size threshold: where does compat wrapper stop intercepting? */
    printf("\n=== Size scan ===\n");
    for (int sz = 0; sz <= 64; sz += 4) {
        uint32_t c = ((uint32_t)3<<30)|(((uint32_t)sz)<<16)|(((uint32_t)0x09)<<8)|(0x10);
        uint8_t buf[64] = {0};
        *(uint32_t*)(buf+0x00) = ctx.id;
        if (sz >= 16) { *(uint64_t*)(buf+0x08) = (uint64_t)(uintptr_t)&ib; *(uint32_t*)(buf+0x10) = 1; }
        errno = 0; r = ioctl(fd, c, buf);
        if (sz == 0 || sz == 20 || sz == 32 || r == 0 || (errno != 22 && errno != 25))
            printf("  sz=%2d cmd=0x%08x: ret=%d errno=%d%s\n", sz, c, r, errno, r==0?" ✅":"");
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
