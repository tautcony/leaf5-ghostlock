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

    struct { uint64_t ga; uint64_t sw; } ib = {0, 1};
    printf("ibdesc at %p\n\n", &ib);

    /* Try all direction combinations for nr=0x10 */
    printf("=== Direction variants for nr=0x10 ===\n");
    int directions[] = {0, 1, 2, 3};  /* NONE, WRITE, READ, RDWR */
    for (int d = 0; d < 4; d++) {
        /* Try with native size (32) */
        uint32_t c32 = ((uint32_t)d << 30) | (((uint32_t)0x20) << 16) |
                       (((uint32_t)0x09) << 8) | (0x10);
        /* Try with compat size (20) */
        uint32_t c20 = ((uint32_t)d << 30) | (((uint32_t)0x14) << 16) |
                       (((uint32_t)0x09) << 8) | (0x10);
        
        uint8_t buf[64] = {0};
        *(uint32_t*)(buf+0x00) = ctx.id;
        *(uint64_t*)(buf+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(buf+0x10) = 1;
        
        errno = 0; r = ioctl(fd, c32, buf);
        printf("  dir=%d sz=32 cmd=0x%08x: ret=%d errno=%d %s\n",
               d, c32, r, errno, r==0?"✅":"");
        
        errno = 0; r = ioctl(fd, c20, buf);
        printf("  dir=%d sz=20 cmd=0x%08x: ret=%d errno=%d %s\n",
               d, c20, r, errno, r==0?"✅":"");
    }

    /* Also try nr=0x10 with upper bits set */
    printf("\n=== High-byte variants ===\n");
    for (int hi = 0; hi <= 3; hi++) {
        uint32_t nr = 0x10 | (hi << 8);
        uint32_t c = ((uint32_t)3 << 30) | (((uint32_t)0x20) << 16) |
                     (((uint32_t)0x09) << 8) | nr;
        uint8_t buf[64] = {0};
        *(uint32_t*)(buf+0x00) = ctx.id;
        *(uint64_t*)(buf+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(buf+0x10) = 1;
        errno = 0; r = ioctl(fd, c, buf);
        printf("  nr=0x%02x cmd=0x%08x: ret=%d errno=%d %s\n",
               nr, c, r, errno, r==0?"✅":"");
    }

    /* Also: what about nr=0x10 with WRITE direction and native struct? */
    printf("\n=== Try WRITE direction (1<<30) crash test ===\n");
    {
        struct { uint64_t ga; uint64_t sw; } ib2 = {0, 0x4141414141414141ULL};
        uint32_t c = (1u << 30) | (0x20u << 16) | (0x09u << 8) | 0x10;
        uint8_t buf[32] = {0};
        *(uint32_t*)(buf+0x00) = ctx.id;
        *(uint64_t*)(buf+0x08) = (uint64_t)(uintptr_t)&ib2;
        *(uint32_t*)(buf+0x10) = 1;
        errno = 0; r = ioctl(fd, c, buf);
        printf("  WRITE dir crash: ret=%d errno=%d %s\n", r, errno,
               r==0?"⚠️ CFU!":strerror(errno));
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
