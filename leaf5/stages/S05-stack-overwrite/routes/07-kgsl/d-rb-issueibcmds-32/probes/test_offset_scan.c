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
    printf("ibdesc at %p\n", &ib);
    
    /* Scan: place cmdlist ptr at different offsets, find which offset works */
    /* The native struct has these candidates for cmdlist position:
       +0x08 (traditional 64-bit ptr), +0x10, +0x18, etc. */
    
    printf("\n=== Scanning cmdlist ptr offset (56-byte struct) ===\n");
    for (int ptr_off = 0; ptr_off < 48; ptr_off += 4) {
        uint8_t sbuf[56];
        memset(sbuf, 0, 56);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        /* Put cmdlist ptr at this offset */
        *(uint64_t*)(sbuf+ptr_off) = (uint64_t)(uintptr_t)&ib;
        /* Put size at ptr_off+8 (guess) */
        *(uint32_t*)(sbuf+ptr_off+8) = 16;
        /* Put numcmds at ptr_off+12 */
        *(uint32_t*)(sbuf+ptr_off+12) = 1;
        
        errno = 0;
        r = ioctl(fd, 0xc038093d, sbuf);
        if (r == 0 || (errno != 22 && errno != 14)) {
            printf("  ptr@+0x%02x size@+0x%02x num@+0x%02x: ret=%d errno=%d %s\n",
                   ptr_off, ptr_off+8, ptr_off+12, r, errno,
                   r==0?"✅":strerror(errno));
        }
    }

    /* Also scan with fixed ptr at +0x08, varying size/num positions */
    printf("\n=== Scanning size/num offset (ptr fixed at +0x08) ===\n");
    for (int s_off = 4; s_off < 48; s_off += 4) {
        uint8_t sbuf[56];
        memset(sbuf, 0, 56);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint64_t*)(sbuf+0x08) = (uint64_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+s_off) = 16;     /* cmdlist_size at s_off */
        *(uint32_t*)(sbuf+s_off+4) = 1;    /* numcmds at s_off+4 */
        
        errno = 0;
        r = ioctl(fd, 0xc038093d, sbuf);
        if (r == 0 || (errno != 22 && errno != 14)) {
            printf("  size@+0x%02x num@+0x%02x: ret=%d errno=%d %s\n",
                   s_off, s_off+4, r, errno,
                   r==0?"✅":strerror(errno));
        }
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
