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

    /* Scan ALL offsets for the ibdesc ptr within 44-byte compat struct */
    printf("=== Scanning ibdesc ptr offset in 44B compat struct ===\n");
    for (int ptr_off = 0; ptr_off < 40; ptr_off += 4) {
        uint8_t sbuf[44];
        memset(sbuf, 0, 44);
        *(uint32_t*)(sbuf+0x00) = ctx.id;               /* context_id at +0 */
        *(uint32_t*)(sbuf+ptr_off) = (uint32_t)(uintptr_t)&ib; /* ptr */
        /* Try size at ptr_off+8, num at ptr_off+12 */
        if (ptr_off + 16 <= 44) {
            *(uint32_t*)(sbuf+ptr_off+8) = 16;
            *(uint32_t*)(sbuf+ptr_off+12) = 1;
        }
        errno = 0; r = ioctl(fd, 0xc02c093d, sbuf);
        if (r == 0 || errno != 14) {
            printf("  ptr@+0x%02x: ret=%d errno=%d %s\n", ptr_off, r, errno,
                   r==0?"✅":strerror(errno));
        }
    }
    printf("  (others: EFAULT)\n");

    /* Now scan size/num offsets with fixed ptr at each position */
    printf("\n=== Scanning size/num offsets (ptr at +0x08) ===\n");
    for (int s_off = 4; s_off < 40; s_off += 4) {
        uint8_t sbuf[44];
        memset(sbuf, 0, 44);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+0x08) = (uint32_t)(uintptr_t)&ib;
        if (s_off + 8 <= 44) {
            *(uint32_t*)(sbuf+s_off) = 16;
            *(uint32_t*)(sbuf+s_off+4) = 1;
        }
        errno = 0; r = ioctl(fd, 0xc02c093d, sbuf);
        if (r == 0 || errno != 14) {
            printf("  sz@+0x%02x num@+0x%02x: ret=%d errno=%d %s\n",
                   s_off, s_off+4, r, errno, r==0?"✅":strerror(errno));
        }
    }

    /* Try ptr at offset 0x20 (from disassembly: fields at +0x20, +0x24) */
    printf("\n=== Specific: ptr at disassembly-suggested offsets ===\n");
    for (int ptr_off = 0x18; ptr_off <= 0x2c; ptr_off += 4) {
        uint8_t sbuf[44];
        memset(sbuf, 0, 44);
        *(uint32_t*)(sbuf+0x00) = ctx.id;
        *(uint32_t*)(sbuf+ptr_off) = (uint32_t)(uintptr_t)&ib;
        /* size at ptr_off-8? or ptr_off+4? */
        *(uint32_t*)(sbuf+8) = 16;   /* try size at +8 */
        *(uint32_t*)(sbuf+12) = 1;   /* try num at +12 */
        errno = 0; r = ioctl(fd, 0xc02c093d, sbuf);
        if (r == 0 || errno != 14) {
            printf("  ptr@+0x%02x (size@+8,num@+12): ret=%d errno=%d %s\n",
                   ptr_off, r, errno, r==0?"✅":"");
        }
    }

    /* The disassembly reads from x19 (compat struct) at offsets +0x18, +0x20, +0x24, +0x2c */
    /* Maybe these are NOT individual fields but PAIR loads (ldp) */
    /* ldp w8, w9, [x2, #0x20] → loads 8 bytes starting at +0x20: w8=+0x20, w9=+0x24 */
    /* ldp w10, w11, [x2, #0x2c] → Would be offset 44, but struct is only 44 bytes! */
    
    /* Let me try: the compat struct might have these fields: */
    /* +0x00: context_id */
    /* +0x04: flags */
    /* +0x08-0x0F: something (8 bytes?) */
    /* +0x10: cmdlist_size? */
    /* +0x14: numcmds? */
    /* +0x18-0x1B: timestamp or other */
    /* +0x1C-0x1F: ? */
    /* +0x20-0x27: ? */  
    /* +0x28-0x2B: ? */
    
    ioctl(fd, 0x40040914, &ctx.id);
    close(fd);
    return 0;
}
