/**
 * test_kgsl_init.c — Try to initialize KGSL device before context creation
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOCTL(nr, sz) \
    (((uint32_t)3 << 30) | (((uint32_t)(sz)) << 16) | (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

int main(void) {
    int fd = open(KGSL_DEVICE, O_RDWR);
    if (fd < 0) { printf("ERROR: open failed\n"); return 1; }
    printf("fd=%d\n", fd);

    /* Try GET_PROPERTY with device info struct from msm_kgsl.h */
    /* struct kgsl_device_getproperty { unsigned int type; void __user *value; unsigned int sizebytes; }; */
    /* size = 16 bytes (type + ptr + size) */
    {
        struct { uint32_t type; uint32_t pad; uint32_t value_ptr; uint32_t sizebytes; } prop = {0};
        char valbuf[256] = {0};
        prop.type = 0; /* KGSL_PROP_DEVICE_INFO */
        prop.value_ptr = (uint32_t)(uintptr_t)valbuf;
        prop.sizebytes = sizeof(valbuf);
        int r = ioctl(fd, KGSL_IOCTL(0x03, 0x10), &prop);
        printf("GETPROP(0x10) type=0: ret=%d errno=%d\n", r, errno);
        if (r == 0) {
            printf("  value[0..15]: ");
            for (int i = 0; i < 16; i++) printf("%02x ", (uint8_t)valbuf[i]);
            printf("\n");
        }
    }

    /* Try different property types */
    for (int ptype = 0; ptype < 10; ptype++) {
        struct { uint32_t type; uint32_t pad; uint32_t value_ptr; uint32_t sizebytes; } prop = {0};
        char valbuf[256] = {0};
        prop.type = ptype;
        prop.value_ptr = (uint32_t)(uintptr_t)valbuf;
        prop.sizebytes = sizeof(valbuf);
        errno = 0;
        int r = ioctl(fd, KGSL_IOCTL(0x03, 0x10), &prop);
        if (errno != 25) { /* not ENOTTY */
            printf("GETPROP type=%d: ret=%d errno=%d\n", ptype, r, errno);
        }
    }

    /* Try SET_PROPERTY */
    {
        uint8_t buf[128] = {0};
        /* struct kgsl_device_setproperty { unsigned int type; void __user *value; unsigned int sizebytes; }; */
        struct { uint32_t type; uint32_t pad; uint32_t value_ptr; uint32_t sizebytes; } sp = {0};
        sp.type = 0;
        sp.value_ptr = (uint32_t)(uintptr_t)buf;
        sp.sizebytes = 4;
        *(uint32_t*)buf = 0;
        int r = ioctl(fd, KGSL_IOCTL(0x02, 0x10), &sp);
        printf("SETPROP type=0: ret=%d errno=%d\n", r, errno);
    }

    /* Try context creation directly after */
    {
        struct { uint32_t flags; uint32_t id; } c = {0x00100000, 0};  /* TYPE_GL */
        errno = 0;
        int r = ioctl(fd, KGSL_IOCTL(0x13, 0x08), &c);
        printf("CREATE (after props): ret=%d id=%u errno=%d (%s)\n",
               r, c.id, errno, r<0?strerror(errno):"OK");
    }

    /* Try with larger ioctl sizes for GETPROP */
    {
        struct { uint32_t type; uint32_t pad; uint32_t value_ptr; uint32_t sizebytes; } prop = {0};
        char valbuf[256] = {0};
        prop.type = 0;
        prop.value_ptr = (uint32_t)(uintptr_t)valbuf;
        prop.sizebytes = sizeof(valbuf);
        int r = ioctl(fd, KGSL_IOCTL(0x03, 0x20), &prop);
        printf("GETPROP(0x20,std) type=0: ret=%d errno=%d\n", r, errno);
    }

    close(fd);
    return 0;
}
