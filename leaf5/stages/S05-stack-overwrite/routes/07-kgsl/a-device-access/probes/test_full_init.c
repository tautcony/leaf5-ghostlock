#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) { printf("open failed: %d\n", errno); return 1; }
    printf("fd=%d\n", fd);

    /* Compat SET_PROPERTY: 0xc00c0902 (size=12 bytes) */
    struct { uint32_t type; uint32_t value_ptr; uint32_t sizebytes; } sp = {0};
    char valbuf[256] = {0};

    /* Try ALL property types that might help initialize the device */
    /* MMU_ENABLE (6) and INTERRUPT_WAITS (7) worked before */
    uint32_t prop_types[] = {
        0x1,  /* DEVICE_INFO - may fail */
        0x3,  /* DEVICE_POWER */
        0x6,  /* MMU_ENABLE - worked */
        0x7,  /* INTERRUPT_WAITS - worked */
        0x8,  /* VERSION */
        0xE,  /* PWRCTRL */
        0x12, /* PWR_CONSTRAINT */
        0x13, /* UCHE_GMEM_VADDR */
        0x18, /* DEVICE_BITNESS */
        0x1A, /* MIN_ACCESS_LENGTH */
        0x1B, /* UBWC_MODE */
        0x20, /* DEVICE_QTIMER */
        0x25, /* SPEED_BIN */
        0x27, /* QUERY_CAPABILITIES */
        0x28, /* CONTEXT_PROPERTY */
    };

    for (int i = 0; i < sizeof(prop_types)/sizeof(prop_types[0]); i++) {
        memset(valbuf, 0, sizeof(valbuf));
        sp.type = prop_types[i];
        sp.value_ptr = (uint32_t)(uintptr_t)valbuf;
        sp.sizebytes = sizeof(valbuf);
        errno = 0;
        int r = ioctl(fd, 0xc00c0902, &sp);
        const char* names[] = {
            [0x1]="DEVICE_INFO", [0x3]="DEVICE_POWER", [0x6]="MMU_ENABLE",
            [0x7]="INT_WAITS", [0x8]="VERSION", [0xE]="PWRCTRL",
            [0x12]="PWR_CONSTRAINT", [0x13]="UCHE_GMEM_VADDR", [0x18]="DEVICE_BITNESS",
            [0x1A]="MIN_ACCESS_LEN", [0x1B]="UBWC_MODE", [0x20]="DEVICE_QTIMER",
            [0x25]="SPEED_BIN", [0x27]="QUERY_CAPABILITIES", [0x28]="CONTEXT_PROPERTY"
        };
        const char* name = (prop_types[i] < 0x30 && names[prop_types[i]]) ? names[prop_types[i]] : "???";
        printf("SETPROP 0x%02x (%s): ret=%d errno=%d\n", prop_types[i], name, r, errno);
    }

    /* Now try GETPROP with compat encoding */
    /* GET_PROPERTY compat: not in the compat table, but try 0xc00c0903 (size=12) */
    struct { uint32_t type; uint32_t value_ptr; uint32_t sizebytes; } gp = {0};
    gp.type = 0x27; /* QUERY_CAPABILITIES */
    gp.value_ptr = (uint32_t)(uintptr_t)valbuf;
    gp.sizebytes = sizeof(valbuf);
    int r = ioctl(fd, 0xc00c0903, &gp);
    printf("GETPROP(compat) QUERY_CAPABILITIES: ret=%d errno=%d\n", r, errno);

    /* Try context creation with mmap'd memory first */
    void *map = mmap(0, 0x10000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    printf("mmap(64K, SHARED): %p errno=%d\n", map, errno);
    if (map != MAP_FAILED) {
        munmap(map, 0x10000);
    }

    /* Now context creation */
    struct { uint32_t flags; uint32_t id; } c = {0x00100000, 0};
    r = ioctl(fd, 0xc0080913, &c);
    printf("CREATE(TYPE_GL): ret=%d id=%u errno=%d (%s)\n", r, c.id, errno, strerror(errno));

    /* Also try with other context types */
    c.flags = 0x00200000; /* TYPE_CL */
    r = ioctl(fd, 0xc0080913, &c);
    printf("CREATE(TYPE_CL): ret=%d id=%u errno=%d\n", r, c.id, errno);

    c.flags = 0; /* default */
    r = ioctl(fd, 0xc0080913, &c);
    printf("CREATE(default): ret=%d id=%u errno=%d\n", r, c.id, errno);

    close(fd);
    return 0;
}
