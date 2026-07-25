/**
 * test_egl.c — Test GPU access through EGL library path
 * This bypasses raw ioctl and uses the standard Adreno EGL driver.
 * Compile: armv7a-linux-androideabi33-clang -static -o test_egl test_egl.c -lEGL -lGLESv2
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

/* Minimal EGL types */
typedef void *EGLDisplay;
typedef void *EGLContext;
typedef void *EGLSurface;
typedef unsigned int EGLBoolean;
typedef int EGLint;
typedef void *EGLConfig;
typedef long EGLNativeDisplayType;

#define EGL_TRUE 1
#define EGL_DEFAULT_DISPLAY ((EGLNativeDisplayType)0)
#define EGL_NO_DISPLAY ((EGLDisplay)0)
#define EGL_NO_CONTEXT ((EGLContext)0)
#define EGL_NO_SURFACE ((EGLSurface)0)

int main(void) {
    printf("=== EGL GPU access test ===\n");

    /* Try to load EGL library dynamically */
    void *egl_handle = dlopen("libEGL.so", RTLD_NOW);
    if (!egl_handle) {
        printf("dlopen libEGL.so: %s\n", dlerror());
        egl_handle = dlopen("libEGL_adreno.so", RTLD_NOW);
        if (!egl_handle) {
            printf("dlopen libEGL_adreno.so: %s\n", dlerror());
        } else {
            printf("Loaded libEGL_adreno.so\n");
        }
    } else {
        printf("Loaded libEGL.so\n");
    }

    if (egl_handle) {
        /* Try to get eglGetDisplay symbol */
        typedef void *(*eglGetDisplay_t)(EGLNativeDisplayType);
        eglGetDisplay_t eglGetDisplay = dlsym(egl_handle, "eglGetDisplay");
        if (eglGetDisplay) {
            EGLDisplay dpy = eglGetDisplay(EGL_DEFAULT_DISPLAY);
            printf("eglGetDisplay: %p\n", dpy);
            if (dpy != EGL_NO_DISPLAY) {
                /* Try eglInitialize */
                typedef EGLBoolean (*eglInitialize_t)(EGLDisplay, EGLint*, EGLint*);
                eglInitialize_t eglInitialize = dlsym(egl_handle, "eglInitialize");
                if (eglInitialize) {
                    EGLint major = 0, minor = 0;
                    EGLBoolean r = eglInitialize(dpy, &major, &minor);
                    printf("eglInitialize: ret=%d major=%d minor=%d\n", r, major, minor);
                }
            }
        } else {
            printf("eglGetDisplay not found\n");
        }
        dlclose(egl_handle);
    }

    /* Also try to open kgsl-3d0 and read some data first */
    printf("\n=== Raw KGSL with read-first approach ===\n");
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
        printf("open kgsl-3d0: errno=%d\n", errno);
        return 1;
    }
    printf("fd=%d\n", fd);

    /* Try a read — maybe this triggers init? */
    char buf[256];
    int r = read(fd, buf, sizeof(buf));
    printf("read: ret=%d errno=%d\n", r, errno);

    /* Try mmap — many GPU drivers need mmap for command buffers */
    void *map = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    printf("mmap: ret=%p errno=%d\n", map, errno);
    if (map != MAP_FAILED) {
        munmap(map, 4096);
    }

    /* Now try creating context */
    struct { uint32_t flags; uint32_t id; } c = {0x00100000, 0};  /* TYPE_GL */
    r = ioctl(fd, ((uint32_t)3 << 30) | (((uint32_t)0x08) << 16) | (((uint32_t)0x09) << 8) | (0x13), &c);
    printf("DRAWCTXT_CREATE: ret=%d id=%u errno=%d (%s)\n",
           r, c.id, errno, r<0?strerror(errno):"OK");

    close(fd);
    return 0;
}
