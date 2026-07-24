# kgsl_probe Makefile — 32-bit ARM compat KGSL ioctl probe
#
# Usage:
#   make                            # Use NDK from env/auto-detect
#   make NDK=/path/to/android-ndk  # Specify NDK path
#   make docker-build               # Build via Docker (no local NDK)
#
# The probe MUST be compiled as 32-bit ARM (armv7a) to trigger
# the TIF_32BIT code path in kgsl_drawobj_cmd_add_ibdesc_list.

TARGET  = kgsl_probe
SRC     = kgsl_probe.c

# ── NDK auto-detection ──────────────────────────────────────────
NDK ?= $(shell ls -d /tmp/ndk_extract/android-ndk-r29 2>/dev/null || \
            ls -d $(HOME)/Library/Android/android-ndk-r29 2>/dev/null || \
            ls -d /usr/local/Caskroom/android-ndk/29/AndroidNDK*.app/Contents/NDK 2>/dev/null | head -1 || \
            ls -d $(HOME)/android-ndk-r29 2>/dev/null || \
            ls -d /usr/local/lib/android/sdk/ndk/29* 2>/dev/null | head -1 || \
            ls -d $(ANDROID_NDK_HOME) 2>/dev/null || \
            ls -d $(ANDROID_SDK_ROOT)/ndk/29* 2>/dev/null | head -1)

_HOST_OS := $(shell uname -s)
ifeq ($(_HOST_OS),Darwin)
  NDK_HOST_TAG ?= darwin-x86_64
else
  NDK_HOST_TAG ?= linux-x86_64
endif

TOOLCHAIN = $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)

# 32-bit ARM compiler (triggers compat ioctl path via TIF_32BIT)
CC = $(TOOLCHAIN)/bin/armv7a-linux-androideabi33-clang

# Fallback: if NDK has different API level
ifeq ($(wildcard $(CC)),)
  CC = $(shell ls $(TOOLCHAIN)/bin/armv7a-linux-androideabi*-clang 2>/dev/null | head -1)
endif

CFLAGS = -static -O2 -Wall

.PHONY: all clean check-ndk docker-build

all: check-ndk $(TARGET)
	@echo "Build complete: $(TARGET)"
	@file $(TARGET)

check-ndk:
ifndef NDK
	@echo "Error: NDK not found. Set NDK=/path/to/ndk or install Android NDK r29"
	@echo "  brew install --cask android-ndk"
	@exit 1
endif
	@test -f $(CC) || (echo "Error: armv7a clang not found at $(CC)"; exit 1)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@

# Deploy to device (requires adb)
deploy: $(TARGET)
	adb push $(TARGET) /data/local/tmp/
	adb shell chmod 755 /data/local/tmp/$(TARGET)
	adb shell /data/local/tmp/$(TARGET)

clean:
	rm -f $(TARGET)

# Build via Docker using project's existing NDK image
docker-build:
	docker run --rm \
	  -v "$(PWD):/src" \
	  -w /src \
	  --entrypoint /opt/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi33-clang \
	  ubuntu:24.04 \
	  -static -O2 /src/$(SRC) -o /src/$(TARGET)
