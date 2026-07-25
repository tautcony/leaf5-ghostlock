# Build a single probe (32-bit ARM static by default)
# Usage:
#   make SRC=foo.c                 # → build/foo (armv7a static)
#   make SRC=foo.c BITS=64         # → build/foo (aarch64 static)
#   make SRC=foo.c deploy

SRC ?=
BITS ?= 32
OUTDIR ?= build

NDK ?= $(shell ls -d /tmp/ndk_extract/android-ndk-r29 2>/dev/null || \
            ls -d $(HOME)/Library/Android/android-ndk-r29 2>/dev/null || \
            ls -d /usr/local/Caskroom/android-ndk/29/AndroidNDK*.app/Contents/NDK 2>/dev/null | head -1 || \
            ls -d $(HOME)/android-ndk-r29 2>/dev/null || \
            ls -d $(ANDROID_NDK_HOME) 2>/dev/null)

_HOST_OS := $(shell uname -s)
ifeq ($(_HOST_OS),Darwin)
  NDK_HOST_TAG ?= darwin-x86_64
else
  NDK_HOST_TAG ?= linux-x86_64
endif

TOOLCHAIN = $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)

ifeq ($(BITS),64)
  CC = $(TOOLCHAIN)/bin/aarch64-linux-android33-clang
  # fallback
  ifeq ($(wildcard $(CC)),)
    CC = $(shell ls $(TOOLCHAIN)/bin/aarch64-linux-android*-clang 2>/dev/null | head -1)
  endif
else
  CC = $(TOOLCHAIN)/bin/armv7a-linux-androideabi33-clang
  ifeq ($(wildcard $(CC)),)
    CC = $(shell ls $(TOOLCHAIN)/bin/armv7a-linux-androideabi*-clang 2>/dev/null | head -1)
  endif
endif

BASENAME = $(basename $(notdir $(SRC)))
OUT = $(OUTDIR)/$(BASENAME)

.PHONY: all clean deploy check

all: check $(OUT)
	@file $(OUT)

check:
	@test -n "$(SRC)" || (echo "Usage: make SRC=file.c [BITS=32|64]"; exit 1)
	@test -n "$(NDK)" || (echo "NDK not found"; exit 1)
	@test -f "$(CC)" || (echo "clang not found: $(CC)"; exit 1)

$(OUT): $(SRC)
	@mkdir -p $(OUTDIR)
	$(CC) -static -O2 -Wall -pthread $< -o $@

deploy: $(OUT)
	adb push $(OUT) /data/local/tmp/$(BASENAME)
	adb shell chmod 755 /data/local/tmp/$(BASENAME)

clean:
	rm -rf $(OUTDIR)
