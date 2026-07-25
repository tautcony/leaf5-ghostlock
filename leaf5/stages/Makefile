# Leaf5 stage probe builder
#
# Outputs (clearly namespaced by stage path + arch):
#   <repo>/out/stages/<path-of-SRC-dir>/<arm32|arm64>/<basename>
#
# Usage (from leaf5/stages/):
#   make SRC=S02-kernelsnitch-leak/probes/test_ks_minimal.c
#   make SRC=S05-stack-overwrite/routes/07-kgsl/e-rb-issueibcmds-64/probes/ghostlock64_opt.c BITS=64
#   make NODE=S02-kernelsnitch-leak          # build every .c under NODE
#   make SRC=... deploy
#   make clean                              # wipe <repo>/out/stages
#
# BITS=32 → armv7a static (TIF_32BIT path)
# BITS=64 → aarch64 static

SRC   ?=
BITS  ?= 32
NODE  ?=

STAGES_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
LEAF5_DIR  := $(abspath $(STAGES_DIR)/..)
REPO_ROOT  := $(abspath $(LEAF5_DIR)/..)
OUT_ROOT   := $(REPO_ROOT)/out/stages

# ── NDK ───────────────────────────────────────────────────────────
NDK ?= $(shell ls -d /tmp/ndk_extract/android-ndk-r29 2>/dev/null || \
            ls -d $(HOME)/Library/Android/android-ndk-r29 2>/dev/null || \
            ls -d /usr/local/Caskroom/android-ndk/29/AndroidNDK*.app/Contents/NDK 2>/dev/null | head -1 || \
            ls -d $(HOME)/android-ndk-r29 2>/dev/null || \
            ls -d $(ANDROID_NDK_HOME) 2>/dev/null || \
            ls -d $(ANDROID_SDK_ROOT)/ndk/29* 2>/dev/null | head -1 || \
            ls -d $(ANDROID_HOME)/ndk/29* 2>/dev/null | head -1)

_HOST_OS := $(shell uname -s)
ifeq ($(_HOST_OS),Darwin)
  NDK_HOST_TAG ?= darwin-x86_64
else
  NDK_HOST_TAG ?= linux-x86_64
endif

TOOLCHAIN = $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)

ifeq ($(BITS),64)
  ARCH_TAG = arm64
  CC = $(TOOLCHAIN)/bin/aarch64-linux-android33-clang
  ifeq ($(wildcard $(CC)),)
    CC = $(shell ls $(TOOLCHAIN)/bin/aarch64-linux-android*-clang 2>/dev/null | head -1)
  endif
else
  ARCH_TAG = arm32
  CC = $(TOOLCHAIN)/bin/armv7a-linux-androideabi33-clang
  ifeq ($(wildcard $(CC)),)
    CC = $(shell ls $(TOOLCHAIN)/bin/armv7a-linux-androideabi*-clang 2>/dev/null | head -1)
  endif
endif

# Resolve SRC → out path mirroring stage tree
SRC_ABS      = $(abspath $(SRC))
SRC_REL      = $(patsubst $(STAGES_DIR)/%,%,$(SRC_ABS))
SRC_REL_DIR  = $(dir $(SRC_REL))
BASENAME     = $(basename $(notdir $(SRC)))
OUT_DIR      = $(OUT_ROOT)/$(SRC_REL_DIR)$(ARCH_TAG)
OUT          = $(OUT_DIR)/$(BASENAME)

.PHONY: all clean deploy check help node-all list-out

help:
	@echo "Leaf5 stage probes → $(OUT_ROOT)/<stage-path>/$(ARCH_TAG)/<name>"
	@echo ""
	@echo "  make SRC=<path-to.c> [BITS=32|64]   build one probe"
	@echo "  make NODE=<S0x-...> [BITS=32|64]    build all .c under node"
	@echo "  make SRC=... deploy                 adb push to /data/local/tmp/stages/..."
	@echo "  make list-out                       show built binaries"
	@echo "  make clean                          remove $(OUT_ROOT)"

# Default goal: single SRC, or NODE batch
ifeq ($(SRC),)
  ifneq ($(NODE),)
all: node-all
  else
all:
	@echo "Usage: make SRC=path/to/file.c [BITS=32|64]"
	@echo "   or: make NODE=S0x-name [BITS=32|64]"
	@exit 1
  endif
else
all: check $(OUT)
	@echo "OK  $(OUT)"
	@file "$(OUT)"
endif

check:
	@test -n "$(SRC)" || (echo "Usage: make SRC=path/to/file.c [BITS=32|64]"; exit 1)
	@test -f "$(SRC_ABS)" || (echo "Error: source not found: $(SRC)"; exit 1)
	@test -n "$(NDK)" || (echo "Error: NDK not found. Set NDK=/path/to/ndk"; exit 1)
	@test -f "$(CC)" || (echo "Error: clang not found: $(CC)"; exit 1)

$(OUT): $(SRC_ABS)
	@mkdir -p "$(OUT_DIR)"
	$(CC) -static -O2 -Wall -pthread "$<" -o "$@"

# Device path mirrors host out layout for clarity
REMOTE_DIR = /data/local/tmp/stages/$(SRC_REL_DIR)$(ARCH_TAG)
REMOTE_BIN = $(REMOTE_DIR)/$(BASENAME)

deploy: $(OUT)
	adb shell mkdir -p "$(REMOTE_DIR)"
	adb push "$(OUT)" "$(REMOTE_BIN)"
	adb shell chmod 755 "$(REMOTE_BIN)"
	@echo "Deployed: $(REMOTE_BIN)"

# Build every .c under NODE (relative to stages/)
node-all:
	@test -n "$(NODE)" || (echo "Usage: make NODE=S02-kernelsnitch-leak [BITS=32|64]"; exit 1)
	@test -d "$(STAGES_DIR)/$(NODE)" || (echo "Error: node not found: $(NODE)"; exit 1)
	@set -e; \
	count=0; \
	while IFS= read -r f; do \
	  rel=$${f#$(STAGES_DIR)/}; \
	  echo "==> $$rel"; \
	  $(MAKE) -f "$(STAGES_DIR)/Makefile" SRC="$$rel" BITS=$(BITS) || exit 1; \
	  count=$$((count+1)); \
	done < <(find "$(STAGES_DIR)/$(NODE)" -name '*.c' -type f | sort); \
	echo "Built $$count probe(s) under $(NODE) ($(ARCH_TAG)) → $(OUT_ROOT)/$(NODE)/"

list-out:
	@if [ -d "$(OUT_ROOT)" ]; then find "$(OUT_ROOT)" -type f | sort; else echo "(empty) $(OUT_ROOT)"; fi

clean:
	rm -rf "$(OUT_ROOT)"
	@echo "Removed $(OUT_ROOT)"
