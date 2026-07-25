# Leaf5 stage probe builder
#
# NDK 编译统一走 Docker 镜像 ghostlock-build（与 exploit/ 相同），本机不安装 NDK。
#
# Outputs:
#   <repo>/out/stages/<path-of-SRC-dir>/<arm32|arm64>/<basename>
#
# Host usage:
#   make docker-build SRC=S02-kernelsnitch-leak/probes/test_ks_minimal.c
#   make docker-build SRC=.../ghostlock64_opt.c BITS=64
#   make docker-build NODE=S02-kernelsnitch-leak BITS=32
#   make docker-build SRC=... && make deploy SRC=...   # adb 在本机
#
# In-container (NDK already mounted):
#   make SRC=... BITS=32|64
#   make NODE=S0x-... BITS=32
#
# BITS=32 → armv7a static | BITS=64 → aarch64 static

.DEFAULT_GOAL := auto

SRC   ?=
BITS  ?= 32
NODE  ?=

STAGES_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
LEAF5_DIR  := $(abspath $(STAGES_DIR)/..)
REPO_ROOT  := $(abspath $(LEAF5_DIR)/..)
OUT_ROOT   := $(REPO_ROOT)/out/stages

IMAGE_NAME ?= ghostlock-build
DOCKERFILE := $(REPO_ROOT)/exploit/Dockerfile

# ── NDK: container only (ANDROID_NDK_HOME) or explicit NDK= ────────
# Do NOT scan host Homebrew / Caskroom / local SDK paths.
NDK ?= $(ANDROID_NDK_HOME)
NDK_HOST_TAG ?= linux-x86_64
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

SRC_ABS      = $(abspath $(SRC))
SRC_REL      = $(patsubst $(STAGES_DIR)/%,%,$(SRC_ABS))
SRC_REL_DIR  = $(dir $(SRC_REL))
BASENAME     = $(basename $(notdir $(SRC)))
OUT_DIR      = $(OUT_ROOT)/$(SRC_REL_DIR)$(ARCH_TAG)
OUT          = $(OUT_DIR)/$(BASENAME)

.PHONY: help auto all check build node-all deploy list-out clean \
        docker-build ensure-image

help:
	@echo "Leaf5 stage probes → $(OUT_ROOT)/<stage-path>/$(ARCH_TAG)/<name>"
	@echo ""
	@echo "  Host (auto Docker NDK — do not install local NDK):"
	@echo "    make SRC=<path-to.c> [BITS=32|64]     # → docker-build"
	@echo "    make NODE=<S0x-...> [BITS=32|64]"
	@echo "    make docker-build SRC=...             # explicit"
	@echo "    make deploy SRC=... [BITS=...]        # host adb after build"
	@echo ""
	@echo "  In-container: same make SRC=... uses image NDK directly"
	@echo "  make list-out | clean"

# Host without NDK → docker-build; container with NDK → native build
auto:
ifeq ($(SRC)$(NODE),)
	@$(MAKE) help
else ifneq ($(wildcard $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)),)
	@$(MAKE) build
else
	@$(MAKE) docker-build
endif

# In-container / with NDK: make SRC=...  or  make NODE=...
all: build

build:
ifneq ($(NODE),)
	@$(MAKE) node-all
else ifneq ($(SRC),)
	@$(MAKE) check $(OUT)
	@echo "OK  $(OUT)"
	@ls -lh "$(OUT)"
	@-command -v file >/dev/null 2>&1 && file "$(OUT)" || true
else
	@echo "Usage: make SRC=path/to/file.c [BITS=32|64]"
	@echo "   or: make NODE=S0x-name [BITS=32|64]"
	@exit 1
endif

check:
	@if [ -z "$(NDK)" ] || [ ! -d "$(NDK)" ]; then \
	  echo "Error: NDK not available here."; \
	  echo "  Host: make docker-build SRC=...  (uses ghostlock-build image)"; \
	  echo "  Do not install a local NDK."; \
	  exit 1; \
	fi
ifneq ($(SRC),)
	@test -f "$(SRC_ABS)" || (echo "Error: source not found: $(SRC)"; exit 1)
	@test -n "$(CC)" && test -f "$(CC)" || (echo "Error: clang not found under $(TOOLCHAIN)"; exit 1)
endif

# test_egl needs dynamic linking for libdl; others stay static.
EXTRA_CFLAGS =
EXTRA_LDFLAGS =
ifneq ($(findstring test_egl.c,$(SRC)),)
  EXTRA_CFLAGS = -fPIE
  EXTRA_LDFLAGS = -pie -ldl
  # non-static: dlopen(libEGL) at runtime
  LINK_MODE =
else
  LINK_MODE = -static
endif

$(OUT): $(SRC_ABS) | check
	@mkdir -p "$(OUT_DIR)"
	$(CC) $(LINK_MODE) -O2 -Wall -pthread $(EXTRA_CFLAGS) "$<" -o "$@" $(EXTRA_LDFLAGS)

REMOTE_DIR = /data/local/tmp/stages/$(SRC_REL_DIR)$(ARCH_TAG)
REMOTE_BIN = $(REMOTE_DIR)/$(BASENAME)

# Host-side adb only (binary must already exist under out/)
deploy:
	@test -n "$(SRC)" || (echo "Usage: make deploy SRC=path/to/file.c [BITS=32|64]"; exit 1)
	@test -f "$(OUT)" || (echo "Error: missing $(OUT) — run: make docker-build SRC=$(SRC) BITS=$(BITS)"; exit 1)
	adb shell mkdir -p "$(REMOTE_DIR)"
	adb push "$(OUT)" "$(REMOTE_BIN)"
	adb shell chmod 755 "$(REMOTE_BIN)"
	@echo "Deployed: $(REMOTE_BIN)"

node-all: check
	@test -n "$(NODE)" || (echo "Usage: make NODE=S02-kernelsnitch-leak [BITS=32|64]"; exit 1)
	@test -d "$(STAGES_DIR)/$(NODE)" || (echo "Error: node not found: $(NODE)"; exit 1)
	@count=0; \
	for f in $$(find "$(STAGES_DIR)/$(NODE)" -name '*.c' -type f | sort); do \
	  rel=$${f#$(STAGES_DIR)/}; \
	  echo "==> $$rel"; \
	  $(MAKE) -f "$(STAGES_DIR)/Makefile" SRC="$$rel" BITS=$(BITS) \
	    NDK="$(NDK)" NDK_HOST_TAG="$(NDK_HOST_TAG)" || exit 1; \
	  count=$$((count+1)); \
	done; \
	echo "Built $$count probe(s) under $(NODE) ($(ARCH_TAG)) → $(OUT_ROOT)/$(NODE)/"

list-out:
	@if [ -d "$(OUT_ROOT)" ]; then find "$(OUT_ROOT)" -type f | sort; else echo "(empty) $(OUT_ROOT)"; fi

clean:
	rm -rf "$(OUT_ROOT)"
	@echo "Removed $(OUT_ROOT)"

# ── Docker (host default for NDK compiles) ────────────────────────
ensure-image:
	@if ! docker image inspect "$(IMAGE_NAME)" >/dev/null 2>&1; then \
	  echo "==> Building Docker image $(IMAGE_NAME) (one-time)…"; \
	  docker build --platform linux/amd64 -t "$(IMAGE_NAME)" -f "$(DOCKERFILE)" "$(REPO_ROOT)"; \
	fi

docker-build: ensure-image
	@if [ -z "$(SRC)" ] && [ -z "$(NODE)" ]; then \
	  echo "Usage: make docker-build SRC=path/to/file.c [BITS=32|64]"; \
	  echo "   or: make docker-build NODE=S0x-name [BITS=32|64]"; \
	  exit 1; \
	fi
	@echo "==> docker make -C leaf5/stages SRC='$(SRC)' NODE='$(NODE)' BITS=$(BITS)"
	docker run --rm \
	  --platform linux/amd64 \
	  -v "$(REPO_ROOT):/src" \
	  -u "$$(id -u):$$(id -g)" \
	  -w /src/leaf5/stages \
	  --entrypoint make \
	  "$(IMAGE_NAME)" \
	  SRC="$(SRC)" NODE="$(NODE)" BITS="$(BITS)" all
