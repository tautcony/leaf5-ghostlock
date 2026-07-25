# Leaf5 GhostLock monorepo helpers
#
# Build artifacts (all under ./out/):
#   out/exploit/{aarch64,armv7a}/...
#   out/stages/<stage-path>/{arm32,arm64}/...
#
# NDK: Docker only (ghostlock-build). Do not install host NDK.
# Python (uv) lives at repo root:  uv sync  →  .venv/

.PHONY: help venv exploit exploit-arm32 exploit-pie probes-help clean-out list-out

help:
	@echo "Targets:"
	@echo "  make venv              uv sync → ./.venv"
	@echo "  make exploit           Docker → out/exploit/aarch64/preload.so"
	@echo "  make exploit-arm32     Docker → out/exploit/armv7a/preload32.so"
	@echo "  make exploit-pie       Docker → out/exploit/armv7a/ghostlock32"
	@echo "  make probes-help       stage probe builder help"
	@echo "  make list-out / clean-out"
	@echo ""
	@echo "Stage probes (Docker NDK auto):"
	@echo "  make -C leaf5/stages SRC=S02-kernelsnitch-leak/probes/test_ks_minimal.c"
	@echo "  make -C leaf5/stages NODE=S02-kernelsnitch-leak BITS=32"

venv:
	uv sync
	@echo "OK  .venv ready — run: source .venv/bin/activate  or  uv run leaf5-collect"

exploit:
	$(MAKE) -C exploit docker-build

exploit-arm32:
	cd exploit && ./docker-build.sh arm32

exploit-pie:
	cd exploit && ./docker-build.sh arm32-pie

probes-help:
	$(MAKE) -C leaf5/stages help

list-out:
	@if [ -d out ]; then find out -type f | sort; else echo "(empty) ./out"; fi

clean-out:
	rm -rf out
	@echo "Removed ./out"
