# 构建产物 out/ — 构建产物目录（gitignore，不入库）

所有 Makefile / docker-build 产物统一写到这里，按 **项目 × 架构 × 流水线路径** 区分。

**NDK 编译只走 Docker 镜像 `ghostlock-build`（`exploit/Dockerfile`），本机不要安装 Android NDK。**

```
out/
├── exploit/
│   ├── aarch64/
│   │   ├── preload.so              # 64-bit LD_PRELOAD
│   │   ├── embed/
│   │   │   └── su_daemon_aarch64_pie
│   │   └── tests/                  # exploit/test-programs/*
│   └── armv7a/
│       ├── preload32.so
│       └── ghostlock32             # 32-bit standalone PIE
│
└── stages/
    └── <与 leaf5/stages 源码镜像的相对路径>/
        ├── arm32/<probe>           # BITS=32
        └── arm64/<probe>           # BITS=64
```

## 示例

```bash
# Exploit（Docker）
make exploit                   # 或: make -C exploit docker-build
cd exploit && ./docker-build.sh arm32-pie

# Stage probe（Docker；路径镜像 stages 树）
make -C leaf5/stages docker-build \
  SRC=S05-stack-overwrite/routes/07-kgsl/e-rb-issueibcmds-64/probes/ghostlock64_opt.c \
  BITS=64
# → out/stages/S05-.../probes/arm64/ghostlock64_opt

# 整节点批量
make -C leaf5/stages docker-build NODE=S02-kernelsnitch-leak BITS=32

# 部署到设备（本机 adb；需先 docker-build）
make -C leaf5/stages deploy SRC=... BITS=32
```

设备上 deploy 路径与 host 对齐：

- `/data/local/tmp/exploit/{aarch64,armv7a}/...`
- `/data/local/tmp/stages/<stage-path>/{arm32,arm64}/...`
