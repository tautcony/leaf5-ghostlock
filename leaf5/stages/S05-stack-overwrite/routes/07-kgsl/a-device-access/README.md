> **节点**: KGSL 设备访问 / 初始化 | **状态**: ✅

# a — 设备访问与 ioctl 基线

## 代码

| 文件 | 架构 | 作用 | 效果 | 原因/备注 |
|------|------|------|------|-----------|
| `probes/kgsl_probe.c` | 32 | 早期 compat 探测 | ✅ 部分 | 确认 open 与部分 ioctl |
| `probes/test_kgsl_init.c` | 32 | 初始化序列 | ⚠️ | 单独 init 不足创建 context |
| `probes/test_kgsl_compat.c` | 32 | compat 表命令 | ✅/❌ 分命令 | 见后续 NR 差异 |
| `probes/test_kgsl_sequence.c` | 32 | 属性/序列组合 | ⚠️ | 多 SETPROP 仍不够时已过时（后发现 0x12） |
| `probes/test_compat_cmd.c` | 32 | SETPROP compat 码 | ✅ 可达 | errno 因 type 而异 |
| `probes/test_full_init.c` | 32 | 完整 init 尝试 | ⚠️ | 历史 |
| `probes/test_egl.c` | 32 | EGL 依赖探测 | ⚠️ 受限 | 需 `-pie -ldl`（非 static）；无完整用户态驱动时有限 |
| `analysis/kgsl-ioctl-scan.py` | host | ioctl 表扫描 | ✅ | |
| `analysis/kgsl-deep-analysis.py` | host | 深度逆向辅助 | ✅ | |
| `analysis/kgsl-final-analysis.py` | host | 汇总 | ✅ | |

## 结论
`/dev/kgsl-3d0` **0666 可 open**；后续阻塞在 context/命令路径而非 open。
