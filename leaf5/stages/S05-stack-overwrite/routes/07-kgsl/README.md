> **路由族**: KGSL `/dev/kgsl-3d0` | **状态**: ⚠️ 部分可达，无 task 覆盖

# 07 — KGSL 栈覆盖族

主攻路径。子目录按利用子步骤与变体排列。

| 子节点 | 状态 | 一句话 |
|--------|------|--------|
| [a-device-access](a-device-access/) | ✅ | 设备可 open，ioctl 分派可达 |
| [b-context-create](b-context-create/) | ✅ | flags=0x12 必需 |
| [c-mem-alloc](c-mem-alloc/) | ❌ | GPUMEM EOPNOTSUPP；CFU 非必需 alloc |
| [d-rb-issueibcmds-32](d-rb-issueibcmds-32/) | ❌ | compat dispatch 拒绝 NR=0x10 |
| [e-rb-issueibcmds-64](e-rb-issueibcmds-64/) | ⚠️ | CFU 触发，位差 ~88B |
| [f-submit-bypass](f-submit-bypass/) | ⚠️ | SUBMIT 可达，CFU 更浅 |
| [g-personality](g-personality/) | ❌ | 不设 TIF_32BIT |

文档：[`../../../../docs/KGSL_STACK_OVERWRITE.md`](../../../../docs/KGSL_STACK_OVERWRITE.md)
