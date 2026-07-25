> **阶段**: S05 | **状态**: ❌ 无可行落地路径 | **最后更新**: 2026-07-25

# S05 — 栈覆盖（CFU → waiter->task）

## 目标
找到用户可控的 `copy_from_user`，在绝对栈偏移上覆盖 stale `rt_mutex_waiter->task`（+0x30）。

## 判定标准
- **成功**：PI chain walk 后出现可控 crash / fops 被改（本设备上从未出现）
- **失败**：内核存活且 configfs/ashmem fops 仍无效

## 路由目录（并列候选）

见各子目录 README。**终局：无一路径同时满足「可到达 + 偏移正确」**。

```
waiter->task @ KSP0-0x2B0
64-bit KGSL CFU 太浅 ~88B
32-bit KGSL CFU 过深 / 或 dispatch 拒绝
```

## 建议阅读顺序
1. `routes/05-global-cfu-scan` — 如何系统找候选  
2. `routes/01`–`04`、`06` — 常规/权限阻塞路径  
3. `routes/07-kgsl` — 主攻路径（最深实测）  
4. `routes/08`–`09` — 备选设备与加深栈
