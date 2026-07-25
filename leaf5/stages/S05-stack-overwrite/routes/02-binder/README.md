> **路由**: binder_thread_write | **状态**: ❌ 关闭

# 02 — Binder 命令路径

## 目标
利用 binder 线程写路径栈布局（Δ≈0）写入可控数据。

## 代码
| 文件 | 效果 | 原因 |
|------|------|------|
| `analysis/ANALYSIS.md` | ✅ 分析完成 | 对齐完美但值是内核指针 |
| `analysis/analyze_binder_commands.py` | ✅ | 映射 BC_* 命令 |
| `analysis/binder_command_mapper.py` | ✅ | 命令→栈写入位置 |

## 结论
- SP 区间覆盖 waiter 字节范围，但内容为 `binder_proc/thread` 指针  
- CFU 落在 SP+0xa8，waiter 范围外  
→ **数据不可控，关闭**
