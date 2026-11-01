# v1.1.2 验证记录

日期：2026-11-01。以下状态仅随实际运行结果更新，不沿用 v1.1.1 的通过结论。

## 本地 Windows

Go 1.26.9 / amd64，loopback 合成靶场，真实 Chrome。

| 检查 | 当前结果 |
| --- | --- |
| 新增 Blind、DOM 必测样例及八标签基线（race） | 通过，八标签 4 TP / 4 TN |
| Python 汇总器门禁测试 | 8 项通过 |
| 完整普通回归 | 运行中 |
| 完整 race 回归 | 待运行 |
| vet / Windows-Linux amd64 构建 | 通过；Windows `--version` 输出 1.1.2，Linux 仅交叉构建 |
| 三轮非 race 基线 | 待运行 |

首次短回归被旧的 `dist/validation/` 临时 `*_test.go` 编译阻塞；已将该生成记录改为 `.go.txt`，不会纳入源码分发。没有将这次失败记为通过。

## GitHub Actions

Windows/Linux 完整流水线待提交后验证。以对应提交的 Actions 结论及 artifacts 为准。

## 测量限制

具体统计口径见 [测试说明](README.md)。八标签是候选发现回归，不表示执行率或真实世界准确率。Go 堆采样不含 Chrome RSS/CPU；Docker 和 macOS 执行尚未验收。
