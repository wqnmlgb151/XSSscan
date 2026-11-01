# 自动化回归（v1.1.2）

源码仓库包含 `cmd/`、`pkg/` 和 `test/integration/` 的 Go 测试以及 `pkg/dom/sinks.js` 测试资源。原有本地测试直接纳入版本控制，补充缺口；扫描架构、算法、CLI 和五类报告格式不变。

## 环境与命令

需要 Go 1.26.9、Chrome/Chromium，race 需要可用的 C 编译器（Windows 可用 GCC）。Chrome 必须可启动；完整回归不能以 `-short` 代替。所有靶场使用进程内 `httptest` 与 loopback 回调，合成凭据，不需要互联网目标或独立数据库。首次准备 Go 依赖、CI Actions 和浏览器需要联网；安装完成后可设 `GOPROXY=off GOTOOLCHAIN=local` 运行。文档与纯解析样例中的域名不作为扫描目标。

```bash
go mod verify
go vet ./...
go test -p 1 -count=1 -timeout 15m ./...
go test -race -p 1 -count=1 -timeout 15m ./...
go build -trimpath -o xsscan ./cmd
# Windows 输出文件使用 xsscan.exe
```

`-p 1` 只限制同时运行的包数，包内 worker、DOM 并发与竞态测试继续运行。缺少浏览器时仅可运行快速子集 `go test -race -short ./...`；它的跳过项必须记录，不能称完整通过。`testenv.NewServer` 避开 Chrome 禁止端口，避免随机分配到 6667 等端口引起假失败；不放宽浏览器安全策略。

## 覆盖映射

| 场景 | 主要公开测试 |
| --- | --- |
| 四类检测正负标签 | `integration/regression_test.go: TestRegressionBaseline`，4 正例 + 4 安全例 |
| 反射误报、JS/HTML 上下文、惰性 URL | `pkg/verify/verifier_fp_test.go`、`response_context_test.go`、`pkg/context/`、`pkg/scanner/probe_regression_test.go` |
| DOM source/sink、执行证据、原生语义与安全例 | `pkg/dom/quality_test.go`、`sources_browser_test.go`、`evidence_browser_test.go`、`native_semantics_browser_test.go` |
| DOM 并发、取消、浏览器上下文回收 | `pkg/dom/quality_test.go: TestDOMMatrixConcurrencyAndCancellation`、`pkg/internal/chromedp/lifecycle_test.go` |
| 存储注入、触发、轮询、并发与中止 | `pkg/stored/scanner_test.go`、`progress_test.go`、`status_test.go`、`evidence_test.go` |
| Blind token 关联、无关回调、Referer 降分 | `pkg/blind/scanner_test.go`、`regression_test.go: TestBlindCorrelationControls` |
| Blind 截止时间与主动取消 | `pkg/blind/regression_test.go: TestBlindObservationDeadlineAndCancellation` |
| worker/dispatcher 退出、adaptive 覆盖、HTTP 预算 | `pkg/scanner/dispatcher_lifecycle_test.go`、`adaptive_coverage_test.go`、`budget_test.go`、`pkg/orchestrator/runner_test.go` |
| 报告和 CLI 兼容 | `pkg/report/`、`pkg/model/release_contract_test.go`、`cmd/` |

加强了既有测试的断言：预期漏洞必须有发现；取消必须返回错误；adaptive 与 exhaustive 不能通过“双方均零发现”假通过；DOM 的必测 fixture 失败不能变成 skip；stdin 使用临时文件复现。SSRF 公网 IP 分类使用地址字面量，移除公网域名 DNS 解析依赖。

## 准确率与性能基线

```bash
mkdir -p ci-results
go test -p 1 -count=3 -run '^TestRegressionBaseline$' -json ./test/integration > ci-results/baseline.json
python test/summarize.py ci-results/baseline.json --baseline-repeats 3 > ci-results/baseline-summary.json
python -m unittest discover -s test -p 'test_summarize.py'
go test -run '^$' -bench . -benchmem -count=3 ./pkg/jsanalysis ./pkg/context ./pkg/scanner
```

先检查 Go 命令退出码，再运行汇总器。CI 使用 `pipefail` 保留失败状态。汇总器拒绝失败包、失败测试、缺失/重复标签、错误结果及零请求样例；输出每个样例的请求数、耗时和 Go 分配量的中位数、最小值与最大值。`BASELINE` 输出包括：

- `target_requests`：本地靶场实际收到的请求，包括 Chrome 的导航/子资源；不等同于产品的 Go HTTP `RequestsSent` 预算。
- `callback_requests`：本地回调服务器记录数，单独统计。
- `wall_ms`：检测阶段墙钟时间，包括 DOM 浏览器创建，排除 fixture 创建及最后资源关闭。
- `go_total_alloc_bytes`：该阶段 Go 进程累计分配增量。
- `go_heap_inuse_after_bytes`：检测完成时整个 Go 测试进程堆占用采样，**不是峰值 RSS，也不包含 Chrome 子进程**。微基准另有 `ns/op`、`B/op` 和 `allocs/op`。

标签评价的是当前模块候选发现：反射用例关闭执行验证，存储/Blind 的 marker 或 callback 关联并非执行证明。DOM 同样不把单纯流转当作执行证明。每轮 4 TP / 4 TN 只是这个八样例语料的期望；不能外推真实世界准确率。环境、浏览器版本和机器负载会影响结果，v1.1.2 先保存观测，不设脆弱的绝对时间门槛。

## CI 与验证边界

`.github/workflows/build.yml` 在 Windows Server 2022 / Ubuntu 24.04 执行依赖验证、vet、完整测试、完整 race、三轮基线、微基准和原生构建，启动前强制检查 Chrome、GCC，记录版本。日志以 `regression-<os>` artifact 保存；失败时也上传已产生的日志。`master`、`codex/**` 分支及 PR 触发，workflow 仅有 contents:read 权限。

结果记录见 [v1.1.2 基线](baseline-v1.1.2.md)。Docker 运行镜像不包含开发测试与 Chrome，本轮不声称完成 Docker 浏览器回归。后续建议扩展有标签语料、Chrome RSS/CPU 采样与容器测试；预算统一、凭据脱敏等 A 路线问题继续单独审计、测试后提交。
