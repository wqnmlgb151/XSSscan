# v1.1.4 Chrome 请求预算与资源控制

基线：master `1717580`，仅在 `codex/v1.1.4-development` 开发。不合并 master，不创建正式 release。

## 原因与接入点

原 `pkg/orchestrator/BudgetTransport` 仅包装 Go HTTP RoundTrip，Chrome 自己拥有 DNS、连接和网络栈，不经过该 transport。DOM、原始 DOM replay、执行验证、认证导航和 SPA rendering 已共用 `pkg/internal/chromedp/guard.go` 的 Fetch 守卫。本轮在同源/SSRF 校验通过后、ContinueRequest 之前计量，复用既有 8 个 worker 和有界队列。

`pkg/requestbudget` 提供同一原子预留实现，HTTP 与 Browser Counter 独立；CLI 每批创建一个 Meter，经 context 传播给全部目标、模块和并发检查。SDK 可将 `requestbudget.WithMeter(ctx, requestbudget.New(httpLimit, browserLimit))` 传给扫描/验证调用；Go HTTP transport 使用同一 Meter 时应设置 BudgetTransport.Meter，Meter 定义其限额。隔离标签显式继承调用期 Meter，浏览器进程仍复用。

## 参数及统计口径

- `--request-budget`：不变，默认 10000，限制 Go HTTP 尝试（含重试/重定向）。`RequestsSent` 仍只表示 Go HTTP。
- `--browser-request-budget`：新增，默认 0 不限；正数为整个批次所有被守卫页面的 HTTP(S) 尝试上限，负数拒绝。YAML 同名，显式 CLI 0 优先。
- 每个 Fetch request-stage 事件预留一次；不再加计 Network 事件。重定向 hop 是新的 Fetch request ID；不按可能复用的 NetworkID 去重。协议继续请求失败仍保留已预留次数，计量不等于服务端收到、响应完成或字节数量。
- 跨域/私网策略拒绝发生在预算之前，不消耗允许请求预算。HTTP 和 Browser 不互相消耗；总量仅为两种预留次数之和，不是统一的旧参数新限额。
- 现有 cross_module observation 的 `request_accounting` 记录两类 admitted/denied 与合计；五种格式沿用现有字段。预算耗尽在 Issues 的 browser-budget 阶段留下原因，模块/扫描不再可报告 completed。没有请求尝试超限时，恰好用完额度不视作失败。

```bash
# 仅演示参数；验证靶场由 Go httptest 自动启动，不依赖该端口已有服务
xsscan --url "http://127.0.0.1:8080/?q=test" --allow-private \
  --request-budget 10000 --browser-request-budget 500 --output safe.json
# 可复现的计数器开销测量
go test -run '^$' -bench '^BenchmarkCounterTake$' -benchmem -count=3 ./pkg/requestbudget
```

## 资源与拒绝顺序

仅取消 CDP 会话可能恢复暂停请求，真实并发测试曾复现超限。本轮在会话仍连接时 FailRequest，再 StopLoading，再取消当前检查，不取消整个 batch 导致其他 Go 模块被当作用户取消。其他并发检查共享原子限额。已耗尽批次的后续检查在守卫初始化时返回明确错误。

守卫在所有返回路径停止并 join worker，最终合并其错误；隔离 BrowserContext 继续沿用显式 dispose/重复关闭保护。DOM Close 先取消 allocator，再通过 browserOnce join 初始化，之后读取 browserCancel，避免并发竞争；认证导航也随调用方取消。没有减少 DOM 输入矩阵、候选生成或验证范围。原 v1.1.3 临时截图私有权限/正常清理及报告脱敏继续保留。

## 本地合成验证

- Counter：100 并发任务争用独立 HTTP/Browser 上限、默认无限及批次隔离；并行微基准。
- Chrome：单个页面 `/start` → `/page` 重定向、脚本、CSS、异步 fetch 精确 5 次，计数与靶场一致；额度 2 拒绝后续子资源。8 并发标签共享 2 次额度，不以 Network 事件重复计数；比较 BrowserContext 列表确认无残留。
- 超时与取消：慢响应等待连接关闭、超时后活跃 handler 归零；取消调用不创建新上下文；既有 lifecycle 测试继续覆盖用户取消、重复 dispose 与父 browser 存活。
- 执行验证：构造器无 Meter、调用时才绑定 Meter，额度仍生效；CLI DOM 超限报告和 errors.Is 原因可追踪，配置 YAML/CLI 0 覆盖及负数校验。
- CI：普通与 race 将 `test/legacy-v1.1.3-tests.txt` 的 1836 个公共身份与 `legacy-v1.1.3-Linux-tests.txt` / `legacy-v1.1.3-Windows-tests.txt` 的 1 个平台专属身份合并，每个平台仍逐项核对基线 1837 身份；本轮没有删除或放宽旧测试。所有网络测试为 loopback 合成数据。

## 实际验收结果与性能

[CI 41403638363](https://github.com/wqnmlgb151/XSSscan/actions/runs/41403638363) 最终 **success**，对应提交 `7e284d3c6b94a80a1dc88440de0765cf88fb8ddd`。Windows Server 2022 / Ubuntu 24.04 均通过依赖验证、vet、Python 汇总器、普通全量、完整 race、三轮标签基线、微基准与原生构建（version/help）。下载两份 artifacts 后从原始日志再次汇总，结果与 CI 摘要一致。

| 平台 | 普通 / race pass 事件 | 两轮各自旧身份 | Counter 并行基准三轮中位数 |
| --- | --- | --- | --- |
| Ubuntu 24.04 | 1847 / 1847 | 1837 / 1837 | 67.49 ns/op，0 B/op、0 allocs/op |
| Windows Server 2022 | 1847 / 1847 | 1837 / 1837 | 54.72 ns/op，0 B/op、0 allocs/op |

1847 包含子测试和 fuzz seed，不是独立函数数；新增 10 个 pass 事件全部通过。每轮 26 个有测试包通过，5 个 skip 包没有测试文件，没有测试用例 skip。全部 v1.1.3 安全回归在对应平台身份范围内。环境、请求/时间/Go 堆区间及 Counter 样本见 [机器可读记录](ci-v1.1.4.json)；完整日志保存在该运行的 `regression-ubuntu-24.04` / `regression-windows-2022` artifacts。

两平台三轮标签结果均为 12 TP / 12 TN、0 FP / 0 FN；八个样例的请求数中位数逐项与 v1.1.3 相同。该语料验证候选发现，不外推真实世界准确率。微基准仅衡量原子预留，未包含网络/CDP 延迟；Go 堆采样不是峰值 RSS，也不包含 Chrome 子进程。普通 SDK 基线未显式绑定 Meter，Counter 开销由独立微基准测量，CLI 绑定与超限由专项集成测试验证。没有以缩减检测制造加速，也不声称整次扫描提速。

本机首轮普通全量 1846 pass（最后一个 HTTP/浏览器隔离用例随后添加并单独 race 通过），完整 race 1847 pass，两者原有 1837 身份全部通过；真实 Chrome 严格计数/并发用例重复 10 次通过，专项 race 和 vet 通过。Counter 本机三轮中位数 51.69 ns/op、0 分配。Windows EXE 与 Linux amd64 交叉构建通过，EXE 显示 1.1.4。

失败记录保留：早期沙箱阻止 loopback，改为允许本地连接后重跑；并发取消时暂停请求恢复的真实超限已修复为先 FailRequest/StopLoading。首轮 CI 41402586619 的 Linux Go 测试 1847 全 pass，但清单误要求 Windows ACL 身份，门禁失败；修复为公共清单加平台清单后重新运行最终 CI 全部成功。独立 Go 审查通过，未安装 staticcheck，不声称运行过该检查。

最终收尾提交只更新文档和观测数据，使用 `[skip ci]`，源码/测试与已验收提交一致；没有合并 master 或创建正式 release。

## 修改文件

- 计量器与 Go transport：`pkg/requestbudget/budget.go`、`budget_test.go`，`pkg/orchestrator/budget.go`、`meter_test.go`。
- CDP 与资源：`pkg/internal/chromedp/guard.go`、`isolated.go`、`budget_test.go`，`pkg/dom/scanner.go`、`replay_browser.go`，`pkg/execverify/verifier.go`、`budget_test.go`，`pkg/crawler/render.go`。
- CLI 配置和不完整结果：`cmd/main.go`、`config.go`、`modules.go`、`browser_budget_test.go`。
- CI 与文档：`.github/workflows/build.yml`、`test/legacy-v1.1.3-tests.txt`、`test/legacy-v1.1.3-Linux-tests.txt`、`test/legacy-v1.1.3-Windows-tests.txt`、`test/ci-v1.1.4.json`、本文件、`test/README.md`、`README.md`、`CHANGELOG.md`、`Makefile`、`Dockerfile`。

## 未覆盖与风险

预算仅覆盖已附加 Fetch 守卫的页面 target。Chrome 自主 favicon、更新/遥测/代理协商、DNS/TLS、浏览器 CDP 控制连接、预连接、WebSocket 帧、WebTransport、ServiceWorker/SharedWorker/独立 worker 或未附加的新窗口 target 的网络不保证可计量或阻止；跨 target/浏览器进程流量不能据此宣称为零。页面中的普通 fetch/XHR/同 target 子资源在守卫存活期间受控，页面离开检查生命周期后的流量不作统计承诺。没有禁用 worker、缓存或减少探测来制造覆盖/性能提升。

计数是“获准尝试”的上限：超时、网络失败或协议错误会使它高于实际送达次数；缓存命中也不代表新增 wire 请求。已有 in-flight 请求在同批其他检查耗尽时可以完成；后续受支持请求被拒绝。CDP/Chrome 崩溃或协议失效时无法证明底层 wire 上限，应按不完整诊断处理。没有断言 Chrome 进程全局 RSS/CPU 上限。
