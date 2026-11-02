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

## 资源与拒绝顺序

仅取消 CDP 会话可能恢复暂停请求，真实并发测试曾复现超限。本轮在会话仍连接时 FailRequest，再 StopLoading，再取消当前检查，不取消整个 batch 导致其他 Go 模块被当作用户取消。其他并发检查共享原子限额。已耗尽批次的后续检查在守卫初始化时返回明确错误。

守卫在所有返回路径停止并 join worker，最终合并其错误；隔离 BrowserContext 继续沿用显式 dispose/重复关闭保护。DOM Close 先取消 allocator，再通过 browserOnce join 初始化，之后读取 browserCancel，避免并发竞争；认证导航也随调用方取消。没有减少 DOM 输入矩阵、候选生成或验证范围。原 v1.1.3 临时截图私有权限/正常清理及报告脱敏继续保留。

## 本地合成验证

- Counter：100 并发任务争用独立 HTTP/Browser 上限、默认无限及批次隔离；并行微基准。
- Chrome：单个页面 `/start` → `/page` 重定向、脚本、CSS、异步 fetch 精确 5 次，计数与靶场一致；额度 2 拒绝后续子资源。8 并发标签共享 2 次额度，不以 Network 事件重复计数；比较 BrowserContext 列表确认无残留。
- 超时与取消：慢响应等待连接关闭、超时后活跃 handler 归零；取消调用不创建新上下文；既有 lifecycle 测试继续覆盖用户取消、重复 dispose 与父 browser 存活。
- 执行验证：构造器无 Meter、调用时才绑定 Meter，额度仍生效；CLI DOM 超限报告和 errors.Is 原因可追踪，配置 YAML/CLI 0 覆盖及负数校验。
- CI：普通与 race 使用 `test/legacy-v1.1.3-tests.txt` 逐项核对基线 1837 身份；本轮没有删除或放宽旧测试。所有网络测试为 loopback 合成数据。

实际全量结果、性能观测和 CI 链接待本轮运行完成后填写，不将短测/沙箱失败当作通过。

## 未覆盖与风险

预算仅覆盖已附加 Fetch 守卫的页面 target。Chrome 自主 favicon、更新/遥测/代理协商、DNS/TLS、浏览器 CDP 控制连接、预连接、WebSocket 帧、WebTransport、ServiceWorker/SharedWorker/独立 worker 或未附加的新窗口 target 的网络不保证可计量或阻止；跨 target/浏览器进程流量不能据此宣称为零。页面中的普通 fetch/XHR/同 target 子资源在守卫存活期间受控，页面离开检查生命周期后的流量不作统计承诺。没有禁用 worker、缓存或减少探测来制造覆盖/性能提升。

计数是“获准尝试”的上限：超时、网络失败或协议错误会使它高于实际送达次数；缓存命中也不代表新增 wire 请求。已有 in-flight 请求在同批其他检查耗尽时可以完成；后续受支持请求被拒绝。CDP/Chrome 崩溃或协议失效时无法证明底层 wire 上限，应按不完整诊断处理。没有断言 Chrome 进程全局 RSS/CPU 上限。
