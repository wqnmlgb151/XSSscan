# Changelog

## 1.1.4（待发布）

- 引入批次级共享请求计量器，Go HTTP 与浏览器各自使用并发安全的独立预算；`--request-budget` 保持原有 Go RoundTrip 语义，新增 `--browser-request-budget`（默认 0、不限；支持 YAML）。
- 在共享 CDP Fetch request-stage 守卫计量同源导航、重定向、子资源及页面异步 HTTP(S) 请求；不重复计入 Network 事件或 Go 请求。统计预留的尝试次数，不宣称是所有 Chrome 进程流量。
- 超限时先拒绝暂停请求、停止页面加载，再取消检查；报告记录浏览器预算原因、请求计量和不完整状态，保留现有 Schema 与五格式脱敏。
- 传递调用期 Meter 到隔离 BrowserContext，修复 DOM Close 与浏览器初始化竞争，回收守卫 worker 并保留迟到的预算错误；未减少检测或验证范围。
- 增加本地 Chrome 并发、精确请求计量、重定向、子资源、后台 fetch、超时与上下文清理、执行验证及 CLI 回归。CI 逐项保留 v1.1.3 的全部 1837 个测试事件身份。限制和实际结果见 `test/browser-budget-v1.1.4.md`。

## 1.1.3（待发布）

- JSON、HTML、Markdown、SARIF、JUnit 共用默认安全导出：隐藏 HTTP 正文、响应片段、Base64 原始副本及截图路径，脱敏认证/Cookie/Token、敏感 URL 参数和已识别凭据的诊断副本；未知 HTTP 头默认隐藏，curl 从脱敏证据重新生成。
- 新增显式 `--include-raw-evidence` / YAML 同名配置，要求 `--output`；保留全部旧参数和 Schema 1.1。内存中的认证、CSRF 与浏览器重放证据仍保真，不改变扫描算法。
- 报告与截图共用私有文件写入：Unix 文件 0600、临时目录 0700；Windows 创建时使用当前用户专属受保护 DACL，并在写入内容前核验，权限失败不降级。
- 默认不采集磁盘截图；SDK 显式采集使用独立随机私有目录，Close/父 context 取消清理，关闭与写入互斥，清理错误可由 Close 获取并重试。
- 补充五格式泄露、Basic/自定义头、form/JSON/multipart、重定向 code、ACL、截图与 raw 兼容回归；CI 按身份核对 v1.1.2 原有 1771 个通过事件，防止仅以新增数量掩盖范围退化。
- 修复 CI 暴露的既有统计测试时序不稳定：仅为合成响应增加毫秒级等待，保留正耗时断言和生产计时逻辑。
- 实际验证、审计位置与风险边界见 `test/security-v1.1.3.md`；仅提交独立分支，不自动发布正式版本。

## 1.1.2（待发布）

- 将现有 Go 单元、浏览器及集成测试纳入公开仓库，包含 DOM 测试嵌入资源；新增 loopback 合成靶场基线，覆盖四类检测正负例。
- 补充 Blind 无关回调、跨主机 Referer 降分、超时与取消回归；加强既有预期漏洞、取消、adaptive 和 stdin 断言，移除公网 DNS 测试依赖。
- 共享浏览器安全端口 fixture，避免随机端口被 Chrome 拒绝造成假失败。
- Windows/Linux CI 增加完整测试、race、vet、构建、三轮准确率/性能基线和原始日志上传；汇总器验证样例完整性并拒绝错误结果。
- 版本标识更新为 1.1.2，保留 Go 分层架构、四类检测逻辑、CLI、报告格式及 Windows EXE 构建。
- 实际验证与限制见 `test/baseline-v1.1.2.md`；本节不表示已创建 Release。

## 1.1.1 — 2026-10-31

- 维护发布：版本一致性、构建与审计资料整理。保留 v1.1.0 扫描行为。
- A 路线审计及基线公开于 `audit/2026-10-31/`。

更早版本见 README 的历史更新日志。
