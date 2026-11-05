# Changelog

## 未发布 — 实战安全加固

### P0-1 代理凭据隔离

- HTTP/HTTPS 代理认证通过 transport 的代理 URL userinfo 处理，CONNECT 和普通代理请求携带认证；目标请求与原始证据不再携带代理认证头。
- 移除 `model.Target.ProxyAuth` 及其重放/去重哈希输入；目标 Cookie、Authorization、请求体等身份信息继续参与隔离。保留代理 CLI 参数及 `ProxyAuthHeader` SDK 辅助函数。
- 代理状态日志只显示 scheme/host；URL 解析错误不回显含凭据的原始地址。新增 loopback HTTP/CONNECT、五格式报告及日志安全回归，接入独立 required-tests 清单。

### P0-4 报告语义保护

- 复现并修复短 Cookie 值全局替换破坏 Payload、Parameter、Context 和 HTTP 语法的问题。所有敏感位置继续脱敏（完整认证/Cookie 头、URL userinfo、敏感参数、正文隐藏）。
- 全局凭据副本替换仅用于至少 8 字节的完整 token 边界；Payload、Parameter 等语义字段只按敏感位置处理。五格式、Schema 1.1、显式 raw opt-in 不变，既有 canary/raw 合约保留。

### P0-5 凭据输入入口

- 新增 `XSSCAN_PASSWORD`、`XSSCAN_PROXY_PASSWORD`、`XSSCAN_OAUTH_CLIENT_SECRET`、`XSSCAN_OAUTH_PASSWORD`、`XSSCAN_JWT`；优先级为显式 CLI > 环境变量（含显式空值）> YAML。新增 `--password-file`、`--jwt-file`、`--password-stdin`；只删除末尾换行，保留空格。
- 同一凭据的多个显式来源互斥；密码 stdin 不得同时作为 URL 列表，输入上限 1 MiB。Unix 含凭据 YAML 对组/其他用户可读时警告；日志不回显凭据。

### P1-1 容器

- 升级到受支持且固定摘要的 Alpine 3.23.7，内置 Chromium/CA，默认非 root，保留 Chrome 沙箱；builder 同样固定摘要。新增网络禁用的容器 loopback 执行验证 CI，测试专用 fixture 不进入 final 镜像。
- 镜像只在构建时安装依赖；本机无 Docker，实际镜像构建/执行结果待 CI。Chrome 沙箱所需权限及 CI 权限放宽边界见 `docs/container.md`。

### P1-2 模块路径（零扫描行为变化）

- module/import 统一为实际仓库 `github.com/wqnmlgb151/XSSscan`，不新增依赖、不改变扫描、CLI、报告。SDK 导入者需要更新路径。
- 历史审计和 legacy 测试清单原文保留；CI 只映射模块前缀，全部历史测试名称继续强制验证，新增路径合约回归。

### P1-3 SSRF 策略与地址边界

- 引入显式不可变 Policy，经请求 context、HTTP 客户端、Chrome 隔离上下文传递；CLI 不再修改包级 AllowPrivate，测试不再依赖修改该全局变量。兼容旧 SDK 的默认入口保留，但不应并发修改兼容全局。
- CIDR 预编译，补全多播/保留/广播/文档/测试/转换地址；解包 IPv4-mapped、NAT64、6to4 和 Teredo，转换/隧道范围保守拒绝。客户端复制构造策略，避免调用者修改切片改变已有客户端。
- 新增默认关闭的实验性 `--chrome-pin-dns`：单一 --url、一次解析并校验全部答案，浏览器固定一个已验证 IP，保留同源子资源；强制浏览器直连，批量目标和未显式直连的代理组合明确报错。

### 行为变化

- P1-3：默认拒绝更多特殊用途地址；授权内网/转换地址可用原 `--allow-private` 显式放开。实验性 DNS 固定默认关闭，`--chrome-pin-dns=false` 恢复普通 DNS；开启时只支持单一目标且 Chrome 直连，优先已验证 IPv4，没有 IPv4 时用首个 IPv6，不保证该固定地址可达。

- P0-5：已有敏感 argv 参数继续可用，非 silent 模式新增一次进程列表/历史风险提示；`--silent` 恢复无提示行为。环境变量现在覆盖 YAML；显式旧 CLI 参数可恢复指定值，未设置环境变量时 YAML 行为保持不变。

- 代理凭据仅提供给代理；自定义目标头中的 `Proxy-Authorization` 也被忽略。这是代理认证泄露修复，不提供向目标泄露代理密码的恢复开关；原有代理用户名/密码参数继续使用。
- P0-2：认证态自动发现的 POST 表单默认跳过；使用 `--allow-form-submit` 恢复提交。密码表单和危险动作路径始终跳过并报告原因；不提供绕过该保护的开关。未认证的普通表单保留自动提交行为。
- P0-2：hidden、select、checkbox/radio 等控件保留页面默认值；仅文本类字段填充 `test`。新增 `--no-forms`、可重复的 `--include-url` / `--exclude-url`，同时支持 YAML。URL 范围显式限制扫描请求，跳过原因进入 ScanIssue。
- P0-3：配置 `--proxy` 时，共享 Chrome allocator 默认同样使用该代理。`--browser-direct` 显式恢复浏览器直连；与代理配置同时使用时 stderr 警告一次。代理密码仅通过 CDP 的匹配 Proxy 认证挑战发送，不出现在 Chrome 参数；`--proxy-insecure` 不改变 Chrome 证书策略。
- Chrome 不支持带认证的 SOCKS5 时明确报错，支持的 HTTP 代理认证保持可用；纯 Go 扫描不受浏览器限制影响。代理认证拒绝保留不完整诊断，不静默当作安全结果。

## 未发布 — 性能排查

- 增加 v1.1.1/v1.1.4 默认配置五轮本地 A/B、隔离检出分模块计时及 pprof 工具；公开实测结果与可比范围。本地语料尚未复现版本退化，未修改扫描算法或缩减检测/安全检查。
- 性能门禁验证完整 DOM 矩阵、Stored 请求/注入数、payload 和浏览器执行验证；支持中断恢复，CI 增加门禁自身的反退化测试。见 `test/performance/README.md`。

## 1.1.4 — 2026-11-02

- 正式发布汇总 v1.1.2～v1.1.4；发布前通过 PR 审查、双平台完整回归和五架构原生产物验收，发布包带 SHA256 与源码/运行记录。流程和已知限制见 `docs/releases/v1.1.4.md`。

- 引入批次级共享请求计量器，Go HTTP 与浏览器各自使用并发安全的独立预算；`--request-budget` 保持原有 Go RoundTrip 语义，新增 `--browser-request-budget`（默认 0、不限；支持 YAML）。
- 在共享 CDP Fetch request-stage 守卫计量同源导航、重定向、子资源及页面异步 HTTP(S) 请求；不重复计入 Network 事件或 Go 请求。统计预留的尝试次数，不宣称是所有 Chrome 进程流量。
- 超限时先拒绝暂停请求、停止页面加载，再取消检查；报告记录浏览器预算原因、请求计量和不完整状态，保留现有 Schema 与五格式脱敏。
- 传递调用期 Meter 到隔离 BrowserContext，修复 DOM Close 与浏览器初始化竞争，回收守卫 worker 并保留迟到的预算错误；未减少检测或验证范围。
- 增加本地 Chrome 并发、精确请求计量、重定向、子资源、后台 fetch、超时与上下文清理、执行验证及 CLI 回归。CI 逐项保留 v1.1.3 的全部 1837 个测试事件身份。限制和实际结果见 `test/browser-budget-v1.1.4.md`。

## 1.1.3（随 v1.1.4 汇总发布）

- JSON、HTML、Markdown、SARIF、JUnit 共用默认安全导出：隐藏 HTTP 正文、响应片段、Base64 原始副本及截图路径，脱敏认证/Cookie/Token、敏感 URL 参数和已识别凭据的诊断副本；未知 HTTP 头默认隐藏，curl 从脱敏证据重新生成。
- 新增显式 `--include-raw-evidence` / YAML 同名配置，要求 `--output`；保留全部旧参数和 Schema 1.1。内存中的认证、CSRF 与浏览器重放证据仍保真，不改变扫描算法。
- 报告与截图共用私有文件写入：Unix 文件 0600、临时目录 0700；Windows 创建时使用当前用户专属受保护 DACL，并在写入内容前核验，权限失败不降级。
- 默认不采集磁盘截图；SDK 显式采集使用独立随机私有目录，Close/父 context 取消清理，关闭与写入互斥，清理错误可由 Close 获取并重试。
- 补充五格式泄露、Basic/自定义头、form/JSON/multipart、重定向 code、ACL、截图与 raw 兼容回归；CI 按身份核对 v1.1.2 原有 1771 个通过事件，防止仅以新增数量掩盖范围退化。
- 修复 CI 暴露的既有统计测试时序不稳定：仅为合成响应增加毫秒级等待，保留正耗时断言和生产计时逻辑。
- 实际验证、审计位置与风险边界见 `test/security-v1.1.3.md`；仅提交独立分支，不自动发布正式版本。

## 1.1.2（随 v1.1.4 汇总发布）

- 将现有 Go 单元、浏览器及集成测试纳入公开仓库，包含 DOM 测试嵌入资源；新增 loopback 合成靶场基线，覆盖四类检测正负例。
- 补充 Blind 无关回调、跨主机 Referer 降分、超时与取消回归；加强既有预期漏洞、取消、adaptive 和 stdin 断言，移除公网 DNS 测试依赖。
- 共享浏览器安全端口 fixture，避免随机端口被 Chrome 拒绝造成假失败。
- Windows/Linux CI 增加完整测试、race、vet、构建、三轮准确率/性能基线和原始日志上传；汇总器验证样例完整性并拒绝错误结果。
- 版本标识更新为 1.1.2，保留 Go 分层架构、四类检测逻辑、CLI、报告格式及 Windows EXE 构建。
- 实际验证与限制见 `test/baseline-v1.1.2.md`；本节不表示已创建 Release。

## 1.1.1 — 2026-10-31

- 维护发布：版本一致性、构建与审计资料整理。保留 v1.1.0 扫描行为。
- A 路线审计及基线公开于 `audit/2026-10-31/`。

更早版本见 [历史 Release](https://github.com/wqnmlgb151/XSSscan/releases) 与 Git 提交记录。
