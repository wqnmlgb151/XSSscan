# v1.1.4 实战安全加固进度

工作分支：`codex/v1.1.4-security-hardening`。按 P0 顺序，先失败复现、再修复，每项独立提交。历史审计目录不修改，测试使用 loopback，Go 依赖离线缓存，不增加依赖。

| 条目 | 状态 |
| --- | --- |
| P0-1 代理凭据隔离 | 原测试 HTTP 407 / HTTPS CONNECT 认证失败已复现；修复后 HTTP/HTTPS、五格式报告、日志及身份隔离目标 race 测试通过；构建、vet、short/race 及指定五包真实 Chrome 串行 race 通过；全仓身份门禁/跨平台 CI 待执行 |
| P0-2 表单与爬取安全 | 已复现并实现；目标 HTTP/Chrome race 回归通过，构建/vet/short-race 通过；完整身份门禁及跨平台 CI 待验证 |
| P0-3 Chrome 代理 | 已复现绕过代理并修复；普通/认证/直连/拒绝的真实 Chrome race 回归、build/vet/short-race 通过；本项跨平台 CI 待执行 |
| P0-4 短凭据脱敏 | 已复现并修复；报告包 race、build/vet/全仓 short-race 通过，指定 Chrome 包与跨平台 CI 待完成 |
| P0-5 凭据输入入口 | 未完成 |
| P1-1 Docker | 未完成，需核实基础镜像维护和摘要 |
| P1-2 模块路径 | 未完成 |
| P1-3 SSRF Policy | 未完成 |
| P1-4 marker | 未完成 |
| P1-5 Chrome 参数 | 待真实 Chrome 验证 |
| P1-6 执行观察 | 未完成 |
| P2-1 公开语料 | 未完成 |
| P2-2 回调闭环 | 未完成 |
| P2-3 外部脚本 | 未完成 |
| P2-4 结构整理 | 未开始；等待 P0/P1 验证通过 |
| P2-5 文档与治理 | 未完成；根 README 下载链接已在此前提交统一至 v1.1.4 |

## P0-1 验证及边界

- 失败记录：`dist/validation/security-hardening/p0-1-before.log`，新回归的 HTTP/HTTPS 两个分支均失败。
- 修复后目标命令：`go test -race -count=1 -run 'TestProxyCredentialsStayAtProxy|TestProxyStatusNeverPrintsPassword|TestApplyHeadersProxyAuth|TestObservationGlobalBoundsAndRequestIdentity|TestPlanKeyIncludesAuthenticationAndBody' ./cmd ./pkg/httpclient ./pkg/internal/request ./pkg/dom ./pkg/scanner`：五包通过。
- 文件：`pkg/httpclient/proxy.go`、`pkg/internal/request/request.go`、`pkg/model/target.go`、`cmd/main.go`、`cmd/proxy_security.go`、`pkg/dom/plan.go`、`pkg/scanner/observation.go`、`pkg/scanner/path.go` 及相关测试、新清单、CI、CHANGELOG。
- 行为：代理认证限定在 transport；旧 CLI 不变；SDK 的 Target.ProxyAuth 字段按任务要求移除。内存证据继续保留目标认证，代理认证不进入目标身份。
- 风险/未验证：SOCKS5 认证和真实 Burp 未运行；浏览器代理修复属于 P0-3，当前仍未完成；不将 Go HTTP 测试称为 Chrome 流量已加固。
- `go build ./...`、`go vet ./...`：通过。`go test -short -race -count=1 ./...`：通过（1732 pass / 51 short skip，不作为完整身份门禁通过证明）。`go test -race -p 1 -count=1 ./pkg/internal/chromedp ./pkg/execverify ./pkg/dom ./pkg/stored ./pkg/crawler`：固定提交 a9332b6 的隔离检出通过（265 pass / 0 skip）。全仓完整身份门禁及 Windows/Linux CI：尚未运行。

## P0-2 验证及边界

- 失败记录：`p0-2-before.log`（认证态自动 POST）、`p0-2-redirect-before.log`（同源重定向访问 logout）、`p0-2-stored-noforms-before.log`（Stored 未继承 no-forms），均位于 `dist/validation/security-hardening/`。三个失败均已修复后转绿。
- 文件：`cmd/{main,config,modules,discovery_security_test}.go`、`pkg/crawler/{crawler,form_fields,form_security_test,scope}.go`、`pkg/orchestrator/discovery*.go`、`pkg/httpclient/httpclient.go`、`pkg/ssrfguard/{ssrfguard,url_filter}.go`、`pkg/internal/chromedp/{guard,isolated}.go`、`pkg/stored/scanner.go`、新测试清单及 CHANGELOG。
- 新增四个兼容 CLI/YAML 入口：exclude-url、include-url、no-forms、allow-form-submit。认证态自动 POST 用显式开关恢复；密码表单、危险动作路径始终跳过。文本类填 test，其他成功控件保留默认值。报告包含跳过原因。
- `go build ./...`、`go vet ./...`、`go test -short -race -count=1 ./...`：通过（1740 pass / 52 short skip）。新增真实 Chrome 危险重定向用例以及 HTTP scope、Stored/no-forms、认证 POST opt-in、控件默认值目标 race 回归通过；复用安全端口靶场。
- 末次 Stored scope 检查及 nil filter 防御改动另通过相关包 short/race。全仓完整身份门禁及 Windows/Linux CI 尚未运行；不以 short 的跳过结果代替完整门禁。
- 风险：路径词表是保守启发式，可能排除同名无害路径，不能保证业务无副作用；URL 正则不等于网络防火墙，仍受 Chrome 可观测请求范围限制。Stored 显式触发 URL 同样遵守危险路径与 scope。

## P0-2 跨平台完整验收补充

固定提交 `12125f7` 的 [CI 41782598300](https://github.com/wqnmlgb151/XSSscan/actions/runs/41782598300) Windows/Linux 均通过：build、vet、完整普通/race 各 1860 pass、0 test skip，required-tests 各 1850/1850（含全部 1837 个历史身份）。本地指定五包真实 Chrome 串行 race 为 268 pass / 0 skip。以上覆盖 P0-1/P0-2，不能替代后续改动的回归。

## P0-3 验证及边界

- 文件：`cmd/{main,config,browser_proxy_security_test}.go`、`pkg/browser/proxy*.go`、`pkg/internal/chromedp/{alloc,guard}.go`、新测试清单和 CHANGELOG。
- 失败记录：`dist/validation/security-hardening/p0-3-before.log`，Go 代理请求可达而 Chrome 导航计数为零；修复后实际执行验证经过代理，认证代理可用，显式直连不经过代理并警告一次，拒绝认证明确为不完整。
- 默认行为变化：`--proxy` 同时用于 Chrome；`--browser-direct` 恢复原浏览器直连。认证只响应指定代理 origin 的 Proxy challenge；密码不在 Chrome 参数中，代理认证事件不重复扣除请求预算。Chrome 证书开关独立。
- 已运行：`go build ./...`、`go vet ./...` 通过；目标真实 Chrome race 通过；`go test -short -race -count=1 ./...` 为 1741 pass / 53 short skip，不代表完整门禁。
- 未验证：真实 Burp、Chrome 认证 HTTPS CONNECT、目标 401 挑战、P0-3 跨平台 CI。Chrome 认证 SOCKS5 明确不支持；纯 Go SOCKS5 不受新浏览器限制。共享 allocator 覆盖 DOM/执行验证/render-spa，但新增代理流量断言直接验证的是执行验证 HTTP 路径。
- 风险：代理路由不等于完整网络防火墙；Chrome 自行解析 DNS，后台进程、Service Worker 等不可观测路径仍遵循 v1.1.4 的既有限制。

- P0-3 指定五包真实 Chrome 串行 race：268 pass / 0 skip；独立 Go 审查无 CRITICAL/HIGH，vet 和 diff-check 通过，staticcheck 未安装未运行。

## P0-4 验证及边界

- 文件：`pkg/report/redact.go`、`pkg/report/redact_semantic_test.go`、required-tests 新清单、CHANGELOG。
- 失败记录：`p0-4-before.log` 证实短值破坏 payload/参数/描述/上下文及 HTTP 版本；`p0-4-headers-before.log` 证实自由文本中 Cookie 后续短值、Digest 认证需完整头行脱敏。均在忽略的本地验证目录。
- 修复：敏感头/URL/键值按位置处理；HTTP 正文与响应片段仍隐藏；全局替换至少 8 字节并有 token 边界，语义字段不做任意值全局替换。五格式与 raw opt-in、Schema 1.1 保持不变；既有 canary/raw 合约未删减。
- 已运行：报告包全部 race 通过；build/vet 通过；全仓 short/race 1745 pass / 53 short skip。独立 Go 审查在完整头值修复后无 CRITICAL/HIGH。
- 限制：短凭据在无标签的普通文本回显、嵌入其他 token 的副本、语义字段中的任意秘密副本不再全局清除；未知编码/应用自定义载体仍可能无法识别。默认报告继续隐藏原始 HTTP 正文，不能将启发式脱敏视为完整 DLP。原始证据显式导出仍含凭据且受文件权限保护。

- P0-4 指定五包真实 Chrome 串行 race：268 pass / 0 skip。跨平台完整门禁待本项提交后的 CI；此时 P0-3 CI 41971526767 仍在运行。
