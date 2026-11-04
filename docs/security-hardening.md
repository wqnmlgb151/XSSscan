# v1.1.4 实战安全加固进度

工作分支：`codex/v1.1.4-security-hardening`。按 P0 顺序，先失败复现、再修复，每项独立提交。历史审计目录不修改，测试使用 loopback，Go 依赖离线缓存，不增加依赖。

| 条目 | 状态 |
| --- | --- |
| P0-1 代理凭据隔离 | 原测试 HTTP 407 / HTTPS CONNECT 认证失败已复现；修复后 HTTP/HTTPS、五格式报告、日志及身份隔离目标 race 测试通过；构建、vet、short/race 通过；完整验证待执行 |
| P0-2 表单与爬取安全 | 未完成 |
| P0-3 Chrome 代理 | 未完成 |
| P0-4 短凭据脱敏 | 待失败测试复现 |
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
- `go build ./...`、`go vet ./...`：通过。`go test -short -race -count=1 ./...`：通过（1732 pass / 51 short skip，不作为完整身份门禁通过证明）。真实 Chrome 串行完整验证及 Windows/Linux CI：尚未运行，后续记录实际结果。
