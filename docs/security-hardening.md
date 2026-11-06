# v1.1.4 实战安全加固进度

工作分支：`codex/v1.1.4-security-hardening`。按 P0 顺序，先失败复现、再修复，每项独立提交。历史审计目录不修改，测试使用 loopback，Go 依赖离线缓存，不增加依赖。

| 条目 | 状态 |
| --- | --- |
| P0-1 代理凭据隔离 | 已完成代码、审查及 Windows/Linux 完整普通/race/历史身份门禁；结果见下方记录 |
| P0-2 表单与爬取安全 | 已完成代码、审查及 Windows/Linux 完整普通/race/历史身份门禁；结果见下方记录 |
| P0-3 Chrome 代理 | 已完成代码、审查及 Windows/Linux 完整普通/race/历史身份门禁；结果见下方记录 |
| P0-4 短凭据脱敏 | 已完成代码、审查及 Windows/Linux 完整普通/race/历史身份门禁；结果见下方记录 |
| P0-5 凭据输入入口 | 已完成代码、审查及 Windows/Linux 完整普通/race/历史身份门禁；结果见下方记录 |
| P1-1 Docker | 已完成代码、审查及 Windows/Linux 完整普通/race/历史身份门禁；结果见下方记录 |
| P1-2 模块路径 | 已完成代码、审查及 Windows/Linux 完整普通/race/历史身份门禁；结果见下方记录 |
| P1-3 SSRF Policy | 已合并至 master，Windows/Linux 完整回归、身份门禁和容器检查通过 |
| P1-4 marker | 已合并至 master，四模块自定义前缀回归及双平台完整 CI 通过 |
| P1-5 Chrome 参数 | 已合并至 master，276 项本地真实 Chrome race 和双平台完整 CI 通过 |
| P1-6 执行观察 | PR #5 已合并至 master，本地五包真实 Chrome 串行 race 和双平台完整 CI 通过 |
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

## P0-5 验证及边界

- 文件：`cmd/{main,credentials,credentials_test,credential_inputs_security_test}.go`、新清单、README、CHANGELOG 与 `docs/credentials.md`。
- 失败记录：`p0-5-before.log`；环境未覆盖 YAML、文件 flag 不存在、argv 警告缺失。修复后 CLI 子进程 loopback 来源与提示回归 race 通过；cmd short/race 通过。
- `go build ./...`、`go vet ./...`、全仓 short/race 通过；最终数量见本条后续记录。独立 Go 审查无 CRITICAL/HIGH。
- 恢复无提示用 `--silent`；CLI 原参数保持可用。显式值 > 环境 > YAML，环境未设置保持旧 YAML 行为。详见凭据文档。
- 未验证：本机未运行 Unix 权限语义（Windows 提前返回）；需 Linux CI 通过后方可声明。环境变量仍可能被同用户诊断工具读取，文件入口不自动修改用户提供文件的权限。

- P0-5 最终本地结果：short/race 1754 pass / 53 short skip；指定五包真实 Chrome 串行 race 268 pass / 0 skip。CI 待推送后运行；Unix 权限分支尚未验证。

## P1-1 验证及边界

- 文件：Dockerfile、.dockerignore、`.github/workflows/build.yml`、`test/containerfixture/main.go`、`test/container-smoke.sh`、`test/integration/container_policy_test.go`、新清单及容器文档。
- 失败记录：`p1-1-before.log`，缺摘要、Chromium、非 root 三项配置契约失败；修复后目标 race 通过。build/vet 通过，全仓 short/race 1755 pass / 53 short skip。
- 仅测试 fixture 与容器配置变化；生产扫描 Go 代码与 P0-5 相同，P0-5 五包串行 Chrome race 268 pass / 0 skip。没有把此结果当作容器运行通过。
- 本机无 Docker，镜像构建/容器真实 Chrome/沙箱执行均未运行。CI 验收待提交触发；固定摘要不固定 apk 依赖快照。非 root 为容器默认行为变化，宿主 CLI 默认不变。CI 权限放宽仅适用于一次性隔离环境。

## P0-3 / P1-1 远程验收补充

- [P0-3 CI 41971526767](https://github.com/wqnmlgb151/XSSscan/actions/runs/41971526767) Windows/Linux 完整普通/race 均 1866 pass、0 test skip；required-tests 1856/1856，保留全部历史身份。
- [P1-1 CI 41973531381](https://github.com/wqnmlgb151/XSSscan/actions/runs/41973531381) 的 container-smoke 作业已通过：runtime/smoke 镜像实际构建、non-root 检查、network none、Chrome 沙箱保留、退出码 2、Schema 1.1、1 个执行验证 finding（Go 请求 4）。本机 Docker 仍未运行；该提交 Windows/Linux 全量回归尚在运行。

## P1-2 验证及边界

- 208 个已跟踪源码/测试/文档文件仅替换模块名前缀为 `github.com/wqnmlgb151/XSSscan`。检测、CLI、Schema 与依赖版本不变。新 module_path_test 防止占位路径复发。
- `p1-2-before.log`（go list 新 module 失败）、`p1-2-test-before.log`（自动化路径断言失败）已保存；新路径断言 race 转绿，build/vet 通过；全仓 short/race 1756 pass / 53 short skip。
- 历史 audit/2026-10-31 与 legacy-v1.1.3 清单原文不动；CI 拼接清单时只映射旧模块前缀，函数/子测试名称逐项保留，不能靠改名逃避门禁。新安全清单混合历史和新命名空间，由同一显式映射处理。
- 独立审查逐文件确认机械替换；跨平台完整身份门禁待提交后 CI。SDK 导入者需更新 module import，这是发布路径纠正，扫描运行行为不变。

- P1-2 指定五包真实 Chrome 串行 race：268 pass / 0 skip；Python 门禁自身 12 个单元测试通过。模块迁移后的完整历史身份门禁由提交后的双平台 CI 验证。

## 已完成提交的完整远程回归

| 条目 | CI | Windows/Linux 普通与 race 各自通过事件 | required-tests |
| --- | --- | --- | --- |
| P0-4 | 41972507484 | 1870 pass / 0 test skip | 1860/1860 |
| P0-5 | 41973111649 | 1879 pass / 0 test skip | 1869/1869 |
| P1-1 | 41973531381 | 1880 pass / 0 test skip | 1870/1870 |
| P1-2 | 41974302001 | 1881 pass / 0 test skip | 1871/1871 |

上述均已下载 JSON 核对；含全部 1837 个原有身份。P0-5 Unix YAML 权限用例已在 Linux 完整/race 中通过；Windows 分支不判断 POSIX 位。P1-1/P1-2 容器 smoke 同样成功，非本地 Docker 执行。

## P1-3 验证及边界

- 文件：`pkg/ssrfguard/{policy,pin,ssrfguard,dial}*.go`、`pkg/httpclient/{httpclient,proxy,policy_security_test}.go`、Chrome allocator/isolated、`pkg/browser/dns.go`、analyze/scanner 预检、cmd 配置/接线/真实 Chrome DNS 用例，旧测试显式策略迁移，新清单与策略文档。
- 失败记录：`p1-3-before.log`（13 个地址缺口）、`p1-3-snapshot-before.log`（调用者切片能放宽已有客户端）、`p1-3-pin-before.log`（功能入口缺失）、`p1-3-iana-before.log`（新增 IPv6 dummy/文档/SRv6 范围）。均转绿。
- 旧测试不再修改 AllowPrivate；静态核对函数名称、断言/skip 调用数量保持不变。认证用例改为显式 context 入口，保留成功/失败断言。CLI 不修改全局，SDK 遗留默认入口保留兼容。
- `go build ./...`、`go vet ./...` 通过；最终全仓 short/race 1761 pass / 54 short skip。真实 Chrome DNS 固定同源脚本/执行验证通过；指定五包 Chrome 串行 race 268 pass / 0 skip。审查发现的切片可变问题已补失败测试并修复，最终无 CRITICAL/HIGH。
- 新行为、恢复开关及网络限制见 CHANGELOG“行为变化”和 `docs/ssrf-policy.md`；实验性固定不提供批量/代理远端 DNS 支持，固定 IP 不保证可达。并非完整网络防火墙；非标准 NAT64 前缀不能自动识别。跨平台完整 CI 待本项提交推送后验证。

## P1-4 验证及边界

- 文件：`pkg/analyze/{marker,analyzer,filterprofile}*.go`、scanner probe factory/engine、DOM plan/scanner、Blind/Stored/orchestrator marker 接线、执行验证 context 入口、cmd flags/YAML 与新回归，CHANGELOG 和 `docs/markers.md`。
- `p1-4-before.log` 复现缺少前缀入口；修复后 CLI 自定义探针、同轮随机前缀一致/轮间变化、加密随机 reader/错误处理/前缀限制，以及自定义前缀四模块（含真实 DOM Chrome）均 race 通过。所有 probe 维度及验证器等价测试通过。
- 默认 xsscan + 12 长度不变；随机前缀默认关闭。旧 GenerateMarker()/InstrumentDialogPayload() SDK 签名保留。DOM hook 原本已按完整 marker 生成，xsspatterns 不匹配固定前缀，未为关键词强行重构。
- build/vet 通过；全仓 short/race 1769 pass / 55 short skip；指定五包真实 Chrome 串行 race 268 pass / 0 skip。独立审查无 CRITICAL/HIGH，三相关包 vet 与两个 marker/probe 单测 race 另通过。
- 风险：熵源故障 fail closed；随机前缀不保证 WAF 绕过或隐匿工具，固定协议参数/内部 hook 名保持兼容。跨平台完整 CI 待提交触发。

## P1-5 验证及边界

- 文件：`pkg/internal/chromedp/{alloc,guard_test,site_isolation_security_test}.go`、`pkg/browser/isolation.go`、cmd flag/YAML 与配置测试、新清单和 `docs/chrome-startup.md`。
- `p1-5-before.log`：恢复隔离的显式前置运行成功，默认禁用隔离的断言失败。恢复默认后新断言转绿。组件更新控制首次真实命令行检查失败后补上显式参数，目标隔离/兼容/三项后台控制 race 通过。
- 默认站点隔离开启、组件更新禁用；原后台网络/同步禁用保留；两个显式兼容开关见 CHANGELOG/--help。保留旧 HTTP scheme 测试身份，新专项用例承担站点隔离断言，未弱化检测矩阵。
- build/vet 通过；全仓 short/race 1770 pass / 60 short skip；指定五包真实 Chrome 串行 race 276 pass / 0 skip。此前中断日志不作为通过证据，重新完整运行 `p1-5-chrome-race-final.json`。独立审查无 CRITICAL/HIGH。
- 本机 Windows 真实 Chrome 已验证，Linux/容器及完整历史门禁待提交后的 CI；命令行参数存在不代表浏览器无后台网络，兼容参数不会关闭预算/SSRF/证书/沙箱策略。

## 已合并批次

[PR #4](https://github.com/wqnmlgb151/XSSscan/pull/4) 以合并提交 `e9f415d` 纳入 P0-1～P0-5、P1-1～P1-5，保留各独立提交。合并后的 [CI 42030836206](https://github.com/wqnmlgb151/XSSscan/actions/runs/42030836206) 已通过。Windows 与 Linux 的普通测试和 race 各为 1905 pass / 0 test skip，required-tests 均为 1895/1895，覆盖原有 1837 项。容器测试通过。P1-5 初次 Linux CI 的 Chrome 调试连接超时在失败作业复跑及 PR 验收中未再出现，未修改历史测试断言。

## P1-6 验证及边界

- 文件集中在 `pkg/execverify/{verifier,settle,settle_security_test}.go`、`pkg/browser/verification.go`、cmd 配置和兼容测试、必跑测试清单及验证文档。
- 三轮预热后的 loopback 惰性负例中位数由 3386.688 ms 降至 422.752 ms，每轮仍是一次请求。2.5 秒延迟 focus/hover、声明式 Shadow DOM 和 HTTP Refresh 仍保留执行证明。原型修改用例在初版优化上未复现漏检，作为防御回归保留。
- 只在 CDP 确认主文档加载完成且解码字节有界时取得正文。原始 HTML 和运行时均判定惰性且网络安静才提前结束。正文未知或超过 256 KiB、脚本/模板、刷新、网络状态溢出均保留完整窗口。
- `go build ./...`、`go vet ./...`、全仓 short/race 通过，1774 pass / 64 short skip。目标真实 Chrome 用例及保守分类、字节上限、取消 race 通过。指定五包真实 Chrome 串行 race 通过 288 项。[PR #5 的完整 CI](https://github.com/wqnmlgb151/XSSscan/actions/runs/42147950243) 在 Windows/Linux 普通和 race 各通过 1918 项，必跑门禁均为 1908/1908。
- `--verify-full-window` 可恢复原完整等待。数据和复现命令见 [执行观察验证](../test/verification-settle.md)。样本仅覆盖本地惰性负例，未测 CPU/RSS。
