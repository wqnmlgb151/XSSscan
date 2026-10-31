# XSSscan v1.1.0：A路线审计与基线（2026-10-31）

本节记录1.1.0审计阶段（之后随1.1.1归档）；该阶段仅审计、故障注入和建立基线，没有修改 cmd/pkg 扫描源码、算法、CLI参数、四类检测、报告格式或发布逻辑；审计阶段未提交、推送或重新发布；后续1.1.1维护发布只归档这些历史结果，不表示下列风险已修复。新增基线脚本与审计材料位于本目录；另有一个按现有规则忽略的本地清理故障测试。

审计对象：Git tag v1.1.0 / `294771fb065f22a8514f67e73a1526d2e63966d7`。Windows EXE SHA-256：`747719a2a08d31d1e6bc87751a088526e3cdcda639d73ef36ed20065296421ce`，与上轮发布附件记录一致。Karpathy原则用于限定改动和验证范围；Go/Python审查均已完成。

## 问题清单与优先级

P1表示下一次优化/发布前应优先处理，P2为后续改进；严重程度区分安全风险和工程风险，不把能力缺口一律当作远程漏洞。本轮没有证实新的远程代码执行、资源泄漏或P0缺陷。

| ID | 严重程度 / 优先级 | 结论与源码位置 | 验证状态 |
|---|---|---|---|
| A01 | 高（资源控制能力缺口）/ P1 | Chrome不共享Go预算，也无报告中的实际浏览器网络计数。`pkg/orchestrator/budget.go:11,19`、`cmd/main.go:189,338,405`、`pkg/internal/chromedp/guard.go:88,126` | 本机已复现：预算8，报告4次，靶场30次 |
| A02 | 高（条件性凭据暴露）/ P1 | 完整凭据同时进入五种报告；Windows 0600不建立私有ACL。`pkg/httpclient/evidence.go:98,217,231`、`pkg/report/reporter.go:75,86,198,371,686`、`pkg/report/sarif.go:72,269` | 五格式合成凭据命中；本机报告ACL含Users RX、Authenticated Users M |
| A03 | 高（回归可复现性）/ P1 | 公开tag没有任何测试，166个原有本地测试文件全部不在公开源码；CI不运行测试。`.gitignore:35,36`、`.dockerignore:7`、`.github/workflows/build.yml:28,36` | Git树与公开源码快照go test均确认 |
| A04 | 中（诊断一致性）/ P2 | 隔离tab的Cancel错误被CancelFunc接口丢弃；Dispose错误另有保留。`pkg/internal/chromedp/isolated.go:43,54`；`pkg/execverify/verifier.go:97`、`pkg/dom/scanner.go:321`的Close无条件nil | 外部关闭target后底层Cancel报错而helper无错；contexts=0，无泄漏证据 |
| A05 | 中（网络安全边界差异）/ P2 | Chrome自行DNS解析及连接，URL预检不能提供Go DialContext的解析后IP钉住保证。`pkg/internal/chromedp/guard.go:38,90,126` 对照 `pkg/ssrfguard/dial.go:14` | 静态确认架构差异；未做DNS重绑定实测，不宣称绕过已成功 |
| A06 | 中（平台兼容与覆盖）/ P2 | Docker运行层只装ca-certificates，无Chrome；CI漂移OS标签，不覆盖Docker、Linux浏览器/真实四模块。`Dockerfile:9`、`.github/workflows/build.yml:14,18` | 静态确认；本机无docker CLI、WSL发行版列表为空，未实跑Linux/Docker |
| A07 | 中（产物追溯）/ P2 | 发布EXE显示1.1.0，但go version -m仍记录ad26c2c+dirty。历史打包staging嵌套在仓库；`.github/workflows/build.yml:36`及`dist/validation/selfcheck-20261030/build-release.ps1:8` | 本地发布同摘要EXE已核实；不等于证明代码是旧版本 |
| A08 | 中（敏感制品留存）/ P2 | 执行截图写入共享命名的临时目录，无Close清理/保留策略；可能保留登录页数据。`pkg/execverify/verifier.go:72,97,319,328` | 静态确认持久留存与0600写入；未证实跨用户读取截图或符号链接利用 |

### A01：预算和计数不能代表整次扫描网络上限

合成HTML在同源执行24个fetch；以`--types reflected --strategy adaptive --max-payloads 4 --request-budget 8`运行，Go计数4、服务端总数30，扫描仍completed并有执行证明。26次额外目标请求不进入Go预算。该flag明确叫“Go HTTP budget”，这不是违反现有Go预算实现；但帮助文案的“Chrome requests counted separately”没有对应实际网络计数，不能被理解为总量受控。DOM logical source checks也不是网络请求数。

复现：运行下方baseline.py，检查raw-results.json中`030-fanout-adaptive-json`，对照`server.total`、`requests`、`budget`。服务端按Sec-Fetch仅作辅助分类；主要证据是相同靶场的总请求和Go请求之差。UA不能可靠区分客户端，探索轮的UA分类结果已排除。这里只测靶场收到的HTTP请求，未测DNS、WebSocket、Chrome后台网络或被拦截请求。

建议先增内部计量和守恒合同（Go尝试、Chrome准许/完成/拒绝/取消分列），再讨论共享预算语义；耗尽必须标记partial/canceled及未开始工作。不得为了“守预算”默默跳过浏览器或少跑source。保持现有CLI及报告格式，若增加字段需兼容旧解析器并明确schema演进。

### A02/A08：保真证据与可分享报告需要清楚的信任边界

`Authorization: Bearer AUDIT_AUTH_SYNTHETIC`、Cookie `AUDIT_COOKIE_SYNTHETIC`和响应Set-Cookie `AUDIT_RESPONSE_SYNTHETIC`在JSON、Markdown、HTML、SARIF、JUnit均可检索。CLI使用silent时stdout/stderr为空，并不等于文件没有敏感值。Base64也不是脱敏；curl、InitialRequest、SubmissionHTTP、RawRequest/Response、URL参数及页面截图都需要纳入审查。

原始证据是认证重放/POC所需的现有设计，README亦有说明；本项是共享、CI工件和多用户落盘的条件性泄漏风险，不声称外部目标能自动取得本地报告。Reporter临时文件写入+0600+原子替换在Unix有保护意图；本机生成文件仍继承`BUILTIN\Users:(RX)`、`Authenticated Users:(M)`，0600不能作为Windows隐私保证，见report-acl.txt；未用第二账户实际读取。

复现：基线最后5个用例关闭执行验证、输出五格式；检查三个合成token布尔值。Windows用`icacls <report>`检查目标ACL。Linux另需验证umask、临时文件及覆盖已有文件；本轮未实跑。建议保留受限的完整重放证据，单独定义展示/分享的脱敏边界；不要直接改Capture中的值导致认证重放失真。先测试所有重复/编码字段，再实现最小ACL、保留期及导出策略。新文件默认行为如需变化，应先做兼容评审，不在本轮决定新CLI参数。

### A03/A06：本地通过不能替代公开可复现测试

`git ls-tree -r --name-only v1.1.0`共123文件，0个`*_test.go`，无test/。审计开始时工作区cmd/pkg/test有166个测试文件（之后新增的本地审计测试另计），约1001个Test/Benchmark声明不是1001次实际运行的保证。公开源码快照`go test -short ./...`退出0但各包均`[no test files]`，见public-source-tests.log。不能把该成功当作回归通过。现有CI的成功只说明Windows/Linux构建、vet、依赖校验和help/version通过。

Docker不含Chrome，按默认四模块及执行验证运行时能力不齐，应得到明确未完成状态；不是本轮已实测的Docker结果。建议保留轻量HTTP镜像的现有兼容入口，并明确浏览器依赖契约；另用固定版本/摘要的测试环境验证完整能力。先公开经过合成数据审查的测试与fixture，移除对`*_test.go`、test/的笼统忽略；AGENTS和本地日志继续忽略。不必将测试放进最终runtime镜像。

### A04：清理诊断复现，不等于泄漏

使用repro-cleanup.go.txt，在测试自己创建的隔离target上调用CDP CloseTarget，再调用helper cleanup。实际结果：`chromedp.Cancel(tab)=No session with given id (-32602)`，helper protocol/cleanup均nil；private BrowserContext数量0。Dispose成功可能已恢复资源，未来应分类处理“目标已不存在”这种可恢复错误和真实资源清理失败，不能简单让所有冗余detach错误使扫描失败。

复现文件需复制到`pkg/internal/chromedp/audit_cleanup_test.go`（现有忽略规则会忽略它），再运行`go test -race -count=1 -v ./pkg/internal/chromedp -run '^TestAuditCleanupExternallyClosedTarget$'`。故障注入不修改产品代码。尚未覆盖OS强杀、启动中取消、浏览器崩溃、进程树失联和长期反复扫描；不能宣称“所有进程无残留”。

### A05/A07：安全与追溯的待补边界

本轮只用127.0.0.1合成HTTP，不访问外部扫描目标；DNS重绑定只能在后续隔离DNS实验环境验证。若加强Chrome连接策略，必须验证同源资源、重定向、Service Worker、WebSocket和IPv6，不能靠关闭JS/阻断全部资源换取安全数字或性能。

EXE的嵌入VCS字段与tag不一致降低追溯可信度；其字节仍与既有发布摘要一致，不能据此断言扫描源码错版。建议从独立checkout或明确VCS策略构建，记录source SHA、toolchain、Chrome、构建参数和制品摘要；tag源码到制品的可复现构建单独验收。

## 性能与检测基线

Windows 11 build26300 / amd64，Ryzen 9 7940HX，Go1.26.9，Python3.13.5，Chrome156.0.8078.79。固定EXE如上；`workers=4,max-payloads=4,types=reflected,verify-timeout=5,module-timeout=40`，执行验证开启；合成认证头/Cookie。独立参数每参4候选，总计划8。50ms是每个文档的服务端sleep，不延迟asset。该小预算仅用于固定测试输入，未改变默认50或算法候选范围。

30次成对计时（5种fixture × 2策略 × 3），加1次fanout和5格式凭据检查，总36次。策略顺序交替；不剔除冷启动；表中为含EXE启动/浏览器验证/报告写入的墙钟时间，不含脚本运行后的100ms计数等待。最终CLI轮在本轮Go/race/微基准结束后单独运行；随后独立重跑微基准。没有保证整台机器独占，也未锁CPU频率。探索轮并发结果不作为最终计时基线。

| 靶场（每策略 n=3） | adaptive 中位秒 [最小–最大] | exhaustive 中位秒 [最小–最大] | Go 请求 A/E | 候选 A/E | 执行证明 A/E |
|---|---:|---:|---:|---:|---:|
| 安全转义 | 0.656 [0.642–0.697] | 0.654 [0.636–0.692] | 3/3 | 0/0 | 0/0 |
| 唯一反射 | 1.879 [1.869–1.920] | 1.774 [1.608–1.812] | 4/7 | 1/4 | 1/1 |
| 唯一反射，每文档延迟50ms | 2.118 [2.096–2.368] | 2.126 [2.071–2.217] | 4/7 | 1/4 | 1/1 |
| 同参双反射 | 2.440 [2.435–2.571] | 1.821 [1.803–1.863] | 7/7 | 4/4 | 1/1 |
| 两个独立参数 | 2.005 [1.969–2.030] | 2.013 [1.969–2.097] | 6/12 | 2/8 | 2/2 |

所有计时样例completed；安全页零发现且exit0，正例exit2。两独立参数分别有执行证明；双反射4/4候选，未提前停止；Coverage守恒断言通过。不能用这30次正负模板估算真实误报率/漏报率，更不能推论全部四模块检测率。adaptive唯一反射少发3项但并未稳定更快；双反射样例耗时更长，后续应profile等待与验证并发，不先改变权限门控。

内部微基准：`-run '^$' -bench . -benchmem -benchtime 200ms -count 3`，详见microbench.log；不是外部扫描速度。

| 微基准（n=3，中位数） | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| BenchmarkRepeatedScript | 163,653.0 | 54,576.0 | 3.0 |
| BenchmarkUncachedScript | 3,330,672.0 | 907,360.0 | 7,441.0 |
| BenchmarkVerify_RepeatedInertReflections | 7,953,277.0 | 1,253,095.0 | 70,039.0 |
| BenchmarkResponseEvidenceRepeated/local_reuse | 3,149,352.0 | 388,480.0 | 36,010.0 |
| BenchmarkCaptureSummaryLargeResponse/full_snapshot | 1,170,604.0 | 1,056,773.0 | 2.0 |
| BenchmarkCaptureSummaryLargeResponse/summary | 367.6 | 208.0 | 4.0 |

Go微基准有并行GOMAXPROCS=32、GC/缓存和频率噪声，详见原始三样本；不做显著性或跨工具排名。B/op是分配字节，不是峰值RSS。此轮未测Chrome CPU/RSS、系统进程峰值、p95/p99、长稳态或真实网络基线；这些属于下一阶段观测工作，不能填成0。Go HTTP计数、逻辑检查数与服务端请求数分列，绝不生成混合覆盖率。

## 稳定性与adaptive审计

- `pkg/scanner/adaptive.go:319`：唯一锚点与匹配上下文才允许收敛；`engine.go:325`对同桶候选权限取交集，`engine.go:416`在浏览器反馈后标记proof。未经支持/含糊候选继续所选范围。
- `pkg/scanner/adaptive_verification.go`及`verification.go:164`验证并发上限4；`pkg/dom/scanner.go:394`同为4；每tab的RequestGuard有8个worker、128项队列（guard.go:88,99），是局部上限，不是整进程统一资源预算。没有据此乘算出“峰值线程/进程”实测数。
- 隔离上下文、取消传播、队列饱和、重复清理及计数恢复、独立参数、双反射、混桶权限、验证池取消、失败后保留诊断、dispatcher收尾共13个顶层定向race测试通过。见browser-contracts.log；清理诊断故障有上述限定。
- 全项目短race在本机通过，见race-short.log。短模式跳过真实Chrome，不能替代浏览器回归；本轮真实Chrome依据是定向合同和CLI靶场，不冒称重跑了全项目完整race。
- 无本轮确认的跨参数抑制、错误继承停止权限或新增假阳性。多个同类位置仍首锚点分桶，不能把一次dialog证据当作每个位置执行证明。尚缺复杂异步负例、外部模块/动态路由、大响应、WebSocket/Service Worker、崩溃恢复的长期语料。

## 建议提交顺序（本轮不执行产品修改）

1. **基线材料与测试可见性**：先审查并公开合成fixture/现有测试，修正忽略规则，建立clean-checkout可运行的短race CI；固定已知Chrome禁用低端口问题，不关闭浏览器安全策略。独立提交，算法不动。
2. **凭据边界合同与Windows权限**：覆盖全部五格式、raw/base64/curl/URL/初始与提交链；测试当前ACL及Unix0600、证据重放保真，再做最小权限及分享策略修改。兼容约束单独评审。
3. **浏览器网络观测**：只接CDP计量、按阶段/结果记录，不改变请求派发；用fanout与Go重试/重定向样例守恒验证。先消除“counted separately”的歧义。
4. **清理诊断一致性**：基于现有所有权模型收集取消/Dispose错误，区分已恢复错误，保留已观察证据。补浏览器崩溃/超时/强制终止测试，禁止全面替换生命周期实现。
5. **跨平台可复现与产物追溯**：Windows/Linux浏览器合同、固定Docker验证环境、EXE/source SHA对应；保留Windows EXE发布、现有CLI及HTTP-only兼容入口。
6. **资源预算/网络策略加强**：在观测数据与隔离DNS验证后设计Chrome/Go协同预算及边界。任何受预算终止都要显式未完成，不允许静默减少四模块/source矩阵。
7. **有profile依据的局部性能改进**：优先检查分配热点、反复解析、模糊桶等待与启动开销，每个提交对比本基线及完整语料；不得放宽唯一锚点、去掉独立参数、缩短异步窗口或降低检测覆盖率换速度。

验收门槛：干净公开checkout能复现测试；CLI兼容；四模块状态显式；五格式保真/权限合同通过；相同语料至少保留原有独立执行证明及候选范围；耗时和CPU/RSS观测必须注明口径。没有先完成这些门槛，不做全面重构。

## 复现与文件

```powershell
$env:GOTOOLCHAIN='local'; $env:GOPROXY='off'
$go='C:/Users/Administrator/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.windows-amd64/bin/go.exe'
& $go test -race -short -count=1 ./...
# 在上述测试完成后，串行运行基线；仅127.0.0.1:24000..24099
python audit/2026-10-31/baseline.py --exe D:/github/XSS/xsscan.exe --out D:/github/XSS/dist/validation/a-route-20261031/recheck
& $go test -run '^$' -bench . -benchmem -benchtime 200ms -count 3 ./pkg/jsanalysis ./pkg/verify ./pkg/httpclient ./pkg/analyze
```

Windows本机测试需要沙箱外回环访问；不要把sandbox connectex拒绝当作扫描器失败。Linux可用同一Python标准库脚本并传本机二进制绝对路径，但本轮尚未执行。无docker CLI；获批`wsl --list --quiet`返回空，本轮无法借WSL补Linux运行证据。禁止自动下载或对外扫描作为替代。

脚本以新建会话/自己启动的PID为边界，超时才终止其进程树并记录失败，禁止按chrome.exe名称全局杀进程；超时清理分支仅代码审查，未实测强杀。正常循环已运行36次。脚本不接受外部目标URL，fixture只绑定loopback；样例只有合成凭据。

- baseline.py：可复用靶场与断言；summary.json、raw-results.json：最终36次计数/时间，未复制原始HTTP正文。
- microbench.log、race-short.log、browser-contracts.log、public-source-tests.log、report-acl.txt：验证依据。
- repro-cleanup.go.txt：仅本地故障测试源码，不进入产品包。
- 原始五格式报告及探索数据保留在dist/validation/a-route-20261031（忽略目录）；不放入公开报告。脚本源码/统计中的AUDIT_*均为明确合成数据。
