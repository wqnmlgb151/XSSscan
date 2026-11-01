# v1.1.3 报告安全审计与验证

基线：v1.1.2 分支提交 `22993bd`。本轮仅处理导出、文件保护和临时截图；Go 分层、四类检测、原有 CLI 参数和报告 Schema 1.1 保留。仅在 `codex/v1.1.3-report-security` 提交推送，不发布正式版本。

## 已确认的问题与修复

| 问题 | 严重程度 | 原位置 / 本轮入口 | 复现与修复 |
| --- | --- | --- | --- |
| 五格式导出真实凭据与正文 | 高 | `pkg/httpclient/evidence.go: WithCapture/Snapshot`；`pkg/report/reporter.go: Generate` | 原始捕获故意保真，旧 Reporter 未建立安全边界。用合成 Authorization/Cookie/Set-Cookie/URL/body 密码生成五格式，初始泄露测试五项均失败；现在在共用入口深拷贝并脱敏，扫描与重放内存不变 |
| 嵌套证据、Base64、curl、诊断中的副本绕过 | 高 | `pkg/report/redact.go`；`pkg/report/sarif.go` | 覆盖 InitialRequest、SubmissionHTTP、模块 Issues、Coverage/CrossModule 文本、Basic 解码、form/JSON/multipart、相对 Location code。默认移除正文/响应片段/Base64，未知头隐藏，curl 从安全字段重建 |
| Windows 0600 未限制继承 ACL | 高 | 原 `Reporter.Write`；`pkg/internal/privatefs/` | 在 Everyone 可继承的测试目录创建/替换文件，检查实际 DACL。现用创建时当前用户独占、禁止继承的 DACL，校验后才写字节；不支持权限保护的文件系统拒绝保存 |
| 共享截图目录、文件长期残留 | 中 | `pkg/execverify/verifier.go` | 原共享 `xsscan-screenshots` 目录未清理。现在默认不采集；显式采集随机私有目录和私有文件，Close/父 context 取消清理自身目录，写入与关闭互斥 |
| 脱敏误改状态/Schema 或静态 Key | 中 | `pkg/report/redact.go` | 新测试检查 Cookie 值等于 `1`、`completed`、枚举值及大整数。保留结构枚举、Schema 与计数；静态数据流 Key 不被误判为凭据值 |

Windows 在文件创建时指定安全描述符，避免先创建再收紧 ACL 的句柄窗口；原理参见 [Microsoft 文件访问控制](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)。本轮实现使用已锁定的 `golang.org/x/sys/windows`，没有升级依赖版本。

## 默认安全报告与显式原始证据

```bash
# 默认：五种格式均脱敏，文件访问受限
xsscan --url "http://127.0.0.1:8080/?q=test" --allow-private --output safe.json --format json
# 显式 raw：包含凭据、正文和原始 Base64，仅写受保护文件
xsscan --url "http://127.0.0.1:8080/?q=test" --allow-private --include-raw-evidence --output private.json
```

上述仅演示 CLI，不要求靶场实际监听；自动化验证使用 `httptest` 和合成凭据。新增开关默认 false，YAML 同名；CLI 显式 false 优先。缺少 `--output` 时拒绝 raw 配置。全部旧参数保留，新增这一项后共有 64 个不同 flag。

默认保留报表字段和计数、状态、执行证明及覆盖含义；HTTP 正文与响应内容片段用明确 REDACTED 标记代替，Base64/截图路径置空。凭据识别包含认证/Cookie、Token/password/API key/CSRF/session 等常见命名，URL userinfo 和敏感参数、HTML 密码/隐藏 token 输入，以及已识别值的常见编码副本。会保守地隐藏未知头和与凭据相同的非敏感文本。脱敏报告不能直接作为字节保真重放证据。

SDK 保持 `report.NewReporter()` 默认安全。需要原始输出时使用 `report.NewReporterWithOptions(report.Options{IncludeRawEvidence: true})`，再调用 `Write` 保存。`Generate` 返回给调用方的 raw 字节不受库外文件操作控制，调用方必须同样保护其存储。

## 权限与截图生命周期

所有报告（含 safe/raw）和显式截图使用同一私有写入组件。Unix 创建文件 0600、目录 0700；Windows 创建时 DACL 只允许当前进程用户，并要求 protected 且没有继承 ACE。替换已有宽松文件不修改其硬链接目标的权限，而是创建新私有文件后同目录 rename；拒绝符号链接/目录输出。创建/权限/写入错误直接返回，不降级成普通写入，失败临时文件回收。

CLI 的执行验证默认不落盘截图。SDK 如需临时图像，可使用：

```go
v, err := execverify.NewVerifierWithOptions(ctx, timeout,
    execverify.VerifierOptions{CaptureScreenshots: true})
if err != nil { return err }
defer v.Close() // 生产调用方应检查 Close 的清理错误
```

`ExecutionResult.ScreenshotPath` 只在该验证器未关闭且父 context 未取消时有效，不承诺长期附件。存储失败保留执行观察但记录截图诊断。Close 可并发/重复调用，清理失败可再次 Close 重试；取消回调的清理错误可由 Close 读取。不会删除旧版本共享目录或其他验证器的目录。

## 自动化验证

- `pkg/report/security_test.go`：五格式默认无合成凭据、嵌套/编码/预制 curl 副本、重定向、大写 URL scheme/编码参数名、LF 自定义头副本、Schema/计数、输入不变。
- 原二进制和 HTTP 保真用例仅改为显式 raw；认证失败原报文用例保留原断言并显式 raw；其他原有测试继续使用默认安全模式。
- `cmd/report_security_test.go`：五格式 safe/raw、输出要求、YAML/CLI 优先级。
- `pkg/internal/privatefs/*_test.go`：替换与失败回收、独立目录、Unix 模式/符号链接、Windows 实际 DACL 与宽松父目录。
- `pkg/execverify/screenshot_security_test.go`：默认不落盘、私有临时文件、并发写入/关闭、取消隔离及真实 Chrome PNG 清理。
- `test/legacy-v1.1.2-tests.txt`：从已验收 CI 41312184259 的原始事件生成 1771 个唯一 `package<TAB>Test` 身份，含子测试与 fuzz seed。CI 普通/race 必须逐项仍 pass，新增数量不能掩盖缺失/skip。
- 第二轮 Windows CI 暴露既有 `TestEngine_Run_StatsPopulated` 的毫秒取整时序失败（Duration 为 0）。仅为该合成靶场增加 2ms 响应等待，原有正耗时及其他断言不变；本机连续 100 次 race 已通过。生产计时与扫描逻辑未修改。

本机专项 race（含真实 Chrome）、全项目短 race 和 vet 已通过。完整本地与 Windows/Linux CI 运行结果待更新，不能将短测试的浏览器 skip 当作全量通过。

## 遗留边界

- 脱敏不是任意业务秘密或 PII 的通用识别器；未标注且不属于已识别凭据的自由文本、目标主机/路径仍可能敏感。终端进度/错误日志不属于五格式文件导出边界，分享前需要检查。
- 内存中的原始证据仍存在，以保持认证和浏览器重放；SDK 直接序列化 model/Capture 可绕过报告安全入口。显式 raw 文件含真实凭据，权限不等于可以公开分享。
- 本地管理员/root、同一用户的其他进程、备份/已泄露副本不受当前文件 ACL 防护；输出父目录应由使用者信任。Windows rename 原子性由 Go/文件系统限制，不作跨平台原子承诺。
- 强制终止/断电可能留下私有截图目录，旧版共享目录和旧报告不会自动追溯清理或修复权限。正常 Close/取消及本轮创建文件已测试；无法自动保证所有崩溃场景。
- 下一版本可扩展业务自定义敏感字段配置和受控的证据保留策略；本轮不增加新的扫描业务模块。
