# XSSscan

基于 Go 的上下文感知 XSS 扫描器，支持 **Reflected、DOM、Stored、Blind** 四类检测、浏览器执行验证及五种报告格式。仅用于已获授权的安全测试。

## 安装

从 [v1.1.4 Release](https://github.com/wqnmlgb151/XSSscan/releases/tag/v1.1.4) 下载对应附件，无需安装 Go：

| 平台 | 下载 |
| --- | --- |
| Windows amd64 | [EXE](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.4/xsscan_1.1.4_windows_amd64.exe) / [ZIP](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.4/xsscan_1.1.4_windows_amd64.zip) |
| Linux amd64 | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.4/xsscan_1.1.4_linux_amd64.tar.gz) |
| Linux arm64 | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.4/xsscan_1.1.4_linux_arm64.tar.gz) |
| macOS Intel | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.4/xsscan_1.1.4_darwin_amd64.tar.gz) |
| macOS Apple Silicon | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.4/xsscan_1.1.4_darwin_arm64.tar.gz) |

附件提供 `SHA256SUMS` 和 `release-validation.json`；压缩包包含程序、许可证及 `BUILDINFO.json`。GitHub 的 Source code 压缩包是源码。二进制未提供 Windows Authenticode 或 Apple 公证，运行范围见[发布说明](docs/releases/v1.1.4.md)。

DOM、执行验证及 SPA 渲染需要本机安装 Chrome/Chromium，可用 `--chrome-path` 指定路径。

### 从源码构建

需要 Go 1.26+，推荐固定工具链 **Go 1.26.9**。在源码目录运行：

```bash
go build -trimpath -ldflags "-s -w -X main.Version=1.1.4" -o xsscan ./cmd
./xsscan --version
```

Windows 使用 `-o xsscan.exe`，然后运行 `.\xsscan.exe --version`。

也可使用 Docker；当前运行镜像不包含 Chrome：

```bash
docker build -t xsscan .
docker run --rm xsscan --url "http://target.test/page?q=test" --types reflected --verify-execution=false
```

## 快速使用

以下为 PowerShell 示例，使用 ZIP 解压后的 `xsscan.exe`；独立 EXE 请使用下载文件名，或重命名为 `xsscan.exe`。Linux/macOS 使用 `./xsscan`。将示例地址替换为已授权目标。

```powershell
# 查看参数
.\xsscan.exe --help

# 默认调度四类检测
.\xsscan.exe --url "http://target.test/page?q=test"

# 仅反射型结构分析，关闭浏览器执行验证
.\xsscan.exe --url "http://target.test/page?q=test" --types reflected --verify-execution=false

# 存储型检测，指定内容展示页
.\xsscan.exe --url "http://target.test/save?q=test" --types stored --trigger-url "http://target.test/view"

# Blind 检测，使用内置本地回调监听器
.\xsscan.exe --url "http://target.test/page?q=test" --types blind --callback "http://127.0.0.1:8080"

# 保存 HTML 报告
.\xsscan.exe --url "http://target.test/page?q=test" --types reflected --format html --output report.html

# 批量目标
Get-Content urls.txt | .\xsscan.exe --silent
```

默认启用浏览器执行验证。结构候选、DOM sink 流转和 Blind 回调关联不能直接当作执行证明，以报告的执行状态为准。

缺少 Chrome、Blind 回调或其他必要能力时，模块会显示原因及 `skipped` / `failed` / `partial` 状态，整次扫描可能未完成。未配置回调时，可用 `--exclude-types blind` 明确排除该模块。

## 常用参数

完整参数及 YAML 配置支持以 `--help` 为准。

| 参数 | 默认值 / 用途 |
| --- | --- |
| `--types` / `--exclude-types` | 默认四类；选择或排除检测模块 |
| `--workers` / `--rate-limit` | 反射扫描 10 个 worker / 每秒 100 次请求 |
| `--timeout` / `--module-timeout` | 请求 30 秒 / 单模块 300 秒 |
| `--max-payloads` | 每参数最多 50；0 为不限 |
| `--strategy` | `adaptive`；`exhaustive` 枚举所选反射候选范围 |
| `--verify-execution` / `--verify-timeout` | 默认启用 / 15 秒 |
| `--stored-poll-interval` / `--stored-max-polls` | 2 秒 / 5 轮 |
| `--request-budget` | 10000；仅限制 Go HTTP，0 为不限 |
| `--browser-request-budget` | **0，不限**；独立浏览器页面请求预算 |
| `--crawl` / `--render-spa` | 同域链接发现 / JavaScript 渲染发现 |
| `--header` / `--cookie` / `--jwt` | 认证信息；另支持表单登录、OAuth |
| `--data` / `--method` | 请求体及 HTTP 方法 |
| `--proxy` / `--config` | HTTP 代理 / YAML 配置 |
| `--silent` / `--verbose` | 关闭进度 / 详细诊断 |

**浏览器预算不是完整网络防火墙。** 它只计量受守卫页面的请求尝试，不保证覆盖独立 worker、新窗口、Chrome 自主流量、DNS/TLS、WebSocket 帧或 WebTransport；尝试次数也不等于实际送达次数。详见[预算范围](test/browser-budget-v1.1.4.md)。

## 报告与退出码

支持 `json`（默认）、`html`、`markdown`、`sarif`、`junit`，保持报告 Schema 1.1。报告默认脱敏；确需原始证据时，显式使用 `--include-raw-evidence --output <文件>`。

报告采用 Unix 私有权限或 Windows 受保护 DACL。脱敏不能识别所有自由文本秘密；raw 文件包含敏感信息，分享前应检查。截图默认不落盘，详见[报告安全说明](test/security-v1.1.3.md)。

| 退出码 | 含义 |
| --- | --- |
| `0` | 完整完成，无发现 |
| `1` | 错误、配置失败或扫描未完成 |
| `2` | 完整完成，有发现 |

## 开发与文档

完整回归需要 Chrome；race 还需要 C 编译器。测试使用本地合成靶场。

```bash
go vet ./...
go test -p 1 -count=1 -timeout 15m ./...
go test -race -p 1 -count=1 -timeout 15m ./...
```

- [CHANGELOG](CHANGELOG.md)：版本变更。
- [v1.1.4 发布说明](docs/releases/v1.1.4.md)：发布包、兼容性及已知限制。
- [测试与基线](test/README.md)：四类检测、误报/漏报、并发与取消回归。
- [性能复现](test/performance/README.md)：五轮 A/B、分阶段计时及 pprof；当前合成语料未复现版本退化，不代表真实目标已修复。
- [历史审计](audit/2026-10-31/REPORT.md)：A 路线审计记录。

[MIT License](LICENSE) · [第三方许可证](THIRD_PARTY_NOTICES.md)
