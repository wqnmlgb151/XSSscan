# xsscan

<p align="center">
<b>上下文感知 XSS 扫描器</b><br>
<em>Context-Aware Reflected / Stored / DOM / Blind XSS Scanner</em>
</p>

<p align="center">
<img src="https://img.shields.io/badge/go-1.26+-00ADD8?logo=go" alt="Go">
<img src="https://img.shields.io/badge/license-MIT-green" alt="License">
<img src="https://img.shields.io/badge/source-1.1.3-orange" alt="Source version">
<img src="https://img.shields.io/badge/repo-github.com%2Fwqnmlgb151%2FXSSscan-lightgrey" alt="Repo">
</p>

---

## [Releases](https://github.com/wqnmlgb151/XSSscan/releases)

当前版本为 **[v1.1.1](https://github.com/wqnmlgb151/XSSscan/releases/tag/v1.1.1)**（2026-10-31）。[下载 Windows EXE](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.1/xsscan_1.1.1_windows_amd64.exe)，其他平台见[安装](#安装)。默认使用 `adaptive` 策略，调度反射型、DOM、存储型和盲 XSS 四类检测，可用 `--types` 选择检测类型。

当前开发源码为 **v1.1.3**，重点完善默认报告脱敏、私有文件权限和截图清理。安全说明与验证见 [v1.1.3 记录](test/security-v1.1.3.md)，复现步骤见 [自动化回归说明](test/README.md)，本轮变更见 [CHANGELOG](CHANGELOG.md)。上方链接仍指向已经发布的 v1.1.1 附件。

发布页的 **Assets** 提供六个预编译附件：Windows EXE/ZIP，以及 Linux、macOS 的 amd64/arm64 TAR.GZ。GitHub 自动提供的 Source code ZIP/TAR.GZ 为源码；直接运行请下载带 `xsscan_1.1.1_` 前缀的附件。压缩包包含程序、说明和许可证。

## 目录

- [Releases](#releases)
- [特性](#特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [默认检测与类型选择](#默认检测与类型选择)
- [扫描模式](#扫描模式)
- [认证扫描](#认证扫描)
- [高级用法](#高级用法)
- [输出格式](#输出格式)
- [架构](#架构)
- [性能指标](#性能指标)
- [开发](#开发)
- [发布验证](#发布验证)
- [更新日志](#更新日志)
- [免责声明](#免责声明)

---

## 特性

### 核心能力

- **上下文感知 Payload 生成** — 通过 HTML Tokenizer 和 JavaScript AST 识别注入上下文，为每种上下文生成针对性的 payload
- **反射型 XSS 检测** — 基于 marker 的反射检测，模糊匹配（URL 编码、HTML 实体、截断）覆盖各种变形
- **存储型 XSS 检测** — 双阶段检测：注入唯一 marker + 轮询触发页面；`--trigger-url` 可省略，自动同域爬虫发现触发 URL（每目标仅爬取一次）
- **DOM XSS 检测** — 无头 Chrome CDP sink hook 跟踪 marker 流转（innerHTML/eval/document.write 等）；保留 10 种基础 source 测试配置并补测已有 query 参数，命中表示待验证候选
- **Blind XSS 检测** — 内置 HTTP 回调服务器，`sync.Cond` 零 CPU 等待

### 智能引擎

- **自动表单发现 + 链接参数挖掘** — 自动提取 `<form>` 字段生成扫描目标；`--crawl` 时从同域链接 `<a href="...?param=value">` 提取参数名自动扫描（dalfox Grep 特性，需显式开启——扫描用户指定的 URL 不会悄悄跟到其他页面）
- **上下文探针** (`--probe`) — 扫描前发送安全探针验证上下文可利用性，多维探测（结构突围 + 引号突围），检测到框架时自动跳过（模板表达式无 HTML 结构字符）
- **WAF 感知绕过** — 17 种变异策略（11 结构 + 6 编码），按 WAF 类型精准选择，首次检测到 WAF 自动启用
- **置信度评分** — 0.0–1.0 评分体系，含交互效应（WAF×无净化、语法×上下文逃逸）；结构分析封顶 0.90，浏览器执行验证后才可达 100%
- **语义去重 + 同参聚合** — 6 元组 key（URL+参数位置+参数名+上下文+向量+exploit 技术）去重后，同位置同参数同上下文折叠为一条 finding，payload 变体作为子项展示
- **引号类型门控** — 检测到 JS 字符串反射的引号类型后，只发送匹配该引号的逃逸 payload（`"-alert(1)-"` 不再发往单引号反射点）
- **URL 子上下文分析** — href/src 反射只有落在 attribute 值开头或应用已输出的可执行 scheme 前缀后（`javascript:`、`data:image/svg+xml,`、`data:text/html,`）才按 URL 注入处理；落在路径/查询串/片段位置（如 `embed src=xsf02.swf?arg=PAYLOAD`）、非可执行 data: MIME、`http:`/`mailto:` 等固定 scheme 之后一律判定为惰性上下文，不生成 payload
- **过滤发现** — 按参数及反射上下文建立 FilterProfile；同上下文多处回显取最宽松能力，未知或超限保留候选
- **JavaScript AST 分析** — Sobek parser 区分代码、字符串、模板、注释和正则；事件属性支持函数体语法，返回响应再次解析并定位候选调用
- **有界 JS 数据流规划** — 从已加载页面的内联脚本追踪输入、局部别名与函数到 sink，补测代码读取的固定 query/hash/存储键；静态线索只辅助动态检查，不作为执行证明

### 认证 & 集成

- **表单登录** — 自动 CSRF Token 提取 + 403 自动重试
- **OAuth 2.0 / OIDC** — 自动发现、ROPC 流、可配置 scope
- **JWT** — `--jwt` 直接传入 Bearer Token
- **HTTP 代理** — 原生支持 Burp Suite 上行代理
- **SSRF 防护** — 多层 IP 范围验证 + 重定向链检查

### 输出 & 报告

- **5 种格式** — JSON / Markdown / HTML / SARIF / JUnit XML
- **POC 生成** — 可点击 URL + curl 命令 + "Copy for Burp" 原始请求
- **CSP 绕过报告** — 每个 finding 附带 CSP 绕过方案
- **CI/CD 友好** — 退出码区分（0=扫描完成且未发现 / 1=错误或扫描未完成 / 2=扫描完成且发现漏洞）

---

## 安装

### 下载预编译版本

从 [v1.1.1 Releases](https://github.com/wqnmlgb151/XSSscan/releases/tag/v1.1.1) 下载对应平台的文件。使用预编译程序无需安装 Go。

| 平台 | 架构 | 下载 |
| --- | --- | --- |
| Windows | amd64（x64） | [EXE](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.1/xsscan_1.1.1_windows_amd64.exe) / [ZIP](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.1/xsscan_1.1.1_windows_amd64.zip) |
| Linux | amd64（x64） | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.1/xsscan_1.1.1_linux_amd64.tar.gz) |
| Linux | arm64 | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.1/xsscan_1.1.1_linux_arm64.tar.gz) |
| macOS | amd64（Intel） | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.1/xsscan_1.1.1_darwin_amd64.tar.gz) |
| macOS | arm64（Apple Silicon） | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.1.1/xsscan_1.1.1_darwin_arm64.tar.gz) |

ZIP/TAR.GZ 包含程序、`README.md`、`LICENSE`、`THIRD_PARTY_NOTICES.md` 和 `BUILDINFO.json`。Windows 下载后在 PowerShell 中运行：

```powershell
# 直接下载 EXE 后，在下载目录执行
.\xsscan_1.1.1_windows_amd64.exe --version
.\xsscan_1.1.1_windows_amd64.exe --help

# 使用 ZIP 时，解压后运行包内的 xsscan.exe
.\xsscan.exe --version
```

Linux/macOS 解压后运行包内的程序，例如 Linux amd64：

```bash
tar -xzf xsscan_1.1.1_linux_amd64.tar.gz
./xsscan --version
./xsscan --help
```

Windows amd64 已实际运行；其他平台产物由交叉编译生成，需在对应平台验证。Chrome 不包含在包内；默认 DOM 和执行验证需要本机已安装 Chrome/Chromium。

### 从源码构建

源码版本为 `1.1.3`。以下命令在当前源码目录中运行；版本参数只设置程序版本显示，不会下载或升级源码。签出 `v1.1.1` 的示例用于重建已发布版本。

```bash
# 需要 Go 1.26+（推荐 Go 1.26.9）
make build
./xsscan --version
```

从 GitHub 重建已发布的 v1.1.1：

```bash
git clone https://github.com/wqnmlgb151/XSSscan.git
cd XSSscan
git checkout v1.1.1
make build VERSION=1.1.1
```

Windows 没有 make 时，在当前源码目录直接构建 EXE：

```powershell
go build -trimpath -ldflags "-s -w -X main.Version=1.1.3" -o xsscan.exe ./cmd
.\xsscan.exe --version
```

默认检查四类能力。只运行反射模块可使用 `--types reflected`；没有 Chrome 且只需 HTTP 结构分析时，同时添加 `--verify-execution=false`。

默认终端显示当前阶段、阶段完成数和耗时，不逐条打印 payload 的 JSON 日志。进度写入 stderr：交互终端单行刷新，重定向时每 5 秒输出一行；`--silent` 关闭进度，`--verbose` 切换为详细诊断。阶段进度不是整次扫描的预计完成时间。存储型轮询显示参数位置、参数名与已完成的触发请求数；确认阶段还显示候选序号，总数表示最多轮询请求预算，提前发现标记时会进入下一阶段。结果中的每个 Module 行显示实际耗时，便于区分 HTTP 分析、浏览器观察和存储轮询。状态消息也写入 stderr，`--silent`（包括 YAML 的 `silent: true`）在打印横幅前生效，并关闭 JWT、配置、词表、目标读取、代理及报告保存等状态；实际错误仍通过非零退出码和报告保留；非静默时错误写入 stderr。

### Docker

```bash
docker build -t xsscan .
docker run --rm xsscan --url "http://target.com/page?q=test"
```

### 依赖

- Go 1.26+（`go.mod` 声明 1.26.0，推荐工具链 1.26.9；旧 Go 可在 `GOTOOLCHAIN=auto` 下自动下载工具链，离线环境先安装新版）
- Chrome/Chromium（默认 DOM/执行验证及 `--render-spa` 使用；缺失时在逐模块结果中明确说明，扫描可能未完成；可用 `--chrome-path` 手动指定）

---

## 快速开始

```bash
# 查看版本
./xsscan --version

# 默认调度全部类型（缺少能力时报告未完成原因）
./xsscan --url "http://target.com/search?q=test"

# 仅检查反射型 XSS，并关闭浏览器执行验证
./xsscan --url "http://target.com/search?q=test" \
  --types reflected --verify-execution=false

# 管道模式 — 从 stdin 读取 URL
echo "http://target.com/search?q=test" | ./xsscan
cat urls.txt | ./xsscan --silent

# 推荐日常用法 — 上下文探测 + WAF 绕过 + 随机 UA
./xsscan --url "http://target.com/search?q=test" \
  --probe --waf-bypass --random-ua

# 四类检测：指定存储展示页和回调地址（需要本机 Chrome）
./xsscan --url "http://target.com/page?q=test" \
  --probe --waf-bypass \
  --trigger-url "http://target.com/profile" --callback "localhost:8080" \
  --discover-headers --random-ua --adaptive-rate
```

---

## 默认检测与类型选择

不指定类型时，调度 reflected、dom、stored、blind 四类能力。浏览器、存储展示页或回调服务缺失时，会在报告的 Modules 中保留 skipped/failed/partial 和具体原因，整次扫描不会显示“全部检查无漏洞”。浏览器执行验证默认启用；`--verify-execution=false` 可关闭。

```bash
xsscan --url "https://authorized.example/page?q=test"
xsscan --url "https://authorized.example/page?q=test" --types reflected
xsscan --url "https://authorized.example/page?q=test" --types reflected,stored --trigger-url "https://authorized.example/comments"
xsscan --url "https://authorized.example/page?q=test" --exclude-types blind,dom
```

`--headless` / `--stored` 保留兼容；显式 `--headless=false` / `--stored=false` 排除对应类型。显式类型与开启的旧开关相冲突时报配置错误。盲检测独立提交，即使没有即时回显也能检查；每个候选使用独立关联 token。本地回调观察完整 30 秒，外部/DNS 回调没有结果收集器时明确标记未完成。

`--module-timeout 300` 为每目标、每模块的时间预算（秒，0 无限制）；`--request-budget 10000` 为整批目标共享的 Go HTTP 请求预算，包括重试和重定向（0 无限制）。Chrome 网络请求暂单独处理，未计入该 HTTP 数值；模块 Candidates 表示提交/检测尝试，非独立漏洞数。默认 DOM 会测试完整源矩阵，耗时明显高于单反射扫描。

页面发现先执行一次，发现的 GET/POST 表单交给同一组检测模块；链接跟随仍需 `--crawl`。DOM 使用原认证头、HttpOnly Cookie 和首文档 POST 请求体，存储源在目标站点初始化；referrer 来源为显式模拟输入，sink 命中仍是候选。

## 扫描模式

### 反射型 XSS

扫描 Query、POST Body (JSON/Form)、Header、Cookie 参数：

```bash
./xsscan --url "http://target.com/page?id=1" --types reflected
```

#### 自动表单发现

**无需手动指定 `--data`** — 扫描器会自动获取目标页面，提取 `<form>` 元素的 action、method 和 input 字段名，生成 POST 扫描目标：

```bash
# 自动发现并扫描页面上的所有表单
./xsscan --url "http://target.com/login" --probe --allow-private
```

- POST 表单：自动生成 `application/x-www-form-urlencoded` body + Content-Type header
- GET 表单：自动拼接 query 参数到 action URL
- 去重：相同 action+method 的表单只扫描一次
- 与 `--crawl` 叠加：爬虫发现的每一页都会提取表单
- `--render-spa`：SPA 页面无静态表单时，自动用 Headless Chrome 渲染 JS 后提取表单
- **URL 已有 query 参数时跳过**：避免对已有参数的目标重复扫描
- **有诊断提示**：页面无表单或请求失败时显示明确原因

#### 手动指定请求体

```bash
# POST JSON
./xsscan --url "http://target.com/api" -X POST \
  -d '{"search":"test","page":1}' \
  -H "Content-Type: application/json"

# POST form-urlencoded
./xsscan --url "http://target.com/search" -X POST -d "q=test&cat=1"

# 手动 --data 或 URL 已有 query 参数时会跳过自动表单发现
```

#### 其他注入点

```bash
# 自定义 Header 注入
./xsscan --url "http://target.com/page" --discover-headers
```

### DOM XSS（无头浏览器）

```bash
# 需要 Chrome/Chromium
./xsscan --url "http://target.com/page?q=test" --types dom
```

保留 10 种 DOM XSS source 测试配置，并逐个覆盖 URL 已有的 query 参数；使用 CDP hook 记录目标代码的 marker 流转：

| 层级 | 方式 | 置信度 |
|------|------|--------|
| **CDP Sink Hook** | 脚本注入 `Page.addScriptToEvaluateOnNewDocument`，拦截 innerHTML/eval/document.write/Function/location.assign 等 11 种 sink | 0.65（待验证候选） |

Hook 不可用或读取失败会记录检测错误；不会用 URL、控制台或静态 DOM 中出现 marker 代替漏洞证据。Sink 命中是候选，尚不代表 payload 已执行。扫描器不再主动创建 onerror 元素后将自身操作当作目标漏洞。

Cookie 与 History 写入属于输入/导航状态，不作为 XSS sink 证据；测试源初始化先于 hook 安装。同一目标、输入源和 sink 的候选合并，保留 payload 变体与流转片段；只有流转证据时按 65% 的中等级候选展示，不能据此认定执行成功。

DOM 保留 10 种基础 source 和已有 query 参数的 5 payload 检查，最多 4 项并发；一次 DOM 模块内复用 Chrome 进程，每项使用独立 BrowserContext 隔离 Cookie 和存储。调度先安排带额外观察阶段的 postMessage 和已有 query 检查，最终结果仍按原矩阵顺序输出。Cookie 批量设置保留认证到目标值的覆盖顺序；空请求头不重复设置，hook 状态和证据一次读取。原始页面加载失败仍立即结束。仅从导航开始没有出现脚本、事件属性或 frame 等可执行内容、且没有待完成网络请求的静态页面允许提前结束；脚本自删除也会保留执行内容记录。含执行内容的页面继续保留 2 秒观察窗口，postMessage 再观察 1 秒，不以 timer 暂时空闲判断检查完成。跨模块进程复用与浏览器请求共享预算尚未实现。

原始页面的同一次加载还会采集内联脚本，用 Sobek AST 生成有界 source→sink 线索。例如 URL 没有 `view` 参数，但脚本读取 `new URLSearchParams(location.search).get('view')` 再传给 `innerHTML`，现在会补测该固定键；`location.hash` 参数及 `localStorage/sessionStorage.getItem('固定键')` 同理。支持局部别名、字符串组合、局部函数/箭头函数参数与返回值、分支合并和全局对象遮蔽识别；优先安排有线索的检查，但完整基础矩阵保持。每个 payload 最多额外补 24 个固定键，已有 query 检查复用而不重复发送。覆盖面扩大可能增加浏览器耗时，不能把解析优化等同于整次扫描加速。

静态线索与实际 marker 命中相同 sink 时，报告附带 `Evidence.data_flow`（source、key、sink、内联脚本编号及原脚本中的字节范围）。HTML/Markdown 明确标为 `Data Flow (static hypothesis)`；这不是完整调用链或执行证明，sink 收到文本也不保证载荷可利用。规划采集失败仍执行原动态矩阵，同时保留未完成诊断。分析不下载外部脚本，不覆盖完整模块图、跨脚本变量、对象堆、解构或循环不动点；没有静态线索不表示页面安全。

| Source | 测试方式 |
|--------|----------|
| URL Fragment | `#payload` |
| Query String | `?q=payload` |
| Pathname | `/payload` |
| window.name | `window.name` 注入 |
| Referer | `document.referrer` |
| javascript:href | `javascript:` 协议 |
| localStorage | `localStorage.setItem` |
| sessionStorage | `sessionStorage.setItem` |
| document.cookie | Cookie 注入 |
| postMessage | `window.postMessage` |

### 存储型 XSS

```bash
# 指定触发页面（存储内容展示的位置）
./xsscan --url "http://target.com/feedback" -X POST \
  -d "message=test" \
  --types stored --trigger-url "http://target.com/view-feedback"

# 不指定 --trigger-url 时自动发现：同域爬虫（BFS，深度 2，最多 20 页）
# 发现的每个页面都会作为触发 URL 轮询，整个扫描只爬取一次
./xsscan --url "http://target.com/comment" -X POST \
  -d "body=test" --types stored

# 自定义轮询参数
./xsscan --url "http://target.com/comment" -X POST \
  -d "body=test" \
  --types stored --trigger-url "http://target.com/posts/123" \
  --stored-max-polls 10 --stored-poll-interval 3
```

存储型检测先提交唯一 marker 定位持久化展示页，再提交上下文候选并检查触发响应。只有 marker 回显不会生成漏洞；转义内容、JSON、纯文本及惰性 textarea 不作为执行结构证据。

`Evidence.detection_method` 为 `stored_context` 时表示结构候选，`stored_execution` 表示候选专属弹窗已被浏览器确认；`Evidence.trigger_url` 指明展示页。存储型执行确认默认启用，可用 `--types stored --verify-timeout 20` 调整验证时间，并保留认证头、Cookie 和原提交体中的其他字段；`--verify-execution=false` 只保留结构分析。

候选生成当前最多 8 个、每种上下文最多 2 个，选择可关联的本地对话框模板；不构成所有可能 payload 的穷尽验证。同一目标 URL 的提交/轮询生命周期串行，防止候选互相覆盖。自动触发发现会排除带同一参数的提交入口及其片段、端口、尾斜杠等价形式；没有独立展示页时明确提示配置 `--trigger-url`。已知安全展示端点可显式指定。

### Blind XSS（回调服务器）

```bash
# 第三方回调地址（Burp Collaborator、xss.ht 等）— payload 直接指向该地址
./xsscan --url "http://target.com/contact" -X POST \
  -d "message=test" \
  --types blind --callback "https://your-server.com/xss"

# 本地回调 — loopback 地址自动启动内置 HTTP 监听器（省略端口默认 :80）
./xsscan --url "http://target.com/contact" -X POST \
  -d "message=test" \
  --types blind --callback "localhost:8080"

# DNS 外带模式 — 裸域名（无 scheme/端口）生成 <xsscan-随机>.<域名> 子域名
# payload；本工具未接入外部 DNS 日志收集，须在对应平台独立核查
./xsscan --url "http://target.com/contact" -X POST \
  -d "message=test" \
  --types blind --callback "abc.dnslog.cn"
```

本地监听模式在提交后等待完整 30 秒收集回调。目标浏览器必须能够访问回调地址；`localhost:8080` 适用于浏览器与监听器在同一台机器的测试环境。第三方 HTTP/DNS 模式仅提交候选，本工具没有对应结果收集器，模块会明确显示未完成，须在回调平台核查。

---

## 认证扫描

### 表单登录

```bash
./xsscan --url "http://target.com/dashboard" \
  --login-url "http://target.com/login" \
  --username admin \
  --password secret
```

自动处理：Session Cookie、CSRF Token 提取、403 自动重试。

### JWT Token

```bash
./xsscan --url "http://target.com/api/user" \
  --jwt "eyJhbGciOiJIUzI1NiIs..."
```

### OAuth 2.0 / OIDC

```bash
# ROPC 流（自动 OIDC 发现）
./xsscan --url "http://target.com/page" \
  --oauth-issuer "https://login.microsoftonline.com/tenant-id" \
  --oauth-client-id "my-app-id" \
  --oauth-username "user@target.com" \
  --oauth-password "password" \
  --oauth-scope "openid profile"
```

### 预认证 Cookie

```bash
./xsscan --url "http://target.com/page" \
  -c "session=abc123" \
  -c "csrf_token=xyz789"
```

---

## 高级用法

### 批量扫描

```bash
# 从文件批量扫描
./xsscan --targets-file urls.txt -o report.html --format html

# 从 stdin 批量扫描
cat urls.txt | ./xsscan --targets-file - --silent -o report.json
```

### 代理转发（Burp Suite）

```bash
./xsscan --url "http://target.com/page?q=test" \
  --proxy http://127.0.0.1:8080 \
  --allow-private \
  --proxy-insecure
```

`--allow-private` 用于允许回环代理或已授权的内网地址。直连 HTTP 会校验 DNS 结果，并连接其中已校验的 IP；代理模式下，本机校验代理连接地址和目标解析结果，但代理端的再次解析与最终连接不受本机控制。`--proxy-insecure` 会关闭该 HTTP Transport 的 TLS 证书校验（包括目标 HTTPS），不会自动改变 Chrome 的证书策略。

### 自动发现与重定向范围

表单、链接参数和 CLI 爬取默认限于同源：协议、主机及有效端口均须一致（HTTP 的 80 和 HTTPS 的 443 可省略）。自动 HTTP 重定向也不能跨来源，因此不会把原目标的认证头和 Cookie 带到另一端口或站点。HTTP → HTTPS 跳转需要直接配置最终 HTTPS URL。

不同来源的目标或登录端点可以由使用者分别显式配置；原有登录域名校验仍生效。跨来源 SSO 自动跳转会被阻止，可使用已取得的 Cookie/JWT 或直接指定合适的认证端点。

### 动态调度（默认）

反射扫描默认使用 `--strategy adaptive`，无需额外参数。每个已区分的调度路径同时只派发一个决策任务；产生结构候选后，等待浏览器验证结束，再决定是否继续。提前停止要求输入身份完整、只有一个有锚点的反射、候选上下文匹配，且同一调度桶内全部候选都满足归因条件，再取得候选专属的浏览器执行证明。多处反射、缺失锚点或上下文不匹配时保留所选候选范围；其他参数独立推进。单次 Run 复用验证器，浏览器验证最多4项并发，已完成的正例、负例和错误直接进入报告，不在末尾重复验证。

```bash
# 默认动态调度；默认仍调度四种检测类型
./xsscan --url "http://target.com/page?q=test"

# 显式发送所选范围内全部反射候选，用于完整枚举或对照
./xsscan --url "http://target.com/page?q=test" --strategy exhaustive
```

YAML 可配置 `strategy: exhaustive` 或 `strategy: adaptive`，显式 CLI 参数优先。`--probe` 是上下文探测开关，与调度策略独立。关闭 `--verify-execution` 或没有执行证明时，不会因结构回显就停止剩余候选；浏览器失败仍报告未完成。同一参数的多个同类反射位置目前仍以首个锚点分桶，无法据弹窗判断实际执行位置，因此不允许该桶提前停止，也不声称逐位置覆盖。动态调度目前复用预生成候选与过滤反馈，并非完整的在线载荷合成器，也不保证每种页面都更快；DOM、stored、blind 的工作不由反射策略缩减。

报告中的 `adaptive_verification_attempts` 统计派发期间请求的候选验证及其完成、失败、取消和未开始数。未来会产生多少结构候选预先未知，因此其计划显示 unknown；它不是 Chrome HTTP 流量。显式 exhaustive 仍使用 `final_verification_groups`。`reflected_candidates.not_started` 包括执行证实后停止、取消等未派发任务，不能称为已测试。

本地对照（2026-10-16，反射模块、20候选、10 workers、开启probe与执行验证，每组3次）：快速回显样例由旧adaptive的20次候选降为新默认的1次，耗时中位数1.812s→1.215s；响应延迟80ms样例为2.577s→1.683s，12次均保留浏览器执行证明。结果仅说明这些本地样例的反馈闭环生效，不代表复杂页面或四模块扫描的统一加速比例。

2026-10-17 自检修复了调度器对已关闭输入通道的忙循环，并等待生产者与完成通知协程退出。本地唯一反射样例交替对照3次，扫描器主进程CPU时间中位数1.6094s→0.6875s，单次扫描耗时中位数1.6977s→1.6445s；CPU统计不包含Chrome子进程。多反射样例保留4/4候选，唯一明确反射仍可在20候选中实际发送1项并保留执行证明。

### Payload 控制

```bash
# 最小 payload 集（快速侦察）
./xsscan --url "http://target.com/page?q=test" \
  --payload-preset minimal

# 完整 payload 集（深度扫描）
./xsscan --url "http://target.com/page?q=test" \
  --payload-preset full

# 自定义 payload 词表
./xsscan --url "http://target.com/page?q=test" \
  --payload-wordlist my-payloads.txt

# 限制每个参数的 payload 数量
./xsscan --url "http://target.com/page?q=test" \
  --max-payloads 5
```

### 浏览器路径

```bash
# 手动指定 Chrome/Chromium 二进制（自动检测失败时）
./xsscan --url "http://target.com/page?q=test" --chrome-path "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

Chrome 默认启用沙箱并校验 TLS 证书。需要兼容自签名证书时显式添加 `--chrome-ignore-cert-errors`；运行环境确实无法使用沙箱时显式添加 `--chrome-no-sandbox`。YAML 使用相同键名，CLI 显式设置（包括 `=false`）优先。

`--headless`、`--render-spa`、`--verify-execution` 共用 HTTP(S) 请求拦截策略，限制导航、重定向和子资源为目标同源；依赖外部 CDN 的页面可能因此无法完整渲染。请求队列满或 CDP 请求处理失败会取消当前标签页，避免监听线程卡死。该策略约束 CDP Fetch 可拦截的请求，并非浏览器网络沙箱：Chrome DNS/实际连接、WebSocket 和其他未覆盖通道不享有 Go HTTP 拨号绑定保证。

### 浏览器执行验证

```bash
# 用真实 Chrome 验证 XSS 是否实际执行
./xsscan --url "http://target.com/page?q=test" \
  --verify-execution --verify-timeout 20
```

验证器为支持的 alert/confirm/prompt 调用生成候选专属标记，只接受本次标记对应的弹窗，导航也必须完成。支持对携带该标记的 `onfocus` / `onmouseover` 元素进行受控 focus 或合成 mouseover，最多处理 16 个候选元素，不点击链接或提交表单；实际交互方式写入报告。

原始反射 `Payload` 与实际发送的 `Evidence.verification_payload` 分开保留，弹窗内容在 `Evidence.dialog_message` 中。当前关联支持参数为 `1` 或简单字符串常量的对话框调用；不支持的候选保留结构发现并记录验证错误。关联探针会扩张/改变载荷，可能受到长度或关键词过滤，探针未执行不代表原始 payload 不可利用。

评分处理：
- 验证通过：置信度 +0.15（上限 1.0）
- 验证失败：置信度 ×0.85

### 速率控制

```bash
# 固定速率
./xsscan --url "http://target.com/page?q=test" \
  --rate-limit 10 --workers 5

# 自适应速率（遇 429 自动降速）
./xsscan --url "http://target.com/page?q=test" \
  --adaptive-rate

# 隐蔽模式
./xsscan --url "http://target.com/page?q=test" \
  --rate-limit 3 --random-ua --adaptive-rate
```

### YAML 配置文件

```yaml
# config.yaml
url: "http://target.com/page?q=test"
workers: 10
rate-limit: 50
timeout: 30
probe: true
waf-bypass: true
random-ua: true
adaptive-rate: true
output: "report"
format: "html"
confidence: 0.6
```

```bash
./xsscan --config config.yaml
```

CLI 参数优先于配置文件。

---

### 配置与认证判据

`--config` 支持全部扫描配置。未知键、重复键、多份 YAML 文档和 merge key 会报错；显式 `false`、`0`、空字符串仍生效，CLI 显式参数优先。比如 `verify-execution: false` 关闭浏览器复核，`request-budget: 0` 不限 Go HTTP 尝试数，`confidence: 0` 保留零阈值。

表单登录的 HTTP 200 不自动表示成功。默认检查新增/变化的非 CSRF Cookie，并排除明显失败页面，这是启发式；目标提供稳定成功标志时，使用 `--login-success-contains "Welcome"` 或 `--login-success-url "https://target.example/account"`，两者同时提供时均须匹配。显式判据优先于默认页面启发式。认证失败仍写入报告，保留失败请求/响应和各类型未运行原因。

OIDC 保留 issuer 租户路径和尾斜杠，发现文档的 issuer 必须精确一致。端点默认限于 issuer 同源；合法跨源认证端点可显式用 `--oauth-allow-origin https://tokens.example` 授权，并继续经过地址/重定向检查。

### 原始 HTTP 证据

从 v1.1.3 起，五种格式默认导出安全脱敏报告：Authorization、Cookie、Set-Cookie、Token 等凭据、敏感 URL 参数以及已识别的凭据副本会被隐藏；完整 HTTP 正文、响应片段、原始 Base64 与临时截图路径不导出，未知 HTTP 头也默认隐藏。HTML 复制按钮和 curl 使用脱敏后的内容，需补齐认证/正文才能重放。浏览器复核仍使用内存中保真的认证状态；存储型内存证据仍区分提交和展示 HTTP 交换。

确需字节保真证据时显式使用 `--include-raw-evidence --output private-report.json`（YAML：`include-raw-evidence: true`），该开关不允许省略输出文件。详见 [安全边界与 SDK 用法](test/security-v1.1.3.md)。

内存证据是 `net/http` 层的逻辑 HTTP 重放快照：方法、编码路径、头和值及读取的 Body，不是 TLS/HTTP2 线上的帧。传输层自动添加的部分头不一定出现，失败请求也不能证明对端已完整接收。每个请求/响应 Body 最多记录 512 KiB，`request_truncated`、`response_truncated`、`response_incomplete` 明确标记限制；截断请求不生成完整 curl，也不用于浏览器重放。显式 raw 报告才包含这些正文和 Base64 原字节副本；默认安全报告保留限制标记。

JSON 保持 `SchemaVersion: "1.1"` 和原有字段名称。所有报告先创建私有同目录临时文件，写入、同步后替换：Unix 使用 0600；Windows 在创建时设置当前用户专属受保护 DACL，写入前检查，失败则拒绝保存。Unix 同目录 rename 为原子替换，Go 不保证 Windows rename 的原子性。默认不将验证截图落盘；SDK 显式截图只在验证器生命周期内保留。

## 输出格式

### JSON（默认）

```bash
./xsscan --url "http://target.com/page?q=test" -o result.json
```

以下为报告结构节选，省略空值与原始 HTTP 证据。顶层和 finding 字段保留 PascalCase，Modules 和 Evidence 内部使用各自的 JSON 字段名；`Duration` 单位为毫秒。

```json
{
  "SchemaVersion": "1.1",
  "Target": "http://target.com/page?q=test",
  "Status": "completed",
  "Duration": 3200,
  "RequestsSent": 30,
  "PayloadsSent": 25,
  "Modules": [
    {
      "type": "reflected",
      "target": "http://target.com/page?q=test",
      "status": "completed",
      "requests": 30,
      "candidates": 25,
      "findings": 1,
      "duration_ms": 3200
    }
  ],
  "Findings": [
    {
      "Parameter": "q",
      "Type": "reflected_xss",
      "Contexts": ["html_body"],
      "Payload": "<script>alert(1)</script>",
      "Confidence": 0.76,
      "Severity": "high",
      "ExecutionVerified": false,
      "Evidence": {
        "reflection": "<script>alert(1)</script>",
        "context": "html_body"
      }
    }
  ]
}
```

### HTML 报告

```bash
./xsscan --url "http://target.com/page?q=test" -o report.html --format html
```

包含：可点击 POC URL、curl 命令、Copy for Burp 按钮、CSP 绕过方案、WAF 信息。

### Markdown

```bash
./xsscan --url "http://target.com/page?q=test" -o report.md --format markdown
```

适合直接粘贴到 HackerOne/Bugcrowd 报告。

### SARIF（CI/CD 集成）

```bash
./xsscan --url "http://target.com/page?q=test" -o results.sarif --format sarif
```

兼容 GitHub Code Scanning、SonarQube。

### JUnit XML

```bash
./xsscan --url "http://target.com/page?q=test" -o results.xml --format junit
```

兼容 Jenkins、GitLab CI、Azure DevOps。

### 扫描完成状态与错误处理

退出码 `0` 表示扫描完成且未发现漏洞，`2` 表示扫描完成且发现漏洞，`1` 表示错误或扫描未完成（即使已经发现漏洞）。未发现不等于目标没有漏洞。未授权私网、请求失败、取消或请求的浏览器功能不可用时，不会输出正常完成的“无漏洞”结论。

报告保留已发现结果，并附上 `Status` 和 `Issues`。状态包括 `completed`、`partial`、`failed`、`canceled`、`skipped`；混合成功与失败通常为 `partial`，取消优先。JSON、Markdown、HTML、SARIF、JUnit 均表达未完成状态。自动化流程应同时检查退出码及报告状态。

`RequestsSent` 是 Go HTTP 请求尝试数，包含分析、探测、重试、发现和存储型检测，CLI 从认证初始化后开始计数；不包含 Chrome 自身网络请求和回调监听。`PayloadsSent` 包含 payload 的重试及变异请求，因此不等于独立 payload 数。

库调用方应处理 `Engine.Run` 同时返回结果与错误的情况，保留部分结果。一个 Engine 的 Run 调用串行执行，等待可取消；目标级状态每次重置，会话 Cookie 仍正常保留。存储型调用方使用 `DetectWithError` 获取失败信息，旧 `Detect` 保持兼容。

浏览器执行验证取消后停止派发剩余分组，保留尚未验证的候选及原始请求，并注明 `VerificationError`，不会把取消当作验证未执行的正常结果。验证分组最多四项同时运行，等待在途调用收尾后关闭验证器。验证回调的 panic 会转为诊断；后续候选验证成功仍保留此前实际发生的错误，整次扫描可能因此保持未完成状态。

DOM 和执行验证器在构造时复制认证 Cookie，调用方后续修改不会改变已创建实例的认证快照。执行重放优先使用捕获的初始请求，保留编码路径、空查询串及实际认证头；多行 Cookie 用分号合并。捕获请求截断、正文长度与声明不符、分块表示或非 origin-form 请求会明确报告无法重放。原始请求证据继续完整保留，不作自动脱敏；这些限制只约束浏览器重放。

1.1.0 报告增加 `coverage`（报告 `SchemaVersion=1.1`），按目标与阶段记录 `planned_known`、`planned`、`started`、`completed`、`failed`、`canceled`、`not_started`。目前记录反射候选、最终执行验证组和 DOM source 检查；基线加载、DOM 独立重放的额外加载、stored/blind 的全部子步骤尚未逐项纳入。没有统计项表示尚未计量，不能当作零工作或完整覆盖。计划已知时，`planned = started + not_started`；收尾后 `started = completed + failed + canceled`。未开始可能来自取消、预算或已证明路径收敛，不等于全部已验证。不同阶段单位分别显示，不生成混合总百分比。

`RequestsSent` 仍只统计 Go HTTP 传输，包括重试与跳转；Chrome 网络不计入该字段或请求预算。DOM 的载荷模板数与实际 source 检查数分别保留，不能拿模板数代替检查次数。JSON、Markdown、HTML、SARIF、JUnit 使用相同完成状态与诊断，包含检查统计和跨模块观察；JUnit 时间按秒输出。协议错误可能影响证据完整性；单纯资源释放失败会保留已取得的证据，同时记录收尾失败，扫描可保持未完成。截图失败只作为附加诊断。

反射结果交接队列改为随 worker 数量有界，并在扫描期间持续收集。浏览器请求与弹窗处理均使用有界工作队列，饱和时明确中止当前检查；退出时等待处理线程。候选列表、保留发现和报告仍随工作量增长，这些队列边界不代表进程总内存固定。

重定向链保存 InitialURL/InitialRequest 与最终 HTTP.Request/Response，反射原始请求和浏览器验证使用初始实际提交。POST→302→GET 的本地 Chrome 回归通过；不同虚拟主机 Host 无法在 Chrome 保持时明确返回不支持复核，不静默验证其他站点。

---

## 架构

### 扫描流水线

CLI 合并配置后构造 ScanPlan；orchestrator 先发现目标，再调度 reflected/dom/stored/blind，并汇总逐模块状态和证据。下面展开反射模块内部流水线，其他模块通过同一 Runner 接口运行。

```
Target URL
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Analyzer                                        │
│  • Marker 注入 → 反射检测                        │
│  • 参数提取 (Query/Body/Cookie/Header/Path/XML)  │
│  • 框架检测 (React/Vue/Angular/Svelte/jQuery)    │
│  • CSP / WAF 检测                                │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Context Detector (HTML Tokenizer)               │
│  • 20 种上下文类型 + JS 子上下文细分            │
│  • HTML Tokenizer + Sobek JS AST/span             │
│  • 优先级排序                                    │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Payload Generator                               │
│  • 上下文特定模板 + 20 polyglot                 │
│  • 框架 payload (React/Vue/Angular/jQuery/Jinja2)│
│  • FilterProfile 过滤发现 + payload 剪枝         │
│  • WAF 绕过变异 (17 种策略: 11 结构 + 6 编码)   │
│  • 自定义词表支持                                │
└─────────────────────────────────────────────────┘
    │
    ▼ (可选)
┌─────────────────────────────────────────────────┐
│  Context Probe (--probe)                         │
│  • 安全探针预验证                                │
│  • 过滤不可利用的反射点                          │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Concurrent Scanner                              │
│  • Worker Pool (可配置并发)                      │
│  • 指数退避重试                                  │
│  • 429 自适应降速                                │
│  • WAF 追踪 + 自动绕过                           │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Semantic Dedup                                  │
│  • 6 元组 key，包含参数位置与参数名              │
│  • exploit 技术分类 (script/event/protocol/...) │
│  • URL 归一化去重，同参数保留有效变体      │
└─────────────────────────────────────────────────┘
    │
    ▼ (默认开启，可关闭)
┌─────────────────────────────────────────────────┐
│  Execution Verification (--verify-execution)     │
│  • 4-worker Chrome 并发验证                     │
│  • Dialog 拦截 (alert/confirm/prompt)            │
│  • 置信度调整 (+0.15 / ×0.85)                   │
└─────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Report Generator                                │
│  • JSON / Markdown / HTML / SARIF / JUnit       │
│  • POC URL + curl 命令 + Copy for Burp           │
│  • CSP 绕过报告                                  │
└─────────────────────────────────────────────────┘
```

### 包结构

| 包 | 职责 |
|----|------|
| `cmd/` | CLI、配置、信号处理与依赖组合 |
| `pkg/orchestrator/` | Plan/Module/Runner、统一发现、逐类型状态、期限与 HTTP 预算 |
| `pkg/scanner/` | 扫描编排：Worker Pool、重试、限速、WAF 追踪、探针、去重 |
| `pkg/analyze/` | 分析引擎：参数提取、反射检测、框架/CSP 检测、WAF 回退 |
| `pkg/context/` | 上下文检测：HTML Tokenizer，20 种上下文类型 |
| `pkg/jsanalysis/` | 只解析 JavaScript，返回字节 span、调用位置与未知诊断 |
| `pkg/payload/` | Payload 引擎：模板存储、上下文生成、WAF 变异、框架 payload |
| `pkg/verify/` | 实际响应上下文及候选调用复核、置信度、12 类 WAF 签名与净化检测 |
| `pkg/report/` | 报告生成：JSON/Markdown/HTML/SARIF/JUnit |
| `pkg/auth/` | 表单认证 + 自动 CSRF 提取 |
| `pkg/auth/oauth/` | OAuth 2.0/OIDC：自动发现、ROPC、PKCE |
| `pkg/dom/` | 无头 Chrome DOM XSS 检测（CDP） |
| `pkg/execverify/` | 浏览器执行验证（4-worker 并发） |
| `pkg/crawler/` | BFS 链接发现 + SPA 路由提取 + Sitemap + JS 渲染 (`--render-spa`) |
| `pkg/stored/` | 存储型 XSS：marker 注入 + 触发轮询 |
| `pkg/blind/` | 独立盲检测提交与候选 token 关联 |
| `pkg/callback/` | Blind XSS HTTP 回调服务器 |
| `pkg/ssrfguard/` | SSRF 防护：IP 验证 + 重定向链检查 |
| `pkg/httpclient/` | HTTP 客户端工厂 + 代理 + UA 池 |

### JavaScript 分析与过滤边界

`pkg/jsanalysis` 使用固定版本 Sobek parser（`f56574604191`，Goja 的分支），不在 Go 中执行目标脚本，也不加载 source map。普通脚本、事件函数体和 `<script type="module">` 分别使用独立解析模式；模块支持 import/export、import.meta、动态 import 与顶层 await 的语法分析，模块依赖不在此阶段加载或执行。Sobek 的 ESM 支持仍为实验性；额外使用固定版本 esbuild（`v0.25.12`）的内存 Transform 检查模块严格模式、声明和导出等 early errors，丢弃转换产物，不改写证据范围、不解析依赖或执行代码。完整模块图与可达性分析尚未实现。脚本中的字符串、正则、注释和模板片段保留原始字节范围；事件属性先按浏览器解码后的属性值解析，允许 `return`，保留内部引号。

分析结果记录 `AnalysisMethod=sobek-ast`、`SourceStart/SourceEnd` 和 `SpanUnit`。脚本范围使用 `document_bytes`，事件属性使用 `attribute_value_bytes`，两者不能混用。实际响应中的调用必须来自候选范围；其他位置的 `alert`、字符串内的调用文本、非执行 script、template、textarea 不提供该证明。Tagged template 和构造调用也参与结构分析。

AST 调用表示语法上的候选证据。分析会排除字面量布尔条件确定不会执行的 `if`/`while` 分支、条件表达式分支及 `false && …` / `true || …` 右侧调用，减少无效浏览器确认；完整语法检查和字符串/模板/正则/注释范围仍保留，HTML `</script>` 逃逸独立判断。未知条件、函数体和动态调用保持保守，不保证程序可达、函数被调用或浏览器实际执行。未验证评分仍封顶 0.90；浏览器收到候选专属消息才标记 ExecutionVerified。实际验证载荷和原 HTTP 交换保留在报告中。

反射执行验证按目标、参数位置、参数名和上下文分组，先尝试支持候选专属弹窗的短载荷，成功后停止验证同组备选；同名 query/body 参数不会合并。主 Payload、POC URL、原请求和执行证据来自同一候选；备选 Payloads 未必逐一验证，不能把主项的执行状态套给每条备选。未证实组仍保留验证失败及不支持验证的诊断。一个执行模块内复用 Chrome，每条候选使用独立 BrowserContext，焦点模拟支持后台标签的 focus 验证；没有匹配弹窗时保留晚期交互重试。外部 script 标签的原样反射只证明标签存在，不证明所指脚本可加载或会执行。

单个 JS 源限制 256 KiB、嵌套 256 层，并限制运算符复杂度与 AST 遍历量；超过限制、无效语法和解析器不支持的语法保留 ParseError，将检查标记为未完整完成，不输出“无漏洞”的可靠结论。事件交互仍以受控 focus/mouseover 为主；其他事件与复杂调用关联尚不保证覆盖。

解析结果按源码摘要和解析模式缓存，最多 256 项、估算保留容量 8 MiB（不是进程总内存上限）；只保存字节范围、数据流线索和诊断，不保留脚本文本或 AST，返回副本以隔离并发扫描。同一脚本的并发首次解析合并为一次，等待者各获独立证据副本。范围与调用位置排序后用二分查询；响应中已证明的候选调用复用该证据，减少重复解析。缓存收益主要发生在同一响应被多个检查使用时，新响应仍需首次解析。单次验证内的上下文、语法与证据检查还会复用同一文档/候选的 JS 调用分析；srcdoc 等嵌套文档独立分析，不借用父文档的判断。

反射扫描的内部反馈层保留类型化判定、字面量/编码匹配、请求与载荷摘要、重试/跳转/读取错误计数及有界样本。每个输入组最多32条样本，每次Run最多128组、256条样本，超出时保留总计数与丢弃数；未回显、解析未知、网络错误和结构候选分别记录。完整请求与响应仍由原证据链保存。当前本地源码已提供 `--strategy exhaustive|adaptive`，默认 `adaptive`，同一位置的后续派发等待执行反馈，已检查证据不重复验证；反馈日志的离线回放本身不发送请求。该策略自 v1.1.0 提供，旧版 Release 不具备此选项。

数据流与上下文分析共用同一 AST，不增加第二次语法解析。单脚本数据流限制 10000 步（含作用域复制/合并）、表达式深度 128、局部调用深度 8、最多 64 条线索。DOM 只采集前 64 个 script 元素中的内联代码，采集限制每段 262144 个 JS 字符、合计 1048576 个字符；Go 解析器另外执行 256 KiB 字节上限，页面最多保留 128 条规划线索。超限、语法不支持或分析不明确不删动态检查；数据流诊断为空也不代表覆盖了全部语义。

过滤探针按参数及上下文隔离，只检查有起止 marker 的注入片段；同上下文任一回显保留字符即保留对应能力。正文超过 256 KiB、反射超过 16 处、片段截断或 JS 解析不明确时不剪枝。当前探针是单轮字符能力检查，不是完整的过滤器逆向。

有限 `--max-payloads` 预算按上下文及直接引号突破类型轮流取候选，保留组内生成顺序，避免正文模板挤掉后面的属性/JS载荷；预算小于分组数时仍无法覆盖全部分组。它限制每参数的基础候选数，WAF派生变异、探针与重试仍会额外发请求，不是总HTTP请求上限。`0` 表示不限条数，未触发上限时保留原列表顺序。精简预设先检查引号兼容性，再选择每个上下文的首条模板，避免双引号 JS 字符串得到空列表。普通 HTML 属性从原始标签记录外层引号，事件属性仍使用内部 JS 引号；不确定时保留候选。混合引号属性载荷若包含实际闭合引号仍保留，不能仅凭首字符删掉自定义或 polyglot 载荷。这些选择不减少默认模块，也不保证精简预设具有完整预设的检测覆盖。

实现研究参考 [XSStrike jsContexter](https://github.com/s0md3v/XSStrike/blob/master/core/jsContexter.py)、[filterChecker](https://github.com/s0md3v/XSStrike/blob/master/core/filterChecker.py) 和 [dalfox 参数分析说明](https://dalfox.hahwul.com/guide/parameters/)。XSStrike 此处是正则处理及逆序分隔符分析，不能描述为完整 JS AST。没有复制其 GPL 源码；新增依赖许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

### 与 dalfox、XSStrike 的工程对照

以下为2026-10-15查阅官方文档/源码后的能力对照，不是三工具同环境命中率或性能排名；没有用旧版功能数量与主观分数宣称领先。

| 维度 | xsscan 当前本地源码 | dalfox 官方文档 | XSStrike 当前相关源码 |
| --- | --- | --- | --- |
| 候选选择 | 上下文/引号门控；有限预算轮流覆盖分组；精简预设选择兼容模板 | 按 HTML、属性、JS 等上下文组织载荷族 | 根据反射位置和字符过滤结果生成载荷 |
| JS 分析 | Sobek AST、字节范围、模块/事件语法、常量死分支；有界局部 source→sink 辅助动态固定键检查，尚无完整程序分析 | 文档区分 AST source→sink 发现和响应中的候选证据 | jsContexter 用正则与分隔符推导突破串 |
| 证明含义 | 结构评分最多0.90；ExecutionVerified要求候选关联的浏览器证据 | V表示真实响应中的静态DOM/JS证据；A表示静态数据流，不等于浏览器执行 | checker评估注入串与回显的相似效率，不能等同执行证明 |
| 请求利用 | 反射探针、上下文剪枝和有限预算覆盖；默认DOM及stored仍有明显等待成本 | 快速反射探针复用已有结果，默认在参数得到验证发现后停止后续载荷 | 按上下文需要探测特殊字符，再据过滤效果组合载荷 |
| 仍需补强 | 包装参数发现、外部脚本/跨模块数据流、过滤器逆向、跨模块调度及统一可复现基准 | 可作为参数发现与候选调度的参考 | 可作为按反射位置分析过滤行为与组合突破的参考 |

对照依据：[dalfox 参数与证据](https://dalfox.hahwul.com/guide/parameters/)、[载荷选择与提前停止](https://dalfox.hahwul.com/guide/payloads/)，以及 XSStrike 的 [filterChecker](https://github.com/s0md3v/XSStrike/blob/master/core/filterChecker.py)、[generator](https://github.com/s0md3v/XSStrike/blob/master/core/generator.py)、[jsContexter](https://github.com/s0md3v/XSStrike/blob/master/core/jsContexter.py)、[checker](https://github.com/s0md3v/XSStrike/blob/master/core/checker.py)。源码和文档可能继续更新。xsscan 的本地正反例回归只验证自身行为，不能据此断言总体误报率或检测率超过其他工具。

### 置信度评分模型

| 因子 | 权重 | 说明 |
|------|------|------|
| Reflected | 0.25 | Payload 在响应中反射 |
| ContextBreak | 0.25 | Payload 逃逸了注入上下文 |
| SyntaxValid | 0.15 | Payload 保持有效语法 |
| NoSanitization | 0.25 | 未检测到过滤/编码 |
| CSPWeak | 0.10 | CSP 弱或可绕过 |

**惩罚项：** LengthLimited ×0.9, WAFBlocked ×0.9（乘法，叠加生效）  
**交互效应：** ContextBreak×SyntaxValid (×0.4), NoSanitization×WAF (×0.3)  
**置信度封顶：** 结构分析最高 **0.90** —— 只有 `--verify-execution` 浏览器确认（+0.15，上限 1.0）才能达到 100%。反射不等于执行。  
**阈值：** 0.60（可通过 `--confidence` 调整）

---

## 性能指标

| 指标 | 数值 |
|------|------|
| 并发 Worker | 可配置（默认 10，最大 1000） |
| 执行验证 | 4-worker Chrome 并发 |
| 爬虫并发 | 10-worker BFS 深度并行 |
| 上下文枚举 | 20 个（包含 unknown / multi） |
| WAF 签名 | 12 种（8 国际 + 阿里云/腾讯云/安全狗/宝塔）+ 17 种绕过策略（11 结构 + 6 编码） |
| DOM XSS Source | 10 种基础配置 + 已有 query 参数 + 有界数据流固定键补测 + CDP sink hook |
| 框架 Payload | 7 种（React, Vue, Angular, Svelte, jQuery, HTMX, Jinja2） |

---

同一台 Windows 主机、同参数及默认全部模块的本机合成样例单次对照（2026-10-12）：

| 样例 | 优化前 | 优化后 |
| --- | --- | --- |
| 裸 HTML 反射 | 18.48 秒 | 15.03 秒 |
| 正文转义 / 属性反射 | 22.88 秒 | 18.02 秒 |

两边 Go HTTP 请求数均为 104 / 300，DOM 仍运行每样例 55 项源/载荷检查；反射执行正例保持 1 条、DOM 无新增发现。没有缩短脚本页观察窗口。本轮性能构建仅在 Windows 验收，Linux/macOS 的前述交叉编译记录对应自检阶段源码。这是合成样例的单次结果，不保证所有目标相同比例加速。

2026-10-15 数据流阶段的本机对照：固定 4 个 Go 调度线程、同一约12KB脚本、重复3次，16调用同时冷解析的中位数为 7.46→1.36ms，分配量约减少87.5%；单次冷解析为 1.31→1.38ms，独立进程缓存命中为 13.47→13.30µs。混合基准的缓存时间波动明显，不能外推整次扫描收益。实际 EXE 的 DOM 固定隐藏 query/存储键样例从零发现变为2条运行时sink候选（非执行证明），完整检查由50增至60项，耗时35.40→40.51秒；安全textContent样例两版均零发现、约35.33→35.35秒。新增覆盖有成本，观察窗口没有缩短。

## 开发

### 常用命令

从 v1.1.2 开始，Go 单元、浏览器及集成测试包含在公开源码中。需要 Go 1.26.9、Chrome 和 race 所需的 C 编译器；完整命令、合成靶场及基线见 [test/README.md](test/README.md)。本地开发记录仍不分发。

```bash
# 构建
make build

# 测试（含竞态检测）
make test

# 无浏览器的单元/本地 HTTP 回归
go test -race -short ./...

# 已安装 Chrome：按包串行执行浏览器回归
go test -race -p 1 -count=1 ./pkg/internal/chromedp ./pkg/execverify ./pkg/dom ./pkg/stored ./pkg/crawler
go test -race -count=1 -run TestJSASTBrowserCorpus ./pkg/scanner

# JS parser 实际模糊测试
go test -run '^$' -fuzz FuzzParseBounded -fuzztime=10s -parallel=2 ./pkg/jsanalysis

# 覆盖率
make coverage
make coverage-scanner   # 仅 scanner 包
make coverage-cli       # 仅 cmd 包

# 开发模式（不编译直接运行；dev target 不转发参数，带 flag 时用 go run）
go run ./cmd --url "http://target.com/page?q=test"

# 静态检查
make lint

# 依赖更新
make deps

# 清理
make clean
```

---

## 发布验证

v1.1.2 的实际运行状态及基线见 [验证记录](test/baseline-v1.1.2.md)，CI 在 Windows/Linux 执行完整普通/race 回归、vet 和构建。

v1.1.1 为版本与审计材料整理发布；当前验证记录随 Release 提供。v1.1.0 的完整回归记录保留如下，不能当作 1.1.1 重新运行的完整回归。


v1.1.0 发布前检查（2026-10-30，Windows / Go 1.26.9）：

| 检查 | 结果 |
| --- | --- |
| 构建、静态与依赖 | `go build ./...`、`go vet ./...`、`go mod verify` 通过 |
| 全项目短回归 | `go test -short -count=1 ./...` 通过 |
| 全项目短 race 回归 | `go test -race -short -count=1 ./...` 通过 |
| 完整 race 回归 | `go test -race -p 1 -count=1 ./...` 通过，包含真实 Chrome |
| Windows 程序 | version/help、五格式安全零发现、静默输出及浏览器执行正例通过 |
| 跨平台附件 | Windows amd64、Linux/macOS amd64/arm64 构建；归档内容及 Unix 可执行权限检查 |
| 验证边界 | Linux/macOS 未实机运行；Docker 未构建；本轮未新增漏洞数据库检查 |

首轮普通完整回归有一项因随机测试端口 6667 被 Chrome 拒绝而失败；后续完整串行 race 回归通过全部用例。上述是 v1.1.0 历史记录；v1.1.2 起测试进入源码分发并统一使用避开受限端口的本地 fixture。远端 CI 状态以提交的 GitHub Actions 页面为准。

### 历史 v1.0.0-rc.1

v1.0.0-rc.1 的发布前检查（2026-10-10）：

| 检查 | 结果 |
| --- | --- |
| 全项目本地回归 | `go test -race -short ./...` 通过 |
| 静态与依赖检查 | `go vet ./...`、`go mod verify` 通过 |
| 真实 Chrome 回归 | 五个浏览器相关包完整 race 回归及九场景 JS 语料通过 |
| 已知依赖漏洞 | `govulncheck` 未发现已知漏洞条目；不代表不存在未知漏洞 |
| Windows amd64 EXE | 本地及从 Release 下载后的程序运行检查通过 |
| 六个 Release 附件 | 远端文件大小与内容摘要均与本地编译产物一致 |
| Linux/macOS/arm64 | 交叉编译通过，未在对应系统实机运行 |
| 远端 CI | Windows/Linux 构建 workflow 已推送；GitHub 返回账号 Actions 被禁用，尚未执行 |
| Docker | 未构建验证 |

跨模块浏览器进程共享、浏览器网络统一计入请求预算及完整模块图分析尚未完成；内联模块的语法分析已支持，实际执行仍以浏览器证据为准。

### v1.1.0 — 2026-10-30

- 2026-10-17自检：修复输入通道关闭后空转与提前收尾问题，等待生产者及relay退出；收紧含糊/缺失锚点/上下文不匹配候选的提前停止权限，同桶权限取全任务交集。

- 整合已有上下文、AST/局部数据流、默认自适应策略、DOM证据与存储型展示页改进；本地后续修订默认策略改为 `adaptive`，保留显式 `exhaustive`，未以功能数量或局部样例宣称优于其他工具。
- 修复取消时丢失候选、错误状态被成功覆盖、重放Cookie/正文形状和认证快照共享问题。
- 有界结果交接、请求/弹窗处理线程收尾；DOM重放使用真正独立的BrowserContext，并接入同源请求策略与同一认证快照。原始POST/正文无法由DOM导航重现时明确报告未完成。
- 新增按阶段的实际检查统计，报告schema升为1.1；五格式保留一致的状态、诊断、计数、浏览器证据与跨模块观察。SARIF规则顺序稳定，JUnit时间单位修正为秒。
- 未覆盖完整外部脚本/跨模块JS程序分析，未统一计量Chrome网络；stored/blind细粒度覆盖仍待补全；默认动态已迁移，持续使用本地对照检查其效率与检测结果。没有三工具同环境误报率/速度排名。
- 历史本地阶段曾受 GCC/TSAN 限制；2026-10-30 已重新执行 race 验证，当前结果见上方发布验证记录。Docker 镜像与 Linux/macOS 交叉编译产物的运行状态单独记录。

### v1.0.2 本地自检（2026-10-12，历史记录）

- 前序自检阶段全项目 `go test -race -count=1 ./...` 通过；修复错误计数及静默输出后，受影响的 `cmd` / `pkg/orchestrator` 再次通过完整 race 回归。
- 2026-10-15候选预算与数据流改动通过全项目 `go test -count=1 ./...`（含本机Chrome）、小预算/混合引号及固定键/安全负例专项。race 仍未完成：项目内临时隔离编译组件后已可编译，但 ThreadSanitizer 启动时内存映射失败；未改动包的控制测试也有同样失败，不能沿用前序结果声称本轮已通过 race。
- 2026-10-15反馈层25A通过全量非race回归、重试/跳转/CSRF/跨Run隔离及离线回放专项；实际exe在本机三类样例各交替对照5次，固定1个worker时请求、载荷、发现及退出码一致。scanner/verify/httpclient的race尝试仍受同一TSAN错误87限制，未完成。
- `go vet ./...`、`go mod verify` 与差异格式检查通过。包含本机真实 Chrome 的执行、DOM、认证、存储及取消/隔离回归；未访问外部扫描目标。
- Windows amd64 使用源码默认版本编译，实际 EXE 验证 `1.0.2`、执行正例、YAML/stdin 静默与被拦截时的失败报告；Linux/macOS amd64、arm64 交叉编译通过，未实机运行。
- 本地程序为根目录 `xsscan.exe`。GitHub 下载仍是上方历史 `v1.0.0-rc.1`，本轮未推送、未发布；Docker 未构建，未新增依赖漏洞数据库检查。

## 更新日志

### v1.1.3 — 开发中

- 默认五格式报告脱敏；原始证据需显式开关并写入私有文件，截图默认关闭、显式采集自动清理。
- Windows 创建时 ACL 与 Linux 权限检查；新增安全回归并对原有 1771 个通过事件做身份门禁。
- 审计与实际结果见 [安全验证记录](test/security-v1.1.3.md)。

### v1.1.2 — 开发中

- 公开既有 Go 测试与本地合成靶场，补强四类检测正负例、Blind 关联、超时/取消及 adaptive 对照断言。
- Windows/Linux CI 执行完整普通/race 测试、vet、构建及重复性能基线，并保存结果记录。
- 详见 [CHANGELOG](CHANGELOG.md) 和 [本轮验证记录](test/baseline-v1.1.2.md)。

### v1.1.1 — 2026-10-31

- 维护发布：统一 CLI、Makefile、Dockerfile、构建示例及下载链接的版本号为 1.1.1。
- 归档 A 路线审计与本地合成基线，见 [审计报告](audit/2026-10-31/REPORT.md)；已知问题及建议顺序不表示已修复。
- 不改变扫描算法、四类检测、CLI 参数或报告格式；报告 schema 保持 1.1。
- 从提交源码的独立归档构建五个平台，包内 BUILDINFO.json 记录源码提交和二进制摘要，避免沿用旧的 dirty VCS 信息。


### v1.1.0 — 2026-10-30

- 发布累计上下文分析、JS 模块与局部数据流、默认自适应调度、DOM 隔离重放及报告改进。
- 自适应调度等待浏览器反馈；只有归因完整、唯一且同桶候选全部允许时才提前停止，含糊反射保持候选范围。
- 报告 schema 1.1 区分逻辑检查覆盖和 Go HTTP 请求数，保留未完成原因及执行证据。
- 对齐 exhaustive 与 adaptive 的浏览器清理错误处理，保留已观察证据并记录未完成诊断。
- 更新下载、构建与验证说明，重建六个跨平台附件；本地测试和开发记录继续按仓库规则排除。

### v1.0.2 — 2026-10-12（本地，未发布）

- 2026-10-15：建立内部有界观察反馈与shadow离线回放契约，保留未发现原因、重试/跳转/读取错误及变异关联；使用轻量请求摘要避免为负结果复制整份响应。动态调度仍处于后续阶段。
- 2026-10-15：增加有界 JS source→sink 规划，补测内联代码读取的固定 query/hash/存储键；保留完整动态矩阵、状态隔离和观察窗口，静态线索不提升为执行证明。合并相同脚本并发冷解析，报告保留线索位置与假设标识。
- 2026-10-15：有限载荷预算轮流覆盖上下文和直接引号突破组；修复精简预设双引号JS候选为空，补齐普通属性引号元数据，保留混合引号候选，并更新与dalfox/XSStrike的工程对照。
- 排除字面量布尔常量死分支中的 JS 调用证据，避免作用域元数据重复遍历使 `var` 初始化误判；保留函数体、未知条件与 HTML 逃逸检查。
- 增加存储型逐参数/逐候选轮询进度与各模块实际耗时，不减少默认检测类型、轮询次数或异步观察预算。
- 减少 DOM 重复 CDP 命令，批量设置 Cookie 并合并证据读取；永久识别执行内容后停止无用 MutationObserver。
- 保留完整源/载荷矩阵和观察窗口，优先调度长观察任务；单次验证复用响应 JS 证据，嵌套文档保持独立。

- 修复编排层对重复错误的计数：合并诊断显示后，仍保留模块实际错误次数；没有提供次数的模块按诊断数补齐。
- 修复静默模式的状态泄漏：合并 CLI/YAML 后再打印横幅，状态统一写 stderr 并受 silent 控制，覆盖 JWT、词表、配置、代理和 stdin/目标文件。
- 同步源码默认版本、Makefile、源码安装命令及本地自检记录；历史 Release 链接继续指向已发布的 `v1.0.0-rc.1`。
- 延续 v1.0.1 本地修复：候选与执行证明一致、浏览器分组及隔离复用、DOM 静态页面优化、JS 模块分析和有界缓存。

### v1.0.1 — 本地阶段版，未发布

- 修复聚合后主 Payload/URL 与执行证据错配，区分同名 query/body 参数；外部脚本标签不再仅凭反射成为可执行候选。
- 反射验证按参数/上下文首次成功停止，复用进程并隔离候选状态；立即执行无需固定等待 3 秒，延迟 focus/hover 保留重试，修复后台标签焦点验证。
- DOM 补测已有 query 参数；纯静态、网络空闲页面可提前结束，含脚本/事件/框架页面保留完整异步观察窗口。

- JS 分析升级至 Sobek AST，区分普通脚本、事件处理函数体和内联模块，支持 import/export、import.meta、动态 import 与顶层 await；模块路径字符串不作为执行调用证据，解析失败保留诊断；内存语法检查拦截模块严格模式及声明/导出错误。
- 增加有容量限制的解析结果缓存，按源码摘要和模式隔离；AST 范围与候选调用使用二分查询，响应已证明的 JS 调用避免重复解析。

- 修复工具写入测试 Cookie 导致的 DOM 自触发误报；Cookie/History 写入不再当作 XSS sink，同一输入源和 sink 的候选合并并保留变体证据。
- DOM 完整检查矩阵改为 4 项并发，复用浏览器进程但隔离每项状态；显式创建隔离窗口，兼容新 Chrome 的目标创建行为。
- 默认输出阶段进度、完成数和耗时，详细逐 payload 日志改为仅 `--verbose` 输出；`--silent` 不输出进度。
- DOM 检测先检查原始页面能否加载；失败时直接报告模块失败，避免对所有输入源重复执行无法完成的导航。
- 浏览器同源限制拦截主文档跳转时，显示原始与被拦截的 origin。`--allow-private` 仅允许私有网络地址，不会放开跨源跳转；需要使用最终页面 URL 作为目标。
- 显式 HTTP 目标关闭 Chrome 的自动 HTTPS 升级；服务端重定向和 HSTS 仍接受范围检查，不放宽证书验证。
- 执行验证失败的发现显示 `Execution: INCOMPLETE`，五种报告格式保存 `VerificationError`（JSON 字段为 `verification_error`）。结构置信度不等于浏览器执行证明；扫描仍保留 partial/failed 状态与非零错误退出码。
- 终端合并相同问题、缩短多行诊断，运行失败不再重复输出整份参数帮助。`--verbose` 查看完整诊断，`--output` 保存完整报告证据。

### v1.0.0-rc.1 — 2026-10-10（预发布）

- 默认调度 reflected/dom/stored/blind，类型选择、能力缺失、预算与逐模块状态由新编排层管理。
- 配置严格校验且保留零值；表单登录成功判据和 OIDC issuer/端点检查加强。
- 报告保留实际凭据、CSRF、请求/响应和存储提交链；二进制证据及截断有明确标记，五格式保持原始值。
- JS 从引号计数迁移到 Goja AST/span；增加正则/注释突破、嵌套模板及 tagged call 关联，按真实响应证明候选来源；按参数/上下文隔离过滤剪枝。
- 修复 HTML 解析依赖的已知漏洞，升级 Go 1.26.9 和 Chrome/CDP 协议依赖。
- 发布 Windows amd64 EXE/ZIP 和 Linux/macOS amd64、arm64 压缩包，附项目与依赖许可证。
- 浏览器进程复用、浏览器网络共享预算及完整 ESM 支持仍未完成，本版本按预发布候选交付。

### v0.9.10 — 2026-10-07

- 修复浏览器执行验证的弹窗检测，覆盖 alert、confirm、prompt 和异步执行。
- 修复验证时原始请求丢失的问题，保留方法、请求体、认证头、Cookie 和目标页面 origin。
- 验证返回响应的实际反射上下文，排除惰性文本、错误引号、重复事件属性和非执行脚本，同时保留真实结构突破和框架表达式。
- 域名归属判断采用 Public Suffix List；IP 地址精确比较，避免跨站登录与盲 XSS 回调误归属。
- 统一路径参数发现、注入和验证的段索引，保留未修改路径段的编码。

## 版本规则

版本号遵循 `x.y.z` 格式：

当前发布版本为 `1.1.1`，开发源码与默认构建标识为 `1.1.3`。发布附件链接以对应 tag 为准。

| 位 | 含义 |
|----|------|
| **x** (major) | 重大架构变更或破坏性改动 |
| **y** (feature) | 新增功能（如新扫描模式、新 flag） |
| **z** (bugfix) | Bug 修复、体验优化 |

构建时通过 ldflags 注入版本：

```bash
make build VERSION=1.1.3
```

`--version` 输出当前构建版本。

---

## 免责声明

**本工具仅用于授权的安全测试。** 使用本工具扫描未授权目标是违法行为。使用者需自行承担一切法律责任。

---

## License

[MIT](LICENSE)；依赖许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
