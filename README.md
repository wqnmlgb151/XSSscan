# xsscan

<p align="center">
<b>上下文感知 XSS 扫描器</b><br>
<em>Context-Aware Reflected / Stored / DOM / Blind XSS Scanner</em>
</p>

<p align="center">
<img src="https://img.shields.io/badge/go-1.26+-00ADD8?logo=go" alt="Go">
<img src="https://img.shields.io/badge/license-MIT-green" alt="License">
<img src="https://img.shields.io/badge/version-1.0.0--rc.1-orange" alt="Version">
<img src="https://img.shields.io/badge/repo-github.com%2Fwqnmlgb151%2FXSSscan-lightgrey" alt="Repo">
</p>

---

当前发布版本为 **[v1.0.0-rc.1](https://github.com/wqnmlgb151/XSSscan/releases/tag/v1.0.0-rc.1)**（2026-10-10，预发布）。[下载 Windows EXE](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.0.0-rc.1/xsscan_1.0.0-rc.1_windows_amd64.exe)，其他平台见[安装](#安装)。默认调度反射型、DOM、存储型和盲 XSS 四类检测，可用 `--types` 选择检测类型。

## 目录

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
- **DOM XSS 检测** — 无头 Chrome CDP sink hook 跟踪 marker 流转（innerHTML/eval/document.write 等）；保留 10 种 source 测试配置，命中表示待验证候选
- **Blind XSS 检测** — 内置 HTTP 回调服务器，`sync.Cond` 零 CPU 等待

### 智能引擎

- **自动表单发现 + 链接参数挖掘** — 自动提取 `<form>` 字段生成扫描目标；`--crawl` 时从同域链接 `<a href="...?param=value">` 提取参数名自动扫描（dalfox Grep 特性，需显式开启——扫描用户指定的 URL 不会悄悄跟到其他页面）
- **上下文探针** (`--probe`) — 扫描前发送安全探针验证上下文可利用性，多维探测（结构突围 + 引号突围），检测到框架时自动跳过（模板表达式无 HTML 结构字符）
- **WAF 感知绕过** — 17 种变异策略（11 结构 + 6 编码），按 WAF 类型精准选择，首次检测到 WAF 自动启用
- **置信度评分** — 0.0–1.0 评分体系，含交互效应（WAF×无净化、语法×上下文逃逸）；结构分析封顶 0.90，浏览器执行验证后才可达 100%
- **语义去重 + 同参聚合** — 5 元组 key（URL+参数+上下文+向量+exploit 技术）去重后，同参数同上下文折叠为一条 finding，payload 变体作为子项展示
- **引号类型门控** — 检测到 JS 字符串反射的引号类型后，只发送匹配该引号的逃逸 payload（`"-alert(1)-"` 不再发往单引号反射点）
- **URL 子上下文分析** — href/src 反射只有落在 attribute 值开头或应用已输出的可执行 scheme 前缀后（`javascript:`、`data:image/svg+xml,`、`data:text/html,`）才按 URL 注入处理；落在路径/查询串/片段位置（如 `embed src=xsf02.swf?arg=PAYLOAD`）、非可执行 data: MIME、`http:`/`mailto:` 等固定 scheme 之后一律判定为惰性上下文，不生成 payload
- **过滤发现** — 按参数及反射上下文建立 FilterProfile；同上下文多处回显取最宽松能力，未知或超限保留候选
- **JavaScript AST 分析** — Goja parser 区分代码、字符串、模板、注释和正则；事件属性支持函数体语法，返回响应再次解析并定位候选调用

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

从 [v1.0.0-rc.1 Releases](https://github.com/wqnmlgb151/XSSscan/releases/tag/v1.0.0-rc.1) 下载对应平台的文件。使用预编译程序无需安装 Go。

| 平台 | 架构 | 下载 |
| --- | --- | --- |
| Windows | amd64（x64） | [EXE](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.0.0-rc.1/xsscan_1.0.0-rc.1_windows_amd64.exe) / [ZIP](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.0.0-rc.1/xsscan_1.0.0-rc.1_windows_amd64.zip) |
| Linux | amd64（x64） | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.0.0-rc.1/xsscan_1.0.0-rc.1_linux_amd64.tar.gz) |
| Linux | arm64 | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.0.0-rc.1/xsscan_1.0.0-rc.1_linux_arm64.tar.gz) |
| macOS | amd64（Intel） | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.0.0-rc.1/xsscan_1.0.0-rc.1_darwin_amd64.tar.gz) |
| macOS | arm64（Apple Silicon） | [TAR.GZ](https://github.com/wqnmlgb151/XSSscan/releases/download/v1.0.0-rc.1/xsscan_1.0.0-rc.1_darwin_arm64.tar.gz) |

ZIP/TAR.GZ 包含程序、`README.md`、`LICENSE` 和 `THIRD_PARTY_NOTICES.md`。Windows 下载后在 PowerShell 中运行：

```powershell
# 直接下载 EXE 后，在下载目录执行
.\xsscan_1.0.0-rc.1_windows_amd64.exe --version
.\xsscan_1.0.0-rc.1_windows_amd64.exe --help

# 使用 ZIP 时，解压后运行包内的 xsscan.exe
.\xsscan.exe --version
```

Linux/macOS 解压后运行包内的程序，例如 Linux amd64：

```bash
tar -xzf xsscan_1.0.0-rc.1_linux_amd64.tar.gz
./xsscan --version
./xsscan --help
```

本版是预发布候选。Windows amd64 已实际运行；其他平台产物由交叉编译生成，需在对应平台验证。Chrome 不包含在包内；默认 DOM 和执行验证需要本机已安装 Chrome/Chromium。

### 从源码构建

```bash
# 需要 Go 1.26+（推荐 Go 1.26.9）
git clone https://github.com/wqnmlgb151/XSSscan.git
cd XSSscan
git checkout v1.0.0-rc.1
make build VERSION=1.0.0-rc.1
```

Windows 没有 make 时可直接构建 EXE：

```powershell
go build -trimpath -ldflags "-X main.Version=1.0.0-rc.1" -o xsscan.exe ./cmd
.\xsscan.exe --version
```

默认检查四类能力。只运行反射模块可使用 `--types reflected`；没有 Chrome 且只需 HTTP 结构分析时，同时添加 `--verify-execution=false`。

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

保留 10 种 DOM XSS source 测试配置，使用 CDP hook 记录目标代码的 marker 流转：

| 层级 | 方式 | 置信度 |
|------|------|--------|
| **CDP Sink Hook** | 脚本注入 `Page.addScriptToEvaluateOnNewDocument`，拦截 innerHTML/eval/document.write/Function/location.assign 等 11 种 sink | 0.85 |

Hook 不可用或读取失败会记录检测错误；不会用 URL、控制台或静态 DOM 中出现 marker 代替漏洞证据。Sink 命中是候选，尚不代表 payload 已执行。扫描器不再主动创建 onerror 元素后将自身操作当作目标漏洞。

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

报告保留实际请求中的 Authorization、Cookie、刷新后的 CSRF、请求体，以及响应 Set-Cookie 和响应体。HTML 的 Copy for Burp、Markdown HTTP 代码块、JSON/SARIF 原始字段保留这些内容；浏览器复核使用捕获请求中的认证状态。存储型证据同时保存提交和展示页面的 HTTP 交换。

这是 `net/http` 层的逻辑 HTTP 重放快照：方法、编码路径、头和值及读取的 Body，不是 TLS/HTTP2 线上的帧。传输层自动添加的部分头不一定出现，失败请求也不能证明对端已完整接收。每个请求/响应 Body 最多记录 512 KiB，`request_truncated`、`response_truncated`、`response_incomplete` 明确标记限制；截断请求不生成完整 curl，也不用于浏览器重放。无效 UTF-8 或 XML 非法控制字节另保留 Base64 字段，JUnit 使用 Base64 表示无法容纳的文本；人类报告也展示对应字段，解码后可恢复记录的原字节。

JSON 增加 `SchemaVersion: "1.0"`，原有字段名称继续保留。文件先在同目录以 0600 写入临时文件、同步并原子替换；Windows 的权限由 ACL 管理，0600 的 Unix 权限尚需 Linux 运行验证。

## 输出格式

### JSON（默认）

```bash
./xsscan --url "http://target.com/page?q=test" -o result.json
```

以下为报告结构节选，省略空值与原始 HTTP 证据。顶层和 finding 字段保留 PascalCase，Modules 和 Evidence 内部使用各自的 JSON 字段名；`Duration` 单位为毫秒。

```json
{
  "SchemaVersion": "1.0",
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
│  • HTML Tokenizer + Goja JS AST/span             │
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
│  • 5 元组 key (URL+param+context+vector+exploit) │
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

`pkg/jsanalysis` 使用固定版本 Goja parser（`a4bedf5f6000`），不在 Go 中执行目标脚本，也不加载 source map。脚本中的字符串、正则、注释和模板片段保留原始字节范围；事件属性先按浏览器解码后的属性值解析，允许 `return`，保留内部引号。

分析结果记录 `AnalysisMethod=goja-ast`、`SourceStart/SourceEnd` 和 `SpanUnit`。脚本范围使用 `document_bytes`，事件属性使用 `attribute_value_bytes`，两者不能混用。实际响应中的调用必须来自候选范围；其他位置的 `alert`、字符串内的调用文本、非执行 script、template、textarea 不提供该证明。Tagged template 和构造调用也参与结构分析。

AST 调用表示语法上的候选证据，不保证分支可达、函数被调用或浏览器实际执行。未验证评分仍封顶 0.90；浏览器收到候选专属消息才标记 ExecutionVerified。实际验证载荷和原 HTTP 交换保留在报告中。

单个 JS 源限制 256 KiB、嵌套 256 层，并限制运算符复杂度与 AST 遍历量；超过限制、无效语法和当前不支持的 ESM import/export 保留 ParseError，将检查标记为未完整完成，不输出“无漏洞”的可靠结论。事件交互仍以受控 focus/mouseover 为主；其他事件与复杂调用关联尚不保证覆盖。

过滤探针按参数及上下文隔离，只检查有起止 marker 的注入片段；同上下文任一回显保留字符即保留对应能力。正文超过 256 KiB、反射超过 16 处、片段截断或 JS 解析不明确时不剪枝。当前探针是单轮字符能力检查，不是完整的过滤器逆向。

实现研究参考 [XSStrike jsContexter](https://github.com/s0md3v/XSStrike/blob/master/core/jsContexter.py)、[filterChecker](https://github.com/s0md3v/XSStrike/blob/master/core/filterChecker.py) 和 [dalfox parameterAnalysis](https://github.com/hahwul/dalfox/blob/main/pkg/scanning/parameterAnalysis.go)。XSStrike 此处是正则处理及逆序分隔符分析，不能描述为完整 JS AST。没有复制其 GPL 源码；新增依赖许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

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
| DOM XSS Source | 10 种测试配置 + CDP sink hook |
| 框架 Payload | 7 种（React, Vue, Angular, Svelte, jQuery, HTMX, Jinja2） |

---

## 开发

### 常用命令

公开仓库和发布包按交付范围保留运行源码；测试与开发记录保存在维护者本地，不随本次分发。下面的测试命令适用于包含本地测试文件的开发目录。

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

浏览器进程复用、浏览器网络统一计入请求预算及完整 ESM 支持尚未完成，因此本版仍标记为预发布候选。

## 更新日志

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

| 位 | 含义 |
|----|------|
| **x** (major) | 重大架构变更或破坏性改动 |
| **y** (feature) | 新增功能（如新扫描模式、新 flag） |
| **z** (bugfix) | Bug 修复、体验优化 |

构建时通过 ldflags 注入版本：

```bash
make build VERSION=1.0.0-rc.1
```

`--version` 输出当前构建版本。

---

## 免责声明

**本工具仅用于授权的安全测试。** 使用本工具扫描未授权目标是违法行为。使用者需自行承担一切法律责任。

---

## License

[MIT](LICENSE)；依赖许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
