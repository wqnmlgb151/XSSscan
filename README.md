# xsscan

<p align="center">
<b>下一代上下文感知 XSS 扫描器</b><br>
<em>Context-Aware Reflected / Stored / DOM / Blind XSS Scanner</em>
</p>

<p align="center">
<img src="https://img.shields.io/badge/go-1.22+-00ADD8?logo=go" alt="Go">
<img src="https://img.shields.io/badge/license-MIT-green" alt="License">
<img src="https://img.shields.io/badge/tests-19packages--race--passing-brightgreen" alt="Tests">
<img src="https://img.shields.io/badge/coverage-9%2F19--≥80%25-blue" alt="Coverage">
<img src="https://img.shields.io/badge/repo-github.com%2Fwqnmlgb151%2FXSSscan-lightgrey" alt="Repo">
</p>

---

## 目录

- [特性](#特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [扫描模式](#扫描模式)
- [认证扫描](#认证扫描)
- [高级用法](#高级用法)
- [输出格式](#输出格式)
- [架构](#架构)
- [性能指标](#性能指标)
- [开发](#开发)
- [免责声明](#免责声明)

---

## 特性

### 核心能力

- **上下文感知 Payload 生成** — 通过 HTML 词法分析器识别 19 种注入上下文，为每种上下文生成针对性的 payload
- **反射型 XSS 检测** — 基于 marker 的反射检测，模糊匹配（URL 编码、HTML 实体、截断）覆盖各种变形
- **存储型 XSS 检测** — 双阶段检测：注入唯一 marker + 轮询触发页面；`--trigger-url` 可省略，自动同域爬虫发现触发 URL（每目标仅爬取一次）
- **DOM XSS 检测** — 无头 Chrome 双层检测：CDP sink hook（innerHTML/eval/document.write 等 11 种 sink）+ 事后 DOM 扫描兜底。覆盖 11 种 source
- **Blind XSS 检测** — 内置 HTTP 回调服务器，`sync.Cond` 零 CPU 等待

### 智能引擎

- **自动表单发现 + 链接参数挖掘** — 自动提取 `<form>` 字段生成扫描目标；`--crawl` 时从同域链接 `<a href="...?param=value">` 提取参数名自动扫描（dalfox Grep 特性，需显式开启——扫描用户指定的 URL 不会悄悄跟到其他页面）
- **上下文探针** (`--probe`) — 扫描前发送安全探针验证上下文可利用性，多维探测（结构突围 + 引号突围），检测到框架时自动跳过（模板表达式无 HTML 结构字符）
- **WAF 感知绕过** — 17 种变异策略（11 结构 + 6 编码），按 WAF 类型精准选择，首次检测到 WAF 自动启用
- **置信度评分** — 0.0–1.0 评分体系，含交互效应（WAF×无净化、语法×上下文逃逸）；结构分析封顶 0.90，浏览器执行验证后才可达 100%
- **语义去重 + 同参聚合** — 5 元组 key（URL+参数+上下文+向量+exploit 技术）去重后，同参数同上下文折叠为一条 finding，payload 变体作为子项展示
- **引号类型门控** — 检测到 JS 字符串反射的引号类型后，只发送匹配该引号的逃逸 payload（`"-alert(1)-"` 不再发往单引号反射点）
- **URL 子上下文分析** — href/src 反射落在已有 URL 的路径/查询串/片段位置（如 `embed src=xsf02.swf?arg=PAYLOAD`）判定为惰性上下文——改不了 scheme 就不生成 `javascript:`/`data:` payload；只有 attribute 值开头（或应用已输出的 `javascript:`/`data:` 前缀后）才按 URL 注入处理
- **过滤发现** — XSStrike 风格 FilterProfile：探测服务器过滤行为，自动剪枝无效 payload 类
- **JS 子上下文分析** — 事件属性内 JS 字符串/模板字面量细分（XSStrike 核心思想）

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
- **CI/CD 友好** — 退出码区分（0=安全 / 1=错误 / 2=发现漏洞）

---

## 安装

### 从源码构建

```bash
# 需要 Go 1.22+
git clone https://github.com/wqnmlgb151/XSSscan.git
cd XSSscan
make build
```

### Docker

```bash
docker build -t xsscan .
docker run --rm xsscan --url "http://target.com/page?q=test"
```

### 依赖

- Go 1.22+（`go.mod` 声明 1.22；依赖 `golang.org/x/sys v0.16.0` 兼容）
- Chrome/Chromium（可选，用于 `--headless`、`--verify-execution`、`--render-spa`；未安装时自动检测并降级跳过，可用 `--chrome-path` 手动指定）

---

## 快速开始

```bash
# 查看版本
./xsscan --version

# 最简扫描
./xsscan --url "http://target.com/search?q=test"

# 管道模式 — 从 stdin 读取 URL
echo "http://target.com/search?q=test" | ./xsscan
cat urls.txt | ./xsscan --silent

# 推荐日常用法 — 上下文探测 + WAF 绕过 + 随机 UA
./xsscan --url "http://target.com/search?q=test" \
  --probe --waf-bypass --random-ua

# 全功能扫描
./xsscan --url "http://target.com/page?q=test" \
  --probe --verify-execution --headless --waf-bypass \
  --stored --trigger-url "http://target.com/profile" \
  --discover-headers --random-ua --adaptive-rate
```

---

## 扫描模式

### 反射型 XSS（默认）

扫描 Query、POST Body (JSON/Form)、Header、Cookie 参数：

```bash
./xsscan --url "http://target.com/page?id=1"
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
./xsscan --url "http://target.com/page?q=test" --headless
```

覆盖 11 种 DOM XSS source，双层检测：

| 层级 | 方式 | 置信度 |
|------|------|--------|
| **CDP Sink Hook** | 脚本注入 `Page.addScriptToEvaluateOnNewDocument`，拦截 innerHTML/eval/document.write/Function/location.assign 等 11 种 sink | 0.85 |
| **事后 DOM 扫描** | 兜底检测，扫描 DOM 中已渲染的 marker（hooks 未命中时启用） | 0.75 |

| Source | 测试方式 |
|--------|----------|
| URL Fragment | `#payload` |
| Query String | `?q=payload` |
| Pathname | `/payload` |
| window.name | `window.name` 注入 |
| Referer | `document.referrer` |
| javascript:href | `javascript:` 协议 |
| Inline Event | 内联事件处理器注入 |
| localStorage | `localStorage.setItem` |
| sessionStorage | `sessionStorage.setItem` |
| document.cookie | Cookie 注入 |
| postMessage | `window.postMessage` |

### 存储型 XSS

```bash
# 指定触发页面（存储内容展示的位置）
./xsscan --url "http://target.com/feedback" -X POST \
  -d "message=test" \
  --stored --trigger-url "http://target.com/view-feedback"

# 不指定 --trigger-url 时自动发现：同域爬虫（BFS，深度 2，最多 20 页）
# 发现的每个页面都会作为触发 URL 轮询，整个扫描只爬取一次
./xsscan --url "http://target.com/comment" -X POST \
  -d "body=test" --stored

# 自定义轮询参数
./xsscan --url "http://target.com/comment" -X POST \
  -d "body=test" \
  --stored --trigger-url "http://target.com/posts/123" \
  --stored-max-polls 10 --stored-poll-interval 3
```

### Blind XSS（回调服务器）

```bash
# 第三方回调地址（Burp Collaborator、xss.ht 等）— payload 直接指向该地址
./xsscan --url "http://target.com/contact" -X POST \
  -d "message=test" \
  --callback "https://your-server.com/xss"

# 本地回调 — loopback 地址自动启动内置 HTTP 监听器（省略端口默认 :80）
./xsscan --url "http://target.com/contact" -X POST \
  -d "message=test" \
  --callback "localhost:8080"

# DNS 外带模式 — 裸域名（无 scheme/端口）生成 <xsscan-随机>.<域名> 子域名
# payload，目标只需发出 DNS 查询即证明执行（HTTP 出口被封时仍然有效）
./xsscan --url "http://target.com/contact" -X POST \
  -d "message=test" \
  --callback "abc.dnslog.cn"
```

扫描后等待 30 秒收集回调（`sync.Cond` 零 CPU 等待）。

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
  --proxy-insecure
```

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
./xsscan --url "http://target.com/page?q=test" --headless   --chrome-path "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

### 浏览器执行验证

```bash
# 用真实 Chrome 验证 XSS 是否实际执行
./xsscan --url "http://target.com/page?q=test" \
  --verify-execution --verify-timeout 20
```

验证器通过拦截 alert/confirm/prompt 对话框判断执行结果：
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

## 输出格式

### JSON（默认）

```bash
./xsscan --url "http://target.com/page?q=test" -o result.json
```

```json
{
  "target": "http://target.com/page?q=test",
  "scan_time": "2026-08-02T10:30:00Z",
  "findings": [
    {
      "id": "XSS-1722586200000000000-1",
      "parameter": "q",
      "type": "reflected",
      "context": "html_body",
      "payload": "<script>alert(1)</script>",
      "confidence": 0.90,
      "severity": "critical",
      "url": "http://target.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
      "curl": "curl -X GET 'http://target.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'"
    }
  ],
  "stats": {
    "parameters_found": 1,
    "payloads_sent": 25,
    "findings_count": 1,
    "duration_seconds": 3.2
  }
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

---

## 架构

### 扫描流水线

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
│  • 19 种上下文类型 + JS 子上下文细分            │
│  • 词法分析 + 正则补充                           │
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
│  • URL 归一化去重，噪音从 50→8 finding/目标      │
└─────────────────────────────────────────────────┘
    │
    ▼ (可选)
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
| `cmd/` | CLI 入口、信号处理、多目标编排 |
| `pkg/scanner/` | 扫描编排：Worker Pool、重试、限速、WAF 追踪、探针、去重 |
| `pkg/analyze/` | 分析引擎：参数提取、反射检测、框架/CSP 检测、WAF 回退 |
| `pkg/context/` | 上下文检测：HTML Tokenizer，19 种上下文类型 |
| `pkg/payload/` | Payload 引擎：模板存储、上下文生成、WAF 变异、框架 payload |
| `pkg/verify/` | 置信度评分、WAF 检测（8 种签名）、净化检测 |
| `pkg/report/` | 报告生成：JSON/Markdown/HTML/SARIF/JUnit |
| `pkg/auth/` | 表单认证 + 自动 CSRF 提取 |
| `pkg/auth/oauth/` | OAuth 2.0/OIDC：自动发现、ROPC、PKCE |
| `pkg/dom/` | 无头 Chrome DOM XSS 检测（CDP） |
| `pkg/execverify/` | 浏览器执行验证（4-worker 并发） |
| `pkg/crawler/` | BFS 链接发现 + SPA 路由提取 + Sitemap + JS 渲染 (`--render-spa`) |
| `pkg/stored/` | 存储型 XSS：marker 注入 + 触发轮询 |
| `pkg/callback/` | Blind XSS HTTP 回调服务器 |
| `pkg/ssrfguard/` | SSRF 防护：IP 验证 + 重定向链检查 |
| `pkg/httpclient/` | HTTP 客户端工厂 + 代理 + UA 池 |

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
| 上下文类型 | 19 种 |
| WAF 签名 | 12 种（8 国际 + 阿里云/腾讯云/安全狗/宝塔）+ 17 种绕过策略（11 结构 + 6 编码） |
| DOM XSS Source | 11 种 + CDP sink hook（11 种 sink） |
| 框架 Payload | 7 种（React, Vue, Angular, Svelte, jQuery, HTMX, Jinja2） |
| 零数据竞争 | `go test -race` 全通过 |

---

## 开发

### 常用命令

```bash
# 构建
make build

# 测试（含竞态检测）
make test

# 覆盖率
make coverage
make coverage-scanner   # 仅 scanner 包
make coverage-cli       # 仅 cmd 包

# 开发模式（不编译直接运行；dev target 不转发参数，带 flag 时用 go run）
go run ./cmd -- --url "http://target.com/page?q=test"

# 静态检查
make lint

# 依赖更新
make deps

# 清理
make clean
```

### 测试覆盖

| 包 | 覆盖率 | 等级 |
|----|--------|------|
| `pkg/report` | 97.4% | ⭐ Excellent |
| `pkg/callback` | 95.7% | ⭐ Excellent |
| `pkg/internal/request` | 95.5% | ⭐ Excellent |
| `pkg/httpclient` | 91.4% | ⭐ Excellent |
| `pkg/verify` | 91.3% | ⭐ Excellent |
| `pkg/csrf` | 89.1% | ⭐ Excellent |
| `pkg/auth` | 88.2% | ⭐ Excellent |
| `pkg/ssrfguard` | 85.5% | ⭐ Excellent |
| `pkg/crawler` | 72.0% | ✅ Good |
| `pkg/scanner` | 82.0% | ⭐ Excellent |
| `pkg/stored` | 77.9% | ✅ Good |
| `pkg/auth/oauth` | 66.2% | ✅ Good |
| `pkg/analyze` | 64.9% | ✅ Good |
| `pkg/context` | 58.7% | ⚠️ Fair |
| `cmd/` | 51.0% | ⚠️ Fair |
| `pkg/payload` | 46.8% | ⚠️ Fair |
| `pkg/execverify` | 38.1% | 🔴 Low (browser-dependent) |
| `pkg/dom` | 19.4% | 🔴 Low (CDP integration) |

---

## 版本规则

版本号遵循 `x.y.z` 格式：

| 位 | 含义 |
|----|------|
| **x** (major) | 重大架构变更或破坏性改动 |
| **y** (feature) | 新增功能（如新扫描模式、新 flag） |
| **z** (bugfix) | Bug 修复、体验优化 |

构建时通过 ldflags 注入版本：

```bash
make build VERSION=1.0.0
```

`--version` 输出当前构建版本。

---

## 免责声明

**本工具仅用于授权的安全测试。** 使用本工具扫描未授权目标是违法行为。使用者需自行承担一切法律责任。

---

## License

MIT
