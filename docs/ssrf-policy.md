# SSRF Policy 与 Chrome DNS 固定（未发布）

CLI 通过 context 传递独立 `ssrfguard.Policy`，HTTP 客户端和代理验证也接收显式策略。隔离 Chrome tab 继承调用策略。旧包级 AllowPrivate 仅用于未传策略的 SDK 兼容入口；CLI 和测试不再修改它。SDK 应传 Policy/WithPolicy，认证等预检使用相同 context。

CIDR 在启动时预编译，覆盖原私网、回环、链路本地、CGNAT，以及多播/保留/广播、文档/测试/基准、IPv6 本地/站点本地/多播、NAT64/6to4/Teredo 等转换范围。IPv4-mapped 先归一化；标准 NAT64/6to4/Teredo 解出 IPv4 后验证。转换范围整体保守拒绝，包括嵌入公网的情形；自定义非标准 NAT64 前缀无法自动识别。`--allow-private` 是授权环境的显式兼容开关。

网段核对依据：[IANA IPv4 特殊用途登记](https://www.iana.org/assignments/iana-ipv4-special-registry)、[IANA IPv6 特殊用途登记](https://www.iana.org/assignments/iana-ipv6-special-registry)（2026-11-05 核对）。保守边界不等同于所有全球路由策略，网络管理员仍需配置出口限制。

`--chrome-pin-dns` 默认关闭，仅支持单一 `--url`，YAML 同名配置可用。Go 解析一次并校验全部答案；优先首个已验证 IPv4，否则选首个 IPv6，用 Chrome host-resolver-rules 固定目标 host。已验证答案在浏览器守卫中复用，不依赖后续 DNS 答案。直接 IP 目标无需 DNS rule，但仍强制浏览器直连。该实验功能不改变 Go HTTP 客户端原有逐次验证/固定 dial 地址的行为。

同 host 的重定向与子资源使用该映射；跨 origin 导航和资源仍由已有守卫限制。与 --proxy 同时使用需要显式 --browser-direct，否则报错；HTTP 请求仍可走代理。系统代理也被禁用，避免代理远端解析绕过固定。批量/文件/stdin 目标暂不支持。固定单个地址会失去 DNS 负载均衡和其他答案的故障回退；需要时关闭该实验开关。

此机制只约束支持的目标源路径，不是 Chrome 网络防火墙，不覆盖全部后台进程、Service Worker、WebSocket/WebRTC、非 HTTP 协议等流量。原有浏览器预算默认仍不限，不改变证书开关或检测矩阵。
