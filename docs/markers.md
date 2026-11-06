# Marker 配置（v1.1.5）

默认仍是 `xsscan` + 12 位小写字母/数字，后缀使用 crypto/rand 均匀采样，不回退 math/rand。`GenerateMarker()` 的 SDK 签名与默认前缀保留；扫描通过 `GenerateMarkerContext(ctx)` / `WithMarkerPrefix` 使用本轮配置。

新增 `--marker-prefix`（默认 xsscan）和 `--random-marker-prefix`（默认关闭），支持 YAML。前缀首字符必须小写字母，其余小写字母/数字，最多 32 字符；空值采用默认前缀。限制确保 HTML 探针、JS 标识和 DNS 回调 label 安全兼容，最长 token 44 字符。随机模式每轮一次生成 10 个随机小写字母，并覆盖指定前缀；同轮并发任务共享不可变 context 值，后缀仍每次重新随机。

恢复默认：`--random-marker-prefix=false --marker-prefix=xsscan`。随机前缀减少固定标识复用，不保证绕过 WAF 或隐藏工具身份；回调参数名 xsscan、JS hook 的内部变量名和现有 payload 模板不因该选项改名。

反射分析、filter/context 探针、DOM 矩阵与 hook marker、Stored 注入、Blind token、执行确认均使用本轮前缀。内部 xsspatterns 只匹配事件处理器结构，不匹配固定 marker；验证器内部从响应临时构造的离线替代 marker 不发送网络，无需依赖本轮前缀。旧 SDK 默认 filter 常量/无 context 入口保留兼容。

后缀生成的熵读取失败时 fail closed（原无 error 的 SDK 入口会 panic，模块 Runner 会标记失败），不会使用弱随机数继续。随机模式前缀生成失败返回错误。加密随机源依赖操作系统；这不是独立网络隔离机制。
