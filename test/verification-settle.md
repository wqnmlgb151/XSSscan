# 执行验证稳定观察（P1-6，未发布）

原先未出匹配弹窗的候选固定等待 3 秒，再重试晚期 focus/hover。现在以 CDP 请求事件判断网络安静，且必须同时具备独立原始 HTML 惰性证明和保守运行时观察，才提前结束。含脚本、事件、模板/Shadow DOM、未知标签/命名空间、刷新头、多文档或未知观测的页面仍保留完整上限；既有末次交互与 100ms 弹窗等待不变。

取得原始正文前要求主文档加载完成、已记录实际解码 DataLength 且不超过 256 KiB。未知/超限不取正文，保留原窗口；不信任压缩 Content-Length。运行时网络 map 上限 4096，溢出保守回退。正文检查看到的 HTML 不受页面 DOM 原型修改影响，不写入报告。已有执行证明、加载失败或完整窗口兼容模式不做额外正文分类。

本机 Windows、race、本地合成惰性 HTML、浏览器预热后 3 轮：

| 轮次 | 修改前 ms | 最终优化后 ms | 请求数（前/后） |
| --- | --- | --- | --- |
| 1 | 3396.080 | 422.752 | 1 / 1 |
| 2 | 3383.508 | 453.107 | 1 / 1 |
| 3 | 3386.688 | 416.308 | 1 / 1 |

中位数 3386.688 → 422.752 ms。数据见 `test/performance/results/verification-settle-windows-20261105.json`。这不是整站扫描提速比例，未测 CPU/RSS；脚本页面不承诺提速。

复现当前优化与兼容窗口（需已安装 Chrome；Go 依赖用本地缓存；只访问 loopback）：

```powershell
$env:GOTOOLCHAIN='local'
$env:GOPROXY='off'
# 使用本机 pinned go.exe 路径代替 go。
$env:XSSCAN_TEST_FULL_WINDOW='0'
go test -race -v -count=1 -run '^TestInertVerificationSettlesBeforeFullWindow$' ./pkg/execverify
$env:XSSCAN_TEST_FULL_WINDOW='1'
go test -race -v -count=1 -run '^TestInertVerificationSettlesBeforeFullWindow$' ./pkg/execverify
Remove-Item Env:XSSCAN_TEST_FULL_WINDOW
```

XSSCAN_TEST_FULL_WINDOW 仅为该测试夹具的开关，不是扫描器环境变量。真实 CLI 用 `--verify-full-window`（YAML 同名）恢复完整观察窗口；默认 false。测试不依赖任何外部站点或运行时下载。

2.5 秒延迟 focus/hover、声明式 Shadow DOM、HTTP Refresh 均有回归。初版优化确实漏掉 Shadow DOM/Refresh，已先写失败测试再收紧；原型篡改用例修复前未复现漏报，保留防御回归。默认报告/Schema/置信度/候选与执行判据不变。无法证明惰性只延长观察，不视为安全证据。
