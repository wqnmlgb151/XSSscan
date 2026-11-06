# Chrome 启动参数（v1.1.5）

恢复站点隔离前，真实 Chrome 在覆盖参数下完成：两个 CreateBrowserContext、localStorage 隔离、同源守卫、两次精确请求预算、页面脚本执行及 BrowserContext 清理。默认配置禁用隔离的失败断言已记录；恢复后该断言转绿。既有 DOM/验证/资源回归继续执行，不改变检测矩阵或置信度。

默认从 disable-features 移除 site-per-process，并增加 --site-per-process。显式增加 --disable-component-update（实测该项原先未启用）；原有 --disable-background-networking 和 --disable-sync 保留。每个参数使用真实 Browser.getBrowserCommandLine 验证，不能据此声称 Chrome 无任何后台网络。

兼容开关：

- --chrome-disable-site-isolation：只恢复旧 site-per-process 禁用配置。
- --chrome-legacy-startup：恢复本项旧隔离和组件更新参数，包括移除新组件更新禁用参数。

均默认 false，支持 YAML。需要定位兼容性问题时显式使用；正常扫描保留默认加固。Chrome 沙箱、证书、代理、DNS 固定和预算配置不会因这些兼容开关自动关闭。

检测结果、CLI 原参数、Schema 1.1 和 Windows EXE 能力保持。Linux/Windows 差异以完整 CI 为准；容器测试不默认打开 --chrome-no-sandbox。
