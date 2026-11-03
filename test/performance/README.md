# v1.1.1 / v1.1.4 性能复现

2026-11-03，Windows amd64、Chrome 156.0.8078.79，同机交替五轮，使用两版正式 EXE。三参数 loopback 靶场、每请求固定 20ms 延迟；扫描配置保留 CLI 默认，仅增加 `--allow-private --silent --format json --output`。不访问用户提供的公网目标。

| 中位数，秒 | v1.1.1 | v1.1.4 |
| --- | ---: | ---: |
| 进程墙钟 | 69.662 | 69.607 |
| Reflected | 0.728 | 0.659 |
| DOM | 44.134 | 44.145 |
| Stored | 24.528 | 24.527 |

每轮均完成 65 项 DOM 检查、24 次 Go HTTP、9 次 payload/marker 提交；Stored 为 3 个注入参数、20 次 Go HTTP，保留全部轮询。每轮保留 id 参数浏览器执行验证发现，Blind 因未配置回调明确 skipped。靶场实际请求数 158～159，包含不纳入页面守卫的自主 favicon；早期样本的连接中止可能影响这个辅助计数，不能把它视为精确预算计数。

**本语料未复现版本退化，不声称已经消除用户公网实测的 20 秒差异。** 靶场仅 id 参数反射，Go 请求少于用户实测的 155 次；页面结构、子资源、DNS 和远端响应延迟均不同，不能外推为该目标已恢复。Stored、DNS/SSRF 生产代码在两 Tag 之间相同。没有证据支持回退安全检查或缩短窗口，因此本分支目前只增加测量和回归门禁。

## 分阶段与 pprof

另行对两个隔离检出注入计时及 CPU/block/mutex/heap 采样，不修改正式 CLI 或主工作区的生产代码。诊断运行有采样扰动，不混入五轮中位数。阶段数据是并发 goroutine 的**累计包含时间**，有嵌套，不能相加当总墙钟。

| 阶段累计毫秒 | v1.1.1 | v1.1.4 |
| --- | ---: | ---: |
| DOM 浏览器初始化 | 372 | 348 |
| DOM 请求守卫安装，66 次 | 402 | 415 |
| DOM DNS/SSRF，200 次 | 412 | 393 |
| DOM CDP Continue，133 次 | 250 | 223 |
| DOM 观察，71 次 | 137024 | 137027 |
| DOM 私有 Context 创建，66 次 | 5495 | 4902 |
| DOM 私有 Context 清理，66 次 | 3282 | 2715 |
| DOM 进程清理 | 168 | 142 |
| Stored 发现 | 46 | 46 |
| Stored DNS/SSRF，41 次 | 78 | 81 |
| Stored HTTP 轮询，15 次 | 402 | 408 |
| Stored 轮询等待，12 次 | 24006 | 24006 |

DOM 保留 66 次两秒观察（含 baseline）及五次一秒 postMessage 观察；四 worker 并发。Stored 三个输入按目标串行，分别保留四次两秒间隔。阻塞 pprof 中 select/channel、WaitGroup、同目标互斥等待占主导。CPU 样本主要位于 runtime.cgocall / ExecAllocator 等待调用链，不能据此推算 Chrome 子进程的 CPU；本轮没有 Chrome RSS/CPU 结论。请求预算计量未成为可观察到的主要热点；单次诊断不能证明其开销为零。

原始十轮数据、阶段数据和 pprof 文本见 [结果](results/windows-20261103.json)。完整本机采样文件在忽略的 `dist/performance/`。

## 复现

```powershell
python test/performance/ab.py --binary v1.1.1=<旧版EXE> --binary v1.1.4=<新版EXE> --rounds 5 --output dist/performance/new-ab
# 中断后用相同参数追加 --resume；只保留通过全部校验的已有样本。
git worktree add --detach dist/performance/profile-old v1.1.1
python test/performance/profile.py --checkout dist/performance/profile-old --go <Go1.26.9路径> --output dist/performance/old-profile.exe
# 另一版同样构建，再单独采样：
python test/performance/ab.py --binary old=dist/performance/old-profile.exe --binary new=dist/performance/new-profile.exe --profile --rounds 1 --output dist/performance/new-profile
go tool pprof -top dist/performance/old-profile.exe dist/performance/new-profile/1-old-profiles/cpu.pprof
```

profile.py 仅接受干净的独立 worktree，修改该检出的已知计时锚点。正式扫描算法、安全策略、预算、矩阵和等待不变。性能脚本拒绝优化 Python 模式，拒绝缺失验证、少检查、少 payload、少 Stored 注入/请求及不完整模块。`test/test_performance.py` 验证这些门禁；普通 CI 同时保留既有四类正负例、Stored 晚触发和安全回归。
