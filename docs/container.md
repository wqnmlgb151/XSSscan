# 容器（v1.1.5）

构建：`docker build --target final -t xsscan .`。运行层使用非 root `xsscan` 用户，内置 Chromium 与 CA，保留 Chrome 沙箱。Go builder 和 Alpine runtime 均固定 manifest 摘要；依赖只在镜像构建时安装，扫描运行不下载浏览器。

[Alpine 官方维护表](https://www.alpinelinux.org/releases/)：3.19 常规支持于 2025-11-01 结束。选择仍受支持的 3.23（支持至 2027-11-01），runtime 3.23.7；摘要于 2026-11-05 从 Docker 官方 Registry 核实。固定基础镜像不等于固定 apk 仓库快照，构建时 Chromium/CA 修订可能变化，CI 记录验收结果。

Chrome 沙箱需要内核允许 user namespace、进程隔离所需系统调用及足够 `/dev/shm`（示例 256 MiB）。默认 Docker seccomp、主机 AppArmor/userns 策略可能阻止启动；必须按部署环境配置相应权限。程序不默认设置 `--chrome-no-sandbox`。

CI 在一次性 runner 内以 `--network none --shm-size=256m --cap-add SYS_ADMIN --security-opt seccomp=unconfined` 运行本地靶场并验证执行证明；这些参数扩大容器权限，只适用于受隔离的测试环境，不是生产加固配置。生产环境应按内核/容器引擎配置受限 seccomp 和 userns 策略；不要直接照搬 CI 的权限放宽。

`smoke` 是测试专用 target，仅比正式 `final` 镜像多一个 loopback fixture；`final` 不包含 fixture 二进制。靶场和扫描位于同一容器，仅访问 127.0.0.1:18080，不使用外部目标。CI 要求扫描退出码 2、JSON Schema 1.1 和真实 `ExecutionVerified`；缺 Chrome 或验证不完整会失败。

本机 Windows 没有 Docker 命令，因此实际镜像构建、沙箱和容器运行均未本地验证；以 CI 的真实结果为准。静态容器策略测试只验证配置契约，不能替代执行验收。
