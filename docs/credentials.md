# 凭据输入（v1.1.5）

v1.1.5 起，凭据输入优先级依次为 显式 CLI（包括文件/stdin）> 环境变量 > YAML；显式空值也生效。

| 用途 | 环境变量 | 可选显式入口 |
| --- | --- | --- |
| 登录密码 | XSSCAN_PASSWORD | --password-file / --password-stdin |
| 代理密码 | XSSCAN_PROXY_PASSWORD | 原 --proxy-password |
| OAuth client secret | XSSCAN_OAUTH_CLIENT_SECRET | 原 --oauth-client-secret |
| OAuth 密码 | XSSCAN_OAUTH_PASSWORD | 原 --oauth-password |
| JWT | XSSCAN_JWT | --jwt-file |

旧 CLI 继续可用。敏感 argv 可能进入进程列表和 shell 历史，非 `--silent` 时警告一次，不打印值；`--silent` 关闭提示。环境变量也可能被同一用户进程或诊断工具读取，不能替代主机访问保护。

文件和 stdin 仅删除末尾 CR/LF，保留空格。同一凭据多个显式来源报错。密码 stdin 上限 1 MiB，不能与目标 URL 列表共用 stdin；使用 `--url` 或普通目标文件。凭据文件应限制权限，避免提交到仓库。

Unix YAML 包含凭据且对组/其他用户可读时给出警告；建议 `chmod 600 config.yaml`。Windows 不使用 POSIX 位判断该配置权限；报告 ACL 策略仍独立生效。
