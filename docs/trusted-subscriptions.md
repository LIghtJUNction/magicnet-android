# 受信任的 NAS 与本地订阅源

MagicNet 默认只下载公网 HTTPS 订阅。要从自己的 NAS、局域网或 Tailnet 地址下载，先在设备 CLI 中授权准确的来源和网段，再在 WebUI 或 CLI 中保存订阅 URL。授权保存在私有的 `.config/sing-box/subscription-trust.list`；缺失或为空时不启用例外。

## 配置一个来源

以下命令在设备的 root shell 执行。示例通过本机 `7892` 端口的 SOCKS5 入口访问 Tailnet NAS；地址和端口须替换为自己的配置。建议用单个 IPv4 的 `/32` 或 IPv6 的 `/128` 限定目标：

```sh
magicnet_cli=/data/adb/modules/MagicNet/cli
trust_rules=$(printf '%s\n' 'http://100.100.1.2:25500 100.100.1.2/32 socks5://127.0.0.1:7892' | base64 | tr -d '\n')
"$magicnet_cli" sub trust set "$trust_rules"
unset trust_rules
```

随后在 WebUI“订阅”中粘贴该服务器的完整订阅 URL，或使用 CLI：

```sh
"$magicnet_cli" sub set sing-box 'http://100.100.1.2:25500/subscription.yaml'
"$magicnet_cli" sub status
```

保存订阅沿用原来的下载、解析、配置校验和提交事务。URL 中的 path/query 不写进信任清单，完整 URL 只在私密订阅入口传递。信任命令只改变访问授权，不下载订阅或启动内核。

## 清单格式

每行是 `origin CIDR [proxy]`，以空白分隔；第三列可选，省略时直连。清单最多 64 条、16 KiB：

```text
http://nas.example:25500 100.100.1.2/32 socks5://127.0.0.1:7892
https://nas.example:8443 192.168.50.0/24
https://nas.example:8443 fd12:3456:789a::/64
```

| 字段 | 规则 |
| --- | --- |
| 来源 | 精确的 `http` 或 `https` scheme、主机与端口。省略端口时分别为 80、443。禁止路径、query、fragment、userinfo 和通配符。 |
| 网段 | 规范 CIDR，主机位必须为零。范围须完整位于 RFC1918、CGNAT、ULA 或 loopback 地址空间。IPv6 来源使用方括号，例如 `http://[fd12::10]:25500`。 |
| 代理，可选 | 仅允许显式端口的 literal loopback `socks5://`，例如 `socks5://127.0.0.1:7892`。禁止 SOCKS5h、HTTP、远端代理、认证字段、path/query。 |
| 多行 | 同一来源可列出多个 CIDR，组成该来源允许的地址集合，但必须使用同一代理路线；不同主机、端口或 scheme 的授权相互独立。 |

公网、link-local、云元数据、multicast、unspecified 等地址范围不能通过这份清单放行。HTTP 授权不包含 HTTPS，HTTPS 授权也不包含 HTTP。使用 HTTPS 时仍验证服务器证书和主机名。

`sub trust set` 替换整份清单，先完整校验，再保存；错误输入保留旧授权。撤销全部例外：

```sh
"$magicnet_cli" sub trust clear
```

清空授权不删除订阅或正在使用的有效配置。后续更新需要重新符合默认公网策略，或重新取得对应的明确授权。升级保留信任清单和已记录的订阅历史；从未记录更新的安装继续显示无历史。

升级只从已安装设备恢复信任清单。构建时会将开发目录里的清单从模块和组件 ZIP 中排除，新安装不会继承构建者的授权。

## 每次下载都重新检查

信任清单限制实际连接地址。每次请求、重试和允许的跳转都重新解析主机；全部解析地址必须属于该来源的授权集合，然后将这些地址固定给下载器。只要混入一个未授权地址，整个请求就会被拒绝。

受信任来源的跳转只允许保持同一 scheme、主机和端口；相对路径跳转可以继续。公网订阅的跳转始终走公网 HTTPS 策略，即使跳转目标恰好出现在本地信任清单，也不会获得本地访问权限。用户 curl 配置、代理环境变量和 `MAGICNET_SUB_PROXY` 不能扩张授权。

现有下载上限继续适用：最多五次跳转、每来源解压后最多 8 MiB、总预算最高 120 秒。HTTP 明文来源只用于自己明确授权的网络；选择 HTTPS 时不会因证书错误回退到明文或关闭证书校验。

直连来源使用设备已有系统路由。NAS 只经 sing-box userspace Tailscale 可达时，第三列可指定模块的 loopback SOCKS5/mixed 入口。本机先解析并检查全部目标地址，再让 SOCKS5 连接已核对的数值 IP；不把目标域名交给代理重新解析。HTTP Host 和 HTTPS 证书主机校验仍使用订阅的原主机，授权清单也不会自动启动代理服务。

## 检查与错误

WebUI 允许填写 HTTP URL，由设备后端根据已保存的信任清单作最终校验。页面中的格式检查不授予权限；信任清单只通过设备 CLI 管理。失败时保留草稿和上一次有效配置。

内部 `sub check-source <scheme> <host> <port>` 检查来源授权，成功不输出内容；`sub resolve-source <scheme> <host> <port> <origin-scheme> <origin-host> <origin-port>` 还检查下载链和全部解析地址，成功每行输出 `IP|direct` 或 `IP|socks5://127.0.0.1:port`，只供私密下载执行器使用。这些入口只接收 authority 字段，不接收含 token 的完整 URL。旧 `sub resolve-host <host> <port>` 继续只校验公网地址。

信任清单、原始订阅 URL 和响应正文不进入公共状态或诊断。`sub.status` 的来源计数、阶段和结果仍沿用现有字段，机器接口不会为配置授权新增隐式写入。
