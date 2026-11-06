# 联网检查、自愈与诊断导出

MagicNet 在服务启动后通过本机 mixed 入口检查 `https://www.google.com/generate_204`。TLS 校验通过且收到 HTTP 204 才记为在线。内核运行状态与 Google 连通性分别显示；刷新页面、读取状态和导出诊断不会触发新的公网请求。

## 检查频率与恢复

正常时每 300 秒检查一次。失败后间隔为 60、120、240、480、960、1800 秒，此后保持 1800 秒。截止时间使用包含休眠的单调时钟，监控进程重启和系统时间调整不会重置同次开机的退避。每个 curl 请求最多 8 秒，父进程预算 9 秒、输出最多 1 KiB，不跟随重定向、不进行内部重试。

Google 失败后才检查独立代理目标；后者也失败后才检查直连出口。仅 Google 不通时保留警告。多个代理探测失败而直连可用时，逐级尝试路由/DNS 修复、订阅更新和当前内核重启。首次失败先诊断；恢复动作至少间隔 300 秒，自动订阅更新至少间隔 3600 秒。订阅更新沿用候选校验、事务与失败恢复，整次自动更新有 300 秒预算。

监控复用 `magicnet-kernel` watchdog，每 60 秒运行一次短命令；未到检查时间立即退出，没有新增常驻 Rust 进程。服务停止、模块停用或进程归属未知时暂停。恢复在生命周期锁内重新核对服务状态，保留用户停止意图、TUN/eBPF 模式与节点选择。修复返回成功和恢复联网分别记录，后续 HTTPS 检查通过后才显示在线。

用户在自动恢复期间显式停止或重启服务时，先停止监控，并只取消已核对身份的本模块维护进程。更新器最多获得 15 秒执行现有回滚/清理，生命周期锁保留到子任务结束；仅该取消场景最多等待锁 20 秒。取消记为 `paused/stop_requested`，不再恢复监控或重放选择。未能取得锁或完成停止时仍明确报错，不声称服务已停。

概览和诊断页显示 Google 状态、延迟、失败警告、下次检查时间及恢复动作。故障/恢复状态转换触发通知；也可通过 `cli health`、`cli --json connectivity status` 和 `.log/connectivity.log` 查看。单次通知失败不影响探测状态。

## 一键导出

在 WebUI 诊断页点击“一键导出诊断包”，生成一个文件：

```text
/sdcard/Download/MagicNet/MagicNet-diagnostics.txt
```

命令行入口：

```sh
su -c '/data/adb/modules/MagicNet/cli support export'
su -c '/data/adb/modules/MagicNet/cli --json support export'
```

`cli support bundle` 输出同样的完整文本报告，适合终端/MCP。Linux 模拟环境保存到测试模块的 `.state/diagnostics/MagicNet-diagnostics.txt`。采集不修复网络、不更新订阅、不重启、不抓取用户流量。

| 内容 | 用途 |
| --- | --- |
| 模块、CLI、内核版本，系统内存、负载 | 定位版本与资源约束 |
| 核心 RSS、线程、FD、调度与 I/O | 定位进程和资源异常 |
| 规范状态、启动步骤、探测与恢复历史 | 区分启动、代理连通性和恢复阶段 |
| 路由顺序、DNS、入站、出站、配置引用关系 | 检查分流配置；私密名称使用报告内稳定别名 |
| `sing-box version/check` 状态与输出 | 定位内核特性和配置错误 |
| IPv4/IPv6 路由、策略规则、模块防火墙规则 | 检查出口和拦截路径 |
| TUN/eBPF、监听、本地 API、内核网络参数 | 检查数据面和平台能力 |
| 订阅类型、数量、事务、刷新及相关日志 | 区分获取、转换、提交和恢复失败 |
| `supervisors` 与 `connectivity-watchdog` 日志 | 保留后台监督器启动超时和监控循环启动失败，避免只有核心日志而漏掉维护故障 |

凭据、订阅 URL、节点名称、应用 UID、设备标识和流量目标自动遮蔽；状态、类型、计数、配置顺序和引用关系保留。外部命令分别标明退出、缺失、超时和截断，没有取得的证据显示不可用。

所有外部命令共享 25 秒预算。单流最多 32 KiB，每节最多 48 KiB，总报告最多 512 KiB；最多八个日志，各最多读取尾部 32 KiB/120 行。文件先独占创建同目录临时文件并同步，再原子替换固定文件。失败保留旧报告；重复导出只保留最新完整报告，并发时最后成功完成的文件生效。支持 Unix 权限的文件系统使用 0600；Android 下载目录由系统共享存储规则管理。

## 机器与状态合同

`connectivity.status` 只读；同一结果也在 `service.status.data.connectivity` 中。状态包含 `unknown/pending/online/degraded/offline/paused/stale`，测量缺失用 `null`；原始错误用有限 reason token 表达。返回目标、路径、检查时间、下次检查时间、退避、失败次数、HTTP/延迟、辅助探测和最近恢复动作。`primary_reason` 保留 Google 的直接错误，`reason` 表达综合判断。

`.state/machines/connectivity.state` 是唯一公共规范状态，由监控 producer 原子发布。开机 token 仅用于判定单调截止时间是否仍有效，不进入 JSON 和诊断包。状态读取不联网、不发布文件、不执行恢复。

`support.export` 是明确的文件写入例外：capabilities 的 commands/mutation_commands 均列出它，且声明 `state_effect="export-only"`、`fresh_network_probe=false`。无参数，成功返回 `{path, bytes}`；失败返回 `support.export_failed`。WebUI 先协商能力，收到完整成功 envelope 后才显示文件位置。未知参数保持结构化失败，不落回人类命令。

## 打包与验证

源码保留测试。最终核心包、完整包、别名与全部组件递归排除测试、fixture、快照、基准、覆盖率和 node_modules 目录；运行时的 `bin/test` 等普通文件保留。打包器及发布验证器对脏包直接失败。

验证分别记录状态机模拟、真实 CLI 进程、sing-box 配置校验、回环代理、公网连接与 Android 设备结果。宿主缺少 netlink/TUN 权限时保留实际失败。主机指标注明测量对象，不用 CLI 内存代替 Android 核心内存。
