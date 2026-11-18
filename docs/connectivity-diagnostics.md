# 联网检查、自愈与诊断导出

MagicNet 分别检查主代理出口和本机 mixed 入口。主代理检查显式使用当前 `proxy` 组，对 `https://www.google.com/generate_204` 与 `https://cp.cloudflare.com/generate_204` 发起 HTTPS GET；两个站点均通过证书校验并返回 HTTP 204，才确认该出口可用。mixed 检查再通过配置中的本机代理入口访问 Google，覆盖入站和实际分流路径。两层都成功时总体显示在线；主代理成功而 mixed 失败时显示 `degraded/mixed_path_failed`。内核运行状态独立显示，刷新页面、读取状态和导出诊断均复用已有观测。

显式出口检查使用内核严格探测接口：`/proxies/{tag}/delay?url=<HTTPS URL>&timeout=4000&expected_status=204`。合法探测执行后，HTTP 200 响应携带 `strict_probe:true`、`expected_status:204` 与 `ok`；成功还须包含 `http_status:204` 和非负延迟。失败返回有限的原因标记及实际 HTTP 状态。旧内核只返回 delay、未提供能力标记时，状态为 `unknown/probe_unsupported`；API 请求失败则为 `unknown/probe_unavailable`。这些观测不增加网络失败计数，也不授权代理恢复动作。CLI 和带 `with_lx_probe` 的内核随同一发布包升级。

正式模块提供独立的 `bin-curl` 组件：curl、静态链接的 OpenSSL/zlib 和内嵌 CA，随组件保存许可证与固定构建来源。安装和增量更新都会校验这些文件，探测和订阅下载无需依赖 Android 自带 curl。调用忽略外部 curl 配置及继承的代理/CA/TLS 覆盖，仅使用产品明确指定的路径和参数。工具缺失或不可执行会保留 `probe_unavailable` 等本机原因并显示警告，不误报为上游断网，也不据此刷新订阅或重启。

## 检查频率与恢复

正常时每 300 秒检查一次。确证失败后间隔为 60、120、240、480、960、1800 秒，此后保持 1800 秒。截止时间使用包含休眠的单调时钟，监控进程重启和系统时间调整保留同次开机的退避。每次严格出口探测最多 4 秒，CLI 调用本地 API 最多等待 6 秒；mixed 和直连 curl 请求最多 8 秒，父进程预算 9 秒、输出最多 1 KiB，均使用 GET、不跟随重定向、不进行内部重试。

每轮都执行两个主代理站点检查；两者确证失败时再检查直连出口。仅一个站点失败时显示 `degraded/endpoint_specific` 并保留警告。自动恢复要求连续两轮主代理失败、直连可用、TUN 状态允许、核心仍由本模块运行，并且实际 Clash 模式明确为 Rule 或 Global。Direct 和无法确认的模式仅记录观测。恢复动作至少间隔 300 秒，自动订阅更新至少间隔 3600 秒。

符合条件时，先尝试当前主代理组内的备用节点。候选必须同时属于配置和实时 API 的允许列表，具有明确的真实代理类型；每轮最多检查三个候选，每个候选分别通过两个严格站点测试。直接连接、阻断、嵌套选择组、自动组和带 detour 的链路成员均不参与。选中候选后，在生命周期锁内重新核对配置、手动请求代次、实际模式和当前选择；只更新仍直接指向同一故障节点、且各自允许该候选的选择组，AI 组继续遵守自身成员限制。

每组切换先保存重启后使用的选择，再写入 API 并读回确认；批量失败按相反顺序补偿已经完成的组。最终还要验证主代理两个站点及 mixed 入口，全部通过才发布恢复在线。补偿时遇到外部新选择保留新选择，并报告 `rollback_failed`；持久化失败、API 未生效或验证失败均保留失败结果。候选检查或失败的切换同样消耗恢复冷却。没有可用候选时沿用分阶段的路由/DNS 修复、订阅更新和当前内核重启；订阅更新继续使用现有候选校验与失败恢复，整次自动更新预算为 300 秒。

监控复用 `magicnet-kernel` watchdog，每 60 秒运行一次短命令；未到检查时间立即退出，没有新增常驻 Rust 进程。服务停止、模块停用或进程归属未知时暂停。恢复在生命周期锁内重新核对服务状态，保留用户停止意图、TUN/eBPF 模式与节点选择。修复返回成功和恢复联网分别记录，后续 HTTPS 检查通过后才显示在线。

核心意外退出时，本地监控在生命周期锁与配置锁内再次确认核心已停止，再调用正常停止流程，撤销 MagicNet 拥有的 DNS 转发、DNS 防泄漏规则、热点和路由资源，恢复原有热点 offload 设置。此清理不等待公网探测退避，不启动核心、不更新订阅、不修改持久化选择，也不触碰外来规则；锁忙、核心重新启动或进程状态未知时暂缓。清理失败保留恢复证据并在后续本地检查重试，状态仍为暂停；读取状态不会执行清理。核心停止时，手动 `connectivity check` 只记录观测；其待处理请求仍允许后续后台 tick 在上述锁与身份复核通过后清理残留资源。

TUN 自动路由另按 60 秒周期检查，不受 Google 退避影响。核心启动满 90 秒后，同一核心启动身份的连续两次完整观测确认必要规则或转发路由缺失，才在同一生命周期锁内复核并重启当前核心。未知观测、未完成事务、eBPF、auto_route=false、Direct 模式、待处理的手动检查和停止状态均不触发。它与其他自动动作共享至少 300 秒冷却；TUN 重启依次退避 300/600/1200 秒，同次开机最多 3 次，worker 重跑、核心换代或规则恢复保留预算；已有预算损坏时停止自动恢复。耗尽后继续观察；实际恢复由后续路由与应用流量验证。

FIB 观察先按 `route_address` 扣除 `route_exclude_address`，只评估目的前缀与所需范围相交的路由。完全位于范围之外或已排除区间内的条件路由不影响覆盖判断；所需普通路由存在时报告完整，缺失时报告缺失。相交的路由带非零 `tos` / `dsfield` 时，只匹配相应流量类别，普通流量覆盖保持未知。此类条件、无法解析的值及缺值保留为 `unknown:route-selectors-unobserved`；明确为零的值仍按默认匹配处理。健康检查与机器状态共用这一判断，未知观测清除连续缺失计数并阻止自动恢复，已有联网结果和恢复预算保留。

用户在自动恢复期间显式停止或重启服务时，先停止监控，并只取消已核对身份的本模块维护进程。更新器最多获得 15 秒执行现有回滚/清理，生命周期锁保留到子任务结束；仅该取消场景最多等待锁 20 秒。取消记为 `paused/stop_requested`，不再恢复监控或重放选择。未能取得锁或完成停止时仍明确报错，不声称服务已停。

概览和诊断页显示 Google 状态、延迟、失败警告、下次检查时间及恢复动作。故障/恢复状态转换触发通知；也可通过 `cli health`、`cli --json connectivity status` 和 `.log/connectivity.log` 查看。单次通知失败不影响探测状态。

## 手动切换后的立即检查

手动选择或模式写入完成后，CLI 在释放生命周期锁后登记一次提前检查请求。下一个 watchdog tick 读取该请求，跳过原有公网探测退避；同一时段的请求合并执行，观测间隔至少 10 秒。请求只调整观测调度，保留自动恢复、订阅刷新和 TUN 的冷却与次数。检查进行中又收到手动选择，即使节点经历 A→B→A，也会丢弃先前结果并等待新一轮真实检查。待处理请求在只读状态中显示 `pending/selection_changed`。

现场验收可直接执行：

```sh
su -c '/data/adb/modules/MagicNet/cli connectivity check'
su -c '/data/adb/modules/MagicNet/cli --json connectivity status'
```

`connectivity check` 执行真实观测并发布规范状态，不触发修复、订阅更新或重启。它与 watchdog 共用 producer 锁；锁忙时请求留待处理并返回 `connectivity.check_queued`，10 秒内重复调用返回 `connectivity.check_throttled`。探测结果失败仍会如实发布为 offline、degraded 或 unknown；命令完成表示检查已执行。`cli health` 和 `connectivity status` 继续只读。`--json connectivity check` 保持明确拒绝写命令的机器合同。

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
| curl版本、HTTPS/TLS/gzip能力、ABI/API、CA和构建来源摘要 | 区分探测/订阅执行器缺失、能力异常和来源问题；版本查询不发送网络请求 |
| 核心 RSS、线程、FD、调度与 I/O | 定位进程和资源异常 |
| 规范状态、启动步骤、探测与恢复历史 | 区分启动、代理连通性和恢复阶段 |
| 路由顺序、DNS、入站、出站、配置引用关系 | 检查分流配置；私密名称使用报告内稳定别名 |
| `sing-box version/check` 状态与输出 | 定位内核特性和配置错误 |
| IPv4/IPv6 路由、策略规则、模块防火墙规则 | 检查出口和拦截路径 |
| TUN/eBPF、监听、本地 API、内核网络参数 | 检查数据面和平台能力 |
| 订阅类型、数量、事务、刷新及相关日志 | 区分获取、转换、提交和恢复失败 |
| `supervisors` 与 `connectivity-watchdog` 日志 | 保留后台监督器启动超时和监控循环启动失败，避免只有核心日志而漏掉维护故障 |

凭据、订阅 URL、节点名称、应用 UID、设备标识和流量目标自动遮蔽；状态、类型、计数、配置顺序和引用关系保留。外部命令分别标明退出、缺失、超时和截断，没有取得的证据显示不可用。

服务、TUN/eBPF 和 DNS 的机器状态按字段脱敏，保留可解析的 JSON 结构、规范状态、数值、布尔和 `null`。私密 URL 或节点名称不会让整段状态消失；固定公共 Google 检查目标可保留，订阅和本地 API 的私密地址继续遮蔽。MCP 使用有效的只读状态入口，未配置时显示停用/未运行，不将命令不支持误当作服务故障。

所有外部命令共享 25 秒预算。单流最多 32 KiB，每节最多 48 KiB，总报告最多 512 KiB；最多八个日志，各最多读取尾部 32 KiB/120 行。文件先独占创建同目录临时文件并同步，再原子替换固定文件。失败保留旧报告；重复导出只保留最新完整报告，并发时最后成功完成的文件生效。支持 Unix 权限的文件系统使用 0600；Android 下载目录由系统共享存储规则管理。

## 机器与状态合同

`connectivity.status` 只读；同一结果也在 `service.status.data.connectivity` 中。状态包含 `unknown/pending/online/degraded/offline/paused/stale`，测量缺失用 `null`；原始错误用有限 reason token 表达。返回目标、路径、检查时间、下次检查时间、退避、失败次数、HTTP/延迟、辅助探测和最近恢复动作。`primary_reason` 保留主代理 Google 检查的直接结果，`reason` 表达综合判断。

| 字段 | 含义 |
| --- | --- |
| `path=selected_proxy` | Google 与 `secondary_status` 指向当前主代理组的严格探测 |
| `mixed_path=mixed_proxy` | 独立的本机代理入口与分流路径 |
| `mixed_status` / `mixed_reason` | mixed 的 online、failed、unknown 或 not_run，以及有限原因标记 |
| `direct_status` | 两个主代理站点失败后执行的直连对照 |
| `last_action=failover` | 本轮消耗了一次有限候选切换预算 |
| `action_status=conflict` | 配置、模式或选择意图变化，自动切换已让位 |
| `action_status=rollback_failed` | 至少一个补偿面未完成，保留实际失败，等待人工检查或后续观测 |

`.state/machines/connectivity.state` 是唯一公共规范状态，由 producer 持 `.state/connectivity.lock` 的 `flock` 后原子发布。私有 `.state/connectivity-check.request` 只合并待检查代次；开机 token、请求代次和手动检查单调时间不进入 JSON 和诊断包。恢复锁顺序为 connectivity producer → config apply → selector store；手动控制先释放 config apply 再请求检查。状态读取不联网、不发布文件、不执行恢复。

规范状态中的 `probe_path=selected_proxy` 标明当前探测合同。升级时，缺少该标记的旧缓存显示 `unknown/not_checked` 并立即进入真实检查，动作、订阅刷新和 TUN 的既有预算继续保留。已带标记的 online 记录还须具备 HTTP 204、有效延迟、第二站点成功和 mixed 成功；证据矛盾显示 `unknown/probe_invalid` 并重新检查。读取状态只计算这些结果，保持磁盘文件原样。

`tun_auto_route` 单独返回 status、warning、检查/恢复时间、连续缺失数、恢复次数/上限和 recovery_status。status 为 not_required/pending/present/missing/unknown/paused/stale；recovery_status 为 none/pending/ok/failed/busy/cooldown/exhausted。TUN 结构、主代理出口和 mixed 入口分别保留证据，重启动作的完成与流量恢复分别记录。

`support.export` 是明确的文件写入例外：capabilities 的 commands/mutation_commands 均列出它，且声明 `state_effect="export-only"`、`fresh_network_probe=false`。无参数，成功返回 `{path, bytes}`；失败返回 `support.export_failed`。WebUI 先协商能力，收到完整成功 envelope 后才显示文件位置。未知参数保持结构化失败，不落回人类命令。

## 打包与验证

源码保留测试。最终核心包、完整包、别名与全部组件递归排除测试、fixture、快照、基准、覆盖率和 node_modules 目录；运行时的 `bin/test` 等普通文件保留。打包器及发布验证器对脏包直接失败。

ARM64生产curl与x86_64模拟器curl使用同一源码锁和构建器。验收核对实际ELF、版本及内嵌CA，并用本地TLS成功/拒绝对照验证证书检查；公网产品验收使用一次 `connectivity check`，保留自动恢复预算。诊断导出另行验证不增加探测次数。

CLI 回归使用本地传输 fixture 运行真实进程，覆盖旧核心能力缺失、自动测试组掩盖手选故障、mixed 入口失败、手动提前检查、Direct 模式、同组候选限制、持久化失败、验证失败逆序补偿、内部补偿失败分类，以及探测中选择变化与 A→B→A 请求竞争。核心测试另验证真实 TLS GET、204/非 204 和超时；这些 fixture 不访问公网。

验证分别记录状态机模拟、真实 CLI 进程、sing-box 配置校验、回环代理、公网连接与 Android 设备结果。宿主缺少 netlink/TUN 权限时保留实际失败。主机指标注明测量对象，不用 CLI 内存代替 Android 核心内存。
