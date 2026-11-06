# MagicNet 跨层重写与原版对照报告

日期：2026-11-06。产品版本保持 v1.8.5 / 10613。

## 结果与比较对象

本轮按已有功能合同替换内部实现，覆盖 kamfw 框架以及 MagicNet 的 Shell 编排、CLI/MCP、WebUI 共用逻辑、安装器和打包链路。修改已分批提交到现有 GitHub 主线，主项目继续通过固定源码子模块接入。已执行的差分场景没有发现功能缺失；原版已有缺陷的修复单独列出，未把有限宿主测试写成所有设备和输入上的等价证明。

| 对象 | 固定版本 |
| --- | --- |
| Android 原版 | `aefcbfbab80fe14008e4467eb0292251f7ce8f89` |
| Android 候选验证点 | 差分与完整回归：`d58dbdc5ed8a43bc1fee5050187b529a0f7136b7`；最终主线整合：`81a60108477d31ca6131f930f955580ad4fa8ba1` |
| kamfw 原版 | `bb0dc7582ee2c27e31e49d2d3b714b97528defef` |
| kamfw 最终依赖 | `a7788737b938a9ed930645befe2526b626999a22` |
| 配方 | 0.3.13，保留同期 0.3.12 的联网维护、诊断和打包合同，新增 M59 重写对照 |

开发期间上游新增的低频 Google 联网检查、指数退避恢复、订阅刷新和单文件诊断已经包含在比较原版中。后续同期 CI 提交 `027e91f19330404d5a52120c1ed171f203d90175` 也已整合。固定的 sing-box 内核、规则数据和配置模板继续复用，未把第三方实现算成本轮独立重写成果。

最终 kamfw pin `a7788737` 是同期新增的仅测试提交；相对宿主回归和性能测量使用的 `ea8758bf`，全部生产文件逐字节相同，只增加 fswatch 字面路径排除回归。新增方法已在四种 Shell × GNU/BusyBox find 的 8 个组合中通过。

完整回归结束后，同期主线 `81a60108477d31ca6131f930f955580ad4fa8ba1` 增加监督器锁分离、两类诊断日志及 Android 验收脚本检查。本轮保留该提交，并对改动路径另行验证。下文原版差分、完整回归和性能数字绑定 `d58dbdc`；最终整合的复验结果单独记录，不将它写成全部套件在最终 SHA 上重新运行。

## 实际重写范围

| 层 | 本轮替换的实现 | 继续保留的合同或实现 |
| --- | --- | --- |
| kamfw | 导入器、阶段、root 管理器、目录、多语言、日志、模板、下载缓存、配置、属性、通知、浏览器、二进制安装、日志轮转、watchdog、fswatch 和共享核心生命周期 | 原有入口与语言回退、资源归属、失败传播和安装流程；兼容修正见下文 |
| Shell | 共用 PID/JSON 处理、API 包装、启动物化次序、DNS/网络配置读取、结构化路由与屏蔽规则发布、Tailscale 私密载荷原子写入、配置指纹和监督器编排 | 订阅格式转换与激活日志、锁与进程归属、TUN/eBPF 事务、热点归属和 DNS 防泄漏算法 |
| Rust CLI/MCP | 命令分派、公共 loopback HTTP、进程状态观察、链式策略与 MCP 设置控制器、日志与诊断输出、Wi-Fi 和节点列表、线性批量应用策略、25 类 MCP 控制的参数转换 | 公开命令和 schema；订阅下载/回滚、覆写与备份事务、eBPF 能力、网络访问修复、Tailscale/更新状态机、联网恢复预算 |
| WebUI | 异步命令结果发布、连接去重、公共文本解析、流量统计与告警、节点延迟计算 | 14 页功能、布局、草稿、读写队列、私密输出、语言和无障碍行为 |
| Go 安装器 | 共用有界 worker、校验后暂存、输入关闭、路径重叠检查、流式目录清理和路由样本缓存 | 校验、权限、模块锁、原子晋升、崩溃恢复、未知目录保护与旧版本迁移 |
| 打包 | ZIP 载荷按块读取、共用实际长度验证、摘要复用、批量归档清理 | 包名、别名、组件清单、模式、时间戳、压缩方式和开发内容排除规则 |

这次精简主要减少重复执行。Shell 原先反复为每一条记录启动处理程序，现集中处理一批记录；WebUI 和批量应用策略用索引保留顺序，避免反复遍历已有结果；打包器按块复制，不同时保留全部解压载荷。核心正常停止和信号处理现在由 kamfw 提供，MagicNet 的重复 `singbox_lifecycle.sh` 已删除。

稳定协议、事务算法和静态声明的保留是明确范围，不声称所有历史代码均已逐行替换。源代码行数也不等于运行内存。kamfw 的 39 个运行时文件由 6,614 降到 3,349 行（减少 49.4%），由 202,859 降到 123,852 字节（减少 38.9%），排除测试。完整统计见 [kamfw-size.json](validation/rewrite-2026-11-06/kamfw-size.json)；CLI 的宿主 release 二进制由 2,638,680 降到 2,622,296 字节，减少 16 KiB。

## 功能对照与回归

| 验收 | 结果与范围 |
| --- | --- |
| CLI 差分 | 104/104 场景、每版 204 次调用；精确比较退出码、stdout/stderr、全部夹具文件字节、本地 API 状态与写入；无忽略字段 |
| MCP 差分 | 57/57 HTTP 请求；状态码、响应体和委派命令参数一致 |
| Shell 差分 | 269 场景 × Bash、POSIX sh、mksh、BusyBox ash，共 1,076 组一致；另有 32 × 4 个紧凑 JSON 场景通过 |
| kamfw 差分 | 30 场景 × 4 Shell；119 组新旧结果一致，1 组原版 mksh 无限循环显式记录为超时，新版验证预期输出；11 个新增回归和 4 个原有回归均经四 Shell 通过；真实 worker 生命周期通过 |
| WebUI 差分 | 1,140 个解析、连接、统计和告警样例，0 差异 |
| WebUI 检查 | 原版与候选均 346 项通过，类型检查和生产构建通过；最终整合后再次通过 |
| Rust | 候选 801 单元 + 64 集成通过，0 失败，1 个原有压力测试忽略；包括真实 kamfw 加载器的 9 个启动交接测试；Clippy 全目标 `-D warnings` 与格式检查通过 |
| 原版 Rust 环境差异 | 原样运行有 1 个测试依赖宿主 `/sys/class/net/lo` 而失败；明确过滤该环境依赖后 799 单元 + 64 集成通过。候选将该测试改为可控接口探针，同时覆盖存在/缺失分支，生产仍读取真实 sysfs |
| 安装器 Go | 两版分别 55 个顶层测试、含子项 85 个结果通过，race 与候选 vet 通过 |
| 安装器差分 | 19 个离线场景；退出码、输出、文件内容、权限、目录和链接一致，仅归一化最后一行的耗时数字 |
| 安装与包装 | 组件 17、KernelSU 生命周期 10、安装器身份 11 个不同方法通过；归档安全 13 项通过 |
| 产物精确对照 | 48 MiB 合成源包、每版 3 次，11 个产物逐个 SHA-256 一致；0 差异 |
| 包内内容清理 | 检查 9 个 ZIP、88 个条目；移除开发目录，保留运行时普通 `bin/test` 等合法文件；重复清理和失败传播通过 |
| 完整宿主回归 | 候选 108 个不同 manifest 检查全部通过；原版 107 个通过，另 1 个旧迁移夹具失败（3 个用例中 2 个失败），修正后的公共夹具对原版生产代码 3/3 通过 |
| 配方 | Recipkg 0.3.13 的目录检查、递归打包、归档检查和完整中文提示词通过；8 个包、59 份 Markdown；发行控制回归 19 项通过 |

完整宿主回归按 manifest 中的不同检查项统计；遇到缺失工具或发现问题后修复并从中断处继续，不把它描述为单次连续全绿。原版迁移测试因旧夹具截取错误出现 `unexpected fi`；保留该失败记录，并另用同期上游修正后的共同夹具对原版生产代码验证，3 个迁移用例均通过。默认宿主套件不包含另行准备路由资源的 `--with-routing-assets` 扩展测试、真实 netns/Android 数据面或真机流量验证。

原始机器可读结果在 [validation/rewrite-2026-11-06](validation/rewrite-2026-11-06/)；没有将重复执行的测试累加成一个“总通过数量”。安装器 BusyBox 方法首次因 PATH 不含已安装工具而跳过，补齐路径后单独通过，计入上表的 11 个不同方法。

## 最终主线整合

最终生产代码整合点为 `81a60108477d31ca6131f930f955580ad4fa8ba1`。受影响的 fswatch 生命周期、connectivity watchdog 和 supervisor 启动策略 3 个宿主检查重新通过；真实两层锁的启停与并发启动覆盖四种 Shell × 两种 flock 后端共 8 个组合，并验证锁不被后台子进程继承、内层竞争时的启停排序以及外层竞争的有界失败。

诊断导出重新通过 10 个单元与 3 个集成测试，严格 Clippy 和格式检查通过。新增的 supervisors 与 connectivity-watchdog 日志继续使用原有脱敏、输入窗口、章节和报告大小限制；这 13 项属于原有测试子集，不追加到 801 + 64 的完整回归数字。Android 验收脚本的宿主单元套件通过 82 项，包括本轮复核后补充的 PID 最大值与越界拒绝检查；其设备交互均为替身，没有启动 Android、ADB 或实际重启。

锁问题的来源根据固定原版代码核对：MagicNet 外层原本持有 `<name>.lifecycle.lock`，并等待 kamfw 启动；kamfw 内层又打开同一个锁文件等待，构成相互等待。81a601 将外层改为 `<name>.controller.lock`。该来源判断有固定 blob 与调用链证据，未声称额外执行了原版设备复现；新的实际宿主组合测试通过。详细命令、文件摘要、输出与限制分别保存在 `host-validation-results.json`、`rust-final-integration.json`、`android-harness-final-integration.json` 中。

## 性能测量

这些是同一宿主、相同输入的局部对照。结果使用中位数。CLI 取 25 对交替样本，打包交替运行 3 组；kamfw 预热后按原版→候选成对运行 5 组。WebUI 预热 3 次后先完成原版 11 次，再完成候选 11 次；Shell 每组执行 5 次生成，先取原版 3 组，再取候选 3 组。共享机器仍存在调度噪声，不据此宣布稳定尾延迟、Android 吞吐或续航改善。

| 工作负载 | 原版 | 候选 | 可解释的变化 |
| --- | ---: | ---: | --- |
| 5,000 个应用批量设置，完整 CLI 调用 | 274.576 ms | 179.752 ms | 约减少 34.5%；RSS 3,880 → 3,216 KiB |
| 原生 HTTP 模块读取 8 MiB 回环响应 | 16.794 ms | 12.733 ms | 约减少 24.2%；RSS 17,436 → 9,244 KiB，约减少 47.0% |
| WebUI 6,000 行、4,800 个唯一连接解析 | 29.633 ms | 11.982 ms | 约减少 59.6%；保留首次出现顺序 |
| sh 生成 128 个 selector 标签，连续 5 次 | 852.842 ms | 14.549 ms | 一次批处理替代逐项转换 |
| sh 生成 128 个域名规则，连续 5 次 | 1,043.333 ms | 36.316 ms | 结构化批量生成；该项 RSS 1,536 → 2,176 KiB，增加 640 KiB |
| 48 MiB 源包拆分 | 290.363 ms | 308.171 ms | 约增加 17.8 ms；RSS 79,288 → 16,736 KiB，约减少 78.9% |

HTTP 行测量的是两个版本的实际原生 HTTP 模块，在回环夹具中编译执行；它不等于完整 `api proxies` 命令，更不等于代理核心内存。普通 CLI 查询的中位数变化约为零点几毫秒，不宣称普遍提速。WebUI 整个 Node 进程的 RSS 差值只有约 260 KiB，不作有效内存改善结论。

kamfw 的逐项测量包含 40 次加载、300 行翻译、300 次四参数模板、400 文件过滤和 400 文件快照。最新样本见 [kamfw-benchmarks.json](validation/rewrite-2026-11-06/kamfw-benchmarks.json)。框架个别项目的峰值 RSS 同样略增，不能把源码减少换算成内存同比减少。

RSS 明确使用独立被测进程或命令树中单进程峰值，不是所有并发子进程内存之和。CLI/Shell 使用先 exec 再启动被测进程的 C `wait4` 辅助器，排除了 Python 父进程高水位污染。打包统计工作进程自身峰值。JSON 保存汇总统计、采样次数和定义；Shell、kamfw、打包另保存逐次样本。CLI 与 WebUI 的 JSON 只保留汇总结果，未保存每次原始时序。

## 审查发现与已修正的差异

原版缺陷在正确性回归中作为明确修正处理，未混入“逐字一致”的差分数字。详细原版／新版 stdout、状态和文件证据见 [kamfw-defect-evidence.json](validation/rewrite-2026-11-06/kamfw-defect-evidence.json)。

| 原版问题 | 新版行为与证据 |
| --- | --- |
| 嵌套导入登记了错误模块；阶段、日志与属性失败被末尾清理语句覆盖；拒绝确认仍返回成功 | 登记实际模块并传播失败；`test_nested_import_registration`、`test_phase_failure_reaches_caller`、`test_declined_confirmation_returns_failure` |
| 延迟安装忽略显式来源；发布资产占位符失效；归档含多个候选时选择不明确 | 使用指定来源，正确展开 TAG/ARCH；歧义时要求 result-name 并保留当前二进制；`test_schedule_explicit_source`、`test_single_archive_install_and_release_placeholders`、`test_ambiguous_archive_preserves_installed_binary` |
| config 的 stdin 标志跨调用残留，键可包含父路径 | 参数局限在单次调用，路径键保持在配置目录内；`test_config_stdin_does_not_leak_and_paths_stay_local` |
| 缓存摘要掩盖目标损坏；远端摘要获取失败后仍继续 | 检查实际目标内容；取不到请求的摘要时保留已安装文件并报错；`test_corrupted_destination_is_repaired`、`test_failed_hash_fetch_preserves_destination` |
| 架构清理没有删除不兼容库 | 正确清理，同时保留支持架构与 dry-run；`test_architecture_pruning_and_dry_run` |
| 属性回滚重新解释变量或命令字符；重复记录覆盖最早原值 | 按字面恢复并兼容旧记录；`test_property_rollback_is_literal_and_first_value_wins`、`test_existing_rollback_survives_upgrade` |
| 00/000 轮询间隔造成忙循环；watchdog 名称允许父路径 | 拒绝这些非法输入；`test_zero_intervals_never_create_busy_loop` 和真实 worker 检查 |
| mksh 翻译表无限循环；重复输出函数变量名拼错 | 转义字面竖线，重复输出使用真实输入；`i18n_table` 与 `x_repeat` |
| 旧属性区域补丁写入转义文本而非预期二进制 | 临时文件夹具验证字节写入；`legacy_property_blob_fixture`。真实 Android 属性区域布局和运行行为尚未验证 |

内部 Rust `__proc-*` 命令带 `--json` 时，新版统一返回结构化 `machine.unsupported_command`，原版可能直接输出原始文本。这是恢复机器接口合同的有意修正，由 `json_flags_always_route_internal_helpers_to_the_machine_dispatcher` 覆盖，不包含在 104 个逐字一致场景内。

共享 sing-box 生命周期采用原有 MagicNet overlay 的正常停止、信号和三态语义，项目行为保持；单独使用旧版 kamfw 的其他调用方会得到这套共享实现。

交叉审查还发现了本轮重写引入的两个问题，均在交付前修正。第一，Python ZIP 读取器可以接受 CRC 正确但解压长度声明过大的成员；新打包器一度会把错误长度写进清单。现在所有读取路径共用计数迭代器，组件写入、元数据读取和 CLI 别名摘要对照都会核对实际字节数；失败在暂存阶段终止，保留原产物。新增了这三个读取路径的同一反例回归。

第二，fswatch 的优化一度只匹配文件名，漏掉 MagicNet 使用的路径后缀排除项。现在按字面路径后缀匹配，并保留祖先目录排除；MagicNet 同步补齐了本轮新出现的三个暂存文件名。通用 cache_download 里新增的固定下载超时也已撤回，以保留原版慢速、大文件下载语义。 两项问题均保留具体失败记录，未删除原有验收或用跳过掩盖。

## 限制与未执行项

浏览器自动化在启动 Chromium 时被宿主 socket 权限阻止；请求扩大执行权限后，自动审批策略拒绝了该操作。262 个浏览器场景都未进入应用测试，不能计为功能失败，也不能计为通过。已有 346 项 WebUI 单元检查、类型检查和构建成功不能替代触屏、焦点和布局的浏览器实测。生产构建仍有超过 500 kB 的分块提示。

本轮没有部署或重启真实 Android 设备，没有使用私密订阅，没有测真实代理出口、手机 RSS、热点吞吐、电池和长时间稳定性。固定核心源码的获取和宿主夹具通过也不等于新的 Android 完整发行包已构建。版本发布继续遵循项目既有门槛；本轮未创建新 Release。

## 复现入口

以下入口使用仓库外的固定原版工作树。先初始化两版各自锁定的子模块并准备相同工具链，所有测试使用合成临时目录。

```sh
# CLI 与 MCP，先分别构建两版宿主 release 二进制
python3 crates/magicnet-cli/tests/compare-cli.py OLD_CLI NEW_CLI \
  --benchmark-rounds 25 --output cli.json \
  --native-http-sources OLD_SOURCE/crates/magicnet-cli/src/local_http.rs \
  NEW_SOURCE/crates/magicnet-cli/src/local_http.rs
python3 crates/magicnet-cli/tests/compare-mcp.py OLD_CLI NEW_CLI

# Shell（--measure-program 使用 tests/measure-cli.c 编译的辅助器）
python3 scripts/test-shell-parity.py --baseline OLD_SOURCE --report shell.json

# WebUI：从 webui/ 运行
node --experimental-strip-types --import ./test-register.mjs \
  scripts/compare-baseline.mjs OLD_SOURCE/webui

# Go 安装器：两版分别用 GO111MODULE=off go build ./installer/components 构建
python3 scripts/test-installer-parity.py OLD_INSTALLER NEW_INSTALLER
python3 scripts/test-package-parity.py OLD_SOURCE/scripts/package-components.py

# 候选回归
cargo test --workspace --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
GO111MODULE=off go test -race ./installer/components
python3 scripts/test-component-archive-safety.py
bash scripts/test-host.sh
```

框架自己的 `tests/test_contracts.py`、`test_regressions.py`、`test_workers.sh` 和 `benchmark.py` 位于独立 kamfw 仓库。测试与本报告均属于开发树，安装包内的对应排除规则已经验收。
