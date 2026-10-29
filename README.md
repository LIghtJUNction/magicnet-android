# MagicNet v1.8.1 candidate — recipe 0.3.1

这是依据冻结构建提示词重新编写的 Android root 网络模块。候选软件版本为 **v1.8.1 / versionCode 10609**，配方版本为 **0.3.1**；构建 channel 为 `candidate`，实现 commit 单独记录。新实现包含 Go 控制器、订阅与策略事务、原生 WebUI、Android Java bridge、安装器，以及实际 Android arm64 核心和组件安装包。它以固定 sing-box fork 执行网络协议和 TUN/eBPF 数据面，未包装或调用旧 MagicNet 程序。

**交付处于可审查的本地重建状态。宿主测试与 Android 交叉构建已分开记录；没有 Android 真机安装、真实应用流量、热点回程或公网稳定性验收结论。** 详见 [VERIFICATION.md](VERIFICATION.md) 与 [需求矩阵](docs/REQUIREMENTS.md)。独立构建阶段由构建者交付本地结果；候选分支同步由主协调者另行记录。构建者未创建 Release，也未自动操作设备。

## 输入与实现边界

唯一项目需求输入是完整递归 `BUILD_PROMPT.md`：335,805 bytes，8 个配方包，53 个 Markdown 文档，SHA-256 为 `502e160a363ffdc6e60477261ac15b74884b07f37de78af69558b0806f8e717a`。构建负责人完整连续阅读了文件；子任务只获得该输入和本轮接口约定。

首版重建没有读取旧 MagicNet/magicnet-android 实现、旧二进制、旧测试、分析目录或独立验收保留用例，也没有克隆 MagicSingBox 旧模板。后续修复只复用本轮新实现，并读取协调者明确公开的三个失败 probe 和 coverage-audit 报告作为开发回归；这些公开用例不再声称是未见独立验收。冻结输入之后新增的 M40 / 发布工作流没有纳入本轮独立重建，也没有操作相应旧仓库或 CI。隔离采用新上下文和明确的读取约束。各构建者共享文件系统，因此这不是操作系统级强隔离，也不能证明人类意义上的所有历史知识都不存在。

新代码使用 Go 标准库承担 CLI、HTTP/MCP、文件事务、网络请求、加密备份和进程管理；YAML 使用 yaml.v3；实际内核观察使用 cilium/ebpf 与 sagernet/netlink。WebUI 使用无需构建框架的原生 ES modules、HTML 与 CSS。Java bridge 通过 Android 框架反射访问应用标签与 AOSP 网络策略，编译成真实 DEX。固定核心、规则、eCapture、zashboard 的复用版本和许可证列在 [BUILD_NOTES.md](BUILD_NOTES.md)、[assets/THIRD_PARTY.json](assets/THIRD_PARTY.json) 与 `assets/licenses/`。

## 安装物与入口

最终生成物位于 `dist/`：

| 文件 | 用途 |
| --- | --- |
| `MagicNet-full.zip` | 完整离线 Android arm64 模块，包含控制器、核心、55 个规则素材、WebUI、DEX bridge、eCapture 和面板 |
| `MagicNet-core.zip` | 控制器与安装器引导包，按组件清单复用、离线读取或下载其余组件 |
| `MagicNet.zip`、`magicnet_installer.zip` | 与 core 包逐字节相同的兼容文件名，模块 ID 均为 `MagicNet` |
| `MagicNet-component-<id>-<identity>.zip` | 7 个内容寻址组件包，身份由路径、权限、长度和 SHA-256 计算 |
| `components.json` | 固定组件、文件、权限、长度与摘要清单 |
| `SHA256SUMS`、`package-sizes.json` | 发行文件摘要与实际大小 |
| `MagicNet-source.tar.gz` | 本次源码归档，包含实际使用的固定核心源码及许可证；不含工具缓存或运行状态 |
| `SOURCE_FILES.json`、`source-archive.json` | 最终交付 commit、功能二进制 commit、每个源码文件的路径/权限/摘要以及源码归档摘要 |

Android 安装路径固定为 `/data/adb/modules/MagicNet`；管理器升级暂存路径为 `/data/adb/modules_update/MagicNet`。主入口为 `cli` → `bin/magicnet-cli`。安装器仅接受 arm64 包，验证 ZIP 本地/中央目录、清单、模块身份、架构、摘要与权限后分阶段发布。配置迁移只使用 [module/migration.json](module/migration.json) 这一份清单；有效配置按例外备份后重新生成固定策略，显式排除私密 payload 和旧规则资产。

默认规则、核心 cache 和自有 Tailscale 目录使用模块相对路径，core check/run 都以物理模块根为工作目录；管理器从 `modules_update` 提升到 `modules` 后继续有效。旧绝对路径仅在固定资产/自有身份可证明时转换，同步维护 checkpoint 与 LKG，并使用独立恢复日志保护中断和外部修改；自定义外部路径保持原值。

已安装目录的原地覆盖升级会在组件发布前明确拒绝，错误码为 `install.in_place_upgrade_requires_staging`。升级需要管理器提供正常暂存目录；这是已知支持边界，不写成未执行的成功迁移。

本地已构建的 Linux amd64 可执行文件位于 `assets/bin/linux-amd64/`，Android arm64 文件位于 `assets/bin/android-arm64/`。Linux 文件用于控制层与固定核心宿主验证。Android ELF、Go build info 和 DEX 都已检查；Android 文件尚未在设备上执行。

## 从源码构建

需要 Linux amd64 主机、Python 3、Git 和联网获取官方构建输入的能力。脚本将 Go 1.26.10、Temurin 21.0.9+10、D8 8.10.21 以及批准的固定依赖放入项目 `.tools/` / `third_party/`，并核对下载摘要。无需 Android SDK 或 NDK；控制器与核心使用 `CGO_ENABLED=0 GOOS=android GOARCH=arm64`，Java 目标为 API 26 DEX。

```bash
python3 scripts/fetch-build-inputs.py
bash scripts/build.sh all
python3 scripts/write-build-metadata.py
python3 scripts/verify-package.py
```

固定核心源码 revision 为 `871b7a3440cd9c850f1b09ef3b4ada9babb4384b`，构建开启 `with_ebpf`、QUIC、WireGuard、uTLS、Clash API、Tailscale、XHTTP、AWG 等配方要求的 tag。固定规则 revision 为 `f3335f9420d07b8c50b26488df2a9492da6bbb44`。构建脚本验证核心 tree 未修改；不会自动切换到最新依赖或生产默认 TUN stack。

默认编译并发为 `-p=1`，适合本轮 8 GiB 内存环境。可显式设置 `MAGICNET_BUILD_JOBS`、`MAGICNET_GO`、`MAGICNET_JDK` 和 `MAGICNET_SOURCE_REVISION`。Go 模块下载和编译缓存均在项目内部；没有复用旧产品的缓存构建物。

`scripts/build.sh cli` 单独构建新控制器和安装器的两种架构；`cli-linux` 仅构建 Linux 控制器；`core` 构建固定核心；`java` 重编 bridge。`scripts/package.py` 只把明确清单文件放入发行包，检查三个 core 别名摘要相同，并调用实际安装助手验证 core/full 包。

源码归档中的新实现保留在根目录，完整固定核心位于 `third_party_sources/sing-box-871b7a3440cd9c850f1b09ef3b4ada9babb4384b/`，便于直接审阅；构建脚本会从固定来源重新建立 `third_party/sing-box`。归档不包含 Git 历史、工具链或 Go 模块缓存，首次重建需要联网取得相同的锁定输入。`SOURCE_ARCHIVE_INFO.json` 区分最终交付 commit 和二进制功能源码 commit。解压归档不需要 `git init`：新控制器构建显式关闭 VCS 自动发现，从归档描述读取功能 commit，并用 `SOURCE_FILES.json` 核验功能源码集合、权限和摘要；外层目录或继承环境中的其他 Git 仓库不会成为版本来源。显式 `MAGICNET_SOURCE_REVISION` 可覆盖控制器版本标签，来源会单独记录；缺少 Git 和归档描述时普通 CLI 构建标为 `uncommitted`，正式归档构建元数据仍要求有效的描述和清单。仓库内运行 `python3 scripts/archive-source.py` 可在干净的已提交 tree 上重新生成归档和逐文件清单。

## 宿主试用

为避免触碰主机网络，用单独的模块目录放入新产物和规则，只初始化和操作停止态配置。以下是可复现的测试目录准备步骤：

```bash
python3 - <<'PY'
from pathlib import Path
import shutil
r = Path('demo-host').resolve()
(r/'bin').mkdir(parents=True, exist_ok=True)
for n in ('magicnet-cli', 'magicnet-installer', 'sing-box'):
    shutil.copy2(Path('assets/bin/linux-amd64')/n, r/'bin'/n)
shutil.copytree('assets/rules', r/'.config/sing-box/rules', dirs_exist_ok=True)
shutil.copytree('webui', r/'webroot', dirs_exist_ok=True)
shutil.copy2('module/module.prop', r/'module.prop')
print(r)
PY
MAGICNET_ROOT="$PWD/demo-host" ./demo-host/bin/magicnet-cli __install
MAGICNET_ROOT="$PWD/demo-host" ./demo-host/bin/magicnet-cli --json capabilities
MAGICNET_ROOT="$PWD/demo-host" ./demo-host/bin/magicnet-cli serve
```

`serve` 显式开启仅绑定 `127.0.0.1:17890` 的调试 WebUI，并在当前终端打印一次会话链接。它默认关闭，使用随机会话密钥、同源检查和专用请求头。Android WebUI 通过管理器原生桥执行受控 argv；不会启动通用远程 shell。宿主示例没有执行 `service start`，也没有声明主机具备 Android TUN/eBPF、UID 或 OEM 网络策略能力。

## 日常功能

### 服务、状态与恢复

`cli service status|start|ensure|stop|restart` 管理已拥有的核心。`transparent set tun|ebpf` 显式切换数据面。进程身份同时核对 PID、启动时刻、boot ID、可执行文件和命令摘要。生命周期锁对交互启停有 10 秒获取预算，配置写操作通常为 2 秒，周期热点协调使用非阻塞争锁。

状态分别展示进程、控制 API、数据面、配置意图与真实观察。TUN readiness 需要自有核心的 TUN descriptor 证据；eBPF 使用真实 cgroup/TC 程序 ID 与核心持有 descriptor 匹配。没有下游时，hybrid 本机平面和 shared pending 分开报告。停止前保存实际资源身份，停止后验证自有 TUN/BPF 对象消失，无法核验时保留待清理状态。

候选配置先经固定核心 `check`，再记录日志、停止自有进程、替换和验证。独立验证的 last-known-good 提供回滚基线；外部修改不会被静默覆盖。有效配置和规则指纹无变化且运行证据正常时不重启核心。服务停止意图下的配置、订阅、WARP/Tailscale 保存不会自行启动核心。

### 订阅与节点

URL 来源每行一个公网 HTTPS，完整接收 1–5 个唯一来源；本地来源与 URL 来源互斥。所有入口共享 URL 规范化、TLS/DNS 校验、逐跳地址固定、大小限制与来源身份。可读取 sing-box JSON、Clash/Mihomo YAML、分享链接文本及 base64；原生支持配方要求的 VLESS、VMess、Trojan、SS、SOCKS、Hysteria2、AnyTLS、TUIC。无法完整表达的字段组合明确拒绝，不通过丢字段“成功”。

来源下载、转换、缓存、命名去冲突、节点归属、配置、用量和 selector 更新属于同一事务。任一来源不可取得且无已证明同身份的可信缓存，整批保留旧代；同名不同节点保留稳定身份。VLESS `encryption` 包括 `none`、空值和合法长字段完整保留。真实加密服务器握手与语法/core check 是独立验证层。

WebUI 使用私密文件 payload，支持 8 MiB 本地输入；接受后删除 payload。批次状态分开列出当前已保存来源、失败候选、缓存、转换贡献和任务 owner。UI 以本次传输 ID、任务 ID 和 generation 绑定回执，超时后保留仍运行的写操作所有权。周期为 off/12/24/48/72 小时，关闭可取消已拥有的刷新任务，等待阶段由实际 fswatch owner 证明。

### 策略、应用与网络

应用策略支持 proxy/direct/bypass、黑白名单、批量选择和多用户 UID 重新解析。共享 UID 中 bypass 优先，且绕过 DNS 捕获；direct 仍经过数据面。名称 bridge 提供 owner-user 应用标签，包 UID 解析覆盖 Android 用户列表。

Wi-Fi 策略支持 SSID/BSSID、3–300 秒轮询，blacklist 命中 direct，其余 rule；whitelist 相反；关闭恢复 rule。名单读取失败保持 unknown。策略期望和 API 观察的实际 mode 分开返回。

热点根据 Android tethering 证据确认下游，不创建热点或替代 DHCP/NAT。下游 CIDR 连接到 hotspot selector；TUN 使用明确表、规则和 route protocol 的原生 netlink 对象，并在每次变更前写所有权日志、变更后读回。出现或消失的下游可协调；有条件时建立 IPv6 路由。offload 的原值可恢复，外部改动触发冲突。路由存在和真实客户端回程始终分别报告。

持久覆写支持 Merge Patch、`expected_revision`、preview/save/apply/reset；增量分流使用受限结构化出站、组和应用/域名规则，保留系统与订阅的归属边界。WARP 导入 WireGuard；Tailscale 使用 userspace endpoint，暂停不登出，显式本地登出只清理模块拥有的身份。网络设置保留 IPv6、MTU、UDP、DNS profile、捕获端口和 CIDR 的配置与有效状态。

AOSP 网络限制修复采用候选、显式确认、共享 UID 身份、私密 journal 与读回；仅清理审核过的 reject-metered 位并保留其他位。恢复日志保留整份最初 UID/策略基线与逐条 pending/applied/restored 进度。部分失败后的 fresh inspect 只用于确认当前状态，不会以剩余受限 UID 子集覆盖原基线；重试、响应丢失和中断回滚均按完整身份集核验。OEM provider 能力无法证明时返回不可用/unknown，不按品牌猜测成功，也不声称 readback 等于 Google Play 可用。

### WebUI、MCP 与诊断

WebUI 提供 14 个产品页面加独立代理组路由，覆盖概览、来源、节点、分组、路由、应用、Wi-Fi、连接、日志、配置、诊断与工具。中文、英文、俄文以及明暗主题；草稿存内存，跨页保留，私密值不进入浏览器持久存储。终端与管理器菜单保留中、英、俄、日、韩五种语言；停止和更新订阅有默认取消的二次确认。

MCP 默认关闭，绑定 loopback，独立 bearer secret。提供冻结合同的 85 个严格 schema 工具、7 个脱敏资源和 2 个提示词；notification 返回 202 且不执行命令。通用 CLI 工具拒绝敏感 getter、日志和备份导出别名，显式私密工具负责相应边界。

健康状态、DNS 测试、HTTP delay/speed、拓扑、连接关闭、脱敏支持包和私密日志均可用。备份可选密码，密码模式采用 AES-256-GCM 与 PBKDF2-SHA256（600,000 轮）；认证失败零写入，恢复使用私密批量 journal 并保留外部修改冲突。明文备份同样是私密导出，不能当支持包分享。

eCapture 仅在用户显式发起时执行，1–60 秒有界；支持 TLS、GoTLS、NSPR 与 pcap。固定 v2.5.2 的 pcap 映射为 `tls -m pcap`，GoTLS 从已选 PID/UID 的真实 Go executable 取证，最多 16 个当前二进制。进程启动、文件非空和成功捕获是三个不同结果；不会安装 CA 或承诺所有浏览器明文。

### 官方模块更新

`module-update check/install` 使用固定官方稳定 Release API、明确 request ID 与精确版本预期。当前 manager marker、owner、恢复意图和记录日志先于历史成功回执核验；阻断时旧 ID 与新 ID 都不会新建 worker 或覆盖 ledger。健康终态 ID 同意图重放，异意图冲突；后台 worker 继承接受阶段文件锁，调用者退出不会丢失写操作所有权。下载验证 GitHub asset digest、SHA256SUMS、模块清单和架构；真实 root manager 安装后再次核验暂存文件。成功暂存只报告 `reboot_required`，不自动重启。设备和管理器验证未在本轮运行。

## 验证与开发

```bash
GOCACHE="$PWD/.tools/gocache" GOMODCACHE="$PWD/.tools/gomodcache" \
  .tools/go/bin/go test -race -p=1 ./... -count=1
GOCACHE="$PWD/.tools/gocache" GOMODCACHE="$PWD/.tools/gomodcache" \
  .tools/go/bin/go vet ./...
python3 tests/host_network.py
python3 tests/host_control.py
node --test webui/tests/contracts.test.mjs
python3 scripts/verify-package.py
```

浏览器测试使用 Playwright 的独立 Chromium profile，具体路径参数见 [BUILD_NOTES.md](BUILD_NOTES.md)。本轮工具沙箱禁止 loopback listener 和部分 `/proc` 观察，因此这些宿主测试在经自动审批的提升环境中执行；没有因此改变产品的 HTTP/MCP 安全边界。

构建者验证报告分别保留首版和修复版证据，不能用首版的通过结果替代新候选验证。浏览器截图仅作为本地检查记录，未放入受跟踪源码或源码归档。

阅读 [运行时验证](docs/RUNTIME_VERIFICATION.md)、[需求矩阵](docs/REQUIREMENTS.md)、[VERIFICATION.md](VERIFICATION.md) 和公开 JSON 报告，判断每一层真实证据。构建者测试不等于父协调者的独立验收，也不等于 Android 发布或设备部署。
