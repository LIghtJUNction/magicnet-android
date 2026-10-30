# 2026-10-30 sing-box 内核集成验收

当前源码将内核固定到 [`ff669d45e6562a790a49ef066340dbed5df46363`](https://github.com/LIghtJUNction/sing-box/commit/ff669d45e6562a790a49ef066340dbed5df46363)，产品基础版本更新为 `1.15.0-alpha.13`。已完成现有构建助手的 Linux amd64 / Android arm64 构建、产物身份核对，以及 Linux 真实核心的配置和 loopback DNS 检查。Android 设备运行与正式发行仍按独立门槛验收。

## 来源与改动边界

| 对象 | 固定身份 |
| --- | --- |
| 本轮消费仓基线 | `0952cb01b001e41e1074c2e5f4a731a4ad42b222` |
| 原消费内核 | `871b7a3440cd9c850f1b09ef3b4ada9babb4384b` |
| 最终内核 | `ff669d45e6562a790a49ef066340dbed5df46363` |
| 最终内核 tree | `b5e4c5a7559369fa8f46842b0a0fc45c5aa1ca13` |
| 上游 testing | `e5d91fa79f6319d5de940d6c81d81f0fe53b9476`，1.15.0-alpha.13 后的固定提交 |
| 通过源码测试的本地 / canonical 对象 | `9caf2637c42113a40f1302b87ff9525220a0ff54` / `d6316199ef905c8271e58b23dbf52456d2e49dde`，相同 tree `a6b2907483435e507d5090cb5ce00d84899d10f5` |
| 配置仓库 MagicSingBox | `e4ecf47499c35bf25e10d04257a21a4f7975ebad` |

最终内核相对已经通过源码测试的对象只增加或更新 `SPECS/` 下的报告与文本证据。最终两份二进制重新从干净 canonical checkout 构建，显示版本为 `1.15.0-alpha.13+LIghtJUNction.ff669d45e656`；没有把旧产物的本地 SHA 改写成新身份。消费仓保留基线中的订阅、服务交接、PID、日志及最新 UI 改动，本轮只更改内核 gitlink、基础版本和验收材料。

内核同步包含 sing-tun 的 ACK 判定记录及 FIN/RST 会话清理、路由握手失败回调、挂接与关闭重叠时的流注册清理，以及 WireGuard 完整复制源码更新。合并中另修复缓存 DNS 拒绝事件和未启动 WireGuard endpoint 的 pause 处理，保留 AWG、eBPF、VLESS Encryption 与全部生产 tags。具体代码、上游差异与红绿回归见[内核实现报告](https://github.com/LIghtJUNction/sing-box/blob/ff669d45e6562a790a49ef066340dbed5df46363/SPECS/TASKS/051-UPSTREAM_MERGE_235/IMPLEMENTATION_REPORT.md)。

## 实际构建

工具链为 `go1.26.10`，宿主为 Linux amd64。使用本仓库未修改的 `scripts/build-sing-box.sh`，从内核读取 `release/DEFAULT_BUILD_TAGS_OTHERS` 和 `release/LDFLAGS`；保留全部 23 个生产 tags，两个目标均为 `CGO_ENABLED=0`。助手使用 `GOTOOLCHAIN=local`、`GOWORK=off`、`-mod=readonly`、`-trimpath` 和 `-buildvcs=false`。本地编译并行度为 `GOMAXPROCS=2`、`GOFLAGS=-p=2`，不改变产品 GOMEMLIMIT/GOGC。

在消费仓根目录执行，`MAGICNET_SINGBOX_SOURCE_DIR` 指向上述固定提交的干净 checkout，Go 1.26.10 位于 PATH：

```sh
MAGICNET_SINGBOX_SOURCE_DIR=/path/to/clean/sing-box \
  GOMAXPROCS=2 GOFLAGS=-p=2 \
  bash scripts/build-sing-box.sh linux amd64 /tmp/sing-box-linux-amd64
MAGICNET_SINGBOX_SOURCE_DIR=/path/to/clean/sing-box \
  GOMAXPROCS=2 GOFLAGS=-p=2 \
  bash scripts/build-sing-box.sh android arm64 /tmp/sing-box-android-arm64
```

两次实际构建均退出 0。Linux 产物真实执行 `version`；两目标均通过 `go version -m` 核对工具链、完整 tags、CGO、GOOS/GOARCH，并核对 ELF 架构和嵌入的完整显示版本。Android 产物未在宿主或设备执行。

| 产物 | 字节数 | SHA-256 |
| --- | ---: | --- |
| Linux amd64 | 86,528,126 | `8bfcadbf1086abbdcb7d1bd9823bda4cb990a2f0f980975fd84f442ceac91c56` |
| Android arm64 | 88,539,396 | `8f0ae06b16da151dd0cec4b47b130b13d819c786480038a3ec8a272d18d22840` |

大小和摘要用于识别产物，不是运行内存测量。现有 GOMEMLIMIT 分档及用户覆盖、默认 TUN stack、配置和规则 gitlink 继续使用原合同。

## 最终产物检查

[结构化原始记录](validation/sing-box-2026-10-30.json)包含源码/tree、构建命令、两目标 build settings、产物摘要、实际烟测输出与退出状态。记录中的本地路径是此次隔离构建位置；复跑时替换为自己的路径。

```sh
/tmp/sing-box-linux-amd64 version
python3 scripts/test-android-tun-proof.py --check-core /tmp/sing-box-linux-amd64
python3 scripts/test-dns-loopback-listeners.py --core /tmp/sing-box-linux-amd64
```

| 检查 | 实际结果与范围 |
| --- | --- |
| 版本 | `1.15.0-alpha.13+LIghtJUNction.ff669d45e656`，Go 1.26.10，完整 tags，CGO disabled |
| TUN 配置夹具 | 两份合法的 positive / reject-sentinel 配置被真实 `check` 接受，退出 0；后者是含 `action=reject` 的合法配置，不是非法输入 |
| 非法配置负例 | 合成 `{"inbounds":[{"type":"magicnet-invalid-test-inbound"}]}` 由真实 `check` 以 `unknown inbound type` 拒绝，按预期退出 1 |
| DNS 通信 | 真正启动核心，IPv4/IPv6 × TCP/UDP 四组全部通过；只使用 loopback 和合成 DNS 应答，随后清理进程 |

这些检查不创建 TUN 或挂载 eBPF，也不改变宿主路由/防火墙。非法配置使用独立临时文件，检查后删除。

## 源码回归和内存证据

[内核 validation 目录](https://github.com/LIghtJUNction/sing-box/blob/ff669d45e6562a790a49ef066340dbed5df46363/SPECS/TASKS/051-UPSTREAM_MERGE_235/validation)保存最终源码测试日志、具体命令与例外。默认 `./...` 有 47 个 `ok` 包：45 个实际执行测试，2 个在显式排除后为 `[no tests to run]`；另有 111 个包无测试文件。生产 tags 的目标测试集有 22 个实际执行测试包通过、11 个包无测试文件，并非完整 production-tags `./...`。最终 lifecycle race 覆盖 11 个选定测试，`go vet` 与复制 WireGuard 的 vet 通过。

默认测试显式排除 13 个环境不支持的顶层测试：1 个 network namespace、3 个 socket/process 查找、3 个外部 TLS、6 个 raw-socket TLS spoofing；完整名称、原因和 anchored `-skip` 在上述目录 README 中。排除项不算通过。最终 canonical commit 只变更报告，未重复全部源码测试；二进制重建和上述烟测全部在最终 SHA 上实际执行。

固定 sing-tun 旧/新版本的共同测试各运行三次：10,000 条 TCP 流收到 ACK 后，旧判定表保留 10,000 项、新表为 0；该路径 GC 后堆留存从 2,561,072 B 降为 1,441,072 B，减少 1,120,000 B（约 1.07 MiB）。FIN/RST 后真实清扫循环在 31 秒虚拟时间内回收 10,000 个会话，活动和单侧 FIN 控制组保留。原始日志、60 条观测和复跑工具都在内核 validation 目录。该结果只证明对应宿主路径，不推算整核心或 Android RSS 的下降比例。

## 尚未完成的设备与发行门槛

本轮没有完整构建或发行新的 MagicNet Android 模块，没有执行 Android 安装、真实 TUN/eBPF、AWG/WireGuard 对端、pause/wake、网络切换、热点或长期 RSS 测量。现有 v1.8.1 发行与历史设备结果保留原身份。设备验收、官方发布与相应状态升级按既有发布合同单独完成。
