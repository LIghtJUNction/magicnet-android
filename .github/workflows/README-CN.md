# MagicNet 工作流

代码质量、打包和真实 Android 仿真分别执行。仿真阶段、缓存规则和未覆盖范围见
[Android / KernelSU 仿真说明](../../docs/android-simulation.md)。

## android-kernelsu-acceptance.yml

每个 PR、合并队列、`main` 推送和手动触发都会运行。先执行不缓存成功结果的
测试框架回归，再启动 Android 15 / KernelSU x86_64 AVD。默认使用本地测试配置，
检查真实安装、重启生命周期和普通应用 UID 的 TUN 数据路径。
`Android Simulation Gate` 对失败或未执行的前置任务报错；仓库的必需检查规则
仍需单独配置，不能把新增工作流等同于已经修改分支保护。

原 `init.yml` 已移除，其中 `kam validate`、`kam check`、发布工作流、订阅用量
和产物清理测试已迁入 Android 构建任务，位于打包之前。Code Quality 的 shell lint
继续保留，没有以减少工作流为由删除这些检查。

可复用入口还接收 `source_sha`、`release_version` 和 `release_version_code`。主仓库
发起发行验收时，先验证固定源码 SHA，再于 harness 和 Android 构建前注入同一目标
版本元数据。

## exec.yml

`exec.yml` 在 `main` 推送、PR 和手动触发时构建并验证源码。它只有仓库读取权限，
产物上传到 Actions artifacts。手动设置 `force_tests=true` 会忽略缓存的测试结果；
`release_quality=true` 会执行完整构建质量检查。

可复用接口接收固定的 `source_sha`、`recipe_sha`、目标 `release_version`、
`release_version_code` 和 `release_quality`。工作流检出指定源码提交，在构建工作区
注入目标版本元数据，源码提交本身不变。输出 `artifact_id` 供调用方选取本次构建的
确切产物。

### 构建、验证和发布版本

统一入口是**主仓库 MagicNet** 的
[Build and release MagicNet](https://github.com/LIghtJUNction/MagicNet/actions/workflows/release.yml)。
点击 **Run workflow** 并选择 **main**。版本选择、发行快照、GitHub Release 和稳定更新
索引均由主仓库管理。完整操作与失败恢复方式见
[发布指南](https://github.com/LIghtJUNction/MagicNet/blob/main/docs/releasing.md)。

| `mode` | 结果 |
| --- | --- |
| `build` | 构建、校验安装包并上传 Actions artifacts；默认选项。 |
| `verify` | 进一步执行全部发布质量检查和 Android/KernelSU 验收；不创建 Release。 |
| `publish` | 通过相同门禁后发布 Release；稳定版随后同步稳定更新索引。 |

选择 `bump=patch`、`minor` 或 `major`，以源码声明版本和已公开版本中较新的版本为
基准递增。自定义版本时，选择 `bump=none`，填写 `version=1.9.0` 或 `v1.9.0`。
`bump=none` 且 `version` 留空时，采用源码声明版本。

`version_code` 留空即可自动选择：版本未变时沿用源码 code，版本变化时取源码与
已公开版本中较大的 code 再加一。手动填写时须为 `1..2147483647` 范围内的整数；
发行时必须大于已公开版本的 code。`build/verify` 以主仓库稳定索引作为预览基线；
`publish` 还会查询 GitHub 已公开版本，包括预发布。

`source_ref` 留空时使用主仓库固定的源码 gitlink；填写 `main`、分支、标签或完整 SHA
可选择另一源码版本。工作流先解析并固定为一个提交，构建与 Android 验收使用同一
SHA。所选提交必须包含新版可复用工作流和 `scripts/stamp-release.py`；迁移前的旧
源码提交不具备这个发布接口。

例如，`mode=verify`、`bump=patch`、`source_ref=main` 会完整验证最新源码的下一个
补丁版；将 `mode` 改为 `publish` 即执行发布。`prerelease=true` 仅用于
`mode=publish`，预发布不会修改稳定更新索引。

官方安装包与下载地址统一属于 `LIghtJUNction/MagicNet`。构建产物包含 `update.json`、
记录源码和配方 SHA 的 `build-source.json`，以及经过验证的 `SHA256SUMS` 清单。
发行标签指向主仓库的固定发行快照。已公开的资产不会被覆盖；中断后按发布指南复用
原运行和快照恢复。

### 构建缓存

Go 缓存覆盖依赖下载和编译产物，缓存键包含 Go 版本、NDK、依赖锁文件、
sing-box fork 提交及构建脚本输入。源码变化时恢复兼容的旧缓存，并在 job 成功后
保存新缓存，避免仅用 `go.sum` 导致编译缓存长期停留在首次运行。

Rust 缓存覆盖 registry/git 依赖与 `target/`；模块构建和质量检查使用不同命名空间。
缓存键包含编译器、锁文件/配置、workspace 源码；Android 构建还包含 NDK。
源码或依赖变化时使用恢复前缀复用兼容产物，Cargo 继续检查自身构建指纹。
缓存命中不会直接跳过编译检查。

`cargo-ndk` 固定版本并单独缓存安装目录，精确命中后不再执行 `cargo install`。
补充 Node/npm 与 Bun 下载缓存，覆盖 WebUI 的两种包管理器。测试、类型检查、
打包、校验和及冒烟检查照常执行；这些新增缓存不包含最终发布 ZIP。

setup-kam 只保留 Kam 自身缓存，关闭整个 `~/.rustup` 的恢复，避免旧缓存覆盖
刚安装的 Rust 工具链。发布构建安装 `aarch64-linux-android` target；AVD 任务另行
安装 `x86_64-linux-android`。新缓存命名空间需要首轮填充，实际加速幅度取决于
后续命中情况。

## quality.yml

`quality.yml` 将代码质量检查与打包流程分离：

- Rust：格式检查、警告即错误的 Clippy、完整 workspace 测试；使用锁定依赖并覆盖所有 targets/features。
- Shell：通过 `bash scripts/lint-shell.sh` 检查主机工具和一方设备脚本，包括被 source 的运行时片段；通过 `bash scripts/test-host.sh` 执行 fixture 回归测试。
- WebUI：通过 `npm ci` 安装锁定依赖，再执行测试、`vue-tsc` 组件类型检查和构建；安装 Chromium 后，通过 `npm run test:ui` 检查手机、横屏和桌面布局，以及弹层焦点、键盘避让和草稿保留。浏览器测试使用 fixture，不访问真机。

本地 `scripts/pre-commit.sh` 复用这些入口，并用 `--with-routing-assets` 加跑需要
宿主机 sing-box 和预备规则集的路由/DNS 集成测试。CI 的 fixture 套件不包含这两项；
真机、打包和安装验证仍需单独执行。

## 按需预览与公网观测

重复自动运行的 `webui.yml` 已替换为仅手动触发的 `webui-preview.yml`，仍可导出
源码与预览产物；自动 WebUI 检查统一由 Code Quality 执行。
`network-regression.yml` 的公网观测也改为手动运行；真实 DNS NAT 测试继续保留，
且每次实际发包，不再复用旧的通过结果。

Android 工作流默认 `public_benchmark=false`。手动启用后，公网代理测试在离线
验收之后运行，不能替代生命周期和应用 UID 的验证。安装引导、卸载浏览器、
网络证据和规则发布工作流仍保留各自独有的检查。

## 本地自定义

这里是 MagicNet 的项目配置，不再是未修改的共享基线。执行 `kam sync workflow`
后需要审查差异，避免重新引入已合并的独立校验或重复的自动 WebUI 工作流。
