# mi18root

Xiaomi 18 Pro（`M610BB` / `hongkong` / `SM8950`）的临时 Root 与 KernelSU 管理器修复工具。
同一套 Android ARM64 二进制和 PowerShell 流程，可在 **Windows** 与 **macOS（Apple Silicon）** 上运行。

> 仅适配 `hongkong` / 内核 `6.18.21-android17-5-g1d099fcb35e0-abogki540753930-4k`。
> 不要用于 Xiaomi 15 或其他机型；预检会拒绝非 `hongkong` 设备。

## 快速开始

### Windows 10/11

双击 `root-windows.cmd`，或在命令行运行：

```bat
root-windows.cmd -Preflight
root-windows.cmd
root-windows.cmd -ManagerOnly
```

首次运行会自动下载便携 Python 和 Android platform-tools 到 `runtime\win\`。
Windows 10/11 自带的 PowerShell 5.1 即可，不要求预装 Python 或 adb。

### macOS（Apple Silicon）

```sh
./root-macos.command -Preflight
./root-macos.command
./root-macos.command -ManagerOnly
```

首次运行会自动下载 PowerShell 7.6.7、便携 Python 3.12 和 Android platform-tools 到
`runtime/mac/`。不需要 Homebrew Python、不需要系统 pwsh、不需要系统 adb。

### 离线使用

如果不想首次联网下载，请使用 GitHub Releases 中的
`mi18root-portable-win-mac.zip`。解压后目录内已包含 `runtime/mac` 和 `runtime/win`，
Windows/macOS 都可以直接运行，不再需要下载运行时。

## 常用参数

```text
-Preflight            只读预检，不写设备
-ManagerOnly          已有 Root 时只检查/修复 KernelSU 管理器
-ForceManagerRescan   强制触发管理器重扫描
-Serial <adb serial>  指定设备；多台设备时必须提供
-AllowKernelMismatch  仅用于确认过内核布局的调试，不要随意使用
```

完整流程约 5–15 分钟；成功判据是 `adb shell su -c id` 返回 `uid=0`。
入口不会自行重启手机。

## 安全边界

- 不刷写 `boot`/`init_boot`，不解 BL；Root 只在本次启动内有效。
- 不执行 `rmmod kernelsu`（实测会导致内核 panic）。
- 不写 `ro.debuggable`。
- `/data` 中的临时文件和权限不会因重启自动全部还原。
- 只对已匹配设备/内核生效，不把授权扩大到其他手机。

## 目录

```text
root-windows.cmd / root-macos.command   双平台入口
bootstrap/                              首次运行下载运行时（离线包不需要）
tool/                                   PowerShell 主流程、设备脚本、Python 辅助
repo/bin/caplog.jar                     设备端日志工具
repo/ksu/                               vmlinux、ksud、KernelSU 模块源
repo/tools/                             模块补丁脚本
out/bin/                                Android ARM64 漏洞/候选二进制
runtime/                                下载的运行时（git 忽略；离线包内自带）
```

## 已验证环境

- Xiaomi 18 Pro / `hongkong` / `M610BB` / SM8950
- `6.18.21-android17-5-g1d099fcb35e0-abogki540753930-4k`
- 2026-10-20 在临时 KernelSU Root 环境验证提权、模块加载、`su` 验收和管理器识别。

Windows 入口按原始 PowerShell 5.1 流程复用；macOS 入口在 Apple Silicon 上实测预检、
`-ManagerOnly` 和完整设备流程。Windows 端未在本仓库的 CI 上做真机回归。

## 运行时来源

- PowerShell 7.6.7（macOS arm64，微软官方 GitHub Release）
- Python 3.12.15（python-build-standalone，astral-sh）
- Android platform-tools 37.0.1（Google）
- `pyelftools 0.33`、`capstone 5.0.9`

具体 URL/SHA-256 见 `bootstrap/bootstrap-macos.sh` 和 `bootstrap/bootstrap-windows.ps1`。
运行时和 Android 二进制只用于本工具，不包含厂商密钥、固件配置或设备备份。

## License

工具代码与上游来源说明见 `LICENSE`、`LICENSE-NOTICE.md`、`THIRD_PARTY_NOTICES.md`。
`repo/ksu/vmlinux.elf` 等生成物仅用于本机内核符号解析。
