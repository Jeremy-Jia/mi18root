# 管理器修复增补验证 · 2026-10-20

新增功能位于 oneclick-root.ps1 的 Invoke-ManagerFix，以及 device/fix_ksu_manager.sh、manager_probe.c / 已编译 manager_probe。复用的是已成功验证的 packages.list 移动事件方法，未修改提权原语或模块机器码。

## 本轮实测

设备 hongkong，已有 KernelSU 临时 Root，boot_id `ea73cf2c-7938-4a6c-8e56-cff783d8c987`。

1. `-Preflight -ManagerOnly`：只读检查通过；Windows PowerShell 5.1 与当前 PowerShell 均验证。5.1 的 ManagerOnly 路径也通过，修正了 adb 进度 stderr 被当作终止错误的兼容问题。PS1 带 UTF-8 BOM，设备端脚本为 LF、无 BOM。
2. `-ManagerOnly`：只读 ioctl 返回 appid=10319，与官方管理器包 UID 一致。输出 `MANAGER_OK already_recognized=1`，不替换包清单，已执行管理器刷新。
3. `-ManagerOnly -ForceManagerRescan`：实际执行备份与原子替换，输出 `MANAGER_OK rescanned=1 appid=10319 restored_mode=640`。
4. 默认运行：已有 Root 时跳过全部提权阶段，约 2–3 秒完成管理器身份检查和刷新。没有推送漏洞二进制、重新写 cred 或重新加载模块。
5. 非 Root 执行返回 ROOT_REQUIRED，错误 boot_id 返回 BOOT_CHANGED，均在修改包清单之前停止。

重扫描前后的内容 SHA-256：

```
62a11ca4ffd66f4dd7fac0d4542ee2197f5c7033121b288c7b00673704509781
```

前后元数据：`1000:1032:640:74457`，SELinux 标签 `u:object_r:packages_list_file:s0`。更换 inode 是触发移动事件所需；未改文件内容，0644 只用于扫描时的暂存副本，完成后恢复 0640。

设备备份：`/data/local/tmp/mi18-ksu-manager-backup.tnB4YI`。本机原始日志：`out/run-20261020-181154`、`out/run-20261020-181301`、`out/run-20261020-181350`、`out/run-20261020-181611`。

boot_id 未变，模块仍为 `kernelsu 192512 1 - Live 0xffffffdacaef8000`。UID 0 的 su 保持可用。没有重启、刷分区、重载模块、新增开机项或更改 Pulse 温控配置。

## 验收依据与边界

成功以当前 GET_MANAGER_APPID ioctl 与包 UID 匹配为准，不依赖旧 dmesg 的 Crowning 日志。未改变官方 APK 签名校验，也未改 ksu_cred；若以后自动扫描再次失败，可重复运行 ManagerOnly。

本轮设备接手时已经识别管理器，因此没有人为撤销管理器身份来重现第一次加冕，也未为了验证重启手机重跑整条漏洞链。首次未识别→成功的早先证据见 `../manager-debug/MANAGER-FIX-20261020.txt`；本轮新增步骤验证了已识别快速路径、实际 0640 重扫描及权限恢复。

只读探针使用官方 KernelSU UAPI 的驱动 FD 获取 magic，随后只执行 GET_MANAGER_APPID。专用 magic 与 Linux 真正重启 magic 不同，不会重启设备。基于 vendor/KernelSU 提交 `0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d` 的接口。ARM64 静态探针 SHA-256：`55f60973b52a2479f122bac1061148762c0a5e0e86abdd0471948c9f5b3c70d2`。

需要重新构建探针时（NDK r29）：

```text
clang --target=aarch64-linux-android26 -O2 -Wall -Wextra -static device/manager_probe.c -o device/manager_probe
```

原始提权阶段保留 Deepseek 实现；本次更新不声称已经重新审计或从无 Root 状态完整复测它。
