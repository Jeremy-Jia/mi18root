# 一键临时 Root 工具（Windows）

针对 **小米 18 Pro / M610BB / SM8950 / 内核 6.18.21-android17-5-g1d099fcb35e0-abogki540753930-4k**。
走 `CVE-2026-64560`：posix-cpu-timers 悬空 rb_node → 8KB AF_UNIX frag 抢页 → rb_erase 变成写原语 → 改 cred → 加载未签名 KernelSU 模块。

**不写分区、不解 BL、不重启。** 撤销方式就是重启。

---

## 先读这一段：它能省什么、省不掉什么

| 环节 | 典型耗时 | 工具作用 |
|---|---|---|
| 部署 / 抓 KASLR / 推导 slide | ~1.5 min | 全自动 |
| SELinux permissive（2 次落地） | 1–6 min | 自动跑，但**落地率只有 2–3%/次** |
| 打 ko / 推模块 / 建 kprobe / 自检 | ~1 min | 全自动 |
| 候选 + 读 cred + 挑人 | ~1.5 min | 全自动 |
| cred 两阶段写（2 次落地） | 2–10 min | 自动跑，同样受落地率限制 |
| ksud install + 验收 | ~1 min | 全自动 |

**结论：手工 overhead（约 5–8 分钟）能全部省掉，但 5–15 分钟的竞态等待省不掉。**
这不是脚本写得不够快——每次 attempt 固定约 5.2 秒，命中率由内核调度决定。
脚本的价值是：不用人盯着、不会漏步、不会踩已知的坑。

---

## 用法

```powershell
cd C:\Users\jiasa\Documents\Codex\2026-10-15\15-bootloader\work\mi18-temp-root-20261020\tool

# 1) 只检查，不动手机（推荐每次都先跑这个）
.\oneclick-root.ps1 -Preflight

# 2) 全流程
.\oneclick-root.ps1

# 3) 只跑到某个阶段（调试用）
.\oneclick-root.ps1 -Through 3

# 4) 候选更多 / 单轮尝试更多（更稳，但更慢）
.\oneclick-root.ps1 -Candidates 24 -Attempts 300
```

如果提示"无法加载文件，因为在此系统上禁止运行脚本"：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\oneclick-root.ps1
```

---

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-Preflight` | 关 | 只做检查：设备、内核、电量、vmlinux、当前是否已 root |
| `-Through` | 7 | 跑到第几个阶段，1–7 |
| `-ManagerOnly` | 关 | 仅修复已有 Root 的管理器，不进入提权链，也不要求 Python/vmlinux |
| `-ForceManagerRescan` | 关 | 即使内核已识别管理器，仍执行一次受保护的重扫描，供诊断使用 |
| `-SkipManagerFix` | 关 | 跳过新增的管理器步骤 |
| `-Serial` | 单设备自动 | 多设备时必填，绑定目标 adb 设备 |
| `-Attempts` | 200 | 单次 v36/v34 的最大 attempt 数。**落地即停**，所以调大不会变慢，只提高兜底 |
| `-Candidates` | 16 | 候选进程数。候选越多越容易找到 `bit16`(CAP_SYS_MODULE)+`bit7`(CAP_SETUID) |
| `-Retries` | 3 | 每个"落地"阶段整轮重跑的次数 |
| `-MinBattery` | 25 | 低于此电量且未充电则拒绝开始 |
| `-AdbPath` / `-PythonPath` | 自动 | 换机器时指定 |
| `-AllowKernelMismatch` | 关 | 内核版本不匹配时仍然继续（**不建议**，符号偏移会错） |

---

## 它会做什么（7 个阶段）

```
1  抓 sched_blocked_reason → 多锚点推导 KASLR slide（至少 3 个不同锚点一致 + 正向自检）
2  t64560_v36 两步写：清 enforcing → 恢复 initialized（保留 permissive，不是 disabled）
3  code 7 打开 kptr_restrict/dmesg_restrict → dump kallsyms → 打 ko → 建探针 → 任意读自检
4  起 N 个候选 → 从 task+0x908 读 cred → 挑带 CAP_SYS_MODULE 的
5  t64560_v34 两阶段写：cap_bset→0，cap_effective→cred+0x40
6  候选进程自动 finit_module（没等到就 DOLOAD 兜底）→ 校验 /proc/modules
7  ksud install → su -c id 验收 → KernelSU 管理器身份检查/必要时重扫描
```

每一步都有判据，不过就停。关键判据：

- slide：至少 3 个锚点指向同一个值，且观测值减 slide 后有足够多的值落回已知函数
- permissive：`getenforce` 为 Permissive **且** `attr/current` 是 `u:r:shell:s0`（否则判定为 disabled 态，直接停）
- 写原语：`rdx` 读到 `selinux_state = 0x100` 才继续
- 提权：候选进程 `Uid: 0 0 0 0` 且 `CapEff = cred+0x40`

---

## 安全约束（脚本内建，改动前请想清楚）

- **永不调用 `rmmod`**。实测 `rmmod kernelsu` 必然内核 panic 重启，已复现两次。
- **不写 `ro.debuggable`**（会让"开发者选项"闪退）。用 `force_feature=adb_root:1`。
- **不用 `STATE_HEX-7` 的单步 SELinux 写法**。`selinux_state` 前 8 字节是 `avc_latest_notif_update.notif_lock`，会被打坏。
- 检测到设备重启（uptime 变小）立即停止，不会在半新半旧的状态上继续。
- 已 Root 时跳过提权链，仅检查/修复管理器；`-Preflight` 仍只检查。
- 模块已加载但 su 不可用时，拒绝重新写内核或重载模块，需先诊断用户态。
- 多设备必须使用 `-Serial` 指定目标，所有操作绑定同一设备。

---

## 常见报错对照

| 输出 | 含义 / 处理 |
|---|---|
| `内核不匹配` | 目标内核不是已知版本，符号偏移不可信。换对应 `vmlinux.elf` 后再说 |
| `slide 推导失败` | 抓包不够或 perfetto 没工作。重跑；仍失败就手看 `run-*/blocked/bl_text.txt` |
| `SELinux 是 Permissive 但 context 异常` | 被打成 disabled 了（`initialized=0`）。**重启**再重跑 |
| `clearing enforcing 未落地` | 3 轮都没命中，重启后重跑 |
| `没有候选拿到 CAP_SYS_MODULE` | 加大 `-Candidates 24/32`，重跑脚本 |
| `候选进程没能变成 uid=0` | 写歪了。重启后重跑；不要在同一 boot 里反复试 |
| `模块没有加载` + `ENOENT` | 符号补丁和当次 boot 不匹配（slide 变了？） |
| `模块没有加载` + `EINVAL` | vermagic 不匹配 |
| `su 仍然不可用` | ksud install 失败，看 `run-*/` 里的 `rsh.out` |

**出任何问题，最稳的处理都是：重启手机 → 重新跑 `-Preflight` → 再跑全流程。**

---

## KernelSU 管理器识别（2026-10-20 已修复）

旧版“锁 BL + late-load 导致管理器不可能显示”的结论已撤回。弱能力集会令初次读取 `0640` 的 packages.list 失败，但可以在已有模块上重新触发正常身份扫描，无需重载模块或改管理器签名校验。

新增步骤先通过官方 GET_MANAGER_APPID ioctl 查询当前内核身份，并与安装包 UID 对照；不以旧 dmesg 中的加冕日志作为成功证据。已经识别时不改包清单，仅重新打开管理器刷新界面。

需要修复时：私有备份 → 比对原清单内容、inode、属主、权限和标签 → 原子替换内容相同的包清单，产生 FS_MOVED_TO。暂存副本扫描期间使用 0644，扫描返回后立即恢复原文件模式（含 0640），退出清理也会尝试恢复。不长期放宽权限，不加载/卸载模块，不刷分区，不新增开机项。KernelSU 自行校验官方管理器 APK 签名。

```powershell
# 只修复管理器：已有 Root 的用户无需等完整提权链
.\oneclick-root.ps1 -ManagerOnly -Serial 495fb913

# 强制走一次完整重扫描，供诊断；默认已识别则跳过
.\oneclick-root.ps1 -ManagerOnly -ForceManagerRescan -Serial 495fb913
```

新脚本可跨启动使用，会捕获并核对当次 boot_id，不复用旧地址。只读查询工具使用 KernelSU 官方获取驱动 FD 的专用 magic ABI，然后执行 GET_MANAGER_APPID；不会重启设备。源码随包，已编译二进制不需要 NDK。

新增步骤失败返回码 2，表示 Root 已可用而管理器修复未通过，不会为了修复界面重跑漏洞。原有其他失败返回码仍为 1。没安装官方管理器、签名不匹配、包清单并发变化或元数据异常时停止，不自动安装/替换 APK。修复前避免安装/卸载应用。

备份在手机 `/data/local/tmp/mi18-ksu-manager-backup.*`，日志在本机 `out/run-*/manager-fix.txt`。文件内容和原权限恢复，但 inode 必须改变才能发出移动事件。若 PackageManager 后续重建文件导致再次识别失败，可重新运行 ManagerOnly；不声称修复了保存的 ksu_cred 本身。

本次仅实测已有 Root 的快速路径、0640 重扫描、元数据恢复与管理器 UI。未为测试重启手机，不把此前完整提权链当成本次重新验证。详见 `MANAGER-FIX-VERIFICATION.md`。

---

## 目录结构

```
tool/
├── oneclick-root.ps1     主脚本
├── README-ONECLICK.md    本文件
├── lib/
│   ├── check_elf.py      校验 vmlinux.elf 关键符号
│   ├── resolve_slide.py  严格版 slide 推导（多锚点 + 正向自检）
│   └── cands.py          候选解析 / 按能力位挑人
└── device/               推到 /data/local/tmp 执行的设备脚本（全部 LF）
    ├── grab_blocked.sh
    ├── setup_kprobe.sh
    ├── rdx.sh
    ├── cstart.sh
    ├── install_ksu.sh
    ├── fix_ksu_manager.sh  管理器修复（不卸载模块）
    ├── manager_probe      已编译 ARM64 只读 UAPI 查询工具
    └── manager_probe.c    对应源码
```

运行产物在 `../out/run-<时间戳>/`：日志、抓包、kallsyms、逐阶段原始输出。

---

## 关于"安卓版"

设备端目前只做执行，`ksu-patched.ko` 必须由 Windows 端按当次 boot 的 slide 打好再推过去——
因为打补丁需要读 `vmlinux.elf` 的符号表（pyelftools），设备上没有 python。

要做成纯设备端一键，需要额外写一个 aarch64 静态小工具，用 `/proc/kallsyms` 就地改 ko 的 `.symtab`
（`SHN_UNDEF` → `SHN_ABS` + 绝对地址）和 `.modinfo`，逻辑与 `tools/ko_patchsyms.py`、`ko_vermagic.py` 一致。
NDK 编译即可，工作量约 1–2 小时。除非你确实需要"手机插上就能自己跑完"，否则没必要。
