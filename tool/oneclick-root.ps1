#Requires -Version 5.1
<#
  oneclick-root.ps1 —— 小米 18 Pro (M610BB / SM8950) / CVE-2026-64560 一键临时 root

  做什么
    按顺序自动执行：部署 → 抓 KASLR → SELinux permissive → kprobe 任意读 →
    起候选挑 cred → cred 两阶段写 → 加载 KernelSU → ksud install → 验收 su → 管理器识别修复。

  不做什么（硬约束）
    * 不刷写 boot/init_boot 等启动分区、不解 BL、不自行重启设备
    * 永不调用 rmmod（实测必崩，已排除）
    * 不写 ro.debuggable（会让开发者选项闪退）
    * 任一步判据不过就停，不自动重试已成功的阶段

  用法
    .\oneclick-root.ps1                 # 全流程
    .\oneclick-root.ps1 -Preflight      # 只做检查，不动设备
    .\oneclick-root.ps1 -Through 3      # 只跑到阶段 3
    .\oneclick-root.ps1 -Attempts 200   # 单次运行的最大尝试次数（更稳但更慢）

  耗时预期
    固定开销约 3 分钟；其余取决于竞态落地率（每次 attempt 约 5.2 秒，命中率 2~3%）。
    实测整链 5~15 分钟属正常，本脚本不能把这段时间压缩掉，只能省掉人工。
#>
[CmdletBinding()]
param(
    # 只做预检，不动设备
    [switch]$Preflight,
    # 仅检查/修复管理器，要求已有 Root；不进入提权阶段
    [switch]$ManagerOnly,
    [switch]$ForceManagerRescan,
    [switch]$SkipManagerFix,
    [string]$Serial,
    # 跑到第几个阶段（1..7），默认全部
    [int]$Through = 7,
    # 单次 v36/v34 运行的最大 attempt 数（落地即停，所以调大不会变慢，只提高兜底上限）
    [int]$Attempts = 200,
    # 候选进程数量；越多越容易找到 bit16+bit7 的
    [int]$Candidates = 16,
    # 每个"落地"阶段的重新运行次数
    [int]$Retries = 3,
    # 电量低于此值给出警告
    [int]$MinBattery = 25,
    [string]$AdbPath,
    [string]$PythonPath,
    [string]$ExpectedKernel = '6.18.21-android17-5-g1d099fcb35e0-abogki540753930-4k',
    [switch]$AllowKernelMismatch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# ---------------------------------------------------------------- 路径与全局

$script:Tool = $PSScriptRoot
$script:Proj = Split-Path -Parent $script:Tool
$script:Repo = Join-Path $script:Proj 'repo'
$script:Out = Join-Path $script:Proj 'out'
$script:Vmlinux = Join-Path $script:Repo 'ksu\vmlinux.elf'
$script:BinDir = Join-Path $script:Out 'bin'
$script:DevDir = Join-Path $script:Tool 'device'
$script:LibDir = Join-Path $script:Tool 'lib'

$script:Adb = if ($AdbPath) { $AdbPath } else {
    $found = Get-Command adb -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $found.Source } else { 'C:\Users\jiasa\Documents\Codex\2026-10-15\15-bootloader\work\android-tools\platform-tools\adb.exe' }
}
$script:Py = if ($PythonPath) { $PythonPath } else {
    $found = Get-Command python3 -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $found) { $found = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if ($found) { $found.Source } else { 'C:\Users\jiasa\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' }
}

$script:RunDir = Join-Path $script:Out ("run-{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmssfff'), $PID)
$script:LogFile = Join-Path $script:RunDir 'oneclick.log'
$script:Slide = $null
$script:Selinux = $null
$script:Chosen = $null
$script:Uptime0 = $null
$script:BootId0 = $null
$script:TmpMode0 = $null
$script:AlreadyRoot = $false
$script:ModuleLoaded = $false
$script:AdbTarget = @()

function Log {
    param([string]$Msg, [string]$Color = 'Gray')
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Msg
    Write-Host $line -ForegroundColor $Color
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 } catch { }
}

function Die {
    param([string]$Msg)
    Log "✗ $Msg" Red
    Log "已停止。重启会清除临时内核状态；已写入 /data 的文件与权限不保证自动还原。" Yellow
    exit 1
}

function HexToU64([string]$h) {
    return [Convert]::ToUInt64(($h -replace '^0[xX]', ''), 16)
}

# ---------------------------------------------------------------- adb 封装

function Sh {
    param([string]$Cmd)
    # Windows PowerShell 5.1 wraps native stderr (including adb progress) as
    # ErrorRecords. Capture it and use the exit code instead of terminating.
    $ErrorActionPreference = 'Continue'
    $out = & $script:Adb @script:AdbTarget shell $Cmd 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Lines = @($out); Text = (@($out) -join "`n") }
}

function AdbOk {
    param([string[]]$ArgList)
    $ErrorActionPreference = 'Continue'
    $out = & $script:Adb @script:AdbTarget @ArgList 2>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Lines = @($out); Text = (@($out) -join "`n") }
}

# 长时间运行的设备命令：逐行流式输出，只打印关键行，避免看起来像卡死
function Invoke-DeviceLong {
    param([string]$Cmd, [string]$Tag)
    $ErrorActionPreference = 'Continue'
    $log = Join-Path $script:RunDir "$Tag.out.txt"
    $lastBeat = Get-Date
    & $script:Adb @script:AdbTarget shell $Cmd 2>&1 | ForEach-Object {
        $line = [string]$_
        try { Add-Content -Path $log -Value $line -Encoding UTF8 } catch { }
        if ($line -match 'LEAK|STEP_OK|STEP_FAIL|phase[12] |phase1 start|phase2 start|landed=[1-9]|phase[12] landed') {
            $c = if ($line -match 'STEP_OK|landed|LEAK') { 'Green' } else { 'DarkGray' }
            Log "    $line" $c
            $lastBeat = Get-Date
        }
        elseif ($line -match 'attempt=(\d+)') {
            $a = [int]$Matches[1]
            if ($a % 20 -eq 0) { Log "    ...第 $a 次尝试（每次约 5 秒）" DarkGray; $lastBeat = Get-Date }
        }
        if (((Get-Date) - $lastBeat).TotalSeconds -ge 45) {
            Log "    ...仍在运行" DarkGray
            $lastBeat = Get-Date
        }
    }
    return $LASTEXITCODE
}

function Get-Uptime {
    $r = Sh 'cat /proc/uptime'
    if ($r.Text -match '^\s*([0-9.]+)') { return [double]$Matches[1] }
    return -1
}

function Assert-NoReboot {
    $boot = (Sh 'cat /proc/sys/kernel/random/boot_id').Text.Trim()
    if ($script:BootId0 -and $boot -ne $script:BootId0) {
        Die "设备启动 ID 已改变，拒绝复用上一启动的地址或候选进程。"
    }
    $now = Get-Uptime
    if ($now -lt 0) { Die "设备失联（adb 读不到 uptime）。可能是内核 panic 后重启中，稍等再运行。" }
    if ($null -ne $script:Uptime0 -and $now -lt ($script:Uptime0 - 5)) {
        Die ("检测到设备重启（uptime {0:N0}s < 开始时 {1:N0}s）。临时状态已全部丢失，请重新运行本脚本。" -f $now, $script:Uptime0)
    }
    return $now
}

# ---------------------------------------------------------------- 部署

function Push-Text {
    param([string]$Local, [string]$Remote)
    if (-not (Test-Path $Local)) { Die "缺少本地文件：$Local" }
    # 统一转 LF：CRLF 会让设备端 sh 报 syntax error
    $txt = [IO.File]::ReadAllText($Local) -replace "`r`n", "`n"
    $tmp = Join-Path $script:RunDir ("normalized-" + [IO.Path]::GetFileName($Local))
    [IO.File]::WriteAllText($tmp, $txt, (New-Object Text.UTF8Encoding($false)))
    $r = AdbOk @('push', $tmp, $Remote)
    if ($r.Code -ne 0) { Die "推送到 $Remote 失败：$($r.Text)" }
}

function Deploy-All {
    Log "部署阶段文件到 /data/local/tmp" Cyan

    $bins = 't64560_v33', 't64560_v34', 't64560_v36', 'forker', 'setname',
            'kprobe_probe', 'coredump', 'filter_spray'
    foreach ($b in $bins) {
        $p = Join-Path $script:BinDir $b
        if (-not (Test-Path $p)) { Die "缺少二进制 $p（先用 NDK 编译 src）" }
        $r = AdbOk @('push', $p, "/data/local/tmp/$b")
        if ($r.Code -ne 0) { Die "推送 $b 失败：$($r.Text)" }
    }

    $scripts = 'grab_blocked.sh', 'setup_kprobe.sh', 'rdx.sh', 'cstart.sh', 'install_ksu.sh'
    foreach ($s in $scripts) { Push-Text (Join-Path $script:DevDir $s) "/data/local/tmp/$s" }

    $jar = Join-Path $script:Repo 'bin\caplog.jar'
    if (-not (Test-Path $jar)) { Die "缺少 caplog.jar：$jar" }
    AdbOk @('push', $jar, '/data/local/tmp/caplog.jar') | Out-Null

    $ksud = Join-Path $script:Repo 'ksu\ksud.arm64'
    if (-not (Test-Path $ksud)) { Die "缺少 ksud：$ksud" }
    AdbOk @('push', $ksud, '/data/local/tmp/ksud') | Out-Null

    $r = Sh ('chmod 755 ' + (@($bins | ForEach-Object { "/data/local/tmp/$_" }) -join ' ') +
             ' /data/local/tmp/ksud ' + (@($scripts | ForEach-Object { "/data/local/tmp/$_" }) -join ' ') + ' 2>&1')
    Sh 'chmod 644 /data/local/tmp/caplog.jar' | Out-Null
    # 候选进程拿到 uid=0 后没有 CAP_DAC_OVERRIDE，写不了 0771 的目录；先放宽
    Sh 'chmod 777 /data/local/tmp' | Out-Null

    $chk = Sh 'ls /data/local/tmp/t64560_v36 /data/local/tmp/rdx.sh /data/local/tmp/caplog.jar 2>&1'
    if ($chk.Text -match 'No such file') { Die "部署校验失败：`n$($chk.Text)" }
    Log "  部署完成" DarkGray
}

# ---------------------------------------------------------------- 预检

function Invoke-Preflight {
    Log "== 预检 ==" Cyan

    if (-not (Test-Path $script:Adb)) { Die "找不到 adb：$($script:Adb)" }

    $dev = AdbOk @('devices')
    $devices = @($dev.Lines | Where-Object { $_ -match '\sdevice\s*$' })
    if ($devices.Count -eq 0) { Die "没有已授权的设备。检查 USB 调试授权。" }
    $ids = @($devices | ForEach-Object { ([string]$_ -split '\s+')[0] })
    if ($Serial) { if ($ids -notcontains $Serial) { Die "指定设备 $Serial 未连接或未授权" }; $selected = $Serial }
    elseif ($ids.Count -eq 1) { $selected = $ids[0] }
    else { Die "检测到多台设备，请用 -Serial 指定目标，拒绝自动选第一台" }
    $script:AdbTarget = @('-s', $selected)
    $script:SelectedSerial = $selected
    Log "  设备：$selected" DarkGray

    $st = Sh 'getprop ro.product.device; getprop ro.build.display.id; uname -r; getenforce; id -u; cat /proc/uptime'
    $l = @($st.Lines)
    if ($l.Count -lt 6) { Die "读取设备信息失败：`n$($st.Text)" }
    $script:Uptime0 = [double]($l[5] -split '\s+')[0]
    $script:BootId0 = (Sh 'cat /proc/sys/kernel/random/boot_id').Text.Trim()
    if ($script:BootId0 -notmatch '^[a-f0-9-]{36}$') { Die "无法读取有效启动 ID，拒绝继续。" }
    $script:TmpMode0 = (Sh 'stat -c %a /data/local/tmp').Text.Trim()
    if ($script:TmpMode0 -notmatch '^[0-7]{3,4}$') { Die "无法记录临时目录原权限，拒绝继续。" }

    Log "  device   = $($l[0])"
    Log "  system   = $($l[1])"
    Log "  kernel   = $($l[2])"
    Log "  selinux  = $($l[3])   uid=$($l[4])"
    if ($l[0].Trim() -ne 'hongkong') { Die "此工具仅适配 hongkong，拒绝操作 $($l[0])" }
    if ($l[2].Trim() -ne $ExpectedKernel -and -not $AllowKernelMismatch) {
        Die ("内核不匹配：`n  期望 $ExpectedKernel`n  实际 $($l[2])`n符号偏移与结构布局都可能不同，拒绝继续。确认要试请加 -AllowKernelMismatch。")
    }

    $bat = Sh 'dumpsys battery'
    $lvl = if ($bat.Text -match 'level:\s*(\d+)') { [int]$Matches[1] } else { -1 }
    $sta = if ($bat.Text -match 'status:\s*(\d+)') { [int]$Matches[1] } else { -1 }
    $charging = ($sta -eq 2)
    $chgTxt = if ($charging) { '充电中' } else { '未充电' }
    Log "  电量     = ${lvl}% ($chgTxt)"
    if ($lvl -ge 0 -and $lvl -lt $MinBattery -and -not $charging) {
        Die "电量 $lvl% 太低且未充电。写内核内存期间掉电会让设备进不确定状态，请先充电。"
    }

    $mod = Sh 'grep kernelsu /proc/modules'
    $su = Sh 'ls /system/bin/su 2>&1'
    if (-not $mod.Text.StartsWith('kernelsu')) {
        Log "  当前状态：未 root（无 kernelsu 模块）" Yellow
    } else {
        $script:ModuleLoaded = $true
        Log "  当前状态：kernelsu 已加载" Yellow
        $t = Sh 'su -c id'
        if ($t.Text -match 'uid=0') {
            Log "  su 已可用：$($t.Text.Trim())" Green
            $script:AlreadyRoot = $true
            Log "  已有 Root：跳过提权链，接下来只处理管理器识别（-Preflight 除外）。" Green
        } else {
            Log "  模块在但 su 不可用：$($su.Text.Trim())" Yellow
        }
    }

    if ($ManagerOnly -and -not $script:AlreadyRoot) { Die "-ManagerOnly 需要已有可用 Root；未运行任何提权阶段" }
    if (-not $script:AlreadyRoot -and -not $ManagerOnly) {
        if (-not (Test-Path $script:Py)) { Die "找不到 python：$($script:Py)" }
        $deps = & $script:Py -c 'import elftools, capstone' 2>&1
        if ($LASTEXITCODE -ne 0) { Die "Python 依赖不完整，需要 pyelftools 和 capstone：`n$($deps -join "`n")" }
        if (-not (Test-Path $script:Vmlinux)) { Die "缺少 vmlinux.elf：$($script:Vmlinux)" }
        $chk = & $script:Py (Join-Path $script:LibDir 'check_elf.py') $script:Vmlinux 2>&1
        if ($LASTEXITCODE -ne 0) { Die "vmlinux.elf 校验失败：`n$($chk -join "`n")" }
        Log "  vmlinux  = $($chk -join ' ')" DarkGray
    }

    New-Item -ItemType Directory -Force -Path $script:RunDir | Out-Null
    Log "本次运行日志：$script:LogFile" DarkGray
}

# ---------------------------------------------------------------- 阶段 1

function Stage-Slide {
    if ($script:Slide) { return }
    Assert-NoReboot | Out-Null
    Log "== 阶段 1：抓 sched_blocked_reason，推导本次启动的 KASLR slide ==" Cyan

    Log "  抓取中（约 40 秒，期间会跑 300 轮 forker 制造阻塞）" DarkGray
    $grab = Sh 'sh /data/local/tmp/grab_blocked.sh'
    if ($grab.Code -ne 0) { Die "抓取失败：`n$($grab.Text)" }
    Assert-NoReboot | Out-Null

    $dir = Join-Path $script:RunDir 'blocked'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    AdbOk @('pull', '/data/local/tmp/bl_text.txt', (Join-Path $dir 'bl_text.txt')) | Out-Null
    foreach ($c in 0..7) {
        AdbOk @('pull', "/data/local/tmp/bl_$c.bin", (Join-Path $dir "bl_$c.bin")) | Out-Null
    }
    $bytes = (Get-ChildItem $dir -File | Measure-Object -Property Length -Sum).Sum
    Log ("  抓包 {0:N1} MB" -f ($bytes / 1MB)) DarkGray
    if ($bytes -lt 1MB) { Die "抓包太小（$bytes 字节），perfetto 可能没工作。检查 /data/local/tmp/bl_text.txt。" }

    $res = & $script:Py (Join-Path $script:LibDir 'resolve_slide.py') $dir --vmlinux $script:Vmlinux 2>&1
    if ($LASTEXITCODE -ne 0) {
        Die ("slide 推导失败（拒绝用不确定的 slide 继续）：`n" + ($res -join "`n"))
    }
    foreach ($line in $res) {
        if ($line -match '^SLIDE=(0x[0-9a-fA-F]+)') { $script:Slide = HexToU64 $Matches[1] }
        if ($line -match '^SELINUX_STATE=(0x[0-9a-fA-F]+)') { $script:Selinux = HexToU64 $Matches[1] }
        if ($line -match '^(ANCHORS=.*)$') { Log "  $($Matches[1])" Green }
    }
    if (-not $script:Slide -or -not $script:Selinux) { Die "解析 slide 输出失败：`n$($res -join "`n")" }
    Log ("  slide = 0x{0:x}" -f $script:Slide) Green

    $kc = Sh ('grep -E " (selinux_state|_text)$" /proc/kallsyms')
    $kcFlat = ($kc.Text.Trim() -replace "`n", ' | ')
    Log "  设备端符号（稍后用于交叉验证）：$kcFlat" DarkGray
}

# ---------------------------------------------------------------- 阶段 2

function Test-Permissive {
    $r = Sh 'getenforce; cat /proc/self/attr/current'
    $lines = @($r.Lines)
    $enf = ($lines[0] -as [string]).Trim()
    $ctx = ($lines[1] -as [string]).Trim()
    return [pscustomobject]@{ Enforcing = $enf; Context = $ctx; Ok = ($enf -eq 'Permissive' -and $ctx -like 'u:r:shell:*') }
}

function Run-V36 {
    param([int]$Pc, [UInt64]$Target)
    $hex = '0x{0:x}' -f $Target
    for ($i = 1; $i -le $Retries; $i++) {
        Log ("  t64560_v36 pc={0} target={1}（第 {2}/{3} 轮，每轮最多 {4} attempts）" -f $Pc, $hex, $i, $Retries, $Attempts)
        $code = Invoke-DeviceLong "/data/local/tmp/t64560_v36 $Pc $hex $Attempts 400 16 6000 12000 4500" "v36-pc$Pc-$i"
        $log = Join-Path $script:RunDir "v36-pc$Pc-$i.out.txt"
        if ((Test-Path $log) -and ((Get-Content -Raw $log) -match 'STEP_OK')) { return $true }
        Log "    本轮未落地" Yellow
        Assert-NoReboot | Out-Null
    }
    return $false
}

function Stage-Permissive {
    Assert-NoReboot | Out-Null
    $cur = Test-Permissive
    if ($cur.Ok) { Log "== 阶段 2：SELinux 已是 permissive，跳过 ==" Cyan; return }
    if ($cur.Enforcing -eq 'Permissive' -and -not $cur.Ok) {
        Die ("SELinux 是 Permissive 但 context 异常（$($cur.Context)），说明 initialized=0 的 disabled 态。`n" +
             "这是被打成 disabled 了，App/zygote 会坏。请重启设备后重跑，不要在此状态继续。")
    }
    Log "== 阶段 2：SELinux → permissive（两步写，保留 initialized=1）==" Cyan

    if (-not (Run-V36 0 $script:Selinux)) { Die "clearing enforcing 未落地（$Retries 轮都没命中）" }
    Assert-NoReboot | Out-Null
    $mid = Test-Permissive
    Log "  第一步后：enforce=$($mid.Enforcing) ctx=$($mid.Context)" DarkGray
    if ($mid.Enforcing -ne 'Permissive') { Die "写入了但 getenforce 不是 Permissive，停止。" }

    if (-not (Run-V36 1 ($script:Selinux + 1))) { Die "恢复 initialized 未落地（$Retries 轮都没命中）" }
    Assert-NoReboot | Out-Null

    $fin = Test-Permissive
    if (-not $fin.Ok) { Die "两步写完但状态不对：enforce=$($fin.Enforcing) ctx=$($fin.Context)" }
    $pv = Sh 'cat /sys/fs/selinux/policyvers'
    Log "  ✓ permissive：ctx=$($fin.Context) policyvers=$($pv.Text.Trim())" Green
}

# ---------------------------------------------------------------- 阶段 3

function Stage-Kprobe {
    Assert-NoReboot | Out-Null
    Log "== 阶段 3：打开符号通道、建 kprobe、校验任意读 ==" Cyan

    $cap = 'CLASSPATH=/data/local/tmp/caplog.jar app_process64 /system/bin CapLog miui.mqsas.IMQSNative 7'
    Sh "$cap /proc/sys/kernel/kptr_restrict '0'" | Out-Null
    Sh "$cap /proc/sys/kernel/dmesg_restrict '0'" | Out-Null

    $ks = Join-Path $script:RunDir 'kallsyms_device.txt'
    & $script:Adb @script:AdbTarget exec-out cat /proc/kallsyms | Set-Content -Path $ks -Encoding Ascii
    $n = (Get-Content $ks | Measure-Object -Line).Lines
    Log "  /proc/kallsyms 行数 = $n" DarkGray
    if ($n -lt 1000) { Die "kallsyms 读不到（$n 行），kptr_restrict 没生效。" }

    $verify = & $script:Py (Join-Path $script:LibDir 'verify_live_symbols.py') $script:Vmlinux $ks ('0x{0:x}' -f $script:Slide) ('0x{0:x}' -f $script:Selinux) 2>&1
    if ($LASTEXITCODE -ne 0) { Die "四个关键符号与当前启动不一致，拒绝加载模块：`n$($verify -join "`n")" }
    Log "  ✓ _text / selinux_state / __set_task_comm / init_cred 均通过数值比对" Green

    Log "  打补丁：vermagic → noenforce → patchsyms" DarkGray
    $ko = Join-Path $script:RunDir 'ko'
    New-Item -ItemType Directory -Force -Path $ko | Out-Null
    $base = Join-Path $script:Repo 'ksu\ksu-v3.3.1-a17-6.18.ko'
    if (-not (Test-Path $base)) { Die "缺少基础模块：$base" }

    $steps = @(
        @('ko_vermagic.py',      @($base, (Join-Path $ko 'step1-v.ko'))),
        @('ko_patch_noenforce.py', @((Join-Path $ko 'step1-v.ko'), (Join-Path $ko 'step2-n.ko'))),
        @('ko_patchsyms.py',     @((Join-Path $ko 'step2-n.ko'), (Join-Path $ko 'ksu-patched.ko'), $ks))
    )
    foreach ($s in $steps) {
        $script = Join-Path $script:Repo "tools\$($s[0])"
        $outTxt = & $script:Py $script @($s[1]) 2>&1
        if ($LASTEXITCODE -ne 0) { Die "补丁失败 $($s[0])：`n$($outTxt -join "`n")" }
        if (($outTxt -join "`n") -match 'STILL MISSING') { Die "符号补丁有遗漏：`n$($outTxt -join "`n")" }
        Log "    $($s[0]) ok" DarkGray
    }
    $patched = Join-Path $ko 'ksu-patched.ko'
    AdbOk @('push', $patched, '/data/local/tmp/ksu-patched.ko') | Out-Null
    Sh 'chmod 644 /data/local/tmp/ksu-patched.ko' | Out-Null

    $setup = Sh 'sh /data/local/tmp/setup_kprobe.sh'
    foreach ($ln in $setup.Lines) { if ($ln -match 'add_rc|enable=|tracing_on') { Log "    $ln" DarkGray } }
    if ($setup.Text -notmatch 'enable=1') { Die "探针没启用：`n$($setup.Text)" }

    $probe = '0x{0:x}' -f $script:Selinux
    $rd = Sh "sh /data/local/tmp/rdx.sh -q $probe"
    if ($rd.Text -notmatch 'v0=(0x[0-9a-f]+)') { Die "任意读失败：`n$($rd.Text)" }
    $val = $Matches[1]
    if ((HexToU64 $val) -ne 0x100) {
        Die ("selinux_state 读到 $val，期望 0x100（enforcing=0, initialized=1）。`n" +
             "说明写原语落点或 SELinux 状态不对，不要继续。")
    }
    Log "  ✓ 任意读正常：selinux_state = 0x100（enforcing=0, initialized=1）" Green
}

# ---------------------------------------------------------------- 阶段 4

function Stage-Candidates {
    Assert-NoReboot | Out-Null
    Log "== 阶段 4：起候选、读 cred、挑 bit16（CAP_SYS_MODULE）==" Cyan

    Sh 'rm -f /data/local/tmp/DOLOAD /data/local/tmp/NOLOAD /data/local/tmp/ROOTED /data/local/tmp/KSU_RESULT /data/local/tmp/rsh.out /data/local/tmp/CMD' | Out-Null
    $start = Sh "sh /data/local/tmp/cstart.sh $Candidates KC"
    $alive = if ($start.Text -match 'alive=(\d+)') { [int]$Matches[1] } else { 0 }
    Log "  候选存活 = $alive" DarkGray
    if ($alive -lt 4) { Die "候选进程起不来（alive=$alive）：`n$($start.Text)" }

    $trace = Join-Path $script:RunDir 'trace.txt'
    & $script:Adb @script:AdbTarget exec-out cat /sys/kernel/tracing/trace | Set-Content -Path $trace -Encoding Ascii

    $candsJson = Join-Path $script:RunDir 'cands.json'
    $addrStr = & $script:Py (Join-Path $script:LibDir 'cands.py') list $trace $candsJson KC
    if ($LASTEXITCODE -ne 0 -or -not $addrStr) { Die "解析候选 task 地址失败：`n$($addrStr -join "`n")" }
    $addrCount = @($addrStr -split '\s+' | Where-Object { $_ }).Count
    Log "  解析到 $addrCount 个候选" DarkGray

    $rd = Sh "sh /data/local/tmp/rdx.sh -q $addrStr"
    $creds = @([regex]::Matches($rd.Text, 'v\d+=(0x[0-9a-f]+)') | ForEach-Object { $_.Groups[1].Value })
    if ($creds.Count -ne $addrCount) { Die "读取 cred 数量不符（$($creds.Count)/$addrCount）：`n$($rd.Text)" }

    $pick = & $script:Py (Join-Path $script:LibDir 'cands.py') pick $candsJson @creds 2>&1
    $pickTxt = $pick -join "`n"
    foreach ($ln in $pick) { if ($ln -match '^KC|^CHOSEN|^CAPS') { Log "    $ln" $(if ($ln -match '^CHOSEN|^CAPS') { 'Green' } else { 'DarkGray' }) } }
    if ($LASTEXITCODE -ne 0 -or $pickTxt -notmatch 'CHOSEN (\S+) (\d+) (0x[0-9a-f]+)') {
        Die ("没有候选拿到 CAP_SYS_MODULE。可以加大候选数（-Candidates 24/32）后重跑阶段 4。`n$pickTxt")
    }
    $script:Chosen = [pscustomobject]@{ Name = $Matches[1]; Pid = [int]$Matches[2]; Cred = HexToU64 $Matches[3] }
    Log ("  ✓ 选中 {0} pid={1} cred=0x{2:x}" -f $script:Chosen.Name, $script:Chosen.Pid, $script:Chosen.Cred) Green
}

# ---------------------------------------------------------------- 阶段 5

function Stage-CredWrite {
    Assert-NoReboot | Out-Null
    if (-not $script:Chosen) { Die "没有选中候选，无法写 cred。" }
    Log "== 阶段 5：cred 两阶段写（cap_bset→0，cap_effective→cred+0x40）==" Cyan

    $credHex = '0x{0:x}' -f $script:Chosen.Cred
    $live = Sh "cat /proc/$($script:Chosen.Pid)/status"
    if ($live.Text -notmatch 'Name:') { Die "候选进程 $($script:Chosen.Pid) 已退出，回阶段 4 重来。" }

    for ($i = 1; $i -le $Retries; $i++) {
        Log "  t64560_v34 cred=$credHex（第 $i/$Retries 轮，每轮最多 $Attempts attempts）"
        Invoke-DeviceLong "/data/local/tmp/t64560_v34 $credHex $Attempts $Attempts 400 16 6000 12000" "v34-$i" | Out-Null
        $log = Join-Path $script:RunDir "v34-$i.out.txt"
        if ((Test-Path $log) -and ((Get-Content -Raw $log) -match 'phase2 landed')) { break }
        Log "    本轮未完成两阶段" Yellow
        Assert-NoReboot | Out-Null
        if ($i -eq $Retries) { Die "cred 两阶段写在 $Retries 轮内没有完成。" }
    }

    Start-Sleep -Milliseconds 800
    $st = Sh "grep -E '^(Name|Uid|CapEff):' /proc/$($script:Chosen.Pid)/status"
    $stFlat = ($st.Text.Trim() -replace "`n", ' | ')
    Log "  $stFlat" DarkGray
    if ($st.Text -notmatch 'Uid:\s*0\s+0\s+0\s+0') { Die "候选进程没能变成 uid=0：`n$($st.Text)" }
    $want = '0x{0:x}' -f ($script:Chosen.Cred + 0x40)
    if ($st.Text -notmatch [regex]::Escape($want.Substring(2))) {
        Die "CapEff 与期望值 $want 不一致，拒绝继续加载模块。"
    } else {
        Log "  ✓ uid=0，CapEff=$want" Green
    }
}

# ---------------------------------------------------------------- 阶段 6

function Wait-Until {
    param([scriptblock]$Cond, [int]$TimeoutSec, [string]$What)
    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $TimeoutSec) {
        if (& $Cond) { return $true }
        Start-Sleep -Milliseconds 600
    }
    Log "  等待超时：$What" Yellow
    return $false
}

function Stage-LoadModule {
    Assert-NoReboot | Out-Null
    Log "== 阶段 6：加载 KernelSU 模块 ==" Cyan

    $mod = Sh 'grep kernelsu /proc/modules'
    if ($mod.Text.StartsWith('kernelsu')) { Log "  模块已加载，跳过" DarkGray; return }

    # 候选进程拿到能力后会自动 finit_module；没等到就显式触发一次
    $ok = Wait-Until { (Sh 'grep kernelsu /proc/modules').Text.StartsWith('kernelsu') } 12 '模块加载'
    if (-not $ok) {
        Log "  候选进程没有自动加载，触发 DOLOAD" DarkGray
        Sh 'touch /data/local/tmp/DOLOAD' | Out-Null
        $ok = Wait-Until { (Sh 'grep kernelsu /proc/modules').Text.StartsWith('kernelsu') } 15 '模块加载(DOLOAD)'
    }
    if (-not $ok) {
        $res = Sh 'cat /data/local/tmp/KSU_RESULT 2>&1'
        Die ("模块没有加载。KSU_RESULT：`n$($res.Text)`n" +
             "  ENOENT → 符号补丁/本次 boot kallsyms 不匹配；EINVAL → vermagic 不匹配。")
    }
    $m = Sh 'grep kernelsu /proc/modules'
    Log "  ✓ $($m.Text.Trim())" Green
    $kres = ((Sh 'cat /data/local/tmp/KSU_RESULT 2>&1').Text.Trim() -replace "`n", ' | ')
    Log "  $kres" DarkGray
}

# ---------------------------------------------------------------- 阶段 7

function Stage-Userspace {
    Assert-NoReboot | Out-Null
    Log "== 阶段 7：ksud install + 验收 su ==" Cyan

    $su = Sh 'su -c id'
    if ($su.Text -match 'uid=0') { Log "  su 已可用，跳过安装" DarkGray }
    else {
        Sh 'rm -f /data/local/tmp/CMD /data/local/tmp/rsh.out' | Out-Null
        Push-Text (Join-Path $script:DevDir 'install_ksu.sh') '/data/local/tmp/CMD.stage'
        # 先 chmod 再改名：直接推 CMD 会被候选进程抢在 chmod 之前消费掉
        $r = Sh 'chmod 755 /data/local/tmp/CMD.stage; mv /data/local/tmp/CMD.stage /data/local/tmp/CMD; echo staged'
        if ($r.Text -notmatch 'staged') { Die "无法布置 CMD：$($r.Text)" }

        $done = Wait-Until { $t = Sh 'cat /data/local/tmp/rsh.out 2>/dev/null'; $t.Text -match '=== done' } 90 'ksud install'
        $out = Sh 'cat /data/local/tmp/rsh.out 2>&1'
        foreach ($ln in $out.Lines) { if ($ln -match 'install_rc|=== |ksud|busybox|bootctl') { Log "    $ln" DarkGray } }
        if (-not $done) { Die "ksud install 超时：`n$($out.Text)" }
        if ($out.Text -notmatch 'install_rc=0') { Die "ksud install 失败：`n$($out.Text)" }
    }

    $final = Sh 'su -c id'
    if ($final.Text -notmatch 'uid=0') { Die "su 仍然不可用：`n$($final.Text)" }

    $info = Sh 'grep kernelsu /proc/modules; getenforce'
    Log ""
    Log "=================================================="  Green
    Log "  临时 root 已就绪" Green
    Log "=================================================="  Green
    $infoFlat = ($info.Text.Trim() -replace "`n", ' | ')
    Log "  $($final.Text.Trim())" Green
    Log "  $infoFlat" Green
    Log ""
    Log "  用法：  adb shell su -c id" White
    Log "          adb shell su -c sh" White
    Log "  撤销：  重启清除临时内核 Root；/data 中的文件和权限不保证自动还原。" White
    Log ""
    if (-not $SkipManagerFix) { Invoke-ManagerFix }
    else { Log "  已按 -SkipManagerFix 跳过管理器修复" Yellow }
    Log "=================================================="  Green
}

# ---------------------------------------------------------------- 主流程

function Invoke-ManagerFix {
    Assert-NoReboot | Out-Null
    Log "== KernelSU 管理器：检查当前 appid，必要时触发正常重扫描 ==" Cyan
    $boot = (Sh 'cat /proc/sys/kernel/random/boot_id').Text.Trim()
    if ($boot -notmatch '^[a-f0-9-]{36}$') { Die "无法读取 boot_id，未运行管理器修复" }
    $tag = "{0}-{1}" -f (Get-Date -Format 'yyyyMMddHHmmssfff'), $PID
    $remoteStage = "/data/local/tmp/mi18-manager-$tag"
    $private = "/data/adb/mi18-manager-$tag"
    $mk = Sh "mkdir -m 700 $remoteStage"
    if ($mk.Code -ne 0) { Die "无法准备管理器工具：$($mk.Text)" }
    $localScript = Join-Path $script:DevDir 'fix_ksu_manager.sh'
    $normalized = Join-Path $script:RunDir 'fix_ksu_manager.sh'
    [IO.File]::WriteAllText($normalized, ([IO.File]::ReadAllText($localScript) -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
    $probe = Join-Path $script:DevDir 'manager_probe'
    $shHash = (Get-FileHash -LiteralPath $normalized -Algorithm SHA256).Hash.ToLowerInvariant()
    $binHash = (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash.ToLowerInvariant()
    foreach ($item in @(@($normalized, "$remoteStage/fix_ksu_manager.sh"), @($probe, "$remoteStage/manager_probe"))) {
        $pushed = AdbOk @('push', $item[0], $item[1])
        if ($pushed.Code -ne 0) { Die "管理器工具推送失败：$($pushed.Text)" }
    }
    # Execute only hash-checked copies in a new Root-private directory.
    $prepare = "mkdir -m 700 $private && cp $remoteStage/fix_ksu_manager.sh $remoteStage/manager_probe $private/ && chown 0:0 $private/* && chmod 700 $private/* && " +
        "[ `"`$(sha256sum $private/fix_ksu_manager.sh | cut -d ' ' -f 1)`" = $shHash ] && [ `"`$(sha256sum $private/manager_probe | cut -d ' ' -f 1)`" = $binHash ]"
    # Avoid nested single quotes in su's command string.
    $prepare = $prepare.Replace("cut -d ' ' -f 1", 'cut -c 1-64')
    $prepared = Sh "su -M -c '$prepare'"
    if ($prepared.Code -ne 0) { Die "管理器工具校验失败，未执行：$($prepared.Text)" }
    $action = if ($ForceManagerRescan) { '--force-rescan' } else { '--repair' }
    $result = Sh "su -M -c 'sh $private/fix_ksu_manager.sh $boot $action'"
    [IO.File]::WriteAllText((Join-Path $script:RunDir 'manager-fix.txt'), $result.Text)
    Sh "rm -f $remoteStage/fix_ksu_manager.sh $remoteStage/manager_probe; rmdir $remoteStage" | Out-Null
    foreach ($line in $result.Lines) { Log "  $line" $(if ($line -match 'MANAGER_OK') { 'Green' } else { 'DarkGray' }) }
    if ($result.Code -ne 0 -or $result.Text -notmatch 'MANAGER_OK') {
        Log "  Root 仍可用，但管理器修复未通过。不会重新提权或重载模块；日志：$script:RunDir\manager-fix.txt" Yellow
        exit 2
    }
    $activity = (Sh 'cmd package resolve-activity --brief --user 0 -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p me.weishu.kernelsu').Lines |
        Where-Object { $_ -match '^me\.weishu\.kernelsu/[A-Za-z0-9_.$]+$' } | Select-Object -Last 1
    if ($activity) {
        $refresh = Sh "am force-stop --user 0 me.weishu.kernelsu; am start --user 0 -n $activity"
        if ($refresh.Code -ne 0) { Log "  内核已识别管理器；界面刷新失败，请手动重新打开 KernelSU。" Yellow }
        else { Log "  ✓ 管理器内核身份已确认，已重新打开 App 刷新显示" Green }
    } else { Log "  内核已识别管理器，请手动重新打开 KernelSU 刷新显示。" Yellow }
}

Log "小米 18 Pro 一键临时 root（CVE-2026-64560）" Cyan
Log "工作目录：$script:Proj" DarkGray

New-Item -ItemType Directory -Force -Path $script:RunDir | Out-Null

Invoke-Preflight
if ($Preflight) { Log "预检完成（-Preflight 不写设备，到此为止）" Green; exit 0 }
if ($ManagerOnly -or $script:AlreadyRoot) {
    if (-not $SkipManagerFix -and ($ManagerOnly -or $Through -eq 7)) { Invoke-ManagerFix }
    else { Log "已有 Root，本次未运行提权链或管理器修复" Green }
    exit 0
}
if ($script:ModuleLoaded) { Die "模块已加载但 su 不可用。拒绝重跑内核写入或重载模块；请先诊断用户态安装。" }

Deploy-All

$stages = @(
    @{ N = 1; Name = 'KASLR slide';      Fn = { Stage-Slide } },
    @{ N = 2; Name = 'SELinux permissive'; Fn = { Stage-Permissive } },
    @{ N = 3; Name = 'kprobe / 任意读';   Fn = { Stage-Kprobe } },
    @{ N = 4; Name = '候选与 cred';       Fn = { Stage-Candidates } },
    @{ N = 5; Name = 'cred 两阶段写';     Fn = { Stage-CredWrite } },
    @{ N = 6; Name = '加载模块';          Fn = { Stage-LoadModule } },
    @{ N = 7; Name = 'ksud 与验收';       Fn = { Stage-Userspace } }
)

foreach ($s in $stages) {
    if ($s.N -gt $Through) { break }
    & $s.Fn
}

if ($Through -eq 7 -and $script:Chosen) {
    Log "== 收尾：关闭本轮候选命令循环，恢复临时目录原权限 ==" Cyan
    $cleanup = & $script:Py (Join-Path $script:LibDir 'cleanup_bootstrap.py') --adb $script:Adb --serial $script:SelectedSerial --boot-id $script:BootId0 --candidates (Join-Path $script:RunDir 'cands.json') --tmp-mode $script:TmpMode0 2>&1
    if ($LASTEXITCODE -ne 0) { Die "Root 已可用，但收尾检查失败：`n$($cleanup -join "`n")" }
    Log "  ✓ 临时候选已退出，KernelSU su 仍然可用，目录权限已恢复" Green
}

if ($Through -lt 7) {
    Log "已按要求停在阶段 $Through（未完成全部）。重启清除临时内核状态，/data 中的文件可能保留。" Yellow
}
