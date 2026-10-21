# First-run runtime bootstrap for Windows 10/11 x64.
# The offline portable zip already contains runtime\win and does not need this script.
$ErrorActionPreference = 'Stop'
$WinPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $WinPs)) { throw 'Windows PowerShell 5.1 is required (Windows 10/11).' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Base = Split-Path -Parent $PSScriptRoot
$Runtime = Join-Path $Base 'runtime\win'
$Cache = Join-Path $Runtime '.downloads'
New-Item -ItemType Directory -Force -Path $Runtime, $Cache | Out-Null

$PythonUrl = 'https://github.com/astral-sh/python-build-standalone/releases/download/20261020/cpython-3.12.15%2B20261020-x86_64-pc-windows-msvc-install_only.tar.gz'
$PythonSha = '5e7d27ae6181fcf1f992c5a221b8fa7a320e7fd576c476434886292ccf2e20fb'
$AdbUrl = 'https://dl.google.com/android/repository/platform-tools-latest-windows.zip'
$AdbSha = '45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99'

function Get-Checked([string]$Url, [string]$Out, [string]$Expected) {
    if (-not (Test-Path -LiteralPath $Out)) {
        Write-Host "  downloading $(Split-Path -Leaf $Out)"
        Invoke-WebRequest -Uri $Url -OutFile $Out -UseBasicParsing
    }
    $Actual = (Get-FileHash -LiteralPath $Out -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected.ToLowerInvariant()) {
        Remove-Item -LiteralPath $Out -Force
        throw "SHA-256 mismatch for $(Split-Path -Leaf $Out)"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $Runtime 'python\python.exe'))) {
    $PyArchive = Join-Path $Cache 'python.tar.gz'
    Get-Checked $PythonUrl $PyArchive $PythonSha
    if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) {
        throw 'tar.exe is required; Windows 10 1803+ provides it.'
    }
    & tar.exe -xzf $PyArchive -C $Runtime
    if ($LASTEXITCODE -ne 0) { throw 'Failed to extract Python runtime' }
}

if (-not (Test-Path -LiteralPath (Join-Path $Runtime 'platform-tools\adb.exe'))) {
    $AdbArchive = Join-Path $Cache 'platform-tools.zip'
    $Vendored = Join-Path $Base 'vendor\platform-tools-windows.zip'
    if (Test-Path -LiteralPath $Vendored) {
        Copy-Item -LiteralPath $Vendored -Destination $AdbArchive -Force
    } else {
        Get-Checked $AdbUrl $AdbArchive $AdbSha
    }
    $Actual = (Get-FileHash -LiteralPath $AdbArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $AdbSha.ToLowerInvariant()) { throw 'SHA-256 mismatch for platform-tools' }
    Expand-Archive -LiteralPath $AdbArchive -DestinationPath $Runtime -Force
}

$Python = Join-Path $Runtime 'python\python.exe'
$Adb = Join-Path $Runtime 'platform-tools\adb.exe'
if (-not (Test-Path -LiteralPath $Python)) { throw "Python runtime missing: $Python" }
if (-not (Test-Path -LiteralPath $Adb)) { throw "adb missing: $Adb" }

& $Python -m pip install --no-cache-dir --disable-pip-version-check pyelftools==0.33 capstone==5.0.9
if ($LASTEXITCODE -ne 0) { throw 'Failed to install pyelftools/capstone' }
& $Python -c 'import elftools, capstone; print("Python runtime OK:", elftools.__version__, capstone.__version__)'
if ($LASTEXITCODE -ne 0) { throw 'Python dependency check failed' }

Remove-Item -LiteralPath $Cache -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Windows runtime ready: $Runtime"
