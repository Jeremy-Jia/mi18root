#!/bin/sh
# First-run runtime bootstrap for Apple Silicon macOS.
# The offline portable zip already contains runtime/mac and does not need this script.
set -eu
umask 077
BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUNTIME="$BASE/runtime/mac"
CACHE="$RUNTIME/.downloads"
mkdir -p "$CACHE"

PWSH_URL='https://github.com/PowerShell/PowerShell/releases/download/v7.6.7/powershell-7.6.7-osx-arm64.tar.gz'
PWSH_SHA='50dde99bb066adacbb9a748182d09eb9beff25119dc3b12e85c84b6b6b1c5da9'
PY_URL='https://github.com/astral-sh/python-build-standalone/releases/download/20261020/cpython-3.12.15%2B20261020-aarch64-apple-darwin-install_only.tar.gz'
PY_SHA='921fc822416bbad146b026d2051dbfe08338ce4144ced64c56afd899a4351752'
ADB_URL='https://dl.google.com/android/repository/platform-tools_r37.0.1-darwin.zip'
ADB_SHA='ee39ad5967e95c2a07f04dbcbde96b1a0c916ba376096db5d2f498b7727a5d1d'

fetch() {
    url=$1; out=$2; expected=$3
    if [ ! -f "$out" ]; then
        echo "  downloading $(basename "$out")"
        curl -L --fail --retry 3 --connect-timeout 20 -o "$out" "$url"
    fi
    actual=$(shasum -a 256 "$out" | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        rm -f "$out"
        echo "SHA-256 mismatch for $(basename "$out")" >&2
        exit 1
    fi
}

if [ ! -x "$RUNTIME/powershell/pwsh" ]; then
    fetch "$PWSH_URL" "$CACHE/powershell.tar.gz" "$PWSH_SHA"
    mkdir -p "$RUNTIME/powershell"
    tar -xzf "$CACHE/powershell.tar.gz" -C "$RUNTIME/powershell"
    chmod +x "$RUNTIME/powershell/pwsh"
fi

if [ ! -x "$RUNTIME/python/bin/python3" ]; then
    fetch "$PY_URL" "$CACHE/python.tar.gz" "$PY_SHA"
    tar -xzf "$CACHE/python.tar.gz" -C "$RUNTIME"
fi

if [ ! -x "$RUNTIME/platform-tools/adb" ]; then
    if [ -f "$BASE/vendor/platform-tools-darwin-37.0.1.zip" ]; then
        cp "$BASE/vendor/platform-tools-darwin-37.0.1.zip" "$CACHE/platform-tools.zip"
    else
        fetch "$ADB_URL" "$CACHE/platform-tools.zip" "$ADB_SHA"
    fi
    actual=$(shasum -a 256 "$CACHE/platform-tools.zip" | awk '{print $1}')
    [ "$actual" = "$ADB_SHA" ] || { echo "SHA-256 mismatch for platform-tools" >&2; exit 1; }
    unzip -q -o "$CACHE/platform-tools.zip" -d "$RUNTIME"
    chmod +x "$RUNTIME/platform-tools/adb"
fi

"$RUNTIME/python/bin/python3" -m pip install --no-cache-dir --disable-pip-version-check \
    pyelftools==0.33 capstone==5.0.9
"$RUNTIME/python/bin/python3" -c 'import elftools, capstone; print("Python runtime OK:", elftools.__version__, capstone.__version__)'
xattr -dr com.apple.quarantine "$RUNTIME" 2>/dev/null || true
rm -rf "$CACHE"
echo "macOS runtime ready: $RUNTIME"
