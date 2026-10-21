#!/bin/sh
# macOS Apple Silicon entry point. Everything platform-specific lives under runtime/mac.
set -eu
umask 077
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNTIME="$BASE/runtime/mac"
PWSH="$RUNTIME/powershell/pwsh"
PYTHON="$RUNTIME/python/bin/python3"
ADB="$RUNTIME/platform-tools/adb"

if [ ! -x "$PWSH" ] || [ ! -x "$PYTHON" ] || [ ! -x "$ADB" ]; then
    echo "macOS runtime missing; downloading PowerShell, Python and adb..."
    "$BASE/bootstrap/bootstrap-macos.sh"
fi

if [ ! -x "$PWSH" ] || [ ! -x "$PYTHON" ] || [ ! -x "$ADB" ]; then
    echo "Runtime setup failed. See bootstrap output above." >&2
    exit 1
fi

# Files copied from a downloaded portable zip may carry quarantine attributes.
xattr -dr com.apple.quarantine "$RUNTIME" 2>/dev/null || true

exec "$PWSH" -NoLogo -NoProfile -NonInteractive \
    -File "$BASE/tool/oneclick-root.ps1" \
    -AdbPath "$ADB" -PythonPath "$PYTHON" "$@"
