#!/system/bin/sh
# install_ksu.sh —— 由拿到 uid=0 的候选进程通过 /data/local/tmp/CMD 机制执行
# 输出会被 run_script() 重定向到 /data/local/tmp/rsh.out
T=/data/local/tmp

echo "=== probe uid=$(id -u)"
if [ ! -x $T/ksud ]; then
    echo "FATAL ksud missing or not executable"
    echo "=== done"
    exit 1
fi

echo "--- ksud install ---"
$T/ksud install 2>&1
echo "install_rc=$?"

echo "--- /data/adb/ksu/bin ---"
ls -l /data/adb/ksu/bin 2>&1

echo "=== done"
