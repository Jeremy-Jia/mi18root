#!/system/bin/sh
# cstart.sh —— 启动 N 个 t64560_v34 候选进程并打印它们的 task/real_cred/cred
# 用法: cstart.sh [N] [prefix]
# 注意: pkill 的匹配串不能出现在本脚本自身的命令行里，否则会把执行者一起杀掉；
#       写成脚本文件执行就是为了避免这个（cmdline 是 sh /data/local/tmp/cstart.sh）。
T=/sys/kernel/tracing
N=${1:-16}
PFX=${2:-KC}

pkill -f "t64560_v34 --cand" 2>/dev/null
sleep 0.3
rm -f /data/local/tmp/cand_*.pid

: > $T/trace 2>/dev/null

i=0
while [ $i -lt $N ]; do
    nohup /data/local/tmp/t64560_v34 --cand $PFX$i >/dev/null 2>&1 &
    i=$((i + 1))
done
sleep 2

echo "alive=$(pgrep -c -f 't64560_v34 --cand')"
grep -E "$PFX[0-9]+-[0-9]+ +\[" $T/trace | grep 'comm:'
