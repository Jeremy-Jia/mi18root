#!/system/bin/sh
# rdx.sh —— 任意内核 8 字节读
# 用法: rdx.sh [-q] 0xADDR [0xADDR2 ...]
# 说明:
#   trace 里 kprobe 事件只显示「事件名」，不显示「组/名」，所以 grep 用 "$EV: "。
#   读到后先 disable 再 printf 删除探针（已启用的探针删除会返回 EBUSY）。
T=/sys/kernel/tracing
EV=r$$
Q=0
if [ "$1" = "-q" ]; then Q=1; shift; fi

printf -- "-:rdx/$EV\n" >> $T/kprobe_events 2>/dev/null
line="p:rdx/$EV __set_task_comm"
n=0
for a in "$@"; do
    line="$line v$n=@$a"
    n=$((n + 1))
done
printf -- "%s\n" "$line" >> $T/kprobe_events || { echo ADD_FAIL; exit 1; }

CLASSPATH=/data/local/tmp/caplog.jar app_process64 /system/bin CapLog \
    miui.mqsas.IMQSNative 7 $T/events/rdx/$EV/enable '1' >/dev/null 2>&1

: > $T/trace 2>/dev/null
echo RDX$EV > /proc/self/comm
sleep 0.25

if [ $Q -eq 1 ]; then
    grep "$EV: " $T/trace | tail -1 | sed "s|.*$EV: ||"
else
    echo "--- $n addrs ---"
    grep "$EV: " $T/trace | tail -1
fi

CLASSPATH=/data/local/tmp/caplog.jar app_process64 /system/bin CapLog \
    miui.mqsas.IMQSNative 7 $T/events/rdx/$EV/enable '0' >/dev/null 2>&1
printf -- "-:rdx/$EV\n" >> $T/kprobe_events 2>/dev/null
exit 0
