#!/system/bin/sh
# setup_kprobe.sh —— 建立 __set_task_comm 探针并打开它
# 前提：SELinux 已 permissive（否则 events/*/enable 写不进去）
#
# 两个已经踩过的坑：
#   1) 已 enable 的探针不能删（EBUSY）——必须先 code 7 写 enable=0 再删；
#   2) toybox 的 echo 会把 "-:name" 当成选项——必须用 printf -- '-:%s\n'。
T=/sys/kernel/tracing
CAP() { CLASSPATH=/data/local/tmp/caplog.jar app_process64 /system/bin CapLog miui.mqsas.IMQSNative 7 "$@"; }

for ev in $(grep -oE '^[pr]:[^ ]+' $T/kprobe_events 2>/dev/null | cut -d: -f2); do
    CAP "$T/events/$ev/enable" '0' >/dev/null 2>&1
    printf -- '-:%s\n' "$ev" >> $T/kprobe_events 2>/dev/null
done

echo 'p:fbc/comm __set_task_comm task=%x0 real=+0x900(%x0) cred=+0x908(%x0)' >> $T/kprobe_events
echo "add_rc=$?"
echo "probes_now=$(grep -c '^[pr]:' $T/kprobe_events 2>/dev/null)"

CAP "$T/events/fbc/comm/enable" '1' >/dev/null 2>&1
echo "enable=$(cat $T/events/fbc/comm/enable 2>/dev/null)"

echo 1 > $T/tracing_on
echo "tracing_on=$(cat $T/tracing_on)"

echo MARKER > /proc/self/comm
sleep 0.3
echo "--- trace tail ---"
tail -2 $T/trace 2>/dev/null
