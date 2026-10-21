#!/usr/bin/env python3
"""Close only this run's candidate command loops after KernelSU su works."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--boot-id", required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--tmp-mode", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-7]{3,4}", args.tmp_mode):
        raise ValueError("Invalid original temporary-directory mode")
    adb = [args.adb, "-s", args.serial, "shell"]

    def shell(command, root=False, check=True):
        text = "su -M -c " + shlex.quote(command) if root else command
        return subprocess.run(adb + [text], capture_output=True, text=True, timeout=15, check=check)

    def same_boot():
        actual = shell("cat /proc/sys/kernel/random/boot_id").stdout.strip()
        if actual != args.boot_id:
            raise ValueError("Boot changed; no candidate cleanup performed")

    same_boot()
    if "uid=0(root)" not in shell("id", root=True).stdout:
        raise ValueError("KernelSU su must work before removing bootstrap processes")
    candidates = json.loads(args.candidates.read_text())
    stopped, skipped = [], []
    for item in candidates:
        pid, name = int(item["pid"]), str(item["name"])
        if pid <= 1 or not re.fullmatch(r"KC\d+", name):
            raise ValueError("Invalid candidate identity")
        same_boot()
        # Check actual argv, rather than killing by a broad pgrep expression.
        result = shell(f"cat /proc/{pid}/cmdline", root=True, check=False)
        argv = result.stdout.rstrip("\0").split("\0")
        if argv != ["/data/local/tmp/t64560_v34", "--cand", name]:
            skipped.append(pid)
            continue
        shell(f"kill -TERM {pid}", root=True)
        stopped.append(pid)
    time.sleep(0.3)
    same_boot()
    # The one persistent tracing probe created by setup_kprobe.sh is no longer needed.
    # Do not disable global tracing or remove any other group's probes.
    shell("if [ -e /sys/kernel/tracing/events/fbc/comm/enable ]; then "
          "echo 0 > /sys/kernel/tracing/events/fbc/comm/enable && "
          "printf -- '-:fbc/comm\\n' >> /sys/kernel/tracing/kprobe_events; fi", root=True)
    shell("rm -f /data/local/tmp/CMD /data/local/tmp/CMD.run /data/local/tmp/DOLOAD "
          "/data/local/tmp/NOLOAD", root=True)
    shell(f"chmod {args.tmp_mode} /data/local/tmp", root=True)
    if "uid=0(root)" not in shell("id", root=True).stdout:
        raise ValueError("KernelSU su check failed after bootstrap cleanup")
    mode = shell("stat -c %a /data/local/tmp", root=True).stdout.strip()
    if int(mode, 8) != int(args.tmp_mode, 8):
        raise ValueError("Temporary-directory permissions not restored")
    report = {"status": "passed", "candidate_pids_stopped": stopped,
              "candidate_pids_already_gone_or_not_matching": skipped,
              "tmp_mode_restored": mode, "su_still_working": True,
              "kernelsu_module_unloaded": False}
    args.candidates.with_name("bootstrap-cleanup.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
