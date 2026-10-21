#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_elf.py — 确认 vmlinux.elf 可用（有一把关键符号）

用法: check_elf.py <vmlinux.elf>
输出: SYMS=<n> MISSING=none|<逗号列表>
退出码 0 表示四个关键符号都在。
"""
import sys

NEED = ["_text", "selinux_state", "__set_task_comm", "init_cred"]


def main(path):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        sys.stderr.write("缺少 pyelftools：pip install pyelftools\n")
        return 3
    try:
        e = ELFFile(open(path, "rb"))
    except Exception as ex:
        sys.stderr.write("打不开 ELF：%s\n" % ex)
        return 2

    names = set()
    for sec in e.iter_sections():
        if not sec.name.startswith(".symtab"):
            continue
        for s in sec.iter_symbols():
            if s.name:
                names.add(s.name)

    miss = [n for n in NEED if n not in names]
    print("SYMS=%d MISSING=%s" % (len(names), ",".join(miss) if miss else "none"))
    if miss:
        sys.stderr.write("vmlinux.elf 缺关键符号：%s\n" % ",".join(miss))
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
