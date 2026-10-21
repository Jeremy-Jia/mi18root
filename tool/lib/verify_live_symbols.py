#!/usr/bin/env python3
"""Fail closed unless four symbols match the ELF plus this boot's slide."""
import json
from pathlib import Path
import sys
from elftools.elf.elffile import ELFFile

REQUIRED = ("_text", "selinux_state", "__set_task_comm", "init_cred")


def verify(elf_path, kallsyms_path, slide, expected_selinux):
    with open(elf_path, "rb") as source:
        elf = ELFFile(source)
        symbols = elf.get_section_by_name(".symtab")
        if symbols is None:
            raise ValueError("ELF has no symbol table")
        linked = {s.name: int(s["st_value"]) for s in symbols.iter_symbols() if s.name in REQUIRED}
    live = {}
    for line in Path(kallsyms_path).read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] in REQUIRED:
            value = int(fields[0], 16)
            if value:
                live.setdefault(fields[2], value)
    checks = {}
    for name in REQUIRED:
        if name not in linked or name not in live:
            raise ValueError(f"Missing or masked symbol: {name}")
        expected = linked[name] + slide
        if live[name] != expected:
            raise ValueError(f"Symbol mismatch: {name}: live={live[name]:#x}, expected={expected:#x}")
        checks[name] = hex(live[name])
    if live["selinux_state"] != expected_selinux:
        raise ValueError("Derived selinux_state differs from the validated live symbol")
    return checks


def main():
    if len(sys.argv) != 5:
        print("usage: verify_live_symbols.py ELF KALLSYMS SLIDE SELINUX_STATE", file=sys.stderr)
        return 2
    try:
        checks = verify(sys.argv[1], sys.argv[2], int(sys.argv[3], 16), int(sys.argv[4], 16))
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({"status": "matched", "symbols": checks}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
