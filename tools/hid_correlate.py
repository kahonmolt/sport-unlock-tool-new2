#!/usr/bin/env python3
"""Correlate SimPro log sendOperation lines with captured HID feature writes."""
import datetime as dt
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
cap = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "usbcap", "hid_api_capture.jsonl")
log = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
    os.environ["LOCALAPPDATA"], "SIMAGIC", "log", "simpro-2026-11-9.log")

ops = []
line_re = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\].*sendOperation.*Operation->(\d+) value->(-?\d+) res->(-?\d+)")
with open(log, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        m = line_re.search(line)
        if m:
            ts = dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f").timestamp()
            ops.append((ts, int(m.group(2)), int(m.group(3)), int(m.group(4))))

rows = []
with open(cap, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if r.get("api") == "HidD_SetFeature" and r.get("phase") == "enter":
            rows.append(r)
rows.sort(key=lambda r: r["ts"])

print(f"log sendOperation lines: {len(ops)}; captured SetFeature: {len(rows)}")
if rows:
    print("capture window:", dt.datetime.fromtimestamp(rows[0]["ts"]), "->", dt.datetime.fromtimestamp(rows[-1]["ts"]))
if ops:
    print("log window:", dt.datetime.fromtimestamp(ops[0][0]), "->", dt.datetime.fromtimestamp(ops[-1][0]))

# For each op line inside the capture window, show the SetFeature events around it.
lo, hi = rows[0]["ts"] - 1, rows[-1]["ts"] + 1
inside = [o for o in ops if lo <= o[0] <= hi]
print(f"\nop lines inside capture window: {len(inside)}")
for ts, op, val, res in inside[:12]:
    near = [r for r in rows if abs(r["ts"] - ts) <= 0.30]
    print(f"\nLOG {dt.datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]} op={op} value={val} res={res}  near={len(near)}")
    for r in near:
        d = r.get("data") or ""
        print(f"   +{(r['ts']-ts)*1000:7.1f}ms len={r['len']} {d[:64]}")

# Distinct full payloads
print("\n--- distinct SetFeature payloads (first 48 hex, len) ---")
c = Counter(((r.get("data") or "")[:48], r["len"]) for r in rows)
for (prefix, ln), n in c.most_common():
    print(f"  {n:5d}  {ln:3d}B  {prefix}")
