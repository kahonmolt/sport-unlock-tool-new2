#!/usr/bin/env python3
"""Summarise the Frida HID capture: unique reports per API/handle/PID."""
import json
import os
import sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "usbcap", "hid_api_capture.jsonl")

rows = []
with open(path, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if line:
            rows.append(json.loads(line))

print(f"events: {len(rows)}")
print("\nby api/phase:")
for k, v in Counter((r.get("api"), r.get("phase")) for r in rows).most_common():
    print(f"  {k[0]:24s} {str(k[1]):6s} {v}")

print("\nby pid:")
for k, v in Counter(r.get("pid") for r in rows).most_common():
    print(f"  {k} {v}")

writes = [r for r in rows if r.get("api") == "WriteFile" and r.get("phase") == "leave" and r.get("ok")]
print(f"\nwrite leaves ok: {len(writes)}")

# Unique output payloads keyed by first 8 bytes + length
print("\nunique output reports (WriteFile enter):")
seen = OrderedDict()
for r in rows:
    if r.get("api") == "WriteFile" and r.get("phase") == "enter" and r.get("data"):
        d = r["data"]
        key = d[:16] + f"/{len(d)}"
        if key not in seen:
            seen[key] = {"count": 0, "first_ts": r["ts"], "pids": set(), "known": r.get("known")}
        seen[key]["count"] += 1
        seen[key]["pids"].add(r.get("pid"))
for key, info in seen.items():
    print(f"  {key} count={info['count']} ts={info['first_ts']:.3f} pids={sorted(info['pids'])} known={info['known']}")

print("\nunique input reports (ReadFile leave), by len+prefix:")
seen2 = OrderedDict()
for r in rows:
    if r.get("api") == "ReadFile" and r.get("phase") == "leave" and r.get("data"):
        d = r["data"]
        key = f"{len(d)//2}B:{d[:12]}"
        if key not in seen2:
            seen2[key] = {"count": 0, "first_ts": r["ts"], "pids": set(), "sample": d}
        seen2[key]["count"] += 1
        seen2[key]["pids"].add(r.get("pid"))
for key, info in list(seen2.items())[:40]:
    print(f"  {key} count={info['count']} sample={info['sample'][:80]}")

print("\nfeature reports:")
seen3 = OrderedDict()
for r in rows:
    if r.get("api") in ("HidD_GetFeature", "HidD_SetFeature") and r.get("phase") == "enter":
        d = r.get("data") or ""
        key = f"{r['api']}:{len(d)//2}B:{d[:16]}"
        seen3[key] = seen3.get(key, 0) + 1
for k, v in seen3.items():
    print(f"  {k} count={v}")
