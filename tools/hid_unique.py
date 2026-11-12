"""Produce a markdown table of unique HID frames from the Frida capture."""
import json
from collections import Counter, OrderedDict

p = "tools/usbcap/hid_api_capture.jsonl"
rows = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]

writes = [r for r in rows if r.get("api") == "HidD_SetFeature" and r.get("phase") == "enter"]
gets = [r for r in rows if r.get("api") == "HidD_GetFeature" and r.get("phase") == "leave"]
reads = [r for r in rows if r.get("api") == "ReadFile" and r.get("phase") == "leave" and r.get("data")]

uniq_w = OrderedDict()
for r in writes:
    d = r["data"]
    key = d[:8]
    if key not in uniq_w:
        uniq_w[key] = {"n": 0, "data": d}
    uniq_w[key]["n"] += 1

uniq_g = OrderedDict()
for r in gets:
    d = r.get("data") or ""
    key = d[:8]
    if key not in uniq_g:
        uniq_g[key] = {"n": 0, "data": d}
    uniq_g[key]["n"] += 1

uniq_r = OrderedDict()
for r in reads:
    d = r["data"]
    key = d[:8]
    if key not in uniq_r:
        uniq_r[key] = {"n": 0, "data": d, "len": r.get("got")}
    uniq_r[key]["n"] += 1

print("## SetFeature (host -> device) unique frames\n")
for k, v in uniq_w.items():
    print(f"count={v['n']} len={len(v['data'])//2}B")
    print(f"```\n{v['data']}\n```\n")

print("## GetFeature (device -> host) unique responses\n")
for k, v in uniq_g.items():
    print(f"count={v['n']} len={len(v['data'])//2}B")
    print(f"```\n{v['data']}\n```\n")

print("## ReadFile (interrupt in) unique reports\n")
for k, v in uniq_r.items():
    print(f"count={v['n']} len={v['len']}B")
    print(f"```\n{v['data']}\n```\n")
