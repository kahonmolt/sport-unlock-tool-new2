#!/usr/bin/env python3
"""Attach Frida to all simpro.exe processes and log HID traffic for N seconds.

Usage: python hid_capture.py [seconds] [outfile]
Requires admin (to inject into simpro.exe).
"""
import json
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "hid_hook.js")


def on_message(msg, data, out, pid):
    if msg.get("type") == "send":
        payload = msg.get("payload", {})
        payload["pid"] = pid
        payload["ts"] = time.time()
        out.write(json.dumps(payload, sort_keys=True) + "\n")
        out.flush()
    else:
        out.write(json.dumps({"pid": pid, "frida_error": msg}) + "\n")
        out.flush()


def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    outpath = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "usbcap", "hid_api_capture.jsonl")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(SCRIPT, "r", encoding="utf-8") as fh:
        source = fh.read()

    device = frida.get_local_device()
    procs = [p for p in device.enumerate_processes() if p.name.lower() == "simpro.exe"]
    if not procs:
        print("no simpro.exe processes found")
        return 2
    print("simpro pids:", [p.pid for p in procs])

    sessions = []
    out = open(outpath, "w", encoding="utf-8")
    for p in procs:
        try:
            sess = device.attach(p.pid)
            script = sess.create_script(source)
            script.on("message", lambda m, d, pid=p.pid: on_message(m, d, out, pid))
            script.load()
            sessions.append(sess)
            print(f"attached {p.pid}")
        except Exception as exc:  # noqa: BLE001
            print(f"attach {p.pid} failed: {exc}")
    print(f"capturing {seconds}s -> {outpath}")
    time.sleep(seconds)
    for sess in sessions:
        try:
            sess.detach()
        except Exception:  # noqa: BLE001
            pass
    out.close()
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
