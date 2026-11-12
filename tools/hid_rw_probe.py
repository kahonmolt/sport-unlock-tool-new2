"""Feature report 0x23 writeability probe (NON-DESTRUCTIVE).

Reads report 0x23, writes the identical 32 bytes back, reads again.
No field is changed. If SetFeature(0x23) fails, the torque report is read-only.
"""
import hid
import time

VID, PID = 0x3670, 0x0500

devs = hid.enumerate(VID, PID)
if not devs:
    raise SystemExit("device not found")
target = next((d for d in devs if d.get("usage_page") == 1 and d.get("usage") == 4), devs[0])
dev = hid.device()
dev.open_path(target["path"])
try:
    before = bytes(dev.get_feature_report(0x23, 32))
    print(f"before ({len(before)}B): {before.hex()}")
    print(f"  byte[5] (max_torque) = {before[5]}")

    to_write = bytes([0x23]) + before[1:32]
    print(f"writing back identical frame: {to_write.hex()}")
    try:
        n = dev.send_feature_report(to_write)
        print(f"send_feature_report returned {n}")
    except Exception as exc:  # noqa: BLE001
        print(f"send_feature_report FAILED: {exc}")

    time.sleep(0.3)
    after = bytes(dev.get_feature_report(0x23, 32))
    print(f"after  ({len(after)}B): {after.hex()}")
    print(f"  byte[5] = {after[5]}  changed={before != after}")
finally:
    dev.close()
