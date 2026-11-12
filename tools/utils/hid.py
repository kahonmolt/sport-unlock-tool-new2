"""Optional read-only HID backup helpers (Alpha Evo Sport).

Protocol facts from FINDINGS_USB.md:

* feature report ``0x23`` (32 bytes) carries ``max_torque`` at byte 5.
* paged config reads use ``SET_REPORT 0x80 05 pp pp`` followed by
  ``GET_REPORT 0x90`` (241 bytes).

Nothing here writes a torque value.  The only SET_REPORT issued is the page
selector, which is exactly what SimPro itself sends while idle.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

VID = 0x3670
PID = 0x0500

STATUS_REPORT_ID = 0x23
STATUS_REPORT_LEN = 32
PAGE_REPORT_ID = 0x90
PAGE_REPORT_LEN = 241
PAGE_SELECT_REPORT_LEN = 64
CONFIG_PAGES = (0xBB, 0xCC, 0xDD, 0x00)


class HIDUnavailable(Exception):
    """Raised when hidapi is missing or no matching device is attached."""


def _hid_module():
    try:
        import hid  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on host
        raise HIDUnavailable(
            "hidapi is not installed; run: pip install hidapi"
        ) from exc
    return hid


def find_device() -> Optional[dict[str, Any]]:
    hid = _hid_module()
    for info in hid.enumerate(VID, PID):
        return dict(info)
    return None


def open_device():
    hid = _hid_module()
    info = find_device()
    if info is None:
        raise HIDUnavailable(
            "no SIMAGIC device with VID 0x%04X / PID 0x%04X" % (VID, PID)
        )
    device = hid.device()
    device.open_path(info["path"])
    return device, info


def parse_status(raw: bytes) -> dict[str, Any]:
    data = bytes(raw)
    parsed: dict[str, Any] = {
        "report_id": "0x%02X" % data[0] if data else None,
        "raw": data.hex(),
        "length": len(data),
    }
    if len(data) > 5 and data[0] == STATUS_REPORT_ID:
        parsed["max_torque"] = data[5]
        parsed["payload_hex"] = data[1:16].hex()
    return parsed


def read_status(device) -> tuple[bytes, dict[str, Any]]:
    raw = bytes(device.get_feature_report(STATUS_REPORT_ID, STATUS_REPORT_LEN))
    return raw, parse_status(raw)


def select_page(device, page: int) -> None:
    report = bytearray(PAGE_SELECT_REPORT_LEN)
    report[0] = 0x80
    report[1] = 0x05
    report[2] = page & 0xFF
    report[3] = page & 0xFF
    device.send_feature_report(bytes(report))


def read_page(device) -> bytes:
    return bytes(device.get_feature_report(PAGE_REPORT_ID, PAGE_REPORT_LEN))


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def backup(output_dir: "str | Path") -> dict[str, Any]:
    """Capture the status report and paged config blocks into ``output_dir``.

    Returns a summary dict.  Raises :class:`HIDUnavailable` when no device or
    hidapi is present so callers can decide whether that is fatal.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    device, info = open_device()
    try:
        status_raw, status = read_status(device)
        pages: dict[str, Any] = {}
        for page in CONFIG_PAGES:
            select_page(device, page)
            time.sleep(0.05)
            raw = read_page(device)
            name = "page_%02x" % page
            (out / (name + ".bin")).write_bytes(raw)
            pages[name] = {"length": len(raw), "hex": raw.hex()}
        summary = {
            "device": {
                key: _json_safe(info.get(key))
                for key in ("path", "vendor_id", "product_id", "serial_number",
                            "manufacturer_string", "product_string")
                if key in info
            },
            "status": status,
            "pages": pages,
        }
        (out / "device_status.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
        )
        return summary
    finally:
        try:
            device.close()
        except Exception:
            pass
