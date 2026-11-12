#!/usr/bin/env python3
"""Decode Simagic HID control + interrupt traffic from a USBPcap pcap."""
import struct
import sys
from collections import Counter, OrderedDict

sys.path.insert(0, "tools")
from pcap_usb_extract import parse_pcap, parse_usbpcap  # noqa: E402

REQ = {
    (0x21, 0x0A): "SET_IDLE",
    (0x21, 0x09): "SET_REPORT",
    (0xA1, 0x01): "GET_REPORT",
    (0x81, 0x06): "GET_DESCRIPTOR",
    (0x21, 0x0B): "SET_PROTOCOL",
    (0x21, 0x0C): "SET_DESCRIPTOR",
}


def req_name(bm, br):
    n = REQ.get((bm, br))
    if n:
        return n
    if bm == 0x21:
        return f"CLASS_OUT(0x{br:02x})"
    if bm == 0xA1:
        return f"CLASS_IN(0x{br:02x})"
    return f"0x{bm:02x}/0x{br:02x}"


def main():
    path = sys.argv[1]
    bus, addr = (int(sys.argv[2]), int(sys.argv[3])) if len(sys.argv) > 3 else (2, 12)
    pkts = parse_pcap(path)
    print(f"file: {path}  packets: {len(pkts)}  device: bus {bus} addr {addr}")

    pending = {}
    exchange = []  # (ts, direction, name, bm, br, value, index, wlen, payload)
    setups = Counter()
    intr_in = Counter()
    intr_first = {}

    for ts_sec, ts_usec, payload in pkts:
        p = parse_usbpcap(payload)
        if not p or p["bus"] != bus or p["device"] != addr:
            continue
        ts = ts_sec + ts_usec / 1e6
        if p["transfer"] == 2:
            d = p["data"]
            if p["from_host"] and len(d) >= 8:
                bm, br, wval, widx, wlen = struct.unpack_from("<BBHHH", d, 0)
                pending[p["irp"]] = (bm, br, wval, widx, wlen)
                out = d[8:]
                if out:
                    exchange.append((ts, "OUT", req_name(bm, br), bm, br, wval, widx, wlen, out))
                setups[(req_name(bm, br), bm, br, wval, widx, wlen)] += 1
            elif p["to_host"] and d and p["irp"] in pending:
                bm, br, wval, widx, wlen = pending[p["irp"]]
                exchange.append((ts, "IN ", req_name(bm, br), bm, br, wval, widx, wlen, d))
        elif p["transfer"] == 1 and p["to_host"] and p["data"]:
            h = p["data"].hex()
            intr_in[h] += 1
            intr_first.setdefault(h, ts)

    print("\n=== unique HID GET/SET_REPORT exchanges ===")
    seen = OrderedDict()
    for ts, direction, name, bm, br, wval, widx, wlen, data in exchange:
        if name not in ("SET_REPORT", "GET_REPORT"):
            continue
        key = (direction, name, wval, wlen, len(data), data[:16].hex())
        if key not in seen:
            seen[key] = {"n": 0, "first": ts, "data": data, "wval": wval, "dir": direction}
        seen[key]["n"] += 1
    for k, v in seen.items():
        print(f"{v['dir']} {k[1]:10s} value=0x{k[2]:04x} (report 0x{k[2] & 0xff:02x}) "
              f"wlen={k[3]} payload={k[4]}B count={v['n']} first={v['first']:.3f}")
        print(f"    {v['data'][:80].hex()}{'...' if len(v['data']) > 80 else ''}")

    print("\n=== interrupt IN reports (unique, len + count) ===")
    for h, n in intr_in.most_common(6):
        b = bytes.fromhex(h)
        print(f"count={n:6d} len={len(b):3d} id=0x{b[0]:02x} {h[:120]}")

    print("\n=== op-14 frames (>7 s apart) ===")
    last = 0
    for ts, direction, name, bm, br, wval, widx, wlen, data in exchange:
        if name == "SET_REPORT" and data[:2] == b"\x80\x05" and ts - last > 7:
            last = ts
            print(f"{ts:.3f} {data[:16].hex()}")
    print("\n=== GET_REPORT responses (report 0x23/0x90/0x03) ===")
    for ts, direction, name, bm, br, wval, widx, wlen, data in exchange:
        if name == "GET_REPORT" and direction == "IN ":
            print(f"{ts:.3f} value=0x{wval:04x} wlen={wlen} got={len(data)} {data[:40].hex()}")


if __name__ == "__main__":
    main()
