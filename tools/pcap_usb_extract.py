#!/usr/bin/env python3
"""Extract Simagic HID transfers from a USBPcap .pcap file.

USBPcap writes a normal libpcap file with DLT_USBPCAP (249). Each record is
followed by a USBPcap header:

    uint16 headerLen      (includes this field)
    uint64 irpId
    uint32 status
    uint16 function
    uint8  info           bit0 = device->host, bit1 = host->device
    uint16 bus
    uint16 device         (USB address)
    uint8  endpoint
    uint8  transfer       0=iso 1=interrupt 2=control 3=bulk
    uint32 dataLength

For self-test:  python pcap_usb_extract.py --selftest
"""
import struct
import sys

USBPcapHeaderLen = 27
TRANSFER = {0: "iso", 1: "interrupt", 2: "control", 3: "bulk"}
# USBPcap info bit 0 (0x01) = PDO->FDO = device -> host.
INFO_TO_HOST = 0x01
INFO_FROM_HOST = 0x00


def parse_pcap(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 24:
        raise SystemExit("file too small")
    magic = struct.unpack_from("<I", blob, 0)[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    elif magic == 0xA1B23C4D:
        endian, nano = "<", True
    else:
        raise SystemExit(f"not a pcap (magic 0x{magic:08x})")
    _, vmaj, vmin, tz, sig, snap, network = struct.unpack_from(endian + "IHHIIII", blob, 0)
    if network != 249:
        print(f"warning: linktype {network} (expected 249 DLT_USBPCAP)", file=sys.stderr)
    off = 24
    pkts = []
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl, orig = struct.unpack_from(endian + "IIII", blob, off)
        off += 16
        if off + incl > len(blob):
            break
        pkts.append((ts_sec, ts_usec, blob[off:off + incl]))
        off += incl
    return pkts


def parse_usbpcap(payload):
    if len(payload) < USBPcapHeaderLen:
        return None
    hlen, irp, status, func, info, bus, dev, ep, transfer, dlen = struct.unpack_from("<HQIHBHHBBI", payload, 0)
    data = payload[hlen:hlen + dlen]
    return {
        "header_len": hlen,
        "irp": irp,
        "status": status,
        "function": func,
        "info": info,
        "bus": bus,
        "device": dev,
        "endpoint": ep,
        "transfer": transfer,
        "data": data,
        "to_host": bool(info & INFO_TO_HOST),
        "from_host": not bool(info & INFO_TO_HOST),
    }


def find_simagic_address(pkts):
    """Return USB addresses whose device descriptor vendor id is 0x3670."""
    found = set()
    for _, _, payload in pkts:
        p = parse_usbpcap(payload)
        if not p or p["transfer"] != 2:
            continue
        d = p["data"]
        # control request setup packet is the first 8 bytes
        if len(d) >= 8:
            bmRequestType, bRequest, wValue, wIndex, wLength = struct.unpack_from("<BBHHH", d, 0)
            if bmRequestType == 0x80 and bRequest == 6 and wValue == 0x0100 and len(d) >= 18:
                vid = struct.unpack_from("<H", d, 8 + 8)[0]
                if vid == 0x3670:
                    found.add((p["bus"], p["device"]))
        # injected descriptor record: device descriptor at data start
        if len(d) >= 18 and d[1] == 1 and struct.unpack_from("<H", d, 8)[0] == 0x3670:
            found.add((p["bus"], p["device"]))
    return found


def main():
    if "--selftest" in sys.argv:
        return selftest()
    if len(sys.argv) < 2:
        raise SystemExit("usage: pcap_usb_extract.py <file.pcap>")
    path = sys.argv[1]
    pkts = parse_pcap(path)
    print(f"packets: {len(pkts)}")
    sim = find_simagic_address(pkts)
    print(f"Simagic (vid 0x3670) bus/address: {sorted(sim)}")
    rows = []
    for ts_sec, ts_usec, payload in pkts:
        p = parse_usbpcap(payload)
        if not p or p["transfer"] != 1:
            continue
        if sim and (p["bus"], p["device"]) not in sim:
            continue
        if not sim and len(p["data"]) not in (64, 65):
            continue
        direction = "IN " if p["to_host"] else "OUT"
        rows.append((ts_sec + ts_usec / 1e6, direction, p["endpoint"], p["data"].hex()))
    print(f"interrupt transfers: {len(rows)}")
    for ts, d, ep, data in rows[:200]:
        print(f"{ts:.6f} {d} ep=0x{ep:02x} {data}")
    print(f"... ({len(rows)} total)")
    return 0


def selftest():
    """Build a synthetic USBPcap file and parse it back."""
    def rec(ts, bus, dev, ep, transfer, info, data):
        uh = struct.pack("<HQIHBHHBBI", 27, 1, 0, 0, info, bus, dev, ep, transfer, len(data))
        return uh + data

    descriptor = bytes([18, 1, 0x00, 0x02, 0, 0, 0, 64]) + struct.pack("<HHH", 0x3670, 0x0500, 0x0210)
    setup = struct.pack("<BBHHH", 0x80, 6, 0x0100, 0, 18)
    packets = [
        rec(1, 97, 2, 0x80, 2, INFO_TO_HOST, setup + descriptor),
        rec(2, 97, 2, 0x01, 1, INFO_FROM_HOST, bytes(range(64))),
        rec(3, 97, 2, 0x81, 1, INFO_TO_HOST, bytes([0x01]) + bytes(63)),
    ]
    body = b"".join(struct.pack("<IIII", 0, 0, len(p), len(p)) + p for p in packets)
    hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 249)
    open("tools/usbcap/_selftest.pcap", "wb").write(hdr + body)
    pkts = parse_pcap("tools/usbcap/_selftest.pcap")
    sim = find_simagic_address(pkts)
    assert sim == {(97, 2)}, sim
    assert len(pkts) == 3
    p_out = parse_usbpcap(pkts[1][2])
    assert p_out["transfer"] == 1 and p_out["from_host"] and p_out["data"][0] == 0
    p_in = parse_usbpcap(pkts[2][2])
    assert p_in["transfer"] == 1 and p_in["to_host"] and p_in["data"][0] == 1
    print("selftest ok: 3 records, Simagic detected at bus 97 address 2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
