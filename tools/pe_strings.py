"""Find RVAs of interesting strings in simpro.exe."""
import re
import sys

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
data = open(path, "rb").read()

terms = [b"sendOperation", b"BaseHidDevice", b"Operation->", b"set base send",
         b"upgradeTorque", b"SyncCurrentTorque", b"upgrade torque", b"torque",
         b"max_torque", b"can_unlock_torque", b"get_dev_upgrade_torque_info"]

# map file offset -> RVA using section headers parsed by pefile
import pefile
pe = pefile.PE(path, fast_load=True)
secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]


def off2rva(off):
    for va, ptr, raw in secs:
        if ptr <= off < ptr + raw:
            return va + (off - ptr)
    return None


for t in terms:
    hits = [m.start() for m in re.finditer(re.escape(t), data)]
    print(f"\n{t!r}: {len(hits)} hits")
    for h in hits[:12]:
        rva = off2rva(h)
        # print surrounding ascii
        s = data[max(0, h - 40):h + 100]
        disp = "".join(chr(c) if 32 <= c < 127 else "." for c in s)
        print(f"  off=0x{h:x} rva={hex(rva) if rva else None}  ...{disp}...")
