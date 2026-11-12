"""Find 4-byte HID command packets built as byte stores in simpro.exe .text."""
import re
import struct

import pefile

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
data = open(path, "rb").read()
secs = [(s.Name.decode().rstrip("\x00"), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
_, tva, tptr, traw = next(s for s in secs if s[0] == ".text")
code = data[tptr:tptr + traw]

# sequence: C6 00 XX (byte [rax]=id) ... C6 40 01 XX ... C6 40 02 XX ... C6 40 03 XX
pat = re.compile(rb"\xc6\x00(.)(?:.{0,40}?)\xc6\x40\x01(.)(?:.{0,40}?)\xc6\x40\x02(.)(?:.{0,40}?)\xc6\x40\x03(.)", re.S)
seen = []
for m in pat.finditer(code):
    rid = m.group(1)[0]
    b1 = m.group(2)[0]
    b2 = m.group(3)[0]
    b3 = m.group(4)[0]
    rva = tva + m.start()
    seen.append((rva, rid, b1, b2, b3))

print(f"4-byte packet builders: {len(seen)}")
for rva, rid, b1, b2, b3 in seen:
    print(f"  rva=0x{rva:06x}  id=0x{rid:02x}  {b1:02x} {b2:02x} {b3:02x}")
