"""Dump printable strings in a byte range of simpro.exe, with RVAs."""
import pefile
import sys

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
data = open(path, "rb").read()
secs = [(s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData, s.Name.decode().rstrip("\x00")) for s in pe.sections]

lo = int(sys.argv[1], 0)
hi = int(sys.argv[2], 0)


def rva2off(rva):
    for va, ptr, raw, name in secs:
        if va <= rva < va + raw:
            return ptr + (rva - va)
    return None


start = rva2off(lo)
blob = data[start:start + (hi - lo)]
cur = bytearray()
curstart = 0
for i, c in enumerate(blob):
    if 32 <= c < 127 or c == 9:
        if not cur:
            curstart = i
        cur.append(c)
    else:
        if len(cur) >= 6:
            print(f"0x{lo + curstart:08x}  {cur.decode('ascii', 'replace')}")
        cur = bytearray()
if len(cur) >= 6:
    print(f"0x{lo + curstart:08x}  {cur.decode('ascii', 'replace')}")
