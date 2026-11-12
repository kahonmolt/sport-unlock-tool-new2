"""Find all direct call/jmp targets to a function RVA and show the surrounding bytes/strings."""
import struct
import sys

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = r"C:\Program Files (x86)\simpro2\bin\simpro.exe"
pe = pefile.PE(path, fast_load=True)
data = open(path, "rb").read()
secs = [(s.Name.decode().rstrip("\x00"), s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
text = next(s for s in secs if s[0] == ".text")
_, tva, tptr, traw = text
code = data[tptr:tptr + traw]

target = int(sys.argv[1], 0)
hits = []
for i in range(len(code) - 5):
    if code[i] in (0xE8, 0xE9):
        disp = struct.unpack_from("<i", code, i + 1)[0]
        if tva + i + 5 + disp == target:
            hits.append(tva + i)

print(f"call/jmp sites to 0x{target:x}: {len(hits)}")
for h in hits:
    # find function start: nearest 0xCC CC padding before, then skip int3
    off = h - tva
    j = off
    while j > 0 and not (code[j - 1] == 0xCC and code[j - 2] == 0xCC):
        j -= 1
    print(f"  site 0x{h:x}   near_func_start 0x{tva + j:x}")
